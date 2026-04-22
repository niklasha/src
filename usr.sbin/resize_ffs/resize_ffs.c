/*	$OpenBSD$	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dkio.h>
#include <sys/disklabel.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ufs/ffs/fs.h>
#include <ufs/ufs/dir.h>
#include <ufs/ufs/dinode.h>

#include "resize_ffs.h"

#ifndef DOS_LABELSECTOR
#define DOS_LABELSECTOR	LABELSECTOR
#endif

#define RESIZE_JOURNAL_MAGIC	"RESIZEJ1"
#define RESIZE_JOURNAL_VERSION	1U
#define RESIZE_REC_MAGIC	0x52454331U

enum resize_jrec_type {
	RESIZE_REC_PHASE = 1,
	RESIZE_REC_INTENT = 2,
	RESIZE_REC_APPLIED = 3,
	RESIZE_REC_COMMIT = 4,
	RESIZE_REC_SBSET = 5
};

enum resize_phase {
	RESIZE_PHASE_PLANNED = 1,
	RESIZE_PHASE_RELOCATING = 2,
	RESIZE_PHASE_METADATA = 3,
	RESIZE_PHASE_COMMITTING = 4,
	RESIZE_PHASE_COMMITTED = 5
};

enum resize_policy {
	RESIZE_POLICY_TRUNCATE = 0,
	RESIZE_POLICY_SHRINK_MOVE = 1,
	RESIZE_POLICY_PUSH_FORWARD = 2
};

struct resize_options {
	const char *target_path;
	const char *journal_path;
	const char *moves_path;
	uint64_t offset_bytes;
	uint64_t size_bytes;
	int have_size;
	int dry_run;
	int recover;
	int revert;
	int resume;
	int force;
	int progress;
	int verbose;
	int check_invariants;
	enum resize_policy policy;
};

struct resize_label_info {
	int valid;
	int via_c_fallback;
	uint64_t secsize;
	uint64_t part_offset_sec;
	uint64_t part_size_sec;
	int err_target;
	int err_raw_c;
	int err_block;
	int err_block_c;
};

struct resize_super {
	uint64_t sb_rel_offset;
	uint64_t sb_abs_offset;
	uint64_t fs_size_blocks;
	uint64_t fs_size_bytes;
	uint32_t fs_fsize;
	uint32_t fs_magic;
	unsigned char raw[SBSIZE];
};

struct resize_jhdr_v1 {
	char magic[8];
	uint32_t version;
	uint32_t header_crc32;
	uint64_t created_unix_ns;
	uint64_t fs_offset_bytes;
	uint64_t old_fs_size_bytes;
	uint64_t new_fs_size_bytes;
	uint64_t sb_rel_offset;
	uint32_t fs_fsize;
	uint32_t phase;
	uint64_t next_seq;
	uint64_t reserved[8];
};

struct resize_jrec_v1 {
	uint32_t rec_magic;
	uint16_t rec_type;
	uint16_t op;
	uint64_t seq;
	uint64_t old_fsb;
	uint64_t new_fsb;
	uint32_t bytes;
	uint32_t flags;
	uint64_t owner_abs_offset;
	uint32_t owner_width;
	uint32_t aux;
	uint32_t rec_crc32;
};

struct resize_journal {
	int fd;
	struct resize_jhdr_v1 hdr;
};

struct resize_move_list {
	struct resize_move *moves;
	size_t nmoves;
	size_t cap;
};

struct resize_alloc_ent {
	uint64_t fsb;
	int allocated;
};

struct resize_alloc_map {
	struct resize_alloc_ent *ents;
	size_t nent;
	size_t cap;
};

struct resize_runtime {
	int tfd;
	uint64_t container_bytes;
	uint64_t fs_offset;
	uint32_t fs_fsize;
	struct fs fs;
	int dry_run;
	int progress;
	int verbose;
	int progress_active;
	const char *progress_phase;
	uint64_t progress_total;
	uint64_t progress_done;
	uint64_t progress_pct;
	struct resize_journal *jr;
	struct resize_alloc_map amap;
};

struct resize_free_pool {
	u_int8_t *map;
	uint64_t nbits;
	uint64_t cursor;
};

struct resize_plan_ctx {
	int tfd;
	uint64_t container_bytes;
	uint64_t fs_offset;
	const struct fs *fs;
	uint64_t old_blocks;
	uint64_t new_blocks;
	uint32_t fs_fsize;
	uint32_t fs_bsize;
	uint32_t ptr_width;
	uint32_t inode_size;
	uint32_t maxsymlinklen;
	int verbose;
	struct resize_free_pool pool;
};

struct resize_inode_view {
	uint16_t mode;
	uint64_t size;
	uint64_t db[NDADDR];
	uint64_t ib[NIADDR];
};

struct resize_ino_vec {
	ufsino_t *v;
	size_t n;
	size_t cap;
};

struct resize_ino_remap_ent {
	ufsino_t old_ino;
	ufsino_t new_ino;
};

struct resize_ino_remap {
	struct resize_ino_remap_ent *ents;
	size_t nent;
	size_t cap;
};

static uint32_t resize_crc32_table[256];
static int resize_crc32_ready;

static int resize_shift_image_up_journal(struct resize_runtime *, uint64_t,
    uint64_t, uint64_t);
static int resize_shift_rebase_super(struct resize_runtime *,
    struct resize_super *, uint64_t, uint64_t);
static int resize_rt_read_cg(struct resize_runtime *, uint32_t, u_int8_t **,
    struct cg **, uint64_t *);
static int resize_expected_cg_ncyl(const struct fs *, uint64_t, int16_t *);

static const char *
resize_policy_name(enum resize_policy p)
{
	switch (p) {
	case RESIZE_POLICY_TRUNCATE:
		return ("truncate");
	case RESIZE_POLICY_SHRINK_MOVE:
		return ("shrink-move");
	case RESIZE_POLICY_PUSH_FORWARD:
		return ("push-forward");
	default:
		return ("unknown");
	}
}

static void
resize_vlog(int enabled, const char *fmt, ...)
{
	va_list ap;

	if (!enabled)
		return;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void
resize_progress_begin(struct resize_runtime *rt, const char *phase,
    uint64_t total)
{
	if (rt == NULL || !rt->progress)
		return;
	if (rt->progress_active) {
		fprintf(stderr, "\n");
		rt->progress_active = 0;
	}
	rt->progress_active = 1;
	rt->progress_phase = (phase == NULL) ? "progress" : phase;
	rt->progress_total = (total == 0) ? 1 : total;
	rt->progress_done = UINT64_MAX;
	rt->progress_pct = UINT64_MAX;
}

static void
resize_progress_update(struct resize_runtime *rt, uint64_t done)
{
	uint64_t shown, pct;

	if (rt == NULL || !rt->progress || !rt->progress_active)
		return;
	shown = (done > rt->progress_total) ? rt->progress_total : done;
	pct = (shown * 100ULL) / rt->progress_total;
	if (shown == rt->progress_done && pct == rt->progress_pct &&
	    shown != rt->progress_total)
		return;
	rt->progress_done = shown;
	rt->progress_pct = pct;
	fprintf(stderr, "\r%-14s %3" PRIu64 "%% (%" PRIu64 "/%" PRIu64 ")",
	    rt->progress_phase, pct, shown, rt->progress_total);
	fflush(stderr);
}

static void
resize_progress_end(struct resize_runtime *rt, int success)
{
	if (rt == NULL || !rt->progress || !rt->progress_active)
		return;
	if (success)
		resize_progress_update(rt, rt->progress_total);
	fprintf(stderr, "\n");
	fflush(stderr);
	rt->progress_active = 0;
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [options] target\n"
	    "options:\n"
	    "  --offset <bytes>             default 0\n"
	    "  --size <bytes>               default partition/file size\n"
	    "  --policy truncate|shrink-move|push-forward  default truncate\n"
	    "  --shrink-side end|beginning  deprecated alias\n"
	    "  --journal <path>             default ./resize.journal\n"
	    "  --moves <path>               relocation plan file\n"
	    "  --dry-run\n"
	    "  --recover\n"
	    "  --revert\n"
	    "  --resume\n"
	    "  --force\n"
	    "  --progress\n"
	    "  --check-invariants\n"
	    "  --verbose\n",
	    getprogname());
}

static int
resize_mul_u64(uint64_t a, uint64_t b, uint64_t *out)
{
	if (a != 0 && b > UINT64_MAX / a)
		return (EOVERFLOW);
	*out = a * b;
	return (0);
}

static int
resize_add_u64(uint64_t a, uint64_t b, uint64_t *out)
{
	if (b > UINT64_MAX - a)
		return (EOVERFLOW);
	*out = a + b;
	return (0);
}

static int
resize_powerof2_u32(uint32_t v)
{
	return (v != 0 && (v & (v - 1U)) == 0);
}

static void
resize_crc32_init(void)
{
	uint32_t c;
	int i, j;

	if (resize_crc32_ready)
		return;
	for (i = 0; i < 256; i++) {
		c = (uint32_t)i;
		for (j = 0; j < 8; j++) {
			if (c & 1U)
				c = 0xedb88320U ^ (c >> 1);
			else
				c >>= 1;
		}
		resize_crc32_table[i] = c;
	}
	resize_crc32_ready = 1;
}

static uint32_t
resize_crc32_calc(const void *buf, size_t len)
{
	const unsigned char *p = buf;
	uint32_t crc = 0xffffffffU;
	size_t i;

	resize_crc32_init();
	for (i = 0; i < len; i++)
		crc = resize_crc32_table[(crc ^ p[i]) & 0xffU] ^ (crc >> 8);
	return (crc ^ 0xffffffffU);
}

static int
resize_parse_size(const char *s, uint64_t *out)
{
	char *ep;
	uint64_t base, mul = 1;
	int error;

	if (s == NULL || *s == '\0')
		return (EINVAL);

	errno = 0;
	base = strtoull(s, &ep, 10);
	if (errno != 0 || ep == s)
		return (EINVAL);

	if (*ep != '\0') {
		if (ep[1] != '\0')
			return (EINVAL);
		switch (*ep) {
		case 'k':
		case 'K':
			mul = 1024ULL;
			break;
		case 'm':
		case 'M':
			mul = 1024ULL * 1024ULL;
			break;
		case 'g':
		case 'G':
			mul = 1024ULL * 1024ULL * 1024ULL;
			break;
		case 't':
		case 'T':
			mul = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
			break;
		default:
			return (EINVAL);
		}
	}

	error = resize_mul_u64(base, mul, out);
	if (error != 0)
		return (error);
	return (0);
}

static int
resize_parse_policy(const char *s, enum resize_policy *policy)
{
	if (strcmp(s, "truncate") == 0) {
		*policy = RESIZE_POLICY_TRUNCATE;
		return (0);
	}
	if (strcmp(s, "shrink-move") == 0) {
		*policy = RESIZE_POLICY_SHRINK_MOVE;
		return (0);
	}
	if (strcmp(s, "push-forward") == 0) {
		*policy = RESIZE_POLICY_PUSH_FORWARD;
		return (0);
	}
	return (EINVAL);
}

static int
resize_parse_options(int argc, char **argv, struct resize_options *opt)
{
	static const struct option lopts[] = {
		{ "offset", required_argument, NULL, 'o' },
		{ "size", required_argument, NULL, 's' },
		{ "policy", required_argument, NULL, 'P' },
		{ "shrink-side", required_argument, NULL, 'S' },
		{ "journal", required_argument, NULL, 'j' },
		{ "moves", required_argument, NULL, 'm' },
		{ "dry-run", no_argument, NULL, 'n' },
		{ "recover", no_argument, NULL, 'r' },
		{ "revert", no_argument, NULL, 'R' },
		{ "resume", no_argument, NULL, 'u' },
		{ "force", no_argument, NULL, 'f' },
		{ "progress", no_argument, NULL, 'p' },
		{ "check-invariants", no_argument, NULL, 'C' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	int ch, error;

	memset(opt, 0, sizeof(*opt));
	opt->journal_path = "resize.journal";
	opt->policy = RESIZE_POLICY_TRUNCATE;

	while ((ch = getopt_long(argc, argv, "", lopts, NULL)) != -1) {
		switch (ch) {
		case 'o':
			error = resize_parse_size(optarg, &opt->offset_bytes);
			if (error != 0)
				return (error);
			break;
		case 's':
			error = resize_parse_size(optarg, &opt->size_bytes);
			if (error != 0)
				return (error);
			opt->have_size = 1;
			break;
		case 'P':
			error = resize_parse_policy(optarg, &opt->policy);
			if (error != 0)
				return (error);
			break;
		case 'S':
			if (strcmp(optarg, "end") == 0)
				opt->policy = RESIZE_POLICY_TRUNCATE;
			else if (strcmp(optarg, "beginning") == 0)
				opt->policy = RESIZE_POLICY_SHRINK_MOVE;
			else
				return (EINVAL);
			break;
		case 'j':
			opt->journal_path = optarg;
			break;
		case 'm':
			opt->moves_path = optarg;
			break;
		case 'n':
			opt->dry_run = 1;
			break;
		case 'r':
			opt->recover = 1;
			break;
		case 'R':
			opt->revert = 1;
			break;
		case 'u':
			opt->resume = 1;
			break;
		case 'f':
			opt->force = 1;
			break;
		case 'p':
			opt->progress = 1;
			break;
		case 'C':
			opt->check_invariants = 1;
			break;
		case 'v':
			opt->verbose = 1;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			return (EINVAL);
		}
	}

	if (optind >= argc)
		return (EINVAL);
	opt->target_path = argv[optind];
	if (optind + 1 != argc)
		return (EINVAL);
	if (opt->recover && opt->revert)
		return (EINVAL);
	if (opt->recover && opt->resume)
		return (EINVAL);
	if (opt->revert && opt->resume)
		return (EINVAL);
	if (opt->revert && opt->dry_run)
		return (EINVAL);
	if (opt->resume && opt->dry_run)
		return (EINVAL);
	return (0);
}

static int
resize_path_partition_index(const char *path, int *idx)
{
	size_t n;
	int pidx;

	if (path == NULL)
		return (EINVAL);
	n = strlen(path);
	if (n == 0)
		return (EINVAL);
	pidx = DL_PARTNAME2NUM(path[n - 1]);
	if (pidx < 0)
		return (ENOENT);
	*idx = pidx;
	return (0);
}

static int
resize_get_partition_bytes(int fd, const char *path, uint64_t *bytes)
{
	struct disklabel dl;
	struct partition *pp;
	int pidx, error;
	uint64_t secbytes, count;

	error = resize_path_partition_index(path, &pidx);
	if (error != 0)
		return (error);
	if (ioctl(fd, DIOCGDINFO, &dl) == -1 &&
	    ioctl(fd, DIOCGPDINFO, &dl) == -1)
		return (errno);
	if (pidx < 0 || pidx >= MAXPARTITIONS)
		return (EINVAL);
	pp = &dl.d_partitions[pidx];
	count = DL_GETPSIZE(pp);
	if (count == 0)
		return (ENOENT);
	secbytes = (dl.d_secsize != 0) ? (uint64_t)dl.d_secsize : DEV_BSIZE;
	error = resize_mul_u64(count, secbytes, bytes);
	if (error != 0)
		return (error);
	if (*bytes == 0)
		return (EINVAL);
	return (0);
}

static int
resize_get_label_info_from_dl(const struct disklabel *dl, int pidx,
    struct resize_label_info *li)
{
	const struct partition *pp;
	uint64_t psize;

	if (pidx < 0 || pidx >= MAXPARTITIONS)
		return (EINVAL);
	pp = &dl->d_partitions[pidx];
	psize = DL_GETPSIZE(pp);
	if (psize == 0)
		return (ENOENT);
	li->valid = 1;
	li->secsize = (dl->d_secsize != 0) ? (uint64_t)dl->d_secsize : DEV_BSIZE;
	li->part_offset_sec = DL_GETPOFFSET(pp);
	li->part_size_sec = psize;
	return (0);
}

static u_int16_t
resize_dkcksum(const struct disklabel *dl)
{
	const u_int16_t *start, *end;
	u_int16_t sum;
	u_int16_t nparts;

	nparts = dl->d_npartitions;
	if (nparts > MAXPARTITIONS)
		nparts = MAXPARTITIONS;
	start = (const u_int16_t *)dl;
	end = (const u_int16_t *)&dl->d_partitions[nparts];
	sum = 0;
	while (start < end)
		sum ^= *start++;
	return (sum);
}

static uint32_t
resize_le32dec(const unsigned char *p)
{
	return ((uint32_t)p[0] |
	    ((uint32_t)p[1] << 8) |
	    ((uint32_t)p[2] << 16) |
	    ((uint32_t)p[3] << 24));
}

static int
resize_scan_label_sector(const unsigned char *sec, struct disklabel *dl)
{
#ifdef MAXPARTITIONS16
	enum { RESIZE_SKINNY_PARTS = MAXPARTITIONS16 };
#else
	enum { RESIZE_SKINNY_PARTS = 16 };
#endif
	struct disklabel cand;
	const size_t lpsz = offsetof(struct disklabel,
	    d_partitions[RESIZE_SKINNY_PARTS]);
	const struct disklabel *dp, *elp;

	if (lpsz > DEV_BSIZE)
		return (ENOTSUP);
	elp = (const struct disklabel *)(const void *)(sec + DEV_BSIZE - lpsz);
	for (dp = (const struct disklabel *)(const void *)sec; dp <= elp;
	    dp = (const struct disklabel *)(const void *)((const char *)dp +
	    sizeof(long))) {
		if (dp->d_magic != DISKMAGIC || dp->d_magic2 != DISKMAGIC)
			continue;
		if (dp->d_npartitions > RESIZE_SKINNY_PARTS)
			continue;
		if (resize_dkcksum(dp) != 0)
			continue;
		memset(&cand, 0, sizeof(cand));
		memcpy(&cand, dp, lpsz);
		*dl = cand;
		return (0);
	}
	return (ENOENT);
}

static int
resize_read_sector512(int fd, uint64_t secno, unsigned char *sec)
{
	uint64_t abs;
	ssize_t n;
	int error;

	error = resize_mul_u64(secno, DEV_BSIZE, &abs);
	if (error != 0)
		return (error);
	n = pread(fd, sec, DEV_BSIZE, (off_t)abs);
	if (n != (ssize_t)DEV_BSIZE)
		return (errno != 0 ? errno : EIO);
	return (0);
}

static int
resize_read_disklabel_from_fd(int fd, struct disklabel *dl)
{
	unsigned char sec[DEV_BSIZE];
	uint64_t lba, partoff;
	size_t i, pass;
	uint8_t ptype;
	int error, have_mbr;
	const unsigned char *dp;

	error = resize_read_sector512(fd, DOS_LABELSECTOR, sec);
	if (error == 0) {
		error = resize_scan_label_sector(sec, dl);
		if (error == 0)
			return (0);
		if (error != ENOENT)
			return (error);
	}

	error = resize_read_sector512(fd, DOSBBSECTOR, sec);
	if (error != 0)
		return (error);
	have_mbr = (sec[DOSMBR_SIGNATURE_OFF] == 0x55 &&
	    sec[DOSMBR_SIGNATURE_OFF + 1] == 0xaa);
	if (!have_mbr)
		return (ENOENT);

	for (pass = 0; pass < 2; pass++) {
		for (i = 0; i < NDOSPART; i++) {
			dp = &sec[DOSPARTOFF + i * sizeof(struct dos_partition)];
			ptype = dp[4];
			partoff = resize_le32dec(dp + 8);
			if (partoff == 0)
				continue;
			if (pass == 0) {
				if (ptype != DOSPTYP_OPENBSD &&
				    ptype != DOSPTYP_NETBSD &&
				    ptype != DOSPTYP_FREEBSD)
					continue;
			} else {
				if (ptype == DOSPTYP_UNUSED ||
				    ptype == DOSPTYP_EXTEND ||
				    ptype == DOSPTYP_EXTENDL)
					continue;
				if (ptype == DOSPTYP_OPENBSD ||
				    ptype == DOSPTYP_NETBSD ||
				    ptype == DOSPTYP_FREEBSD)
					continue;
			}
			error = resize_add_u64(partoff, DOS_LABELSECTOR, &lba);
			if (error != 0)
				return (error);
			error = resize_read_sector512(fd, lba, sec);
			if (error != 0)
				continue;
			error = resize_scan_label_sector(sec, dl);
			if (error == 0)
				return (0);
			if (error != ENOENT)
				return (error);
		}
	}
	return (ENOENT);
}

static int
resize_get_label_info(int fd, const char *path, struct resize_label_info *li)
{
	struct disklabel dl;
	int pidx, error;

	memset(li, 0, sizeof(*li));
	error = resize_path_partition_index(path, &pidx);
	if (error != 0)
		return (error);
	if (ioctl(fd, DIOCGDINFO, &dl) == -1 &&
	    ioctl(fd, DIOCGPDINFO, &dl) == -1)
		return (errno);
	return (resize_get_label_info_from_dl(&dl, pidx, li));
}

static int
resize_make_c_path(const char *path, char *buf, size_t buflen)
{
	size_t n;

	n = strlen(path);
	if (n == 0 || n + 1 > buflen)
		return (ENAMETOOLONG);
	memcpy(buf, path, n + 1);
	if (DL_PARTNAME2NUM(buf[n - 1]) < 0)
		return (EINVAL);
	buf[n - 1] = 'c';
	return (0);
}

static int
resize_make_block_path(const char *path, char *buf, size_t buflen)
{
	const char *base, *slash;
	size_t dirlen, baselen;

	if (path == NULL || buf == NULL || buflen == 0)
		return (EINVAL);
	slash = strrchr(path, '/');
	if (slash == NULL)
		return (EINVAL);
	base = slash + 1;
	baselen = strlen(base);
	if (baselen < 2 || base[0] != 'r')
		return (ENOENT);
	dirlen = (size_t)(slash - path) + 1;
	if (dirlen + baselen > buflen)
		return (ENAMETOOLONG);
	memcpy(buf, path, dirlen);
	memcpy(buf + dirlen, base + 1, baselen);
	return (0);
}

static int
resize_read_label_any(int fd, struct disklabel *dl)
{
	if (ioctl(fd, DIOCGDINFO, dl) == -1 &&
	    ioctl(fd, DIOCGPDINFO, dl) == -1)
		return (resize_read_disklabel_from_fd(fd, dl));
	return (0);
}

static int
resize_get_label_info_from_path(const char *path, int pidx, int via_c,
    struct resize_label_info *li)
{
	struct resize_label_info out;
	struct disklabel dl;
	int fd, error;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return (errno);
	error = resize_read_label_any(fd, &dl);
	close(fd);
	if (error != 0)
		return (error);
	memset(&out, 0, sizeof(out));
	error = resize_get_label_info_from_dl(&dl, pidx, &out);
	if (error != 0)
		return (error);
	if (via_c)
		out.via_c_fallback = 1;
	*li = out;
	return (0);
}

static int
resize_get_label_info_with_fallback(int fd, const char *path,
    struct resize_label_info *li)
{
	char cpath[PATH_MAX], bpath[PATH_MAX], bcpath[PATH_MAX];
	int pidx, error, first_error;

	li->err_target = 0;
	li->err_raw_c = 0;
	li->err_block = 0;
	li->err_block_c = 0;

	first_error = resize_get_label_info(fd, path, li);
	if (first_error == 0)
		return (0);
	li->err_target = first_error;
	if (resize_path_partition_index(path, &pidx) != 0)
		return (first_error);

	/*
	 * Try corresponding raw 'c' partition first; if that fails, try block
	 * device variants (/dev/rvnd0a -> /dev/vnd0a and /dev/vnd0c).
	 */
	error = resize_make_c_path(path, cpath, sizeof(cpath));
	if (error == 0) {
		error = resize_get_label_info_from_path(cpath, pidx, 1, li);
		if (error == 0)
			return (0);
		li->err_raw_c = error;
		if (first_error == ENOENT && error != ENOENT)
			first_error = error;
	} else {
		li->err_raw_c = error;
	}
	if (resize_make_block_path(path, bpath, sizeof(bpath)) == 0) {
		error = resize_get_label_info_from_path(bpath, pidx, 0, li);
		if (error == 0)
			return (0);
		li->err_block = error;
		if (first_error == ENOENT && error != ENOENT)
			first_error = error;
	} else {
		li->err_block = ENOENT;
	}
	if (resize_make_c_path(path, cpath, sizeof(cpath)) == 0 &&
	    resize_make_block_path(cpath, bcpath, sizeof(bcpath)) == 0) {
		error = resize_get_label_info_from_path(bcpath, pidx, 1, li);
		if (error == 0)
			return (0);
		li->err_block_c = error;
		if (first_error == ENOENT && error != ENOENT)
			first_error = error;
	} else {
		li->err_block_c = ENOENT;
	}
	return (first_error);
}

static int
resize_get_container_bytes(int fd, const char *path, const struct stat *st,
    uint64_t *bytes)
{
	off_t off;
	int error;

	if (S_ISREG(st->st_mode)) {
		if (st->st_size < 0)
			return (EINVAL);
		*bytes = (uint64_t)st->st_size;
		return (*bytes == 0 ? EINVAL : 0);
	}

	error = resize_get_partition_bytes(fd, path, bytes);
	if (error == 0 && *bytes != 0)
		return (0);

	off = lseek(fd, 0, SEEK_END);
	if (off != (off_t)-1) {
		if (off > 0) {
			*bytes = (uint64_t)off;
			return (0);
		}
	}
	return (error != 0 ? error : EINVAL);
}

static int
resize_open_target(const char *path, int writable, int *fdp, struct stat *stp,
    uint64_t *bytesp, int allow_unknown_size)
{
	int fd, flags;
	int error;

	flags = writable ? O_RDWR : O_RDONLY;
	fd = open(path, flags);
	if (fd == -1)
		return (errno);
	if (fstat(fd, stp) == -1) {
		error = errno;
		close(fd);
		return (error);
	}
	error = resize_get_container_bytes(fd, path, stp, bytesp);
	if (error != 0) {
		if (!allow_unknown_size) {
			close(fd);
			return (error);
		}
		*bytesp = UINT64_MAX;
	}
	*fdp = fd;
	return (0);
}

static int
resize_super_size_blocks(const struct fs *fs, uint64_t *nblocksp)
{
	int64_t n64;

	if (fs->fs_magic == FS_UFS1_MAGIC) {
		n64 = (int64_t)(uint32_t)fs->fs_ffs1_size;
		if (n64 <= 0 && fs->fs_size > 0)
			n64 = fs->fs_size;
	} else {
		n64 = fs->fs_size;
	}
	if (n64 <= 0)
		return (EINVAL);
	*nblocksp = (uint64_t)n64;
	return (0);
}

static int
resize_validate_super_at(const struct fs *fs, uint64_t sbloc_rel)
{
	if (fs->fs_magic != FS_UFS1_MAGIC && fs->fs_magic != FS_UFS2_MAGIC)
		return (EINVAL);
	if (fs->fs_magic == FS_UFS1_MAGIC && sbloc_rel == SBLOCK_UFS2)
		return (EINVAL);
	if ((u_int)fs->fs_bsize > MAXBSIZE)
		return (EINVAL);
	if ((u_int)fs->fs_bsize < sizeof(struct fs))
		return (EINVAL);
	if ((u_int)fs->fs_sbsize > SBSIZE || fs->fs_sbsize <= 0)
		return (EINVAL);
	if ((u_int)fs->fs_frag > MAXFRAG || fs->fs_frag <= 0)
		return (EINVAL);
	if (fs->fs_inodefmt == FS_42INODEFMT)
		return (EINVAL);
	if (fs->fs_maxsymlinklen <= 0)
		return (EINVAL);
	if (fs->fs_fsize <= 0 || fs->fs_bsize <= 0)
		return (EINVAL);
	if (fs->fs_fsize > fs->fs_bsize)
		return (EINVAL);
	if (fs->fs_fsize % DEV_BSIZE != 0)
		return (EINVAL);
	if (fs->fs_ncg == 0)
		return (EINVAL);
	return (0);
}

static int
resize_plan_error(const struct resize_plan_ctx *pc, const char *where, int err,
    uint64_t a, uint64_t b)
{
	if (pc != NULL && pc->verbose) {
		fprintf(stderr,
		    "auto-plan: %s failed (%s) a=%" PRIu64 " b=%" PRIu64 "\n",
		    where, strerror(err), a, b);
	}
	return (err);
}

static int
resize_try_super_at(int fd, uint64_t offset, uint64_t container_bytes,
    uint64_t sbloc_rel, struct resize_super *sb)
{
	uint64_t abs, end, size_blocks;
	ssize_t n;
	int error;
	const struct fs *fs;

	error = resize_add_u64(offset, sbloc_rel, &abs);
	if (error != 0)
		return (error);
	error = resize_add_u64(abs, SBSIZE, &end);
	if (error != 0)
		return (error);
	if (end > container_bytes)
		return (EINVAL);

	n = pread(fd, sb->raw, SBSIZE, (off_t)abs);
	if (n != SBSIZE)
		return (EINVAL);
	fs = (const struct fs *)sb->raw;
	error = resize_validate_super_at(fs, sbloc_rel);
	if (error != 0)
		return (EINVAL);
	error = resize_super_size_blocks(fs, &size_blocks);
	if (error != 0)
		return (error);

	sb->sb_rel_offset = sbloc_rel;
	sb->sb_abs_offset = abs;
	sb->fs_size_blocks = size_blocks;
	sb->fs_fsize = (uint32_t)fs->fs_fsize;
	sb->fs_magic = (uint32_t)fs->fs_magic;
	error = resize_mul_u64(size_blocks, (uint64_t)sb->fs_fsize,
	    &sb->fs_size_bytes);
	if (error != 0)
		return (error);
	return (0);
}

static int
resize_read_super(int fd, uint64_t offset, uint64_t container_bytes,
    struct resize_super *sb)
{
	const uint64_t search[] = {
		SBLOCK_UFS2,
		SBLOCK_UFS1,
		SBLOCK_PIGGY,
		SBOFF,
		32ULL * DEV_BSIZE
	};
	uint64_t rel, rel_limit, end;
	size_t i, j;
	int error;
	int duplicate;

	memset(sb, 0, sizeof(*sb));

	for (i = 0; i < sizeof(search) / sizeof(search[0]); i++) {
		error = resize_try_super_at(fd, offset, container_bytes, search[i],
		    sb);
		if (error == 0)
			return (0);
	}

	/*
	 * Fallback probe: scan first 8 MiB in DEV_BSIZE steps. This catches
	 * non-standard placements while still keeping false positives unlikely.
	 */
	error = resize_add_u64(offset, SBSIZE, &end);
	if (error != 0 || end > container_bytes)
		return (EINVAL);
	rel_limit = container_bytes - offset;
	if (rel_limit > (8ULL * 1024ULL * 1024ULL))
		rel_limit = 8ULL * 1024ULL * 1024ULL;

	for (rel = 0; rel + SBSIZE <= rel_limit; rel += DEV_BSIZE) {
		duplicate = 0;
		for (j = 0; j < sizeof(search) / sizeof(search[0]); j++) {
			if (rel == search[j]) {
				duplicate = 1;
				break;
			}
		}
		if (duplicate)
			continue;
		error = resize_try_super_at(fd, offset, container_bytes, rel, sb);
		if (error == 0)
			return (0);
	}

	return (EINVAL);
}

static int
resize_move_push(struct resize_move_list *ml, const struct resize_move *mv)
{
	struct resize_move *nmoves;
	size_t ncap;

	if (ml->nmoves == ml->cap) {
		ncap = (ml->cap == 0) ? 64 : ml->cap * 2;
		nmoves = reallocarray(ml->moves, ncap, sizeof(*nmoves));
		if (nmoves == NULL)
			return (ENOMEM);
		ml->moves = nmoves;
		ml->cap = ncap;
	}
	ml->moves[ml->nmoves++] = *mv;
	return (0);
}

static int
resize_parse_move_line(const char *line, struct resize_move *mv)
{
	uint64_t old_fsb, new_fsb, bytes, owner_off, owner_w;
	int nconv;

	nconv = sscanf(line, "%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
	    " %" SCNu64, &old_fsb, &new_fsb, &bytes, &owner_off, &owner_w);
	if (nconv != 5)
		return (EINVAL);
	if (bytes == 0 || bytes > UINT32_MAX)
		return (EINVAL);
	if (owner_w != 4 && owner_w != 8)
		return (EINVAL);

	memset(mv, 0, sizeof(*mv));
	mv->old_fsb = old_fsb;
	mv->new_fsb = new_fsb;
	mv->bytes = (uint32_t)bytes;
	mv->owner_abs_offset = owner_off;
	mv->owner_width = (uint32_t)owner_w;
	mv->owner.kind = RESIZE_OWNER_INDIRECT_SLOT;
	return (0);
}

static int
resize_load_moves(const char *path, struct resize_move_list *ml)
{
	FILE *fp;
	char line[1024];
	char *p;
	struct resize_move mv;
	int error, lineno = 0;

	memset(ml, 0, sizeof(*ml));
	fp = fopen(path, "r");
	if (fp == NULL)
		return (errno);

	while (fgets(line, sizeof(line), fp) != NULL) {
		lineno++;
		p = line;
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '\0' || *p == '\n' || *p == '#')
			continue;
		error = resize_parse_move_line(p, &mv);
		if (error != 0) {
			fclose(fp);
			fprintf(stderr, "%s:%d: invalid move line\n", path,
			    lineno);
			return (EINVAL);
		}
		error = resize_move_push(ml, &mv);
		if (error != 0) {
			fclose(fp);
			return (error);
		}
	}
	if (ferror(fp)) {
		error = errno;
		fclose(fp);
		return (error);
	}
	fclose(fp);
	return (0);
}

static int
resize_move_cmp_end(const void *a, const void *b)
{
	const struct resize_move *ma = a, *mb = b;

	if (ma->old_fsb < mb->old_fsb)
		return (-1);
	if (ma->old_fsb > mb->old_fsb)
		return (1);
	if (ma->new_fsb < mb->new_fsb)
		return (-1);
	if (ma->new_fsb > mb->new_fsb)
		return (1);
	if (ma->owner_abs_offset < mb->owner_abs_offset)
		return (-1);
	if (ma->owner_abs_offset > mb->owner_abs_offset)
		return (1);
	if (ma->owner_width < mb->owner_width)
		return (-1);
	if (ma->owner_width > mb->owner_width)
		return (1);
	return (0);
}

static int
resize_move_cmp_begin(const void *a, const void *b)
{
	return (resize_move_cmp_end(b, a));
}

static void
resize_reorder_moves(struct resize_move_list *ml, bool descending)
{
	if (ml->nmoves < 2)
		return;
	if (!descending)
		qsort(ml->moves, ml->nmoves, sizeof(ml->moves[0]),
		    resize_move_cmp_end);
	else
		qsort(ml->moves, ml->nmoves, sizeof(ml->moves[0]),
		    resize_move_cmp_begin);
}

static int
resize_ino_vec_push(struct resize_ino_vec *vv, ufsino_t ino)
{
	ufsino_t *nv;
	size_t ncap;

	if (vv->n == vv->cap) {
		ncap = (vv->cap == 0) ? 128 : vv->cap * 2;
		nv = reallocarray(vv->v, ncap, sizeof(*nv));
		if (nv == NULL)
			return (ENOMEM);
		vv->v = nv;
		vv->cap = ncap;
	}
	vv->v[vv->n++] = ino;
	return (0);
}

static void
resize_ino_vec_free(struct resize_ino_vec *vv)
{
	free(vv->v);
	memset(vv, 0, sizeof(*vv));
}

static int
resize_ino_remap_push(struct resize_ino_remap *rm, ufsino_t old_ino,
    ufsino_t new_ino)
{
	struct resize_ino_remap_ent *ne;
	size_t ncap;

	if (rm->nent == rm->cap) {
		ncap = (rm->cap == 0) ? 128 : rm->cap * 2;
		ne = reallocarray(rm->ents, ncap, sizeof(*ne));
		if (ne == NULL)
			return (ENOMEM);
		rm->ents = ne;
		rm->cap = ncap;
	}
	rm->ents[rm->nent].old_ino = old_ino;
	rm->ents[rm->nent].new_ino = new_ino;
	rm->nent++;
	return (0);
}

static void
resize_ino_remap_free(struct resize_ino_remap *rm)
{
	free(rm->ents);
	memset(rm, 0, sizeof(*rm));
}

static int
resize_ino_cmp_u32(const void *a, const void *b)
{
	const ufsino_t *ia = a, *ib = b;

	if (*ia < *ib)
		return (-1);
	if (*ia > *ib)
		return (1);
	return (0);
}

static int
resize_ino_remap_cmp_old(const void *a, const void *b)
{
	const struct resize_ino_remap_ent *ea = a, *eb = b;

	if (ea->old_ino < eb->old_ino)
		return (-1);
	if (ea->old_ino > eb->old_ino)
		return (1);
	return (0);
}

static int
resize_ino_remap_find(const struct resize_ino_remap *rm, ufsino_t old_ino,
    ufsino_t *new_inop)
{
	size_t lo, hi, mid;

	lo = 0;
	hi = rm->nent;
	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		if (rm->ents[mid].old_ino == old_ino) {
			*new_inop = rm->ents[mid].new_ino;
			return (0);
		}
		if (rm->ents[mid].old_ino < old_ino)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (ENOENT);
}

static int
resize_ino_remap_has_old(const struct resize_ino_remap *rm, ufsino_t old_ino)
{
	ufsino_t tmp;

	return (resize_ino_remap_find(rm, old_ino, &tmp) == 0);
}

static int
resize_bit_is_set(const u_int8_t *map, uint64_t bit)
{
	return ((map[bit / NBBY] & (1U << (bit % NBBY))) != 0);
}

static void
resize_bit_set(u_int8_t *map, uint64_t bit)
{
	map[bit / NBBY] |= (u_int8_t)(1U << (bit % NBBY));
}

static void
resize_bit_clear(u_int8_t *map, uint64_t bit)
{
	map[bit / NBBY] &= (u_int8_t)~(1U << (bit % NBBY));
}

static uint64_t
resize_u64_min(uint64_t a, uint64_t b)
{
	return (a < b ? a : b);
}

static int
resize_div_round_up_u64(uint64_t num, uint64_t den, uint64_t *out)
{
	uint64_t q;

	if (den == 0)
		return (EINVAL);
	q = num / den;
	if ((num % den) != 0) {
		if (q == UINT64_MAX)
			return (EOVERFLOW);
		q++;
	}
	*out = q;
	return (0);
}

static int
resize_lbn_bytes(const struct fs *fs, uint64_t inode_size, uint64_t lbn,
    uint32_t *bytesp)
{
	uint64_t block_start, rem;
	int error;

	if (fs->fs_bsize <= 0 || fs->fs_fsize <= 0)
		return (EINVAL);
	error = resize_mul_u64(lbn, (uint64_t)fs->fs_bsize, &block_start);
	if (error != 0)
		return (error);
	if (inode_size <= block_start)
		return (EINVAL);
	rem = inode_size - block_start;
	if (rem > (uint64_t)fs->fs_bsize)
		rem = (uint64_t)fs->fs_bsize;
	if (rem % (uint64_t)fs->fs_fsize != 0) {
		if (rem > UINT64_MAX - ((uint64_t)fs->fs_fsize - 1))
			return (EOVERFLOW);
		rem = ((rem + (uint64_t)fs->fs_fsize - 1) /
		    (uint64_t)fs->fs_fsize) * (uint64_t)fs->fs_fsize;
	}
	if (rem == 0 || rem > UINT32_MAX)
		return (EINVAL);
	*bytesp = (uint32_t)rem;
	return (0);
}

static int
resize_fs_abs_for_fsb(uint64_t fs_offset, uint32_t fs_fsize, uint64_t fsb,
    size_t len, uint64_t container_bytes, uint64_t *absp)
{
	uint64_t rel, abs, end;
	int error;

	error = resize_mul_u64(fsb, (uint64_t)fs_fsize, &rel);
	if (error != 0)
		return (error);
	error = resize_add_u64(fs_offset, rel, &abs);
	if (error != 0)
		return (error);
	error = resize_add_u64(abs, (uint64_t)len, &end);
	if (error != 0)
		return (error);
	if (end > container_bytes)
		return (EINVAL);
	*absp = abs;
	return (0);
}

static int
resize_pread_exact(int fd, void *buf, size_t len, uint64_t abs)
{
	ssize_t n;

	n = pread(fd, buf, len, (off_t)abs);
	if (n != (ssize_t)len)
		return (errno != 0 ? errno : EIO);
	return (0);
}

static int
resize_pwrite_exact(int fd, const void *buf, size_t len, uint64_t abs)
{
	ssize_t n;

	n = pwrite(fd, buf, len, (off_t)abs);
	if (n != (ssize_t)len)
		return (errno != 0 ? errno : EIO);
	return (0);
}

static int
resize_read_bytes_any(int fd, uint64_t container_bytes, uint64_t abs, void *buf,
    size_t len)
{
	u_int8_t *tmp;
	uint64_t base, head, need, span, end;
	int error;

	if (len == 0)
		return (0);
	error = resize_add_u64(abs, (uint64_t)len, &end);
	if (error != 0)
		return (error);
	if (container_bytes != UINT64_MAX && end > container_bytes)
		return (EINVAL);
	if ((abs % DEV_BSIZE) == 0 && (len % DEV_BSIZE) == 0)
		return (resize_pread_exact(fd, buf, len, abs));

	base = abs & ~(uint64_t)(DEV_BSIZE - 1);
	head = abs - base;
	error = resize_add_u64(head, (uint64_t)len, &need);
	if (error != 0)
		return (error);
	span = (need + (DEV_BSIZE - 1)) & ~(uint64_t)(DEV_BSIZE - 1);
	if (span > SIZE_MAX)
		return (EOVERFLOW);
	error = resize_add_u64(base, span, &end);
	if (error != 0)
		return (error);
	if (container_bytes != UINT64_MAX && end > container_bytes)
		return (EINVAL);

	tmp = malloc((size_t)span);
	if (tmp == NULL)
		return (ENOMEM);
	error = resize_pread_exact(fd, tmp, (size_t)span, base);
	if (error == 0)
		memcpy(buf, tmp + head, len);
	free(tmp);
	return (error);
}

static int
resize_write_bytes_any(int fd, uint64_t container_bytes, uint64_t abs,
    const void *buf, size_t len)
{
	u_int8_t *tmp;
	uint64_t base, head, need, span, end;
	int error;

	if (len == 0)
		return (0);
	error = resize_add_u64(abs, (uint64_t)len, &end);
	if (error != 0)
		return (error);
	if (container_bytes != UINT64_MAX && end > container_bytes)
		return (EINVAL);
	if ((abs % DEV_BSIZE) == 0 && (len % DEV_BSIZE) == 0)
		return (resize_pwrite_exact(fd, buf, len, abs));

	base = abs & ~(uint64_t)(DEV_BSIZE - 1);
	head = abs - base;
	error = resize_add_u64(head, (uint64_t)len, &need);
	if (error != 0)
		return (error);
	span = (need + (DEV_BSIZE - 1)) & ~(uint64_t)(DEV_BSIZE - 1);
	if (span > SIZE_MAX)
		return (EOVERFLOW);
	error = resize_add_u64(base, span, &end);
	if (error != 0)
		return (error);
	if (container_bytes != UINT64_MAX && end > container_bytes)
		return (EINVAL);

	tmp = malloc((size_t)span);
	if (tmp == NULL)
		return (ENOMEM);
	error = resize_pread_exact(fd, tmp, (size_t)span, base);
	if (error != 0) {
		free(tmp);
		return (error);
	}
	memcpy(tmp + head, buf, len);
	error = resize_pwrite_exact(fd, tmp, (size_t)span, base);
	free(tmp);
	return (error);
}

static int
resize_pool_init(struct resize_free_pool *pool, uint64_t nbits)
{
	uint64_t nbytes64;
	size_t nbytes;

	memset(pool, 0, sizeof(*pool));
	if (nbits == 0)
		return (EINVAL);
	if (nbits > UINT64_MAX - (NBBY - 1))
		return (EOVERFLOW);
	nbytes64 = (nbits + (NBBY - 1)) / NBBY;
	if (nbytes64 > SIZE_MAX)
		return (EOVERFLOW);
	nbytes = (size_t)nbytes64;
	if (nbytes == 0)
		return (EINVAL);
	pool->map = calloc(1, nbytes);
	if (pool->map == NULL)
		return (ENOMEM);
	pool->nbits = nbits;
	return (0);
}

static void
resize_pool_free(struct resize_free_pool *pool)
{
	free(pool->map);
	memset(pool, 0, sizeof(*pool));
}

static int
resize_pool_mark_free(struct resize_free_pool *pool, uint64_t fsb)
{
	if (fsb >= pool->nbits)
		return (EINVAL);
	resize_bit_set(pool->map, fsb);
	return (0);
}

static int
resize_pool_alloc_run(struct resize_free_pool *pool, uint64_t nfrags,
    uint64_t align, uint64_t *startp)
{
	uint64_t i, j, end, start, skip;
	int pass, ok;

	if (nfrags == 0 || nfrags > pool->nbits)
		return (ENOSPC);
	if (align == 0)
		align = 1;
	start = pool->cursor;
	for (pass = 0; pass < 2; pass++) {
		if (start > pool->nbits)
			start = pool->nbits;
		if (pool->nbits < nfrags)
			break;
		end = pool->nbits - nfrags + 1;
		for (i = start; i < end; i++) {
			if (align > 1 && (i % align) != 0) {
				skip = align - (i % align);
				i += skip - 1;
				continue;
			}
			ok = 1;
			for (j = 0; j < nfrags; j++) {
				if (!resize_bit_is_set(pool->map, i + j)) {
					ok = 0;
					break;
				}
			}
			if (!ok)
				continue;
			for (j = 0; j < nfrags; j++)
				resize_bit_clear(pool->map, i + j);
			pool->cursor = i + nfrags;
			if (pool->cursor >= pool->nbits)
				pool->cursor = 0;
			*startp = i;
			return (0);
		}
		start = 0;
	}
	return (ENOSPC);
}

static int
resize_plan_owner_abs_inode_slot(const struct resize_plan_ctx *pc,
    uint64_t ino_abs, int is_indirect, int idx, uint64_t *owner_absp)
{
	uint64_t owner_abs, end;
	size_t off;
	int error;

	if (idx < 0)
		return (EINVAL);
	if (pc->ptr_width == 4) {
		if (is_indirect)
			off = offsetof(struct ufs1_dinode, di_ib) +
			    (size_t)idx * sizeof(int32_t);
		else
			off = offsetof(struct ufs1_dinode, di_db) +
			    (size_t)idx * sizeof(int32_t);
	} else if (pc->ptr_width == 8) {
		if (is_indirect)
			off = offsetof(struct ufs2_dinode, di_ib) +
			    (size_t)idx * sizeof(int64_t);
		else
			off = offsetof(struct ufs2_dinode, di_db) +
			    (size_t)idx * sizeof(int64_t);
	} else {
		return (EINVAL);
	}
	error = resize_add_u64(ino_abs, (uint64_t)off, &owner_abs);
	if (error != 0)
		return (error);
	error = resize_add_u64(owner_abs, (uint64_t)pc->ptr_width, &end);
	if (error != 0)
		return (error);
	if (end > pc->container_bytes)
		return (EINVAL);
	*owner_absp = owner_abs;
	return (0);
}

static int
resize_plan_owner_abs_indir_slot(const struct resize_plan_ctx *pc,
    uint64_t indir_fsb, uint64_t slot, uint64_t *owner_absp)
{
	uint64_t blk_abs, slot_off, owner_abs, end;
	int error;

	error = resize_fs_abs_for_fsb(pc->fs_offset, pc->fs_fsize, indir_fsb,
	    pc->ptr_width, pc->container_bytes, &blk_abs);
	if (error != 0)
		return (error);
	error = resize_mul_u64(slot, (uint64_t)pc->ptr_width, &slot_off);
	if (error != 0)
		return (error);
	error = resize_add_u64(blk_abs, slot_off, &owner_abs);
	if (error != 0)
		return (error);
	error = resize_add_u64(owner_abs, (uint64_t)pc->ptr_width, &end);
	if (error != 0)
		return (error);
	if (end > pc->container_bytes)
		return (EINVAL);
	*owner_absp = owner_abs;
	return (0);
}

static int
resize_plan_load_ptr(const void *blk, uint32_t width, uint64_t idx,
    uint64_t *ptrp)
{
	const u_int8_t *p = blk;
	int32_t v32;
	int64_t v64;
	size_t off;

	if (width != 4 && width != 8)
		return (EINVAL);
	off = (size_t)idx * (size_t)width;
	if (width == 4) {
		memcpy(&v32, p + off, sizeof(v32));
		if (v32 < 0)
			return (EINVAL);
		*ptrp = (uint64_t)(uint32_t)v32;
	} else {
		memcpy(&v64, p + off, sizeof(v64));
		if (v64 < 0)
			return (EINVAL);
		*ptrp = (uint64_t)v64;
	}
	return (0);
}

static int
resize_plan_inode_has_blocks(const struct resize_plan_ctx *pc, uint16_t mode,
    uint64_t size)
{
	switch (mode & IFMT) {
	case IFREG:
	case IFDIR:
		return (1);
	case IFLNK:
		return (size > pc->maxsymlinklen);
	default:
		return (0);
	}
}

static int
resize_plan_read_inode(const struct resize_plan_ctx *pc, uint64_t ino,
    uint64_t *inode_absp, struct resize_inode_view *iv)
{
	u_int8_t *blk;
	uint64_t ifsb, blk_abs, idx_off, inode_abs, end;
	ufsino_t uino;
	struct ufs1_dinode di1;
	struct ufs2_dinode di2;
	int error, i;

	if (ino > UINT32_MAX)
		return (EOVERFLOW);
	uino = (ufsino_t)ino;
	ifsb = (uint64_t)ino_to_fsba(pc->fs, uino);
	if (ifsb >= pc->old_blocks)
		return (ENOENT);
	error = resize_fs_abs_for_fsb(pc->fs_offset, pc->fs_fsize, ifsb,
	    pc->fs_bsize, pc->container_bytes, &blk_abs);
	if (error != 0)
		return (error);
	error = resize_mul_u64((uint64_t)ino_to_fsbo(pc->fs, uino),
	    (uint64_t)pc->inode_size, &idx_off);
	if (error != 0)
		return (error);
	error = resize_add_u64(blk_abs, idx_off, &inode_abs);
	if (error != 0)
		return (error);
	error = resize_add_u64(inode_abs, (uint64_t)pc->inode_size, &end);
	if (error != 0)
		return (error);
	if (end > pc->container_bytes)
		return (EINVAL);

	if (idx_off > pc->fs_bsize || pc->inode_size > pc->fs_bsize ||
	    idx_off + pc->inode_size > pc->fs_bsize)
		return (EINVAL);

	blk = malloc(pc->fs_bsize);
	if (blk == NULL)
		return (ENOMEM);
	error = resize_read_bytes_any(pc->tfd, pc->container_bytes, blk_abs, blk,
	    pc->fs_bsize);
	if (error != 0) {
		free(blk);
		return (error);
	}

	if (pc->ptr_width == 4) {
		memcpy(&di1, blk + idx_off, sizeof(di1));
		iv->mode = di1.di_mode;
		iv->size = di1.di_size;
		if (resize_plan_inode_has_blocks(pc, iv->mode, iv->size)) {
			for (i = 0; i < NDADDR; i++) {
				if (di1.di_db[i] < 0) {
					error = EINVAL;
					goto out;
				}
				iv->db[i] = (uint64_t)(uint32_t)di1.di_db[i];
			}
			for (i = 0; i < NIADDR; i++) {
				if (di1.di_ib[i] < 0) {
					error = EINVAL;
					goto out;
				}
				iv->ib[i] = (uint64_t)(uint32_t)di1.di_ib[i];
			}
		} else {
			memset(iv->db, 0, sizeof(iv->db));
			memset(iv->ib, 0, sizeof(iv->ib));
		}
	} else if (pc->ptr_width == 8) {
		memcpy(&di2, blk + idx_off, sizeof(di2));
		iv->mode = di2.di_mode;
		iv->size = di2.di_size;
		if (resize_plan_inode_has_blocks(pc, iv->mode, iv->size)) {
			for (i = 0; i < NDADDR; i++) {
				if (di2.di_db[i] < 0) {
					error = EINVAL;
					goto out;
				}
				iv->db[i] = (uint64_t)di2.di_db[i];
			}
			for (i = 0; i < NIADDR; i++) {
				if (di2.di_ib[i] < 0) {
					error = EINVAL;
					goto out;
				}
				iv->ib[i] = (uint64_t)di2.di_ib[i];
			}
		} else {
			memset(iv->db, 0, sizeof(iv->db));
			memset(iv->ib, 0, sizeof(iv->ib));
		}
	} else {
		error = EINVAL;
		goto out;
	}
	error = 0;
out:
	free(blk);
	*inode_absp = inode_abs;
	return (error);
}

static int
resize_inode_locate(const struct resize_plan_ctx *pc, ufsino_t ino,
    uint64_t *blk_fsb, uint64_t *blk_abs, uint64_t *idx_off,
    uint64_t *inode_abs)
{
	uint64_t ifsb, babs, ioff, iabs;
	int error;

	ifsb = (uint64_t)ino_to_fsba(pc->fs, ino);
	if (ifsb >= pc->old_blocks)
		return (ENOENT);
	error = resize_fs_abs_for_fsb(pc->fs_offset, pc->fs_fsize, ifsb,
	    pc->fs_bsize, pc->container_bytes, &babs);
	if (error != 0)
		return (error);
	error = resize_mul_u64((uint64_t)ino_to_fsbo(pc->fs, ino),
	    (uint64_t)pc->inode_size, &ioff);
	if (error != 0)
		return (error);
	if (ioff + pc->inode_size > pc->fs_bsize)
		return (EINVAL);
	error = resize_add_u64(babs, ioff, &iabs);
	if (error != 0)
		return (error);
	if (blk_fsb != NULL)
		*blk_fsb = ifsb;
	if (blk_abs != NULL)
		*blk_abs = babs;
	if (idx_off != NULL)
		*idx_off = ioff;
	if (inode_abs != NULL)
		*inode_abs = iabs;
	return (0);
}

static int
resize_inode_read_raw(const struct resize_plan_ctx *pc, ufsino_t ino,
    u_int8_t *raw)
{
	u_int8_t *blk;
	uint64_t blk_abs, idx_off;
	int error;

	blk = malloc(pc->fs_bsize);
	if (blk == NULL)
		return (ENOMEM);
	error = resize_inode_locate(pc, ino, NULL, &blk_abs, &idx_off, NULL);
	if (error != 0)
		goto out;
	error = resize_read_bytes_any(pc->tfd, pc->container_bytes, blk_abs, blk,
	    pc->fs_bsize);
	if (error != 0)
		goto out;
	memcpy(raw, blk + idx_off, pc->inode_size);
out:
	free(blk);
	return (error);
}

static int
resize_inode_raw_is_dir(const struct resize_plan_ctx *pc, const u_int8_t *raw,
    int *is_dir)
{
	uint16_t mode;

	if (pc->inode_size == sizeof(struct ufs1_dinode)) {
		const struct ufs1_dinode *di1;

		di1 = (const struct ufs1_dinode *)raw;
		mode = di1->di_mode;
	} else if (pc->inode_size == sizeof(struct ufs2_dinode)) {
		const struct ufs2_dinode *di2;

		di2 = (const struct ufs2_dinode *)raw;
		mode = di2->di_mode;
	} else {
		return (EINVAL);
	}
	*is_dir = ((mode & IFMT) == IFDIR);
	return (0);
}

static int
resize_inode_write_raw(const struct resize_plan_ctx *pc, ufsino_t ino,
    const u_int8_t *raw)
{
	u_int8_t *blk;
	uint64_t blk_abs, idx_off;
	int error;

	blk = malloc(pc->fs_bsize);
	if (blk == NULL)
		return (ENOMEM);
	error = resize_inode_locate(pc, ino, NULL, &blk_abs, &idx_off, NULL);
	if (error != 0)
		goto out;
	error = resize_read_bytes_any(pc->tfd, pc->container_bytes, blk_abs, blk,
	    pc->fs_bsize);
	if (error != 0)
		goto out;
	memcpy(blk + idx_off, raw, pc->inode_size);
	error = resize_write_bytes_any(pc->tfd, pc->container_bytes, blk_abs, blk,
	    pc->fs_bsize);
out:
	free(blk);
	return (error);
}
static int
resize_inode_zero_raw(const struct resize_plan_ctx *pc, ufsino_t ino)
{
	u_int8_t *raw;
	int error;

	raw = calloc(1, pc->inode_size);
	if (raw == NULL)
		return (ENOMEM);
	error = resize_inode_write_raw(pc, ino, raw);
	free(raw);
	return (error);
}

static int
resize_cg_read_abs(const struct resize_plan_ctx *pc, uint32_t cgx,
    u_int8_t **bufp, struct cg **cgpp, uint64_t *cg_absp)
{
	u_int8_t *buf;
	struct cg *cgp;
	uint64_t cg_fsb, cg_abs;
	size_t cgsize;
	int error;

	if (pc->fs->fs_cgsize <= 0 || pc->fs->fs_cgsize > MAXBSIZE)
		return (EINVAL);
	cgsize = (size_t)pc->fs->fs_cgsize;
	buf = malloc(cgsize);
	if (buf == NULL)
		return (ENOMEM);
	cg_fsb = (uint64_t)cgtod(pc->fs, cgx);
	error = resize_fs_abs_for_fsb(pc->fs_offset, pc->fs_fsize, cg_fsb,
	    cgsize, pc->container_bytes, &cg_abs);
	if (error != 0) {
		free(buf);
		return (error);
	}
	error = resize_read_bytes_any(pc->tfd, pc->container_bytes, cg_abs, buf,
	    cgsize);
	if (error != 0) {
		free(buf);
		return (error);
	}
	cgp = (struct cg *)buf;
	if (!cg_chkmagic(cgp)) {
		free(buf);
		return (EINVAL);
	}
	*bufp = buf;
	*cgpp = cgp;
	*cg_absp = cg_abs;
	return (0);
}

static int
resize_inode_bitmap_flip(const struct resize_plan_ctx *pc, ufsino_t ino,
    int set_allocated, int is_dir)
{
	u_int8_t *cgbuf, *imap;
	struct cg *cgp;
	uint64_t cg_abs;
	uint32_t cgx;
	size_t idx;
	int error;

	cgx = (uint32_t)ino_to_cg(pc->fs, ino);
	error = resize_cg_read_abs(pc, cgx, &cgbuf, &cgp, &cg_abs);
	if (error != 0)
		return (error);
	idx = (size_t)(ino % pc->fs->fs_ipg);
	imap = cg_inosused(cgp);
	if (set_allocated) {
		if (resize_bit_is_set(imap, idx)) {
			free(cgbuf);
			return (EEXIST);
		}
		resize_bit_set(imap, idx);
		cgp->cg_cs.cs_nifree--;
		if (is_dir)
			cgp->cg_cs.cs_ndir++;
	} else {
		if (!resize_bit_is_set(imap, idx)) {
			free(cgbuf);
			return (ENOENT);
		}
		resize_bit_clear(imap, idx);
		cgp->cg_cs.cs_nifree++;
		if (is_dir) {
			if (cgp->cg_cs.cs_ndir <= 0) {
				free(cgbuf);
				return (EINVAL);
			}
			cgp->cg_cs.cs_ndir--;
		}
	}
	error = resize_write_bytes_any(pc->tfd, pc->container_bytes, cg_abs, cgbuf,
	    (size_t)pc->fs->fs_cgsize);
	free(cgbuf);
	return (error);
}

static int
resize_inode_is_allocated(const struct resize_plan_ctx *pc, ufsino_t ino,
    int *is_allocated)
{
	u_int8_t *cgbuf, *imap;
	struct cg *cgp;
	uint64_t cg_abs;
	uint32_t cgx;
	size_t idx;
	int error;

	cgx = (uint32_t)ino_to_cg(pc->fs, ino);
	error = resize_cg_read_abs(pc, cgx, &cgbuf, &cgp, &cg_abs);
	if (error != 0)
		return (error);
	idx = (size_t)(ino % pc->fs->fs_ipg);
	imap = cg_inosused(cgp);
	*is_allocated = resize_bit_is_set(imap, idx);
	free(cgbuf);
	return (0);
}

static int
resize_walk_inode_indirect_data(const struct resize_plan_ctx *pc, uint64_t ptr_fsb,
    int level, uint64_t base_lbn, uint64_t need_data_blks, uint64_t inode_size,
    int (*cb)(const struct resize_plan_ctx *, uint64_t, uint32_t, void *),
    void *cookie)
{
	u_int8_t *blk;
	uint64_t nindir, subcover, entries, i, child_need, child_ptr, v;
	uint32_t bytes;
	int j, error;

	if (ptr_fsb == 0 || need_data_blks == 0)
		return (0);
	blk = malloc(pc->fs_bsize);
	if (blk == NULL)
		return (ENOMEM);
	error = resize_fs_abs_for_fsb(pc->fs_offset, pc->fs_fsize, ptr_fsb,
	    pc->fs_bsize, pc->container_bytes, &v);
	if (error != 0)
		goto out;
	error = resize_read_bytes_any(pc->tfd, pc->container_bytes, v, blk,
	    pc->fs_bsize);
	if (error != 0)
		goto out;
	nindir = (uint64_t)NINDIR(pc->fs);
	if (nindir == 0) {
		error = EINVAL;
		goto out;
	}
	subcover = 1;
	for (j = 1; j < level; j++) {
		if (subcover > UINT64_MAX / nindir) {
			subcover = UINT64_MAX;
			break;
		}
		subcover *= nindir;
	}
	error = resize_div_round_up_u64(need_data_blks, subcover, &entries);
	if (error != 0)
		goto out;
	entries = resize_u64_min(entries, nindir);
	for (i = 0; i < entries; i++) {
		error = resize_plan_load_ptr(blk, pc->ptr_width, i, &child_ptr);
		if (error != 0)
			goto out;
		if (child_ptr == 0)
			continue;
		error = resize_mul_u64(i, subcover, &v);
		if (error != 0)
			goto out;
		if (v >= need_data_blks)
			break;
		child_need = resize_u64_min(subcover, need_data_blks - v);
		if (level == 1) {
			error = resize_lbn_bytes(pc->fs, inode_size, base_lbn + i,
			    &bytes);
			if (error != 0)
				goto out;
			error = cb(pc, child_ptr, bytes, cookie);
		} else {
			error = resize_walk_inode_indirect_data(pc, child_ptr,
			    level - 1, base_lbn + v, child_need, inode_size, cb,
			    cookie);
		}
		if (error != 0)
			goto out;
	}
out:
	free(blk);
	return (error);
}

static int
resize_walk_inode_data_blocks(const struct resize_plan_ctx *pc,
    const struct resize_inode_view *iv,
    int (*cb)(const struct resize_plan_ctx *, uint64_t, uint32_t, void *),
    void *cookie)
{
	uint64_t nblks, remaining, nindir, cover, need, base_lbn;
	uint32_t bytes;
	int level, i, j, error;

	error = resize_div_round_up_u64(iv->size, pc->fs_bsize, &nblks);
	if (error != 0)
		return (error);
	for (i = 0; i < NDADDR && (uint64_t)i < nblks; i++) {
		if (iv->db[i] == 0)
			continue;
		error = resize_lbn_bytes(pc->fs, iv->size, (uint64_t)i, &bytes);
		if (error != 0)
			return (error);
		error = cb(pc, iv->db[i], bytes, cookie);
		if (error != 0)
			return (error);
	}
	if (nblks <= NDADDR)
		return (0);
	remaining = nblks - NDADDR;
	nindir = (uint64_t)NINDIR(pc->fs);
	base_lbn = NDADDR;
	for (level = 1; level <= NIADDR && remaining != 0; level++) {
		cover = 1;
		for (j = 0; j < level; j++) {
			if (cover > UINT64_MAX / nindir) {
				cover = UINT64_MAX;
				break;
			}
			cover *= nindir;
		}
		need = resize_u64_min(remaining, cover);
		if (iv->ib[level - 1] != 0) {
			error = resize_walk_inode_indirect_data(pc, iv->ib[level - 1],
			    level, base_lbn, need, iv->size, cb, cookie);
			if (error != 0)
				return (error);
		}
		remaining -= need;
		if (cover == UINT64_MAX || base_lbn > UINT64_MAX - cover)
			break;
		base_lbn += cover;
	}
	return (0);
}

static int
resize_plan_add_move(struct resize_plan_ctx *pc, struct resize_move_list *ml,
    uint64_t old_fsb, uint32_t bytes, uint64_t owner_abs, uint32_t owner_width)
{
	struct resize_move mv;
	uint64_t nfrags, new_fsb, align;
	size_t i;
	int error;

	if (old_fsb < pc->new_blocks || old_fsb >= pc->old_blocks)
		return (0);
	if (bytes == 0 || bytes % pc->fs_fsize != 0)
		return (EINVAL);
	nfrags = (uint64_t)bytes / pc->fs_fsize;
	if (nfrags == 0)
		return (EINVAL);
	align = (bytes == pc->fs_bsize) ? pc->fs->fs_frag : 1;

	for (i = 0; i < ml->nmoves; i++) {
		if (ml->moves[i].old_fsb != old_fsb)
			continue;
		if (ml->moves[i].bytes != bytes) {
			resize_vlog(pc->verbose,
			    "auto-plan: old_fsb=%" PRIu64
			    " has conflicting widths (%u vs %u)\n", old_fsb,
			    ml->moves[i].bytes, bytes);
			return (ENOTSUP);
		}
		if (ml->moves[i].owner_abs_offset == owner_abs &&
		    ml->moves[i].owner_width == owner_width) {
			resize_vlog(pc->verbose,
			    "auto-plan: duplicate owner slot ignored old_fsb=%" PRIu64
			    " owner_abs=%" PRIu64 " width=%u\n", old_fsb,
			    owner_abs, owner_width);
			return (0);
		}
		memset(&mv, 0, sizeof(mv));
		mv.old_fsb = old_fsb;
		mv.new_fsb = ml->moves[i].new_fsb;
		mv.bytes = bytes;
		mv.owner_abs_offset = owner_abs;
		mv.owner_width = owner_width;
		mv.owner.kind = RESIZE_OWNER_INDIRECT_SLOT;
		return (resize_move_push(ml, &mv));
	}

	error = resize_pool_alloc_run(&pc->pool, nfrags, align, &new_fsb);
	if (error != 0)
		return (error);

	memset(&mv, 0, sizeof(mv));
	mv.old_fsb = old_fsb;
	mv.new_fsb = new_fsb;
	mv.bytes = bytes;
	mv.owner_abs_offset = owner_abs;
	mv.owner_width = owner_width;
	mv.owner.kind = RESIZE_OWNER_INDIRECT_SLOT;
	return (resize_move_push(ml, &mv));
}

static int
resize_plan_scan_indirect(struct resize_plan_ctx *pc, struct resize_move_list *ml,
    uint64_t inode_size, uint64_t ptr_fsb, uint64_t owner_abs, int level,
    uint64_t base_lbn, uint64_t needed_data_blks)
{
	u_int8_t *blk;
	uint64_t nindir, subcover, entries, i, child_need, child_ptr;
	uint64_t slot_abs, slot_base, v;
	uint32_t bytes;
	int j, error;

	if (ptr_fsb == 0 || needed_data_blks == 0)
		return (0);
	if (ptr_fsb >= pc->old_blocks)
		return (EINVAL);
	if (level < 1 || level > NIADDR)
		return (EINVAL);

	blk = malloc(pc->fs_bsize);
	if (blk == NULL)
		return (ENOMEM);
	error = resize_fs_abs_for_fsb(pc->fs_offset, pc->fs_fsize, ptr_fsb,
	    pc->fs_bsize, pc->container_bytes, &slot_base);
	if (error != 0)
		goto out_err_abs;
	error = resize_pread_exact(pc->tfd, blk, pc->fs_bsize, slot_base);
	if (error != 0)
		goto out_err_read;

	nindir = (uint64_t)NINDIR(pc->fs);
	if (nindir == 0) {
		error = EINVAL;
		goto out;
	}
	subcover = 1;
	for (j = 1; j < level; j++) {
		if (subcover > UINT64_MAX / nindir) {
			subcover = UINT64_MAX;
			break;
		}
		subcover *= nindir;
	}
	error = resize_div_round_up_u64(needed_data_blks, subcover, &entries);
	if (error != 0)
		goto out_err_math;
	entries = resize_u64_min(entries, nindir);
	for (i = 0; i < entries; i++) {
		error = resize_plan_load_ptr(blk, pc->ptr_width, i, &child_ptr);
		if (error != 0)
			goto out_err_slot;
		if (child_ptr == 0)
			continue;
		error = resize_mul_u64(i, subcover, &v);
		if (error != 0)
			goto out_err_math;
		if (v >= needed_data_blks)
			break;
		child_need = resize_u64_min(subcover, needed_data_blks - v);
		error = resize_plan_owner_abs_indir_slot(pc, ptr_fsb, i, &slot_abs);
		if (error != 0)
			goto out_err_owner;
		if (level == 1) {
			error = resize_lbn_bytes(pc->fs, inode_size, base_lbn + i,
			    &bytes);
			if (error != 0)
				goto out_err_lbn;
			error = resize_plan_add_move(pc, ml, child_ptr,
			    bytes, slot_abs, pc->ptr_width);
		} else {
			error = resize_plan_scan_indirect(pc, ml, inode_size,
			    child_ptr, slot_abs, level - 1, base_lbn + v,
			    child_need);
		}
		if (error != 0)
			goto out_err_child;
	}

	/*
	 * Post-order planning keeps parent-indirect relocation after child
	 * slot rewrites. Child repoints are then copied into the relocated
	 * parent block and remain reachable.
	 */
	error = resize_plan_add_move(pc, ml, ptr_fsb, pc->fs_bsize, owner_abs,
	    pc->ptr_width);
out:
	free(blk);
	return (error);
out_err_abs:
	error = resize_plan_error(pc, "scan-indirect/abs", error, ptr_fsb,
	    (uint64_t)level);
	goto out;
out_err_read:
	error = resize_plan_error(pc, "scan-indirect/read", error, ptr_fsb,
	    (uint64_t)level);
	goto out;
out_err_math:
	error = resize_plan_error(pc, "scan-indirect/math", error, ptr_fsb,
	    (uint64_t)level);
	goto out;
out_err_slot:
	error = resize_plan_error(pc, "scan-indirect/load-slot", error, ptr_fsb,
	    i);
	goto out;
out_err_owner:
	error = resize_plan_error(pc, "scan-indirect/owner-slot", error, ptr_fsb,
	    i);
	goto out;
out_err_lbn:
	error = resize_plan_error(pc, "scan-indirect/lbn-bytes", error, ptr_fsb,
	    base_lbn + i);
	goto out;
out_err_child:
	error = resize_plan_error(pc, "scan-indirect/child", error, ptr_fsb, i);
	goto out;
}

static int
resize_plan_scan_inode(struct resize_plan_ctx *pc, struct resize_move_list *ml,
    uint64_t ino)
{
	struct resize_inode_view iv;
	uint64_t inode_abs, owner_abs, nblks;
	uint64_t remaining, nindir, cover, need, base_lbn;
	uint32_t bytes;
	int level, error, i, j;

	memset(&iv, 0, sizeof(iv));
	error = resize_plan_read_inode(pc, ino, &inode_abs, &iv);
	if (error != 0)
		return (resize_plan_error(pc, "scan-inode/read-inode", error, ino,
		    0));
	if (!resize_plan_inode_has_blocks(pc, iv.mode, iv.size))
		return (0);

	error = resize_div_round_up_u64(iv.size, pc->fs_bsize, &nblks);
	if (error != 0)
		return (error);
	nblks = resize_u64_min(nblks, NDADDR +
	    (uint64_t)NINDIR(pc->fs) +
	    (uint64_t)NINDIR(pc->fs) * (uint64_t)NINDIR(pc->fs) +
	    (uint64_t)NINDIR(pc->fs) * (uint64_t)NINDIR(pc->fs) *
	    (uint64_t)NINDIR(pc->fs));
	for (i = 0; i < NDADDR && (uint64_t)i < nblks; i++) {
		if (iv.db[i] == 0)
			continue;
		error = resize_lbn_bytes(pc->fs, iv.size, (uint64_t)i, &bytes);
		if (error != 0)
			return (resize_plan_error(pc, "scan-inode/lbn-bytes",
			    error, ino, i));
		error = resize_plan_owner_abs_inode_slot(pc, inode_abs, 0, i,
		    &owner_abs);
		if (error != 0)
			return (resize_plan_error(pc, "scan-inode/owner-db",
			    error, ino, i));
		error = resize_plan_add_move(pc, ml, iv.db[i], bytes,
		    owner_abs, pc->ptr_width);
		if (error != 0)
			return (resize_plan_error(pc, "scan-inode/add-db", error,
			    ino, iv.db[i]));
	}

	if (nblks <= NDADDR)
		return (0);
	remaining = nblks - NDADDR;
	nindir = (uint64_t)NINDIR(pc->fs);
	base_lbn = NDADDR;
	for (level = 1; level <= NIADDR && remaining != 0; level++) {
		cover = 1;
		for (j = 0; j < level; j++) {
			if (cover > UINT64_MAX / nindir) {
				cover = UINT64_MAX;
				break;
			}
			cover *= nindir;
		}
		need = resize_u64_min(remaining, cover);
		if (iv.ib[level - 1] != 0) {
			error = resize_plan_owner_abs_inode_slot(pc, inode_abs,
			    1, level - 1, &owner_abs);
			if (error != 0)
				return (resize_plan_error(pc,
				    "scan-inode/owner-ib", error, ino, level));
			error = resize_plan_scan_indirect(pc, ml, iv.size,
			    iv.ib[level - 1], owner_abs, level, base_lbn, need);
			if (error != 0)
				return (resize_plan_error(pc,
				    "scan-inode/indirect", error, ino, level));
		}
		remaining -= need;
		if (cover == UINT64_MAX)
			break;
		if (base_lbn > UINT64_MAX - cover)
			break;
		base_lbn += cover;
	}
	return (0);
}

static int
resize_plan_read_cg(struct resize_plan_ctx *pc, uint32_t cgx, u_int8_t **bufp,
    struct cg **cgpp)
{
	u_int8_t *buf;
	struct cg *cgp;
	uint64_t cg_fsb, cg_abs;
	size_t cgsize;
	int error;

	if (pc->fs->fs_cgsize <= 0 || pc->fs->fs_cgsize > MAXBSIZE)
		return (EINVAL);
	cgsize = (size_t)pc->fs->fs_cgsize;
	buf = malloc(cgsize);
	if (buf == NULL)
		return (ENOMEM);
	cg_fsb = (uint64_t)cgtod(pc->fs, cgx);
	error = resize_fs_abs_for_fsb(pc->fs_offset, pc->fs_fsize, cg_fsb,
	    cgsize, pc->container_bytes, &cg_abs);
	if (error != 0) {
		free(buf);
		return (error);
	}
	error = resize_pread_exact(pc->tfd, buf, cgsize, cg_abs);
	if (error != 0) {
		free(buf);
		return (error);
	}
	cgp = (struct cg *)buf;
	if (!cg_chkmagic(cgp)) {
		free(buf);
		return (EINVAL);
	}
	*bufp = buf;
	*cgpp = cgp;
	return (0);
}

static int
resize_plan_build_free_pool(struct resize_plan_ctx *pc)
{
	u_int8_t *cgbuf, *bfree;
	struct cg *cgp;
	uint64_t cgx, cg_base, frag_count, keep_count, d;
	int error;

	error = resize_pool_init(&pc->pool, pc->new_blocks);
	if (error != 0)
		return (error);
	for (cgx = 0; cgx < pc->fs->fs_ncg; cgx++) {
		error = resize_plan_read_cg(pc, (uint32_t)cgx, &cgbuf, &cgp);
		if (error != 0)
			return (resize_plan_error(pc, "build-pool/read-cg",
			    error, cgx, 0));
		cg_base = cgx * (uint64_t)pc->fs->fs_fpg;
		if (cg_base >= pc->old_blocks) {
			free(cgbuf);
			continue;
		}
		frag_count = resize_u64_min((uint64_t)pc->fs->fs_fpg,
		    pc->old_blocks - cg_base);
		if (cg_base >= pc->new_blocks)
			keep_count = 0;
		else
			keep_count = resize_u64_min(frag_count,
			    pc->new_blocks - cg_base);
		bfree = cg_blksfree(cgp);
		for (d = 0; d < keep_count; d++) {
			if (resize_bit_is_set(bfree, d))
				resize_pool_mark_free(&pc->pool, cg_base + d);
		}
		free(cgbuf);
	}
	return (0);
}

static int
resize_plan_scan_inodes(struct resize_plan_ctx *pc, struct resize_move_list *ml)
{
	u_int8_t *cgbuf, *inosused;
	struct cg *cgp;
	uint64_t cgx, ino_base, i, ino;
	int error;

	for (cgx = 0; cgx < pc->fs->fs_ncg; cgx++) {
		error = resize_plan_read_cg(pc, (uint32_t)cgx, &cgbuf, &cgp);
		if (error != 0)
			return (resize_plan_error(pc, "scan-inodes/read-cg",
			    error, cgx, 0));
		inosused = cg_inosused(cgp);
		ino_base = cgx * (uint64_t)pc->fs->fs_ipg;
		for (i = 0; i < pc->fs->fs_ipg; i++) {
			if (!resize_bit_is_set(inosused, i))
				continue;
			ino = ino_base + i;
			if (ino < ROOTINO)
				continue;
			if (ino > UINT32_MAX) {
				free(cgbuf);
				return (resize_plan_error(pc,
				    "scan-inodes/inumber-overflow", EOVERFLOW,
				    ino, cgx));
			}
			error = resize_plan_scan_inode(pc, ml, ino);
			if (error == ENOENT)
				continue;
			if (error != 0) {
				free(cgbuf);
				return (resize_plan_error(pc,
				    "scan-inodes/scan-inode", error, ino, cgx));
			}
		}
		free(cgbuf);
	}
	return (0);
}

static int
resize_build_inode_remap(struct resize_plan_ctx *pc, uint64_t new_blocks,
    struct resize_ino_remap *rm)
{
	struct resize_ino_vec doomed, freev;
	u_int8_t *cgbuf, *inosused;
	struct cg *cgp;
	uint64_t cgx, ino_base, i, ifsb;
	ufsino_t ino;
	size_t k;
	int error;

	memset(&doomed, 0, sizeof(doomed));
	memset(&freev, 0, sizeof(freev));
	memset(rm, 0, sizeof(*rm));

	for (cgx = 0; cgx < pc->fs->fs_ncg; cgx++) {
		error = resize_plan_read_cg(pc, (uint32_t)cgx, &cgbuf, &cgp);
		if (error != 0)
			goto out;
		inosused = cg_inosused(cgp);
		ino_base = cgx * (uint64_t)pc->fs->fs_ipg;
		for (i = 0; i < pc->fs->fs_ipg; i++) {
			if (ino_base + i > UINT32_MAX)
				break;
			ino = (ufsino_t)(ino_base + i);
			if (ino < ROOTINO)
				continue;
			ifsb = (uint64_t)ino_to_fsba(pc->fs, ino);
			if (ifsb >= pc->old_blocks)
				continue;
			if (resize_bit_is_set(inosused, i)) {
				if (ifsb >= new_blocks) {
					error = resize_ino_vec_push(&doomed, ino);
					if (error != 0) {
						free(cgbuf);
						goto out;
					}
				}
			} else {
				if (ifsb < new_blocks) {
					error = resize_ino_vec_push(&freev, ino);
					if (error != 0) {
						free(cgbuf);
						goto out;
					}
				}
			}
		}
		free(cgbuf);
	}

	if (doomed.n == 0) {
		error = 0;
		goto out;
	}
	qsort(doomed.v, doomed.n, sizeof(doomed.v[0]), resize_ino_cmp_u32);
	qsort(freev.v, freev.n, sizeof(freev.v[0]), resize_ino_cmp_u32);
	if (freev.n < doomed.n) {
		error = ENOSPC;
		goto out;
	}
	for (k = 0; k < doomed.n; k++) {
		error = resize_ino_remap_push(rm, doomed.v[k], freev.v[k]);
		if (error != 0)
			goto out;
	}
	qsort(rm->ents, rm->nent, sizeof(rm->ents[0]), resize_ino_remap_cmp_old);
	error = 0;
out:
	if (error != 0)
		resize_ino_remap_free(rm);
	resize_ino_vec_free(&doomed);
	resize_ino_vec_free(&freev);
	return (error);
}

struct resize_dir_fix_ctx {
	const struct resize_ino_remap *rm;
	uint64_t changed_blocks;
	uint64_t changed_entries;
	uint64_t remaining_bytes;
};

static int
resize_dir_fix_block_cb(const struct resize_plan_ctx *pc, uint64_t fsb,
    uint32_t bytes, void *cookie)
{
	struct resize_dir_fix_ctx *ctx = cookie;
	u_int8_t *buf;
	struct direct *dp;
	uint64_t abs;
	size_t boff, lim, off;
	uint32_t scan_bytes;
	uint16_t reclen;
	ufsino_t new_ino;
	int changed, error;

	if (fsb == 0 || bytes == 0)
		return (0);
	error = resize_fs_abs_for_fsb(pc->fs_offset, pc->fs_fsize, fsb, bytes,
	    pc->container_bytes, &abs);
	if (error != 0)
		return (error);
	buf = malloc(bytes);
	if (buf == NULL)
		return (ENOMEM);
	error = resize_read_bytes_any(pc->tfd, pc->container_bytes, abs, buf,
	    bytes);
	if (error != 0) {
		free(buf);
		return (error);
	}
	if (ctx->remaining_bytes == 0) {
		free(buf);
		return (0);
	}
	if (ctx->remaining_bytes < (uint64_t)bytes)
		scan_bytes = (uint32_t)ctx->remaining_bytes;
	else
		scan_bytes = bytes;
	ctx->remaining_bytes -= scan_bytes;

	changed = 0;
	for (boff = 0; boff < scan_bytes; boff += DIRBLKSIZ) {
		lim = scan_bytes - boff;
		if (lim > DIRBLKSIZ)
			lim = DIRBLKSIZ;
		off = 0;
		while (off < lim) {
			if (lim - off < offsetof(struct direct, d_name)) {
				free(buf);
				return (EINVAL);
			}
			dp = (struct direct *)(buf + boff + off);
			reclen = dp->d_reclen;
			if (reclen == 0 || (reclen & 0x3) != 0 ||
			    reclen > lim - off || dp->d_namlen > MAXNAMLEN ||
			    reclen < DIRECTSIZ(dp->d_namlen)) {
				free(buf);
				return (EINVAL);
			}
			if (dp->d_ino != 0 &&
			    resize_ino_remap_find(ctx->rm, dp->d_ino, &new_ino)
			    == 0) {
				dp->d_ino = new_ino;
				changed = 1;
				ctx->changed_entries++;
			}
			off += reclen;
		}
		if (off != lim) {
			free(buf);
			return (EINVAL);
		}
	}
	if (changed) {
		error = resize_write_bytes_any(pc->tfd, pc->container_bytes, abs,
		    buf, bytes);
		if (error != 0) {
			free(buf);
			return (error);
		}
		ctx->changed_blocks++;
	}
	free(buf);
	return (0);
}

static int
resize_rewrite_dirs_for_inode_remap(struct resize_plan_ctx *pc,
    const struct resize_ino_remap *rm)
{
	struct resize_dir_fix_ctx dctx;
	u_int8_t *cgbuf, *inosused;
	struct cg *cgp;
	struct resize_inode_view iv;
	uint64_t ino_abs, cgx, ino_base, i;
	ufsino_t ino;
	int error;

	memset(&dctx, 0, sizeof(dctx));
	dctx.rm = rm;

	for (cgx = 0; cgx < pc->fs->fs_ncg; cgx++) {
		error = resize_plan_read_cg(pc, (uint32_t)cgx, &cgbuf, &cgp);
		if (error != 0)
			return (error);
		inosused = cg_inosused(cgp);
		ino_base = cgx * (uint64_t)pc->fs->fs_ipg;
		for (i = 0; i < pc->fs->fs_ipg; i++) {
			if (!resize_bit_is_set(inosused, i))
				continue;
			if (ino_base + i > UINT32_MAX)
				break;
			ino = (ufsino_t)(ino_base + i);
			if (ino < ROOTINO)
				continue;
			if (resize_ino_remap_has_old(rm, ino))
				continue;
			error = resize_plan_read_inode(pc, ino, &ino_abs, &iv);
			if (error != 0)
				continue;
			if ((iv.mode & IFMT) != IFDIR)
				continue;
			dctx.remaining_bytes = iv.size;
			error = resize_walk_inode_data_blocks(pc, &iv,
			    resize_dir_fix_block_cb, &dctx);
			if (error != 0) {
				free(cgbuf);
				return (error);
			}
		}
		free(cgbuf);
	}
	if (pc->verbose) {
		fprintf(stderr,
		    "inode-remap: rewritten directory blocks=%" PRIu64
		    " entries=%" PRIu64 "\n", dctx.changed_blocks,
		    dctx.changed_entries);
	}
	return (0);
}

static int
resize_apply_inode_remap(struct resize_plan_ctx *pc, struct resize_super *sb,
    const struct resize_ino_remap *rm)
{
	u_int8_t *raw;
	const struct fs *ofs;
	struct fs *sfs;
	size_t i, j;
	ufsino_t new_ino;
	int old_alloc, new_alloc, is_dir;
	int error;

	if (rm->nent == 0)
		return (0);
	raw = malloc(pc->inode_size);
	if (raw == NULL)
		return (ENOMEM);

	for (i = 0; i < rm->nent; i++) {
		error = resize_inode_is_allocated(pc, rm->ents[i].old_ino,
		    &old_alloc);
		if (error != 0)
			goto out;
		error = resize_inode_is_allocated(pc, rm->ents[i].new_ino,
		    &new_alloc);
		if (error != 0)
			goto out;
		if (!old_alloc && new_alloc)
			continue;
		if (!old_alloc && !new_alloc) {
			error = EINVAL;
			goto out;
		}
		if (!new_alloc) {
			error = resize_inode_read_raw(pc, rm->ents[i].old_ino, raw);
			if (error != 0)
				goto out;
			error = resize_inode_raw_is_dir(pc, raw, &is_dir);
			if (error != 0)
				goto out;
			error = resize_inode_write_raw(pc, rm->ents[i].new_ino, raw);
			if (error != 0)
				goto out;
			error = resize_inode_bitmap_flip(pc, rm->ents[i].new_ino, 1,
			    is_dir);
			if (error != 0 && error != EEXIST)
				goto out;
		}
	}

	error = resize_rewrite_dirs_for_inode_remap(pc, rm);
	if (error != 0)
		goto out;

	for (i = 0; i < rm->nent; i++) {
		error = resize_inode_is_allocated(pc, rm->ents[i].old_ino,
		    &old_alloc);
		if (error != 0)
			goto out;
		if (!old_alloc)
			continue;
		error = resize_inode_read_raw(pc, rm->ents[i].old_ino, raw);
		if (error != 0)
			goto out;
		error = resize_inode_raw_is_dir(pc, raw, &is_dir);
		if (error != 0)
			goto out;
		error = resize_inode_zero_raw(pc, rm->ents[i].old_ino);
		if (error != 0)
			goto out;
		error = resize_inode_bitmap_flip(pc, rm->ents[i].old_ino, 0, is_dir);
		if (error != 0 && error != ENOENT)
			goto out;
	}

	/* Keep snapshot inode references coherent if any were remapped. */
	ofs = (const struct fs *)sb->raw;
	sfs = (struct fs *)sb->raw;
	for (j = 0; j < FSMAXSNAP; j++) {
		if (ofs->fs_snapinum[j] == 0)
			continue;
		if (resize_ino_remap_find(rm, ofs->fs_snapinum[j], &new_ino) == 0)
			sfs->fs_snapinum[j] = new_ino;
	}

	if (fsync(pc->tfd) == -1) {
		error = errno;
		goto out;
	}
	error = 0;
out:
	free(raw);
	return (error);
}

static int
resize_plan_ctx_init_from_super(struct resize_plan_ctx *pc, int tfd,
    uint64_t container_bytes, uint64_t fs_offset, int verbose,
    const struct resize_super *sb)
{
	const struct fs *fs;

	memset(pc, 0, sizeof(*pc));
	fs = (const struct fs *)sb->raw;
	if (fs->fs_magic != FS_UFS1_MAGIC && fs->fs_magic != FS_UFS2_MAGIC)
		return (EINVAL);
	pc->tfd = tfd;
	pc->container_bytes = container_bytes;
	pc->fs_offset = fs_offset;
	pc->fs = fs;
	pc->old_blocks = sb->fs_size_blocks;
	pc->new_blocks = sb->fs_size_blocks;
	pc->fs_fsize = sb->fs_fsize;
	pc->fs_bsize = (uint32_t)fs->fs_bsize;
	pc->verbose = verbose;
	if (fs->fs_magic == FS_UFS1_MAGIC) {
		pc->ptr_width = 4;
		pc->inode_size = sizeof(struct ufs1_dinode);
		pc->maxsymlinklen = MAXSYMLINKLEN_UFS1;
	} else {
		pc->ptr_width = 8;
		pc->inode_size = sizeof(struct ufs2_dinode);
		pc->maxsymlinklen = MAXSYMLINKLEN_UFS2;
	}
	return (0);
}

static int
resize_plan_auto_shrink_end(int tfd, uint64_t container_bytes,
    const struct resize_options *opt, const struct resize_super *sb,
    uint64_t target_size, struct resize_move_list *ml)
{
	struct resize_plan_ctx pc;
	const struct fs *fs;
	int error;

	if (target_size >= sb->fs_size_bytes)
		return (0);
	if (target_size % sb->fs_fsize != 0)
		return (EINVAL);
	memset(&pc, 0, sizeof(pc));
	fs = (const struct fs *)sb->raw;
	if (fs->fs_fsize <= 0 || fs->fs_bsize <= 0 || fs->fs_frag <= 0)
		return (EINVAL);
	pc.tfd = tfd;
	pc.container_bytes = container_bytes;
	pc.fs_offset = opt->offset_bytes;
	pc.fs = fs;
	pc.old_blocks = sb->fs_size_blocks;
	pc.new_blocks = target_size / sb->fs_fsize;
	pc.fs_fsize = sb->fs_fsize;
	pc.fs_bsize = (uint32_t)fs->fs_bsize;
	pc.verbose = opt->verbose;
	if (fs->fs_magic == FS_UFS1_MAGIC) {
		pc.ptr_width = 4;
		pc.inode_size = sizeof(struct ufs1_dinode);
		pc.maxsymlinklen = MAXSYMLINKLEN_UFS1;
	} else if (fs->fs_magic == FS_UFS2_MAGIC) {
		pc.ptr_width = 8;
		pc.inode_size = sizeof(struct ufs2_dinode);
		pc.maxsymlinklen = MAXSYMLINKLEN_UFS2;
	} else {
		return (EINVAL);
	}

	error = resize_plan_build_free_pool(&pc);
	if (error != 0)
		goto out;
	error = resize_plan_scan_inodes(&pc, ml);
	if (error != 0)
		goto out;
	resize_vlog(opt->verbose,
	    "auto-plan: generated %zu moves for shrink-end\n", ml->nmoves);
out:
	resize_pool_free(&pc.pool);
	return (error);
}

static int
resize_journal_write_header(struct resize_journal *jr)
{
	struct resize_jhdr_v1 tmp;
	ssize_t n;

	tmp = jr->hdr;
	tmp.header_crc32 = 0;
	jr->hdr.header_crc32 = resize_crc32_calc(&tmp, sizeof(tmp));

	n = pwrite(jr->fd, &jr->hdr, sizeof(jr->hdr), 0);
	if (n != (ssize_t)sizeof(jr->hdr))
		return (errno != 0 ? errno : EIO);
	return (0);
}

static int
resize_journal_create(const char *path, uint64_t fs_offset, uint64_t old_size,
    uint64_t new_size, uint64_t sb_rel, uint32_t fs_fsize,
    struct resize_journal *jr)
{
	struct timespec ts;
	int error;

	memset(jr, 0, sizeof(*jr));
	jr->fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
	if (jr->fd == -1)
		return (errno);

	memset(&jr->hdr, 0, sizeof(jr->hdr));
	memcpy(jr->hdr.magic, RESIZE_JOURNAL_MAGIC, sizeof(jr->hdr.magic));
	jr->hdr.version = RESIZE_JOURNAL_VERSION;
	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		jr->hdr.created_unix_ns = 0;
	else
		jr->hdr.created_unix_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
		    (uint64_t)ts.tv_nsec;
	jr->hdr.fs_offset_bytes = fs_offset;
	jr->hdr.old_fs_size_bytes = old_size;
	jr->hdr.new_fs_size_bytes = new_size;
	jr->hdr.sb_rel_offset = sb_rel;
	jr->hdr.fs_fsize = fs_fsize;
	jr->hdr.phase = RESIZE_PHASE_PLANNED;
	jr->hdr.next_seq = 1;

	error = resize_journal_write_header(jr);
	if (error != 0) {
		close(jr->fd);
		return (error);
	}
	if (fsync(jr->fd) == -1) {
		error = errno;
		close(jr->fd);
		return (error);
	}
	return (0);
}

static int	resize_journal_record_count(struct resize_journal *, size_t *);
static int	resize_journal_read_record(struct resize_journal *, size_t,
		    struct resize_jrec_v1 *);

static int
resize_journal_open_existing(const char *path, struct resize_journal *jr)
{
	struct resize_jhdr_v1 tmp;
	size_t nrecs;
	ssize_t n;
	uint32_t crc;
	int error;

	memset(jr, 0, sizeof(*jr));
	jr->fd = open(path, O_RDWR);
	if (jr->fd == -1)
		return (errno);
	n = pread(jr->fd, &jr->hdr, sizeof(jr->hdr), 0);
	if (n != (ssize_t)sizeof(jr->hdr)) {
		close(jr->fd);
		return (EINVAL);
	}
	if (memcmp(jr->hdr.magic, RESIZE_JOURNAL_MAGIC, sizeof(jr->hdr.magic))
	    != 0 || jr->hdr.version != RESIZE_JOURNAL_VERSION) {
		close(jr->fd);
		return (EINVAL);
	}
	tmp = jr->hdr;
	crc = tmp.header_crc32;
	tmp.header_crc32 = 0;
	if (resize_crc32_calc(&tmp, sizeof(tmp)) != crc) {
		close(jr->fd);
		return (EINVAL);
	}
	error = resize_journal_record_count(jr, &nrecs);
	if (error != 0) {
		close(jr->fd);
		return (error);
	}
	return (0);
}

static int
resize_journal_record_count(struct resize_journal *jr, size_t *nrecsp)
{
	struct stat st;
	uint64_t nrecs64, recbytes, wantbytes;
	int error;

	if (fstat(jr->fd, &st) == -1)
		return (errno);
	if (st.st_size < 0 || (uint64_t)st.st_size < sizeof(jr->hdr))
		return (EINVAL);
	if (jr->hdr.next_seq == 0)
		return (EINVAL);
	nrecs64 = jr->hdr.next_seq - 1;
	if (nrecs64 > SIZE_MAX)
		return (EINVAL);
	error = resize_mul_u64(nrecs64, sizeof(struct resize_jrec_v1), &recbytes);
	if (error != 0)
		return (EINVAL);
	error = resize_add_u64(sizeof(jr->hdr), recbytes, &wantbytes);
	if (error != 0)
		return (EINVAL);
	if ((uint64_t)st.st_size < wantbytes)
		return (EINVAL);
	*nrecsp = (size_t)nrecs64;
	return (0);
}

static int
resize_journal_read_record(struct resize_journal *jr, size_t idx,
    struct resize_jrec_v1 *rec)
{
	uint64_t rel, abs, seq;
	ssize_t n;
	uint32_t crc;
	int error;

	error = resize_mul_u64((uint64_t)idx, sizeof(*rec), &rel);
	if (error != 0)
		return (EINVAL);
	error = resize_add_u64(sizeof(jr->hdr), rel, &abs);
	if (error != 0 || abs > INT64_MAX)
		return (EINVAL);
	n = pread(jr->fd, rec, sizeof(*rec), (off_t)abs);
	if (n != (ssize_t)sizeof(*rec))
		return (EINVAL);
	if (rec->rec_magic != RESIZE_REC_MAGIC)
		return (EINVAL);
	seq = (uint64_t)idx + 1;
	if (rec->seq != seq)
		return (EINVAL);
	crc = rec->rec_crc32;
	rec->rec_crc32 = 0;
	rec->rec_crc32 = resize_crc32_calc(rec, sizeof(*rec));
	if (rec->rec_crc32 != crc)
		return (EINVAL);
	rec->rec_crc32 = crc;
	return (0);
}

static int
resize_journal_sync(struct resize_journal *jr)
{
	if (fsync(jr->fd) == -1)
		return (errno);
	return (0);
}

static int
resize_journal_append(struct resize_journal *jr, uint16_t type, uint16_t op,
    const struct resize_move *mv, uint32_t aux)
{
	struct resize_jrec_v1 rec;
	off_t off;
	ssize_t n;
	int error;

	memset(&rec, 0, sizeof(rec));
	rec.rec_magic = RESIZE_REC_MAGIC;
	rec.rec_type = type;
	rec.op = op;
	rec.seq = jr->hdr.next_seq++;
	if (mv != NULL) {
		rec.old_fsb = mv->old_fsb;
		rec.new_fsb = mv->new_fsb;
		rec.bytes = mv->bytes;
		rec.flags = mv->flags;
		rec.owner_abs_offset = mv->owner_abs_offset;
		rec.owner_width = mv->owner_width;
	}
	rec.aux = aux;
	rec.rec_crc32 = 0;
	rec.rec_crc32 = resize_crc32_calc(&rec, sizeof(rec));

	off = (off_t)sizeof(jr->hdr) + (off_t)(rec.seq - 1) * (off_t)sizeof(rec);
	n = pwrite(jr->fd, &rec, sizeof(rec), off);
	if (n != (ssize_t)sizeof(rec))
		return (errno != 0 ? errno : EIO);

	error = resize_journal_write_header(jr);
	if (error != 0)
		return (error);
	return (0);
}

static int
resize_journal_set_phase(struct resize_journal *jr, uint32_t phase)
{
	int error;

	if (phase < jr->hdr.phase)
		return (EINVAL);
	error = resize_journal_append(jr, RESIZE_REC_PHASE, 0, NULL, phase);
	if (error != 0)
		return (error);
	jr->hdr.phase = phase;
	return (resize_journal_write_header(jr));
}

static int
resize_journal_reset(struct resize_journal *jr)
{
	int error;

	if (ftruncate(jr->fd, (off_t)sizeof(jr->hdr)) == -1)
		return (errno);
	jr->hdr.phase = RESIZE_PHASE_PLANNED;
	jr->hdr.next_seq = 1;
	error = resize_journal_write_header(jr);
	if (error != 0)
		return (error);
	return (resize_journal_sync(jr));
}

static void
resize_journal_close(struct resize_journal *jr)
{
	if (jr->fd != -1)
		close(jr->fd);
	jr->fd = -1;
}

static int
resize_alloc_find(struct resize_alloc_map *amap, uint64_t fsb, size_t *idxp)
{
	size_t i;

	for (i = 0; i < amap->nent; i++) {
		if (amap->ents[i].fsb == fsb) {
			*idxp = i;
			return (0);
		}
	}
	return (ENOENT);
}

static int
resize_alloc_set(struct resize_alloc_map *amap, uint64_t fsb, int allocated)
{
	struct resize_alloc_ent *nents;
	size_t idx, ncap;
	int error;

	error = resize_alloc_find(amap, fsb, &idx);
	if (error == 0) {
		amap->ents[idx].allocated = allocated;
		return (0);
	}
	if (amap->nent == amap->cap) {
		ncap = (amap->cap == 0) ? 128 : amap->cap * 2;
		nents = reallocarray(amap->ents, ncap, sizeof(*nents));
		if (nents == NULL)
			return (ENOMEM);
		amap->ents = nents;
		amap->cap = ncap;
	}
	amap->ents[amap->nent].fsb = fsb;
	amap->ents[amap->nent].allocated = allocated;
	amap->nent++;
	return (0);
}

static int
resize_alloc_init_from_moves(struct resize_alloc_map *amap,
    const struct resize_move_list *ml)
{
	size_t i;
	int error;

	memset(amap, 0, sizeof(*amap));
	for (i = 0; i < ml->nmoves; i++) {
		error = resize_alloc_set(amap, ml->moves[i].old_fsb, 1);
		if (error != 0)
			return (error);
		error = resize_alloc_set(amap, ml->moves[i].new_fsb, 0);
		if (error != 0)
			return (error);
	}
	return (0);
}

static void
resize_alloc_free(struct resize_alloc_map *amap)
{
	free(amap->ents);
	memset(amap, 0, sizeof(*amap));
}

static int
resize_runtime_abs_for_fsb(struct resize_runtime *rt, uint64_t fsb, size_t len,
    uint64_t *abs)
{
	uint64_t rel, tmp;
	int error;

	error = resize_mul_u64(fsb, (uint64_t)rt->fs_fsize, &rel);
	if (error != 0)
		return (error);
	error = resize_add_u64(rt->fs_offset, rel, &tmp);
	if (error != 0)
		return (error);
	error = resize_add_u64(tmp, (uint64_t)len, &rel);
	if (error != 0)
		return (error);
	if (rel > rt->container_bytes)
		return (EINVAL);
	*abs = tmp;
	return (0);
}

static int
rt_read_block(void *cookie, uint64_t fsb, void *buf, size_t len)
{
	struct resize_runtime *rt = cookie;
	uint64_t abs;
	int error;
	ssize_t n;

	error = resize_runtime_abs_for_fsb(rt, fsb, len, &abs);
	if (error != 0)
		return (error);
	n = pread(rt->tfd, buf, len, (off_t)abs);
	if (n != (ssize_t)len)
		return (errno != 0 ? errno : EIO);
	return (0);
}

static int
rt_write_block(void *cookie, uint64_t fsb, const void *buf, size_t len)
{
	struct resize_runtime *rt = cookie;
	uint64_t abs;
	int error;
	ssize_t n;

	error = resize_runtime_abs_for_fsb(rt, fsb, len, &abs);
	if (error != 0)
		return (error);
	if (rt->dry_run)
		return (0);
	n = pwrite(rt->tfd, buf, len, (off_t)abs);
	if (n != (ssize_t)len)
		return (errno != 0 ? errno : EIO);
	return (0);
}

static int
rt_sync_target(void *cookie)
{
	struct resize_runtime *rt = cookie;

	if (rt->dry_run)
		return (0);
	if (fsync(rt->tfd) == -1)
		return (errno);
	return (0);
}

static int
rt_journal_intent(void *cookie, enum resize_mutation_op op,
    const struct resize_move *mv)
{
	struct resize_runtime *rt = cookie;
	return (resize_journal_append(rt->jr, RESIZE_REC_INTENT, (uint16_t)op,
	    mv, 0));
}

static int
rt_journal_applied(void *cookie, enum resize_mutation_op op,
    const struct resize_move *mv)
{
	struct resize_runtime *rt = cookie;
	return (resize_journal_append(rt->jr, RESIZE_REC_APPLIED, (uint16_t)op,
	    mv, 0));
}

static int
rt_sync_journal(void *cookie)
{
	struct resize_runtime *rt = cookie;
	return (resize_journal_sync(rt->jr));
}

static int
rt_owner_get(void *cookie, const struct resize_owner_ref *owner, uint64_t *fsb)
{
	struct resize_runtime *rt = cookie;
	uint32_t v32;
	uint64_t v64;
	uint64_t abs = owner->owner_block_fsb;
	uint32_t width = owner->slot_index;
	uint64_t end;
	int error;

	if (width == 0)
		width = 8;
	if (width != 4 && width != 8)
		return (EINVAL);
	error = resize_add_u64(abs, (uint64_t)width, &end);
	if (error != 0)
		return (error);
	if (end > rt->container_bytes)
		return (EINVAL);
	if (width == 4) {
		error = resize_read_bytes_any(rt->tfd, rt->container_bytes, abs,
		    &v32, sizeof(v32));
		if (error != 0)
			return (error);
		*fsb = v32;
	} else {
		error = resize_read_bytes_any(rt->tfd, rt->container_bytes, abs,
		    &v64, sizeof(v64));
		if (error != 0)
			return (error);
		*fsb = v64;
	}
	return (0);
}

static int
rt_owner_set(void *cookie, const struct resize_owner_ref *owner, uint64_t fsb)
{
	struct resize_runtime *rt = cookie;
	uint64_t abs = owner->owner_block_fsb;
	uint32_t width = owner->slot_index;
	uint32_t v32;
	uint64_t end;
	int error;

	if (width == 0)
		width = 8;
	if (width != 4 && width != 8)
		return (EINVAL);
	error = resize_add_u64(abs, (uint64_t)width, &end);
	if (error != 0)
		return (error);
	if (end > rt->container_bytes)
		return (EINVAL);
	if (rt->dry_run)
		return (0);
	if (width == 4) {
		if (fsb > UINT32_MAX)
			return (EOVERFLOW);
		v32 = (uint32_t)fsb;
		return (resize_write_bytes_any(rt->tfd, rt->container_bytes, abs,
		    &v32, sizeof(v32)));
	} else {
		return (resize_write_bytes_any(rt->tfd, rt->container_bytes, abs,
		    &fsb, sizeof(fsb)));
	}
}

static int
rt_alloc_is_free(void *cookie, uint64_t fsb, int *is_free)
{
	struct resize_runtime *rt = cookie;
	u_int8_t *cgbuf, *bfree;
	struct cg *cgp;
	uint64_t cg_abs;
	uint64_t frag;
	uint32_t cgx;
	size_t idx;
	int error;

	error = resize_alloc_find(&rt->amap, fsb, &idx);
	if (error == 0) {
		*is_free = (rt->amap.ents[idx].allocated == 0);
		return (0);
	}
	if (error != ENOENT)
		return (error);
	cgx = (uint32_t)dtog(&rt->fs, fsb);
	error = resize_rt_read_cg(rt, cgx, &cgbuf, &cgp, &cg_abs);
	if (error != 0)
		return (error);
	(void)cg_abs;
	frag = (uint64_t)dtogd(&rt->fs, fsb);
	if (frag >= cgp->cg_ndblk) {
		free(cgbuf);
		return (EINVAL);
	}
	bfree = cg_blksfree(cgp);
	*is_free = resize_bit_is_set(bfree, frag);
	free(cgbuf);
	(void)resize_alloc_set(&rt->amap, fsb, (*is_free ? 0 : 1));
	return (0);
}

static int
resize_rt_read_cg(struct resize_runtime *rt, uint32_t cgx, u_int8_t **bufp,
    struct cg **cgpp, uint64_t *cg_absp)
{
	u_int8_t *buf;
	struct cg *cgp;
	uint64_t cg_fsb, cg_abs;
	size_t cgsize;
	int error;

	if (rt->fs.fs_cgsize <= 0 || rt->fs.fs_cgsize > MAXBSIZE)
		return (EINVAL);
	cgsize = (size_t)rt->fs.fs_cgsize;
	buf = malloc(cgsize);
	if (buf == NULL)
		return (ENOMEM);
	cg_fsb = (uint64_t)cgtod(&rt->fs, cgx);
	error = resize_runtime_abs_for_fsb(rt, cg_fsb, cgsize, &cg_abs);
	if (error != 0) {
		free(buf);
		return (error);
	}
	error = resize_read_bytes_any(rt->tfd, rt->container_bytes, cg_abs, buf,
	    cgsize);
	if (error != 0) {
		free(buf);
		return (error);
	}
	cgp = (struct cg *)buf;
	if (!cg_chkmagic(cgp)) {
		free(buf);
		return (EINVAL);
	}
	*bufp = buf;
	*cgpp = cgp;
	*cg_absp = cg_abs;
	return (0);
}

static int
resize_cg_reserved_range_frag(const struct fs *fs, uint32_t cgx, uint64_t *startp,
    uint64_t *endp)
{
	daddr_t base, sblk, dmin;

	if (startp == NULL || endp == NULL)
		return (EINVAL);
	base = cgbase(fs, cgx);
	if (cgx == 0)
		sblk = base;
	else
		sblk = cgsblock(fs, cgx);
	dmin = cgdmin(fs, cgx);
	if (sblk < base || dmin < sblk)
		return (EINVAL);
	*startp = (uint64_t)(sblk - base);
	*endp = (uint64_t)(dmin - base);
	return (0);
}

static int
resize_cg_inode_range_frag(const struct fs *fs, uint32_t cgx, uint64_t *startp,
    uint64_t *endp)
{
	daddr_t base, imin, dmin;

	if (startp == NULL || endp == NULL)
		return (EINVAL);
	base = cgbase(fs, cgx);
	imin = cgimin(fs, cgx);
	dmin = cgdmin(fs, cgx);
	if (imin < base || dmin < imin)
		return (EINVAL);
	*startp = (uint64_t)(imin - base);
	*endp = (uint64_t)(dmin - base);
	return (0);
}

static int
resize_rt_zero_fsb_range(struct resize_runtime *rt, uint64_t start_fsb,
    uint64_t end_fsb)
{
	u_int8_t zbuf[64 * 1024];
	uint64_t fsb, max_frags, todo, bytes, abs;
	int error;

	if (end_fsb <= start_fsb)
		return (0);
	if (rt->fs.fs_fsize <= 0)
		return (EINVAL);
	memset(zbuf, 0, sizeof(zbuf));
	max_frags = sizeof(zbuf) / (uint64_t)rt->fs.fs_fsize;
	if (max_frags == 0)
		max_frags = 1;
	for (fsb = start_fsb; fsb < end_fsb; fsb += todo) {
		todo = end_fsb - fsb;
		if (todo > max_frags)
			todo = max_frags;
		error = resize_mul_u64(todo, (uint64_t)rt->fs.fs_fsize, &bytes);
		if (error != 0)
			return (error);
		if (bytes > sizeof(zbuf))
			return (EOVERFLOW);
		error = resize_runtime_abs_for_fsb(rt, fsb, (size_t)bytes, &abs);
		if (error != 0)
			return (error);
		error = resize_write_bytes_any(rt->tfd, rt->container_bytes, abs, zbuf,
		    (size_t)bytes);
		if (error != 0)
			return (error);
	}
	return (0);
}

static int
resize_cg_rebuild_clusters(const struct fs *fs, struct cg *cgp, uint64_t keep)
{
	u_int8_t *bfree, *clusters, *mapp;
	int32_t *sump;
	uint64_t b, lim, f, rem, cluster, run, ncluster;
	size_t clbytes, sumbytes;
	int maxcluster, map, bit;

	if (fs->fs_contigsumsize <= 0)
		return (0);
	if (fs->fs_frag <= 0)
		return (EINVAL);
	maxcluster = fragstoblks(fs, fs->fs_fpg);
	if (maxcluster < 0)
		return (EINVAL);
	if (maxcluster == 0)
		return (0);
	ncluster = keep / (uint64_t)fs->fs_frag;
	if (ncluster > (uint64_t)maxcluster)
		return (EINVAL);
	clbytes = (size_t)howmany(maxcluster, NBBY);
	sumbytes = ((size_t)fs->fs_contigsumsize + 1) * sizeof(int32_t);
	clusters = cg_clustersfree(cgp);
	sump = cg_clustersum(cgp);
	bfree = cg_blksfree(cgp);
	memset(clusters, 0, clbytes);
	memset(sump, 0, sumbytes);

	for (b = 0, cluster = 0; b < keep && cluster < ncluster;
	    b += (uint64_t)fs->fs_frag, cluster++) {
		lim = keep - b;
		if (lim > (uint64_t)fs->fs_frag)
			lim = (uint64_t)fs->fs_frag;
		if (lim != (uint64_t)fs->fs_frag)
			continue;
		rem = 0;
		for (f = 0; f < lim; f++) {
			if (resize_bit_is_set(bfree, b + f))
				rem++;
		}
		if (rem == (uint64_t)fs->fs_frag)
			resize_bit_set(clusters, cluster);
	}

	mapp = clusters;
	map = *mapp++;
	bit = 1;
	run = 0;
	for (cluster = 0; cluster < ncluster; cluster++) {
		if ((map & bit) != 0) {
			run++;
		} else if (run != 0) {
			if (run > (uint64_t)fs->fs_contigsumsize)
				run = (uint64_t)fs->fs_contigsumsize;
			sump[run]++;
			run = 0;
		}
		if ((cluster & (NBBY - 1)) != (NBBY - 1))
			bit <<= 1;
		else {
			map = *mapp++;
			bit = 1;
		}
	}
	if (run != 0) {
		if (run > (uint64_t)fs->fs_contigsumsize)
			run = (uint64_t)fs->fs_contigsumsize;
		sump[run]++;
	}
	return (0);
}

static int
resize_rt_init_cg(struct resize_runtime *rt, const struct fs *fs,
    const struct cg *ref, uint32_t cgx, u_int8_t **bufp, struct cg **cgpp,
    uint64_t *cg_absp)
{
	u_int8_t *buf, *bfree;
	struct cg *cgp;
	uint64_t cg_abs, cg_fsb, cg_base, keep, rem, f, reserve_start;
	uint64_t reserve_end, inode_start, inode_end;
	uint64_t zero_start_fsb, zero_end_fsb;
	uint64_t want_nclusterblks;
	int16_t want_ncyl;
	size_t cgsize;
	time_t now;
	int error;

	if (ref == NULL || fs->fs_cgsize <= 0 || fs->fs_cgsize > MAXBSIZE)
		return (EINVAL);
	cgsize = (size_t)fs->fs_cgsize;
	buf = calloc(1, cgsize);
	if (buf == NULL)
		return (ENOMEM);
	cg_fsb = (uint64_t)cgtod(fs, cgx);
	error = resize_runtime_abs_for_fsb(rt, cg_fsb, cgsize, &cg_abs);
	if (error != 0) {
		free(buf);
		return (error);
	}
	cgp = (struct cg *)buf;
	now = time(NULL);
	cgp->cg_magic = CG_MAGIC;
	cgp->cg_time = (int32_t)now;
	cgp->cg_ffs2_time = (int64_t)now;
	cgp->cg_cgx = cgx;
	cgp->cg_btotoff = ref->cg_btotoff;
	cgp->cg_boff = ref->cg_boff;
	cgp->cg_iusedoff = ref->cg_iusedoff;
	cgp->cg_freeoff = ref->cg_freeoff;
	cgp->cg_nextfreeoff = ref->cg_nextfreeoff;
	cgp->cg_clustersumoff = ref->cg_clustersumoff;
	cgp->cg_clusteroff = ref->cg_clusteroff;
	cgp->cg_niblk = ref->cg_niblk;

	cg_base = (uint64_t)cgx * (uint64_t)fs->fs_fpg;
	if (cg_base >= (uint64_t)fs->fs_size) {
		keep = 0;
	} else {
		rem = (uint64_t)fs->fs_size - cg_base;
		keep = resize_u64_min(rem, (uint64_t)fs->fs_fpg);
	}
	if (keep > UINT32_MAX) {
		free(buf);
		return (EOVERFLOW);
	}
	cgp->cg_ndblk = (u_int32_t)keep;
	if (fs->fs_magic == FS_UFS1_MAGIC) {
			error = resize_expected_cg_ncyl(fs, cgx, &want_ncyl);
		if (error != 0) {
			free(buf);
			return (error);
		}
		cgp->cg_ncyl = want_ncyl;
		cgp->cg_initediblk = 0;
		cgp->cg_ffs2_niblk = 0;
	} else {
		cgp->cg_ncyl = 0;
		cgp->cg_ffs2_niblk = (u_int32_t)fs->fs_ipg;
		cgp->cg_initediblk = 0;
	}
	cgp->cg_rotor = 0;
	cgp->cg_frotor = 0;
	cgp->cg_irotor = 0;
	cgp->cg_cs.cs_ndir = 0;
	cgp->cg_cs.cs_nifree = fs->fs_ipg;
	cgp->cg_cs.cs_nbfree = 0;
	cgp->cg_cs.cs_nffree = 0;
	if (fs->fs_contigsumsize > 0)
		want_nclusterblks = keep / (uint64_t)fs->fs_frag;
	else
		want_nclusterblks = 0;
	if (want_nclusterblks > UINT32_MAX) {
		free(buf);
		return (EOVERFLOW);
	}
	cgp->cg_nclusterblks = (u_int32_t)want_nclusterblks;

	error = resize_cg_reserved_range_frag(fs, cgx, &reserve_start,
	    &reserve_end);
	if (error != 0) {
		free(buf);
		return (error);
	}
	if (reserve_start > keep)
		reserve_start = keep;
	if (reserve_end > keep)
		reserve_end = keep;
	error = resize_cg_inode_range_frag(fs, cgx, &inode_start, &inode_end);
	if (error != 0) {
		free(buf);
		return (error);
	}
	if (inode_start > keep)
		inode_start = keep;
	if (inode_end > keep)
		inode_end = keep;
	if (inode_end > inode_start) {
		error = resize_add_u64(cg_base, inode_start, &zero_start_fsb);
		if (error != 0) {
			free(buf);
			return (error);
		}
		error = resize_add_u64(cg_base, inode_end, &zero_end_fsb);
		if (error != 0) {
			free(buf);
			return (error);
		}
		error = resize_rt_zero_fsb_range(rt, zero_start_fsb, zero_end_fsb);
		if (error != 0) {
			free(buf);
			return (error);
		}
	}
	bfree = cg_blksfree(cgp);
	for (f = 0; f < keep; f++)
		resize_bit_set(bfree, f);
	for (f = reserve_start; f < reserve_end; f++)
		resize_bit_clear(bfree, f);
	error = resize_cg_rebuild_clusters(fs, cgp, keep);
	if (error != 0) {
		free(buf);
		return (error);
	}

	error = resize_write_bytes_any(rt->tfd, rt->container_bytes, cg_abs, buf,
	    cgsize);
	if (error != 0) {
		free(buf);
		return (error);
	}
	*bufp = buf;
	*cgpp = cgp;
	*cg_absp = cg_abs;
	return (0);
}

static int
resize_super_csaddr_fsb(const struct fs *fs, uint64_t *fsbp)
{
	int64_t v;

	if (fs->fs_magic == FS_UFS1_MAGIC) {
		v = fs->fs_ffs1_csaddr;
	} else {
		v = fs->fs_csaddr;
		if (v <= 0 && fs->fs_ffs1_csaddr > 0)
			v = fs->fs_ffs1_csaddr;
	}
	if (v <= 0)
		return (EINVAL);
	*fsbp = (uint64_t)v;
	return (0);
}

static int
resize_super_write_all(struct resize_runtime *rt, struct resize_super *sb)
{
	struct fs *fs = (struct fs *)sb->raw;
	uint64_t sb_bytes, sb_fsb, rel, abs, end;
	u_int32_t cgx;
	ssize_t n;
	int error;

	if (rt->dry_run)
		return (0);
	if (fs->fs_sbsize <= 0 || (uint64_t)fs->fs_sbsize > sizeof(sb->raw))
		return (EINVAL);
	if (fs->fs_fsize <= 0)
		return (EINVAL);
	sb_bytes = (uint64_t)fs->fs_sbsize;

	n = pwrite(rt->tfd, sb->raw, (size_t)sb_bytes, (off_t)sb->sb_abs_offset);
	if (n != (ssize_t)sb_bytes)
		return (errno != 0 ? errno : EIO);

	for (cgx = 0; cgx < fs->fs_ncg; cgx++) {
		sb_fsb = (uint64_t)cgsblock(fs, cgx);
		if (sb_fsb >= (uint64_t)fs->fs_size)
			continue;
		error = resize_mul_u64(sb_fsb, (uint64_t)fs->fs_fsize, &rel);
		if (error != 0)
			return (error);
		error = resize_add_u64(rt->fs_offset, rel, &abs);
		if (error != 0)
			return (error);
		if (abs == sb->sb_abs_offset)
			continue;
		error = resize_add_u64(abs, sb_bytes, &end);
		if (error != 0)
			return (error);
		if (end > rt->container_bytes)
			return (EINVAL);
		n = pwrite(rt->tfd, sb->raw, (size_t)sb_bytes, (off_t)abs);
		if (n != (ssize_t)sb_bytes)
			return (errno != 0 ? errno : EIO);
	}
	return (rt_sync_target(rt));
}

static int
resize_rt_update_frag_alloc(struct resize_runtime *rt, uint64_t fsb,
    int allocated)
{
	u_int8_t *cgbuf, *bfree;
	struct cg *cgp;
	uint64_t cg_abs;
	uint32_t cgx;
	uint64_t frag;
	int is_free;
	int error;

	cgx = (uint32_t)dtog(&rt->fs, fsb);
	error = resize_rt_read_cg(rt, cgx, &cgbuf, &cgp, &cg_abs);
	if (error != 0)
		return (error);
	frag = (uint64_t)dtogd(&rt->fs, fsb);
	if (frag >= cgp->cg_ndblk) {
		free(cgbuf);
		return (EINVAL);
	}
	bfree = cg_blksfree(cgp);
	is_free = resize_bit_is_set(bfree, frag);
	if (allocated) {
		if (!is_free) {
			free(cgbuf);
			return (0);
		}
		resize_bit_clear(bfree, frag);
	} else {
		if (is_free) {
			free(cgbuf);
			return (0);
		}
		resize_bit_set(bfree, frag);
	}
	error = resize_write_bytes_any(rt->tfd, rt->container_bytes, cg_abs, cgbuf,
	    (size_t)rt->fs.fs_cgsize);
	free(cgbuf);
	return (error);
}

static int
resize_recompute_free_summaries(struct resize_runtime *rt, struct resize_super *sb)
{
	struct fs *fs = (struct fs *)sb->raw;
	u_int8_t *cgbuf, *bfree;
	struct cg *cgp;
	struct cg refcg;
	uint64_t cg_abs, cgx, cg_base, keep, rem;
	uint64_t reserve_start, reserve_end, inode_start, inode_end;
	uint64_t zero_start_fsb, zero_end_fsb, zero_rel_start, zero_rel_end;
	uint64_t csaddr_fsb, cs_abs, cs_off, cs_ent_abs, cs_end;
	uint64_t b, lim, f, run, old_ndblk, want_nclusterblks;
	int64_t tot_ndir, tot_nbfree, tot_nifree, tot_nffree;
	int64_t cg_nbfree, cg_nffree;
	int32_t cg_ndir, cg_nifree;
	int16_t want_ncyl;
	time_t now;
	int have_refcg;
	int error;

	if (fs->fs_frag <= 0 || fs->fs_frag > MAXFRAG)
		return (EINVAL);
	if (fs->fs_fpg <= 0)
		return (EINVAL);
	error = resize_super_csaddr_fsb(fs, &csaddr_fsb);
	if (error != 0)
		return (error);
	error = resize_runtime_abs_for_fsb(rt, csaddr_fsb, 0, &cs_abs);
	if (error != 0)
		return (error);
	if (fs->fs_ncg < 1)
		return (EINVAL);
	have_refcg = 0;
	error = resize_rt_read_cg(rt, 0, &cgbuf, &cgp, &cg_abs);
	if (error != 0)
		return (error);
	memcpy(&refcg, cgp, sizeof(refcg));
	have_refcg = 1;
	free(cgbuf);

	tot_ndir = 0;
	tot_nbfree = 0;
	tot_nifree = 0;
	tot_nffree = 0;
	for (cgx = 0; cgx < fs->fs_ncg; cgx++) {
		error = resize_rt_read_cg(rt, (uint32_t)cgx, &cgbuf, &cgp,
		    &cg_abs);
		if (error != 0) {
			if (error == EINVAL && have_refcg && cgx != 0) {
				error = resize_rt_init_cg(rt, fs, &refcg, (uint32_t)cgx,
				    &cgbuf, &cgp, &cg_abs);
			}
			if (error != 0)
				return (error);
		}
		cg_base = cgx * (uint64_t)fs->fs_fpg;
		if (cg_base >= (uint64_t)fs->fs_size) {
			keep = 0;
		} else {
			rem = (uint64_t)fs->fs_size - cg_base;
			keep = resize_u64_min(rem, (uint64_t)fs->fs_fpg);
		}
		if (keep > UINT32_MAX) {
			free(cgbuf);
			return (EOVERFLOW);
		}
		cgp->cg_cgx = (u_int32_t)cgx;
		old_ndblk = cgp->cg_ndblk;
		cgp->cg_ndblk = (u_int32_t)keep;
		if (cgp->cg_rotor >= keep)
			cgp->cg_rotor = 0;
		if (cgp->cg_frotor >= keep)
			cgp->cg_frotor = 0;
		if (fs->fs_magic == FS_UFS1_MAGIC) {
			error = resize_expected_cg_ncyl(fs, cgx, &want_ncyl);
			if (error != 0) {
				free(cgbuf);
				return (error);
			}
			cgp->cg_ncyl = want_ncyl;
			if (cgp->cg_irotor >= (u_int32_t)fs->fs_ipg)
				cgp->cg_irotor = 0;
			cgp->cg_initediblk = 0;
			cgp->cg_ffs2_niblk = 0;
		} else {
			cgp->cg_ncyl = 0;
			cgp->cg_ffs2_niblk = (u_int32_t)fs->fs_ipg;
			if (cgp->cg_initediblk > cgp->cg_ffs2_niblk)
				cgp->cg_initediblk = cgp->cg_ffs2_niblk;
			if (cgp->cg_irotor >= cgp->cg_ffs2_niblk)
				cgp->cg_irotor = 0;
		}
		if (fs->fs_contigsumsize > 0)
			want_nclusterblks = keep / (uint64_t)fs->fs_frag;
		else
			want_nclusterblks = 0;
		if (want_nclusterblks > UINT32_MAX) {
			free(cgbuf);
			return (EOVERFLOW);
		}
		cgp->cg_nclusterblks = (u_int32_t)want_nclusterblks;
		error = resize_cg_inode_range_frag(fs, (uint32_t)cgx,
		    &inode_start, &inode_end);
		if (error != 0) {
			free(cgbuf);
			return (error);
		}
		if (inode_start > keep)
			inode_start = keep;
		if (inode_end > keep)
			inode_end = keep;
		if (keep > old_ndblk && old_ndblk < inode_end) {
			zero_rel_start = old_ndblk;
			if (zero_rel_start < inode_start)
				zero_rel_start = inode_start;
			zero_rel_end = inode_end;
			if (zero_rel_end > zero_rel_start) {
				error = resize_add_u64(cg_base,
				    zero_rel_start, &zero_start_fsb);
				if (error != 0) {
					free(cgbuf);
					return (error);
				}
				error = resize_add_u64(cg_base,
				    zero_rel_end, &zero_end_fsb);
				if (error != 0) {
					free(cgbuf);
					return (error);
				}
				error = resize_rt_zero_fsb_range(rt,
				    zero_start_fsb, zero_end_fsb);
				if (error != 0) {
					free(cgbuf);
					return (error);
				}
			}
		}
		bfree = cg_blksfree(cgp);
		if (keep > old_ndblk) {
			for (f = old_ndblk; f < keep; f++)
				resize_bit_set(bfree, f);
		}
		error = resize_cg_reserved_range_frag(fs, (uint32_t)cgx,
		    &reserve_start, &reserve_end);
		if (error != 0) {
			free(cgbuf);
			return (error);
		}
		if (reserve_start > keep)
			reserve_start = keep;
		if (reserve_end > keep)
			reserve_end = keep;
		for (f = reserve_start; f < reserve_end; f++)
			resize_bit_clear(bfree, f);
		error = resize_cg_rebuild_clusters(fs, cgp, keep);
		if (error != 0) {
			free(cgbuf);
			return (error);
		}
		/*
		 * Fragments beyond fs_size in this cg map must not be marked
		 * free, even if legacy bitmap bits are still set.
		 */
		for (f = keep; f < (uint64_t)fs->fs_fpg; f++)
			resize_bit_clear(bfree, f);
		memset(cgp->cg_frsum, 0, sizeof(cgp->cg_frsum));
		cg_nbfree = 0;
		cg_nffree = 0;
		for (b = 0; b < keep; b += (uint64_t)fs->fs_frag) {
			lim = keep - b;
			if (lim > (uint64_t)fs->fs_frag)
				lim = (uint64_t)fs->fs_frag;
			rem = 0;
			for (f = 0; f < lim; f++) {
				if (resize_bit_is_set(bfree, b + f))
					rem++;
			}
			if (lim == (uint64_t)fs->fs_frag &&
			    rem == (uint64_t)fs->fs_frag)
				cg_nbfree++;
			else {
				cg_nffree += (int64_t)rem;
				run = 0;
				for (f = 0; f < lim; f++) {
					if (resize_bit_is_set(bfree, b + f)) {
						run++;
						continue;
					}
					if (run > 0) {
						if (run >= (uint64_t)MAXFRAG) {
							free(cgbuf);
							return (EOVERFLOW);
						}
						cgp->cg_frsum[run]++;
						run = 0;
					}
				}
				if (run > 0) {
					if (run >= (uint64_t)MAXFRAG) {
						free(cgbuf);
						return (EOVERFLOW);
					}
					cgp->cg_frsum[run]++;
				}
			}
		}
		if (cg_nbfree > INT32_MAX || cg_nffree > INT32_MAX) {
			free(cgbuf);
			return (EOVERFLOW);
		}
		cgp->cg_cs.cs_nbfree = (int32_t)cg_nbfree;
		cgp->cg_cs.cs_nffree = (int32_t)cg_nffree;
		error = resize_write_bytes_any(rt->tfd, rt->container_bytes, cg_abs,
		    cgbuf, (size_t)fs->fs_cgsize);
		if (error == 0) {
			error = resize_mul_u64(cgx, (uint64_t)sizeof(struct csum),
			    &cs_off);
		}
		if (error == 0)
			error = resize_add_u64(cs_abs, cs_off, &cs_ent_abs);
		if (error == 0)
			error = resize_add_u64(cs_ent_abs,
			    (uint64_t)sizeof(struct csum), &cs_end);
		if (error == 0 && cs_end > rt->container_bytes)
			error = EINVAL;
		if (error == 0) {
			error = resize_write_bytes_any(rt->tfd, rt->container_bytes,
			    cs_ent_abs, &cgp->cg_cs, sizeof(cgp->cg_cs));
		}
		cg_ndir = cgp->cg_cs.cs_ndir;
		cg_nifree = cgp->cg_cs.cs_nifree;
		free(cgbuf);
		if (error != 0)
			return (error);
		tot_ndir += cg_ndir;
		tot_nbfree += cg_nbfree;
		tot_nifree += cg_nifree;
		tot_nffree += cg_nffree;
	}
	fs->fs_cstotal.cs_ndir = tot_ndir;
	fs->fs_cstotal.cs_nbfree = tot_nbfree;
	fs->fs_cstotal.cs_nifree = tot_nifree;
	fs->fs_cstotal.cs_nffree = tot_nffree;
	if (tot_ndir > INT32_MAX || tot_ndir < INT32_MIN ||
	    tot_nbfree > INT32_MAX || tot_nbfree < INT32_MIN ||
	    tot_nifree > INT32_MAX || tot_nifree < INT32_MIN ||
	    tot_nffree > INT32_MAX || tot_nffree < INT32_MIN)
		return (EOVERFLOW);
	fs->fs_ffs1_cstotal.cs_ndir = (int32_t)tot_ndir;
	fs->fs_ffs1_cstotal.cs_nbfree = (int32_t)tot_nbfree;
	fs->fs_ffs1_cstotal.cs_nifree = (int32_t)tot_nifree;
	fs->fs_ffs1_cstotal.cs_nffree = (int32_t)tot_nffree;
	now = time(NULL);
	fs->fs_time = (int64_t)now;
	fs->fs_ffs1_time = (int32_t)now;
	return (resize_super_write_all(rt, sb));
}

static int
resize_invariant_fail(const char *phase, const char *fmt, ...)
{
	va_list ap;

	if (phase != NULL)
		fprintf(stderr, "invariant-check(%s): ", phase);
	else
		fprintf(stderr, "invariant-check: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	return (EINVAL);
}

static int
resize_check_super_replicas(struct resize_runtime *rt, struct resize_super *sb,
    const char *phase)
{
	struct fs *fs = (struct fs *)sb->raw;
	u_int8_t *sbuf;
	uint64_t sb_fsb, rel, abs, end;
	u_int32_t cgx;
	size_t sb_bytes;
	int error;

	if (fs->fs_sbsize <= 0 || (uint64_t)fs->fs_sbsize > sizeof(sb->raw))
		return (EINVAL);
	if (fs->fs_fsize <= 0)
		return (EINVAL);
	sb_bytes = (size_t)fs->fs_sbsize;
	sbuf = malloc(sb_bytes);
	if (sbuf == NULL)
		return (ENOMEM);

	for (cgx = 0; cgx < fs->fs_ncg; cgx++) {
		sb_fsb = (uint64_t)cgsblock(fs, cgx);
		if (sb_fsb >= (uint64_t)fs->fs_size)
			continue;
		error = resize_mul_u64(sb_fsb, (uint64_t)fs->fs_fsize, &rel);
		if (error != 0) {
			free(sbuf);
			return (error);
		}
		error = resize_add_u64(rt->fs_offset, rel, &abs);
		if (error != 0) {
			free(sbuf);
			return (error);
		}
		if (abs == sb->sb_abs_offset)
			continue;
		error = resize_add_u64(abs, sb_bytes, &end);
		if (error != 0) {
			free(sbuf);
			return (error);
		}
		if (end > rt->container_bytes) {
			free(sbuf);
			return (resize_invariant_fail(phase,
			    "super replica cg=%u out of container bounds", cgx));
		}
		error = resize_read_bytes_any(rt->tfd, rt->container_bytes, abs, sbuf,
		    sb_bytes);
		if (error != 0) {
			free(sbuf);
			return (error);
		}
		if (memcmp(sbuf, sb->raw, sb_bytes) != 0) {
			free(sbuf);
			return (resize_invariant_fail(phase,
			    "super replica mismatch at cg=%u", cgx));
		}
	}
	free(sbuf);
	return (0);
}

static int
resize_check_invariants(struct resize_runtime *rt, struct resize_super *sb,
    const char *phase, int check_free_summaries, int check_global_summaries)
{
	struct fs *fs = (struct fs *)sb->raw;
	struct resize_plan_ctx pc;
	u_int8_t *cgbuf, *bfree, *imap;
	struct cg *cgp;
	struct csum csum_disk;
	u_int8_t iraw[sizeof(struct ufs2_dinode)];
	uint64_t cg_abs, cgx, cg_base, keep, rem, ino_base;
	uint64_t csaddr_fsb, cs_abs, cs_off, cs_ent_abs, cs_end;
	uint64_t b, lim, f, run;
	uint64_t used_inodes, dir_inodes;
	uint64_t want_nclusterblks;
	int64_t tot_ndir, tot_nbfree, tot_nifree, tot_nffree;
	int64_t cg_nbfree, cg_nffree, expect_nifree;
	int64_t have_nbfree, have_nffree, have_nifree, have_ndir;
	int32_t frsum_expect[MAXFRAG];
	int32_t have_frsum;
	ufsino_t ino;
	uint32_t cg_header, cg_ndblk, cg_u32;
	int16_t want_ncyl, have_ncyl;
	int is_dir;
	int error;
	int64_t ncg, cpg, ncyl;

	if (fs->fs_magic != FS_UFS1_MAGIC && fs->fs_magic != FS_UFS2_MAGIC)
		return (resize_invariant_fail(phase, "unsupported fs magic 0x%x",
		    fs->fs_magic));
	if (fs->fs_ncg < 1)
		return (resize_invariant_fail(phase, "invalid fs_ncg=%d",
		    fs->fs_ncg));
	if (fs->fs_cpg < 1)
		return (resize_invariant_fail(phase, "invalid fs_cpg=%d",
		    fs->fs_cpg));
	if (fs->fs_sbsize <= 0 || (uint64_t)fs->fs_sbsize > SBSIZE)
		return (resize_invariant_fail(phase, "invalid fs_sbsize=%d",
		    fs->fs_sbsize));
	if (fs->fs_bsize < MINBSIZE || fs->fs_bsize > MAXBSIZE ||
	    !resize_powerof2_u32((uint32_t)fs->fs_bsize))
		return (resize_invariant_fail(phase, "invalid fs_bsize=%d",
		    fs->fs_bsize));
	if (fs->fs_fsize <= 0 || fs->fs_fsize > fs->fs_bsize ||
	    fs->fs_fsize < fs->fs_bsize / MAXFRAG ||
	    !resize_powerof2_u32((uint32_t)fs->fs_fsize))
		return (resize_invariant_fail(phase, "invalid fs_fsize=%d",
		    fs->fs_fsize));
	if (fs->fs_magic == FS_UFS1_MAGIC) {
		ncg = fs->fs_ncg;
		cpg = fs->fs_cpg;
		ncyl = fs->fs_ncyl;
		if (ncyl < 1)
			return (resize_invariant_fail(phase, "invalid fs_ncyl=%" PRIi64,
			    ncyl));
		if (ncg > INT64_MAX / cpg)
			return (resize_invariant_fail(phase,
			    "ncg*cpg overflow ncg=%" PRIi64 " cpg=%" PRIi64,
			    ncg, cpg));
		if (ncg * cpg < ncyl || (ncg - 1) * cpg >= ncyl) {
			return (resize_invariant_fail(phase,
			    "ufs1 geom mismatch: fs_ncyl=%" PRIi64
			    " fs_ncg=%" PRIi64 " fs_cpg=%" PRIi64,
			    ncyl, ncg, cpg));
		}
	}
	if (fs->fs_frag <= 0 || fs->fs_frag > MAXFRAG)
		return (resize_invariant_fail(phase, "invalid fs_frag=%d",
		    fs->fs_frag));
	if (fs->fs_fpg <= 0)
		return (resize_invariant_fail(phase, "invalid fs_fpg=%d",
		    fs->fs_fpg));
	error = resize_plan_ctx_init_from_super(&pc, rt->tfd, rt->container_bytes,
	    rt->fs_offset, rt->verbose, sb);
	if (error != 0)
		return (error);
	error = resize_super_csaddr_fsb(fs, &csaddr_fsb);
	if (error != 0)
		return (error);
	error = resize_runtime_abs_for_fsb(rt, csaddr_fsb, 0, &cs_abs);
	if (error != 0)
		return (error);

	tot_ndir = 0;
	tot_nbfree = 0;
	tot_nifree = 0;
	tot_nffree = 0;
	for (cgx = 0; cgx < fs->fs_ncg; cgx++) {
		error = resize_rt_read_cg(rt, (uint32_t)cgx, &cgbuf, &cgp,
		    &cg_abs);
		if (error != 0)
			return (error);
		if (cgp->cg_cgx != (uint32_t)cgx) {
			cg_header = cgp->cg_cgx;
			free(cgbuf);
			return (resize_invariant_fail(phase,
			    "cg index mismatch cg=%" PRIu64 " header=%u", cgx,
			    cg_header));
		}
		cg_base = cgx * (uint64_t)fs->fs_fpg;
		if (cg_base >= (uint64_t)fs->fs_size) {
			keep = 0;
		} else {
			rem = (uint64_t)fs->fs_size - cg_base;
			keep = resize_u64_min(rem, (uint64_t)fs->fs_fpg);
		}
			if (cgp->cg_ndblk != keep) {
				cg_ndblk = cgp->cg_ndblk;
				free(cgbuf);
				return (resize_invariant_fail(phase,
				    "cg_ndblk mismatch cg=%" PRIu64 " have=%u want=%" PRIu64,
				    cgx, cg_ndblk, keep));
			}
			if (fs->fs_magic == FS_UFS1_MAGIC) {
				error = resize_expected_cg_ncyl(fs, cgx, &want_ncyl);
				if (error != 0) {
					free(cgbuf);
					return (error);
				}
				if (cgp->cg_ncyl != want_ncyl) {
					have_ncyl = cgp->cg_ncyl;
					free(cgbuf);
					return (resize_invariant_fail(phase,
					    "cg_ncyl mismatch cg=%" PRIu64
					    " have=%d want=%d",
					    cgx, (int)have_ncyl, (int)want_ncyl));
				}
				if (cgp->cg_irotor >= (u_int32_t)fs->fs_ipg) {
					cg_u32 = cgp->cg_irotor;
					free(cgbuf);
					return (resize_invariant_fail(phase,
					    "cg_irotor out-of-range cg=%" PRIu64
					    " have=%u limit=%d",
					    cgx, cg_u32, fs->fs_ipg));
				}
				if (cgp->cg_initediblk != 0) {
					cg_u32 = cgp->cg_initediblk;
					free(cgbuf);
					return (resize_invariant_fail(phase,
					    "cg_initediblk mismatch cg=%" PRIu64
					    " have=%u want=0",
					    cgx, cg_u32));
				}
			} else {
				if (cgp->cg_ncyl != 0) {
					have_ncyl = cgp->cg_ncyl;
					free(cgbuf);
					return (resize_invariant_fail(phase,
					    "cg_ncyl mismatch (ufs2) cg=%" PRIu64
					    " have=%d want=0",
					    cgx, (int)have_ncyl));
				}
				if (cgp->cg_ffs2_niblk != (u_int32_t)fs->fs_ipg) {
					cg_u32 = cgp->cg_ffs2_niblk;
					free(cgbuf);
					return (resize_invariant_fail(phase,
					    "cg_ffs2_niblk mismatch cg=%" PRIu64
					    " have=%u want=%d",
					    cgx, cg_u32, fs->fs_ipg));
				}
				if (cgp->cg_initediblk > cgp->cg_ffs2_niblk) {
					free(cgbuf);
					return (resize_invariant_fail(phase,
					    "cg_initediblk out-of-range cg=%" PRIu64
					    " have=%u limit=%u",
					    cgx, cgp->cg_initediblk,
					    cgp->cg_ffs2_niblk));
				}
				if (cgp->cg_irotor >= cgp->cg_ffs2_niblk) {
					cg_u32 = cgp->cg_irotor;
					free(cgbuf);
					return (resize_invariant_fail(phase,
					    "cg_irotor out-of-range cg=%" PRIu64
					    " have=%u limit=%u",
					    cgx, cg_u32, cgp->cg_ffs2_niblk));
				}
			}
			if (cgp->cg_rotor >= keep) {
				cg_u32 = cgp->cg_rotor;
				free(cgbuf);
				return (resize_invariant_fail(phase,
				    "cg_rotor out-of-range cg=%" PRIu64
				    " have=%u limit=%" PRIu64,
				    cgx, cg_u32, keep));
			}
			if (cgp->cg_frotor >= keep) {
				cg_u32 = cgp->cg_frotor;
				free(cgbuf);
				return (resize_invariant_fail(phase,
				    "cg_frotor out-of-range cg=%" PRIu64
				    " have=%u limit=%" PRIu64,
				    cgx, cg_u32, keep));
			}
			if (fs->fs_contigsumsize > 0)
				want_nclusterblks = keep / (uint64_t)fs->fs_frag;
			else
				want_nclusterblks = 0;
			if (cgp->cg_nclusterblks != want_nclusterblks) {
				cg_u32 = cgp->cg_nclusterblks;
				free(cgbuf);
				return (resize_invariant_fail(phase,
				    "cg_nclusterblks mismatch cg=%" PRIu64
				    " have=%u want=%" PRIu64,
				    cgx, cg_u32, want_nclusterblks));
			}
			bfree = cg_blksfree(cgp);
			for (f = keep; f < (uint64_t)fs->fs_fpg; f++) {
				if (resize_bit_is_set(bfree, f)) {
					free(cgbuf);
				return (resize_invariant_fail(phase,
				    "free bit set beyond fs_size cg=%" PRIu64
				    " frag=%" PRIu64, cgx, f));
			}
		}
		cg_nbfree = 0;
		cg_nffree = 0;
		if (check_free_summaries) {
			memset(frsum_expect, 0, sizeof(frsum_expect));
			for (b = 0; b < keep; b += (uint64_t)fs->fs_frag) {
				lim = keep - b;
				if (lim > (uint64_t)fs->fs_frag)
					lim = (uint64_t)fs->fs_frag;
				rem = 0;
				for (f = 0; f < lim; f++) {
					if (resize_bit_is_set(bfree, b + f))
						rem++;
				}
				if (lim == (uint64_t)fs->fs_frag &&
				    rem == (uint64_t)fs->fs_frag) {
					cg_nbfree++;
					continue;
				}
				cg_nffree += (int64_t)rem;
				run = 0;
				for (f = 0; f < lim; f++) {
					if (resize_bit_is_set(bfree, b + f)) {
						run++;
						continue;
					}
					if (run > 0) {
						if (run >= (uint64_t)MAXFRAG) {
							free(cgbuf);
							return (EOVERFLOW);
						}
						frsum_expect[run]++;
						run = 0;
					}
				}
				if (run > 0) {
					if (run >= (uint64_t)MAXFRAG) {
						free(cgbuf);
						return (EOVERFLOW);
					}
					frsum_expect[run]++;
				}
			}
			if (cgp->cg_cs.cs_nbfree != cg_nbfree ||
			    cgp->cg_cs.cs_nffree != cg_nffree) {
				have_nbfree = cgp->cg_cs.cs_nbfree;
				have_nffree = cgp->cg_cs.cs_nffree;
				free(cgbuf);
				return (resize_invariant_fail(phase,
				    "cg summary mismatch cg=%" PRIu64
				    " nbfree=%d/%" PRIi64 " nffree=%d/%" PRIi64,
				    cgx, (int)have_nbfree, cg_nbfree,
				    (int)have_nffree, cg_nffree));
			}
				for (f = 1; f < (uint64_t)fs->fs_frag; f++) {
					if (cgp->cg_frsum[f] !=
					    (u_int32_t)frsum_expect[f]) {
						have_frsum = cgp->cg_frsum[f];
						free(cgbuf);
						return (resize_invariant_fail(phase,
						    "cg frsum mismatch cg=%" PRIu64
					    " run=%" PRIu64 " have=%d want=%d",
					    cgx, f, have_frsum, frsum_expect[f]));
				}
			}
		}

		imap = cg_inosused(cgp);
		used_inodes = 0;
		dir_inodes = 0;
		ino_base = cgx * (uint64_t)fs->fs_ipg;
		for (f = 0; f < (uint64_t)fs->fs_ipg; f++) {
			if (!resize_bit_is_set(imap, f))
				continue;
			used_inodes++;
			if (ino_base + f > UINT32_MAX) {
				free(cgbuf);
				return (EOVERFLOW);
			}
			ino = (ufsino_t)(ino_base + f);
			error = resize_inode_read_raw(&pc, ino, iraw);
			if (error != 0) {
				free(cgbuf);
				return (error);
			}
			error = resize_inode_raw_is_dir(&pc, iraw, &is_dir);
			if (error != 0) {
				free(cgbuf);
				return (error);
			}
			if (is_dir)
				dir_inodes++;
		}
		expect_nifree = (int64_t)fs->fs_ipg - (int64_t)used_inodes;
		if (cgp->cg_cs.cs_nifree != expect_nifree ||
		    cgp->cg_cs.cs_ndir != (int64_t)dir_inodes) {
			have_nifree = cgp->cg_cs.cs_nifree;
			have_ndir = cgp->cg_cs.cs_ndir;
			free(cgbuf);
			return (resize_invariant_fail(phase,
			    "cg inode summary mismatch cg=%" PRIu64
			    " nifree=%d/%" PRIi64 " ndir=%d/%" PRIu64,
			    cgx, (int)have_nifree, expect_nifree, (int)have_ndir,
			    dir_inodes));
		}

		if (check_global_summaries) {
			error = resize_mul_u64(cgx, (uint64_t)sizeof(struct csum),
			    &cs_off);
			if (error == 0)
				error = resize_add_u64(cs_abs, cs_off, &cs_ent_abs);
			if (error == 0)
				error = resize_add_u64(cs_ent_abs,
				    (uint64_t)sizeof(struct csum), &cs_end);
			if (error == 0 && cs_end > rt->container_bytes)
				error = EINVAL;
			if (error == 0) {
				error = resize_read_bytes_any(rt->tfd,
				    rt->container_bytes, cs_ent_abs, &csum_disk,
				    sizeof(csum_disk));
			}
			if (error != 0) {
				free(cgbuf);
				return (error);
			}
			if (csum_disk.cs_ndir != cgp->cg_cs.cs_ndir ||
			    csum_disk.cs_nbfree != cgp->cg_cs.cs_nbfree ||
			    csum_disk.cs_nifree != cgp->cg_cs.cs_nifree ||
			    csum_disk.cs_nffree != cgp->cg_cs.cs_nffree) {
				free(cgbuf);
				return (resize_invariant_fail(phase,
				    "fs_csaddr entry mismatch cg=%" PRIu64, cgx));
			}
		}

		tot_ndir += cgp->cg_cs.cs_ndir;
		if (check_free_summaries)
			tot_nbfree += cg_nbfree;
		else
			tot_nbfree += cgp->cg_cs.cs_nbfree;
		tot_nifree += expect_nifree;
		if (check_free_summaries)
			tot_nffree += cg_nffree;
		else
			tot_nffree += cgp->cg_cs.cs_nffree;
		free(cgbuf);
	}

	if (check_global_summaries) {
		if (fs->fs_cstotal.cs_ndir != tot_ndir ||
		    fs->fs_cstotal.cs_nbfree != tot_nbfree ||
		    fs->fs_cstotal.cs_nifree != tot_nifree ||
		    fs->fs_cstotal.cs_nffree != tot_nffree) {
			return (resize_invariant_fail(phase,
			    "super cstotal mismatch ndir=%" PRIi64 "/%" PRIi64
			    " nbfree=%" PRIi64 "/%" PRIi64
			    " nifree=%" PRIi64 "/%" PRIi64
			    " nffree=%" PRIi64 "/%" PRIi64,
			    fs->fs_cstotal.cs_ndir, tot_ndir,
			    fs->fs_cstotal.cs_nbfree, tot_nbfree,
			    fs->fs_cstotal.cs_nifree, tot_nifree,
			    fs->fs_cstotal.cs_nffree, tot_nffree));
		}
		if (fs->fs_magic == FS_UFS1_MAGIC &&
		    (fs->fs_ffs1_cstotal.cs_ndir != fs->fs_cstotal.cs_ndir ||
		    fs->fs_ffs1_cstotal.cs_nbfree != fs->fs_cstotal.cs_nbfree ||
		    fs->fs_ffs1_cstotal.cs_nifree != fs->fs_cstotal.cs_nifree ||
		    fs->fs_ffs1_cstotal.cs_nffree != fs->fs_cstotal.cs_nffree)) {
			return (resize_invariant_fail(phase,
			    "ffs1 cstotal mirror mismatch"));
		}
	}
	if (rt->dry_run)
		return (0);
	return (resize_check_super_replicas(rt, sb, phase));
}

static int
resize_check_invariants_phase(const struct resize_options *opt,
    struct resize_runtime *rt, struct resize_super *sb, const char *phase)
{
	int check_free_summaries, check_global_summaries;
	int error;

	if (!opt->check_invariants)
		return (0);
	check_free_summaries = 1;
	check_global_summaries = 1;
	if (phase != NULL && strcmp(phase, "post-relocating") == 0) {
		check_free_summaries = 0;
		check_global_summaries = 0;
	} else if (phase != NULL && strcmp(phase, "post-inode-remap") == 0) {
		check_global_summaries = 0;
	}
	error = resize_check_invariants(rt, sb, phase, check_free_summaries,
	    check_global_summaries);
	if (error == 0 && opt->verbose)
		fprintf(stderr, "invariant-check(%s): ok\n", phase);
	return (error);
}

static int
resize_superblock_set_clean_state(struct resize_runtime *rt,
    struct resize_super *sb, int clean)
{
	struct fs *fs = (struct fs *)sb->raw;
	time_t now;

	if (clean) {
		fs->fs_flags &= ~FS_UNCLEAN;
		fs->fs_ffs1_flags &= ~FS_UNCLEAN;
		fs->fs_clean = FS_ISCLEAN;
	} else {
		fs->fs_flags |= FS_UNCLEAN;
		fs->fs_ffs1_flags |= FS_UNCLEAN;
		fs->fs_clean = 0;
	}
	now = time(NULL);
	fs->fs_time = (int64_t)now;
	fs->fs_ffs1_time = (int32_t)now;
	return (resize_super_write_all(rt, sb));
}

static int
rt_alloc_mark_allocated(void *cookie, uint64_t fsb)
{
	struct resize_runtime *rt = cookie;
	int error;

	error = resize_rt_update_frag_alloc(rt, fsb, 1);
	if (error != 0)
		return (error);
	return (resize_alloc_set(&rt->amap, fsb, 1));
}

static int
rt_alloc_mark_free(void *cookie, uint64_t fsb)
{
	struct resize_runtime *rt = cookie;
	int error;

	error = resize_rt_update_frag_alloc(rt, fsb, 0);
	if (error != 0)
		return (error);
	return (resize_alloc_set(&rt->amap, fsb, 0));
}

static int
resize_trim_ncg_for_size(struct fs *fs, uint64_t new_blocks)
{
	uint64_t cg_span_frags, cg_fsb, end_fsb;
	u_int32_t ncg;
	int error;

	if (fs->fs_ncg == 0 || fs->fs_fsize <= 0 || fs->fs_cgsize <= 0)
		return (EINVAL);
	error = resize_div_round_up_u64((uint64_t)fs->fs_cgsize,
	    (uint64_t)fs->fs_fsize, &cg_span_frags);
	if (error != 0)
		return (error);
	ncg = fs->fs_ncg;
	while (ncg > 1) {
		cg_fsb = (uint64_t)cgtod(fs, ncg - 1);
		error = resize_add_u64(cg_fsb, cg_span_frags, &end_fsb);
		if (error != 0)
			return (error);
		if (end_fsb <= new_blocks)
			break;
		ncg--;
	}
	if (ncg == 0)
		return (EINVAL);
	fs->fs_ncg = ncg;
	return (0);
}

static int
resize_expand_ncg_for_size(struct fs *fs, uint64_t new_blocks)
{
	uint64_t need_ncg;
	int error;

	if (fs->fs_fpg <= 0)
		return (EINVAL);
	error = resize_div_round_up_u64(new_blocks, (uint64_t)fs->fs_fpg,
	    &need_ncg);
	if (error != 0)
		return (error);
	if (need_ncg == 0 || need_ncg > UINT32_MAX)
		return (EOVERFLOW);
	if ((u_int32_t)need_ncg > fs->fs_ncg)
		fs->fs_ncg = (u_int32_t)need_ncg;
	return (0);
}

static int
resize_ufs1_recompute_ncyl(struct fs *fs)
{
	uint64_t ncyl64;

	if (fs->fs_magic != FS_UFS1_MAGIC)
		return (0);
	if (fs->fs_ncg < 1)
		return (EINVAL);
	if (fs->fs_cpg < 1)
		return (EINVAL);
	ncyl64 = (uint64_t)fs->fs_ncg * (uint64_t)fs->fs_cpg;
	if (ncyl64 == 0 || ncyl64 > INT32_MAX)
		return (EOVERFLOW);
	fs->fs_ncyl = (int32_t)ncyl64;
	return (0);
}

static int
resize_expected_cg_ncyl(const struct fs *fs, uint64_t cgx, int16_t *out_ncyl)
{
	int64_t rem;

	if (out_ncyl == NULL)
		return (EINVAL);
	if (fs->fs_magic != FS_UFS1_MAGIC) {
		*out_ncyl = 0;
		return (0);
	}
	if (fs->fs_ncg < 1 || fs->fs_cpg < 1 || fs->fs_ncyl < 1)
		return (EINVAL);
	if (cgx >= (uint64_t)fs->fs_ncg)
		return (EINVAL);
	if (cgx == (uint64_t)fs->fs_ncg - 1)
		rem = fs->fs_ncyl % fs->fs_cpg;
	else
		rem = fs->fs_cpg;
	if (rem < INT16_MIN || rem > INT16_MAX)
		return (EOVERFLOW);
	*out_ncyl = (int16_t)rem;
	return (0);
}

static int
resize_superblock_set_size(struct resize_runtime *rt, struct resize_super *sb,
    uint64_t new_size_bytes)
{
	struct fs *fs = (struct fs *)sb->raw;
	struct resize_move mv;
	uint64_t new_blocks, old_blocks;
	int64_t delta;
	int64_t old_dsize, new_dsize;
	time_t now;
	int error;

	if (new_size_bytes % sb->fs_fsize != 0)
		return (EINVAL);
	new_blocks = new_size_bytes / sb->fs_fsize;
	old_blocks = sb->fs_size_blocks;
	if (new_blocks == old_blocks)
		return (0);

	if (new_blocks > INT64_MAX)
		return (EOVERFLOW);
	if (old_blocks > INT64_MAX)
		return (EOVERFLOW);
	delta = (int64_t)new_blocks - (int64_t)old_blocks;

	if (fs->fs_magic == FS_UFS1_MAGIC)
		old_dsize = (int64_t)fs->fs_ffs1_dsize;
	else
		old_dsize = fs->fs_dsize;
	new_dsize = old_dsize + delta;
	if (new_dsize <= 0)
		return (EINVAL);
	error = resize_expand_ncg_for_size(fs, new_blocks);
	if (error != 0)
		return (error);
	error = resize_trim_ncg_for_size(fs, new_blocks);
	if (error != 0)
		return (error);
	error = resize_ufs1_recompute_ncyl(fs);
	if (error != 0)
		return (error);

	memset(&mv, 0, sizeof(mv));
	mv.old_fsb = old_blocks;
	mv.new_fsb = new_blocks;
	mv.bytes = sizeof(sb->raw);

	error = resize_journal_append(rt->jr, RESIZE_REC_SBSET, RESIZE_MUT_SB_SIZE,
	    &mv, 0);
	if (error != 0)
		return (error);
	error = resize_journal_sync(rt->jr);
	if (error != 0)
		return (error);

	fs->fs_size = (int64_t)new_blocks;
	fs->fs_dsize = new_dsize;
	if (fs->fs_magic == FS_UFS1_MAGIC) {
		if (new_blocks > INT32_MAX || new_dsize > INT32_MAX)
			return (EOVERFLOW);
		fs->fs_ffs1_size = (int32_t)new_blocks;
		fs->fs_ffs1_dsize = (int32_t)new_dsize;
	}
	now = time(NULL);
	fs->fs_time = (int64_t)now;
	fs->fs_ffs1_time = (int32_t)now;

	if (!rt->dry_run) {
		error = resize_super_write_all(rt, sb);
		if (error != 0)
			return (error);
	}

	error = resize_journal_append(rt->jr, RESIZE_REC_APPLIED,
	    RESIZE_MUT_SB_SIZE, &mv, 0);
	if (error != 0)
		return (error);
	error = resize_journal_sync(rt->jr);
	if (error != 0)
		return (error);

	sb->fs_size_blocks = new_blocks;
	sb->fs_size_bytes = new_size_bytes;
	return (0);
}

static int
resize_match_rec(const struct resize_jrec_v1 *a, const struct resize_jrec_v1 *b)
{
	return (a->op == b->op &&
	    a->old_fsb == b->old_fsb &&
	    a->new_fsb == b->new_fsb &&
	    a->bytes == b->bytes &&
	    a->owner_abs_offset == b->owner_abs_offset &&
	    a->owner_width == b->owner_width);
}

static const char *
resize_mutation_name(uint16_t op)
{
	switch (op) {
	case RESIZE_MUT_COPY:
		return ("copy");
	case RESIZE_MUT_REPOINT:
		return ("repoint");
	case RESIZE_MUT_FREE:
		return ("free");
	case RESIZE_MUT_SB_SIZE:
		return ("sb-size");
	case RESIZE_MUT_INODE_REMAP_MAP:
		return ("inode-remap-map");
	case RESIZE_MUT_INODE_REMAP_EXEC:
		return ("inode-remap-exec");
	case RESIZE_MUT_SHIFT_CHUNK:
		return ("shift-chunk");
	default:
		return ("unknown");
	}
}

static int
resize_superblock_apply_blocks_nojournal(struct resize_runtime *rt,
    uint64_t new_blocks)
{
	struct resize_super sb;
	struct fs *fs;
	int64_t delta, old_dsize, new_dsize;
	int error;
	time_t now;

	error = resize_read_super(rt->tfd, rt->fs_offset, rt->container_bytes,
	    &sb);
	if (error != 0)
		return (error);
	if (new_blocks > INT64_MAX || sb.fs_size_blocks > INT64_MAX)
		return (EOVERFLOW);

	delta = (int64_t)new_blocks - (int64_t)sb.fs_size_blocks;
	fs = (struct fs *)sb.raw;
	if (fs->fs_magic == FS_UFS1_MAGIC)
		old_dsize = (int64_t)fs->fs_ffs1_dsize;
	else
		old_dsize = fs->fs_dsize;
	new_dsize = old_dsize + delta;
	if (new_dsize <= 0)
		return (EINVAL);
	error = resize_trim_ncg_for_size(fs, new_blocks);
	if (error != 0)
		return (error);
	error = resize_ufs1_recompute_ncyl(fs);
	if (error != 0)
		return (error);

	fs->fs_size = (int64_t)new_blocks;
	fs->fs_dsize = new_dsize;
	if (fs->fs_magic == FS_UFS1_MAGIC) {
		if (new_blocks > INT32_MAX || new_dsize > INT32_MAX)
			return (EOVERFLOW);
		fs->fs_ffs1_size = (int32_t)new_blocks;
		fs->fs_ffs1_dsize = (int32_t)new_dsize;
	}
	now = time(NULL);
	fs->fs_time = (int64_t)now;
	fs->fs_ffs1_time = (int32_t)now;

	if (!rt->dry_run)
		return (resize_super_write_all(rt, &sb));
	return (0);
}

static int
resize_replay_record(struct resize_runtime *rt, const struct resize_jrec_v1 *rec)
{
	struct resize_move mv;
	struct resize_owner_ref owner;
	unsigned char *buf;
	uint64_t nfrags, i;
	int error;

	memset(&mv, 0, sizeof(mv));
	mv.old_fsb = rec->old_fsb;
	mv.new_fsb = rec->new_fsb;
	mv.bytes = rec->bytes;
	mv.owner_abs_offset = rec->owner_abs_offset;
	mv.owner_width = rec->owner_width;
	memset(&owner, 0, sizeof(owner));
	owner.owner_block_fsb = rec->owner_abs_offset;
	owner.slot_index = rec->owner_width;
	mv.owner = owner;

	switch (rec->op) {
	case RESIZE_MUT_COPY:
		if (rt->fs_fsize == 0 || mv.bytes == 0 ||
		    mv.bytes % rt->fs_fsize != 0)
			return (EINVAL);
		nfrags = (uint64_t)mv.bytes / (uint64_t)rt->fs_fsize;
		buf = malloc(mv.bytes);
		if (buf == NULL)
			return (ENOMEM);
		error = rt_read_block(rt, mv.old_fsb, buf, mv.bytes);
		if (error == 0)
			error = rt_write_block(rt, mv.new_fsb, buf, mv.bytes);
		free(buf);
		if (error != 0)
			return (error);
		error = rt_sync_target(rt);
		if (error != 0)
			return (error);
		for (i = 0; i < nfrags; i++) {
			error = rt_alloc_mark_allocated(rt, mv.new_fsb + i);
			if (error != 0)
				return (error);
		}
		return (rt_sync_target(rt));
	case RESIZE_MUT_REPOINT:
		error = rt_owner_set(rt, &mv.owner, mv.new_fsb);
		if (error != 0)
			return (error);
		return (rt_sync_target(rt));
	case RESIZE_MUT_FREE:
		if (rt->fs_fsize == 0 || mv.bytes == 0 ||
		    mv.bytes % rt->fs_fsize != 0)
			return (EINVAL);
		nfrags = (uint64_t)mv.bytes / (uint64_t)rt->fs_fsize;
		for (i = 0; i < nfrags; i++) {
			error = rt_alloc_mark_free(rt, mv.old_fsb + i);
			if (error != 0)
				return (error);
		}
		return (rt_sync_target(rt));
	case RESIZE_MUT_SB_SIZE:
		return (resize_superblock_apply_blocks_nojournal(rt, rec->new_fsb));
	case RESIZE_MUT_INODE_REMAP_MAP:
	case RESIZE_MUT_INODE_REMAP_EXEC:
		return (0);
	case RESIZE_MUT_SHIFT_CHUNK:
		buf = malloc(mv.bytes);
		if (buf == NULL)
			return (ENOMEM);
		error = resize_read_bytes_any(rt->tfd, rt->container_bytes,
		    rec->old_fsb, buf, mv.bytes);
		if (error == 0)
			error = resize_write_bytes_any(rt->tfd, rt->container_bytes,
			    rec->new_fsb, buf, mv.bytes);
		free(buf);
		if (error != 0)
			return (error);
		return (rt_sync_target(rt));
	default:
		return (EINVAL);
	}
}

static int
resize_collect_inode_remap_from_journal(struct resize_journal *jr, size_t nrecs,
    struct resize_ino_remap *rm)
{
	struct resize_jrec_v1 rec;
	size_t i;
	int error;

	memset(rm, 0, sizeof(*rm));
	for (i = 0; i < nrecs; i++) {
		error = resize_journal_read_record(jr, i, &rec);
		if (error != 0) {
			resize_ino_remap_free(rm);
			return (error);
		}
		if (rec.rec_type != RESIZE_REC_INTENT)
			continue;
		if (rec.op != RESIZE_MUT_INODE_REMAP_MAP)
			continue;
		if (rec.old_fsb > UINT32_MAX || rec.new_fsb > UINT32_MAX) {
			resize_ino_remap_free(rm);
			return (EOVERFLOW);
		}
		error = resize_ino_remap_push(rm, (ufsino_t)rec.old_fsb,
		    (ufsino_t)rec.new_fsb);
		if (error != 0) {
			resize_ino_remap_free(rm);
			return (error);
		}
	}
	if (rm->nent > 1)
		qsort(rm->ents, rm->nent, sizeof(rm->ents[0]),
		    resize_ino_remap_cmp_old);
	return (0);
}

static int
resize_replay_inode_remap_exec(struct resize_runtime *rt, struct resize_journal *jr,
    size_t nrecs)
{
	struct resize_ino_remap rm;
	struct resize_super sb;
	struct resize_plan_ctx pc;
	int error;

	error = resize_collect_inode_remap_from_journal(jr, nrecs, &rm);
	if (error != 0)
		return (error);
	if (rm.nent == 0) {
		resize_ino_remap_free(&rm);
		return (0);
	}
	error = resize_read_super(rt->tfd, rt->fs_offset, rt->container_bytes,
	    &sb);
	if (error != 0) {
		resize_ino_remap_free(&rm);
		return (error);
	}
	error = resize_plan_ctx_init_from_super(&pc, rt->tfd, rt->container_bytes,
	    rt->fs_offset, rt->verbose, &sb);
	if (error != 0) {
		resize_ino_remap_free(&rm);
		return (error);
	}
	error = resize_apply_inode_remap(&pc, &sb, &rm);
	resize_ino_remap_free(&rm);
	return (error);
}

static int
resize_recover_journal(struct resize_runtime *rt, struct resize_journal *jr)
{
	struct resize_jrec_v1 rec, cand;
	size_t nrecs = 0, i, j;
	size_t nintent = 0, npending = 0, nreplayed = 0;
	int has_applied;
	int error;

	error = resize_journal_record_count(jr, &nrecs);
	if (error != 0)
		return (error);

	for (i = 0; i < nrecs; i++) {
		error = resize_journal_read_record(jr, i, &rec);
		if (error != 0)
			return (error);
		if (rec.rec_type != RESIZE_REC_INTENT &&
		    rec.rec_type != RESIZE_REC_SBSET)
			continue;
		nintent++;
		has_applied = 0;
		for (j = i + 1; j < nrecs; j++) {
			error = resize_journal_read_record(jr, j, &cand);
			if (error != 0)
				return (error);
			if (cand.rec_type != RESIZE_REC_APPLIED)
				continue;
			if (resize_match_rec(&rec, &cand)) {
				has_applied = 1;
				break;
			}
		}
		if (has_applied)
			continue;
		npending++;

		resize_vlog(rt->verbose,
		    "recover: replay op=%u old=%" PRIu64 " new=%" PRIu64
		    " bytes=%u owner_off=%" PRIu64 " owner_w=%u\n",
		    rec.op, rec.old_fsb, rec.new_fsb, rec.bytes,
		    rec.owner_abs_offset, rec.owner_width);
		if (rec.op == RESIZE_MUT_INODE_REMAP_EXEC)
			error = resize_replay_inode_remap_exec(rt, jr, nrecs);
		else
			error = resize_replay_record(rt, &rec);
		if (error != 0)
			return (error);
		{
			struct resize_move mv;

			memset(&mv, 0, sizeof(mv));
			mv.old_fsb = rec.old_fsb;
			mv.new_fsb = rec.new_fsb;
			mv.bytes = rec.bytes;
			mv.flags = rec.flags;
			mv.owner_abs_offset = rec.owner_abs_offset;
			mv.owner_width = rec.owner_width;
			error = resize_journal_append(jr, RESIZE_REC_APPLIED,
			    rec.op, &mv, 0);
		}
		if (error != 0)
			return (error);
		error = resize_journal_sync(jr);
		if (error != 0)
			return (error);
		nreplayed++;
	}
	resize_vlog(rt->verbose,
	    "recover: intents=%zu pending=%zu replayed=%zu\n",
	    nintent, npending, nreplayed);
	if (rt->verbose && nreplayed == 0)
		fprintf(stderr,
		    "recover: journal appears fully applied; nothing to replay\n");
	return (0);
}

static int
resize_resume_journal(const struct resize_options *opt, struct resize_runtime *rt,
    struct resize_journal *jr)
{
	struct resize_jrec_v1 rec, cand;
	struct resize_super sb;
	size_t nrecs = 0, i, j;
	size_t npending;
	int has_applied, has_commit, has_sbset, has_shift;
	int delta_set;
	uint64_t delta, d, fs_offset;
	int error;

	if (jr->hdr.phase < RESIZE_PHASE_METADATA) {
		if (opt->verbose) {
			fprintf(stderr,
			    "resume: phase=%u is before metadata; cannot auto-finish\n",
			    jr->hdr.phase);
		}
		return (ENOTSUP);
	}
	error = resize_journal_record_count(jr, &nrecs);
	if (error != 0)
		return (error);

	npending = 0;
	has_commit = 0;
	has_sbset = 0;
	has_shift = 0;
	delta_set = 0;
	delta = 0;
	for (i = 0; i < nrecs; i++) {
		error = resize_journal_read_record(jr, i, &rec);
		if (error != 0)
			return (error);
		if (rec.rec_type == RESIZE_REC_APPLIED) {
			if (rec.op == RESIZE_MUT_SB_SIZE)
				has_sbset = 1;
			else if (rec.op == RESIZE_MUT_SHIFT_CHUNK) {
				has_shift = 1;
				if (rec.new_fsb < rec.old_fsb)
					return (EINVAL);
				d = rec.new_fsb - rec.old_fsb;
				if (!delta_set) {
					delta = d;
					delta_set = 1;
				} else if (d != delta)
					return (EINVAL);
			}
		} else if (rec.rec_type == RESIZE_REC_COMMIT) {
			has_commit = 1;
		}
		if (rec.rec_type != RESIZE_REC_INTENT &&
		    rec.rec_type != RESIZE_REC_SBSET)
			continue;
		has_applied = 0;
		for (j = i + 1; j < nrecs; j++) {
			error = resize_journal_read_record(jr, j, &cand);
			if (error != 0)
				return (error);
			if (cand.rec_type != RESIZE_REC_APPLIED)
				continue;
			if (resize_match_rec(&rec, &cand)) {
				has_applied = 1;
				break;
			}
		}
		if (!has_applied)
			npending++;
	}
	if (npending != 0) {
		if (opt->verbose) {
			fprintf(stderr,
			    "resume: %zu pending intent(s) remain after replay\n",
			    npending);
		}
		return (EBUSY);
	}

	fs_offset = jr->hdr.fs_offset_bytes;
	if (has_shift && delta_set) {
		error = resize_add_u64(fs_offset, delta, &fs_offset);
		if (error != 0)
			return (error);
	}
	rt->fs_offset = fs_offset;
	error = resize_read_super(rt->tfd, rt->fs_offset, rt->container_bytes, &sb);
	if (error != 0)
		return (error);
	rt->fs = *(const struct fs *)sb.raw;
	rt->fs_fsize = sb.fs_fsize;

	if (!has_sbset && !has_shift) {
		if (opt->verbose) {
			fprintf(stderr,
			    "resume: no sb-size/shift records; nothing to finalize\n");
		}
		return (0);
	}

	error = resize_recompute_free_summaries(rt, &sb);
	if (error != 0)
		return (error);

	if (jr->hdr.phase < RESIZE_PHASE_COMMITTING) {
		error = resize_journal_set_phase(jr, RESIZE_PHASE_COMMITTING);
		if (error != 0)
			return (error);
		error = resize_journal_sync(jr);
		if (error != 0)
			return (error);
	}
	if (!has_commit) {
		error = resize_journal_append(jr, RESIZE_REC_COMMIT, 0, NULL, 0);
		if (error != 0)
			return (error);
		error = resize_journal_sync(jr);
		if (error != 0)
			return (error);
	}
	if (jr->hdr.phase < RESIZE_PHASE_COMMITTED) {
		error = resize_journal_set_phase(jr, RESIZE_PHASE_COMMITTED);
		if (error != 0)
			return (error);
		error = resize_journal_sync(jr);
		if (error != 0)
			return (error);
	}
	error = resize_superblock_set_clean_state(rt, &sb, 1);
	if (error != 0)
		return (error);
	if (opt->check_invariants) {
		error = resize_check_invariants_phase(opt, rt, &sb, "post-resume");
		if (error != 0)
			return (error);
	}
	if (opt->verbose) {
		fprintf(stderr,
		    "resume: finalized at fs_offset=%" PRIu64
		    " (shift-delta=%" PRIu64 ")\n",
		    rt->fs_offset, has_shift ? delta : 0);
	}
	return (0);
}

static int
resize_revert_record(struct resize_runtime *rt, const struct resize_jrec_v1 *rec)
{
	struct resize_move mv;
	struct resize_super sb;
	uint64_t nfrags, i;
	int error;

	memset(&mv, 0, sizeof(mv));
	mv.old_fsb = rec->old_fsb;
	mv.new_fsb = rec->new_fsb;
	mv.bytes = rec->bytes;
	mv.flags = rec->flags;
	mv.owner_abs_offset = rec->owner_abs_offset;
	mv.owner_width = rec->owner_width;
	mv.owner.owner_block_fsb = rec->owner_abs_offset;
	mv.owner.slot_index = rec->owner_width;

	switch (rec->op) {
	case RESIZE_MUT_COPY:
		if (rt->fs_fsize == 0 || mv.bytes == 0 ||
		    mv.bytes % rt->fs_fsize != 0)
			return (EINVAL);
		nfrags = (uint64_t)mv.bytes / (uint64_t)rt->fs_fsize;
		for (i = 0; i < nfrags; i++) {
			error = rt_alloc_mark_free(rt, mv.new_fsb + i);
			if (error != 0)
				return (error);
		}
		return (rt_sync_target(rt));
	case RESIZE_MUT_REPOINT:
		error = rt_owner_set(rt, &mv.owner, mv.old_fsb);
		if (error != 0)
			return (error);
		return (rt_sync_target(rt));
	case RESIZE_MUT_FREE:
		if (rt->fs_fsize == 0 || mv.bytes == 0 ||
		    mv.bytes % rt->fs_fsize != 0)
			return (EINVAL);
		nfrags = (uint64_t)mv.bytes / (uint64_t)rt->fs_fsize;
		for (i = 0; i < nfrags; i++) {
			error = rt_alloc_mark_allocated(rt, mv.old_fsb + i);
			if (error != 0)
				return (error);
		}
		return (rt_sync_target(rt));
	case RESIZE_MUT_SB_SIZE:
		error = resize_superblock_apply_blocks_nojournal(rt, rec->old_fsb);
		if (error != 0)
			return (error);
		error = resize_read_super(rt->tfd, rt->fs_offset, rt->container_bytes,
		    &sb);
		if (error != 0)
			return (error);
		rt->fs = *(const struct fs *)sb.raw;
		rt->fs_fsize = sb.fs_fsize;
		return (0);
	case RESIZE_MUT_INODE_REMAP_MAP:
		return (0);
	default:
		return (ENOTSUP);
	}
}

static int
resize_revert_journal(const struct resize_options *opt, struct resize_runtime *rt,
    struct resize_journal *jr)
{
	struct resize_jrec_v1 rec;
	struct resize_super sb;
	size_t nrecs = 0, i;
	size_t napplied, nreverted;
	int error;

	error = resize_journal_record_count(jr, &nrecs);
	if (error != 0)
		return (error);

	napplied = 0;
	nreverted = 0;
	for (i = 0; i < nrecs; i++) {
		error = resize_journal_read_record(jr, i, &rec);
		if (error != 0)
			return (error);
		if (rec.rec_type != RESIZE_REC_APPLIED)
			continue;
		if (rec.op == RESIZE_MUT_INODE_REMAP_MAP)
			continue;
		napplied++;
		if (rec.op == RESIZE_MUT_INODE_REMAP_EXEC ||
		    rec.op == RESIZE_MUT_SHIFT_CHUNK) {
			if (opt->verbose) {
				fprintf(stderr,
				    "revert: unsupported applied op=%u (%s)\n",
				    rec.op, resize_mutation_name(rec.op));
			}
			return (ENOTSUP);
		}
	}
	if (napplied == 0) {
		if (opt->verbose)
			fprintf(stderr,
			    "revert: journal has no applied reversible records\n");
		return (0);
	}

	error = resize_read_super(rt->tfd, rt->fs_offset, rt->container_bytes, &sb);
	if (error != 0)
		return (error);
	rt->fs = *(const struct fs *)sb.raw;
	rt->fs_fsize = sb.fs_fsize;

	error = resize_superblock_set_clean_state(rt, &sb, 0);
	if (error != 0)
		return (error);

	for (i = nrecs; i > 0; i--) {
		error = resize_journal_read_record(jr, i - 1, &rec);
		if (error != 0)
			return (error);
		if (rec.rec_type != RESIZE_REC_APPLIED)
			continue;
		if (rec.op == RESIZE_MUT_INODE_REMAP_MAP)
			continue;
		resize_vlog(opt->verbose,
		    "revert: undo op=%u (%s) old=%" PRIu64
		    " new=%" PRIu64 " bytes=%u owner_off=%" PRIu64 " owner_w=%u\n",
		    rec.op, resize_mutation_name(rec.op), rec.old_fsb, rec.new_fsb,
		    rec.bytes, rec.owner_abs_offset, rec.owner_width);
		error = resize_revert_record(rt, &rec);
		if (error != 0)
			return (error);
		nreverted++;
	}

	error = resize_read_super(rt->tfd, rt->fs_offset, rt->container_bytes, &sb);
	if (error != 0)
		return (error);
	rt->fs = *(const struct fs *)sb.raw;
	rt->fs_fsize = sb.fs_fsize;

	error = resize_recompute_free_summaries(rt, &sb);
	if (error != 0)
		return (error);
	error = resize_superblock_set_clean_state(rt, &sb, 1);
	if (error != 0)
		return (error);
	if (opt->check_invariants) {
		error = resize_check_invariants_phase(opt, rt, &sb, "post-revert");
		if (error != 0)
			return (error);
	}
	if (opt->verbose)
		fprintf(stderr, "revert: applied=%zu reverted=%zu\n",
		    napplied, nreverted);

	error = resize_journal_reset(jr);
	if (error != 0)
		return (error);
	return (0);
}

static int
resize_run_relocation(struct resize_runtime *rt, struct resize_move_list *ml)
{
	struct resize_ctx ctx;
	struct resize_backend_ops ops;
	size_t i, j, k, ngroups, gdone;
	uint64_t old_fsb, new_fsb;
	uint32_t bytes;
	int error;

	memset(&ops, 0, sizeof(ops));
	ops.read_block = rt_read_block;
	ops.write_block = rt_write_block;
	ops.sync_target = rt_sync_target;
	ops.journal_intent = rt_journal_intent;
	ops.journal_applied = rt_journal_applied;
	ops.sync_journal = rt_sync_journal;
	ops.owner_get = rt_owner_get;
	ops.owner_set = rt_owner_set;
	ops.alloc_is_free = rt_alloc_is_free;
	ops.alloc_mark_allocated = rt_alloc_mark_allocated;
	ops.alloc_mark_free = rt_alloc_mark_free;

	memset(&ctx, 0, sizeof(ctx));
	ctx.cookie = rt;
	ctx.ops = &ops;
	ctx.fs_fsize = rt->fs_fsize;

	ngroups = 0;
	for (i = 0; i < ml->nmoves;) {
		old_fsb = ml->moves[i].old_fsb;
		i++;
		while (i < ml->nmoves && ml->moves[i].old_fsb == old_fsb)
			i++;
		ngroups++;
	}
	if (ngroups != 0)
		resize_progress_begin(rt, "relocating", ngroups);
	gdone = 0;

	for (i = 0; i < ml->nmoves; i = j) {
		old_fsb = ml->moves[i].old_fsb;
		new_fsb = ml->moves[i].new_fsb;
		bytes = ml->moves[i].bytes;
		j = i + 1;
		while (j < ml->nmoves && ml->moves[j].old_fsb == old_fsb)
			j++;
		for (k = i; k < j; k++) {
			ml->moves[k].owner.owner_block_fsb =
			    ml->moves[k].owner_abs_offset;
			ml->moves[k].owner.slot_index = ml->moves[k].owner_width;
			if (ml->moves[k].new_fsb != new_fsb ||
			    ml->moves[k].bytes != bytes) {
				resize_vlog(rt->verbose,
				    "relocate: inconsistent old_fsb=%" PRIu64
				    " group new_fsb/bytes mismatch\n", old_fsb);
				error = EINVAL;
				goto out;
			}
		}
		resize_vlog(rt->verbose,
		    "[%zu/%zu] copy old_fsb=%" PRIu64 " -> new_fsb=%" PRIu64
		    " bytes=%u refs=%zu\n",
		    i + 1, ml->nmoves, ml->moves[i].old_fsb, ml->moves[i].new_fsb,
		    ml->moves[i].bytes, j - i);
		error = resize_copy_stage(&ctx, &ml->moves[i]);
		if (error != 0)
			goto out;
		for (k = i + 1; k < j; k++)
			ml->moves[k].flags |= RESIZE_MOVE_F_COPIED;
		for (k = i; k < j; k++) {
			resize_vlog(rt->verbose,
			    "[%zu/%zu] repoint owner_abs=%" PRIu64 " width=%u\n",
			    k + 1, ml->nmoves, ml->moves[k].owner_abs_offset,
			    ml->moves[k].owner_width);
			error = resize_repoint_stage(&ctx, &ml->moves[k]);
			if (error != 0)
				goto out;
		}
		resize_vlog(rt->verbose,
		    "[%zu/%zu] free old_fsb=%" PRIu64 "\n", i + 1, ml->nmoves,
		    ml->moves[i].old_fsb);
		error = resize_free_stage(&ctx, &ml->moves[i]);
		if (error != 0)
			goto out;
		for (k = i + 1; k < j; k++)
			ml->moves[k].flags |= RESIZE_MOVE_F_FREED;
		gdone++;
		resize_progress_update(rt, gdone);
	}
	error = 0;
out:
	resize_progress_end(rt, error == 0);
	return (error);
}

static int
resize_execute(const struct resize_options *opt, int tfd, uint64_t container_bytes,
    struct resize_super *sb, uint64_t target_size, struct resize_move_list *ml,
    const struct resize_ino_remap *irm, uint64_t shift_delta)
{
	struct resize_runtime rt;
	struct resize_plan_ctx pc;
	struct resize_move mv;
	uint64_t old_size_bytes;
	size_t i;
	struct resize_journal jr;
	const char *where;
	int error;

	memset(&jr, 0, sizeof(jr));
	jr.fd = -1;
	where = "journal-create";
	error = resize_journal_create(opt->journal_path, opt->offset_bytes,
	    sb->fs_size_bytes, target_size, sb->sb_rel_offset, sb->fs_fsize, &jr);
	if (error != 0)
		return (error);

	memset(&rt, 0, sizeof(rt));
	rt.tfd = tfd;
	rt.container_bytes = container_bytes;
	rt.fs_offset = opt->offset_bytes;
	rt.fs_fsize = sb->fs_fsize;
	rt.fs = *(const struct fs *)sb->raw;
	rt.dry_run = opt->dry_run;
	rt.progress = (opt->progress && !opt->verbose &&
	    isatty(STDERR_FILENO));
	rt.verbose = opt->verbose;
	rt.jr = &jr;
	old_size_bytes = sb->fs_size_bytes;

	where = "superblock/mark-dirty";
	error = resize_superblock_set_clean_state(&rt, sb, 0);
	if (error != 0)
		goto out;
	where = "invariants/post-mark-dirty";
	error = resize_check_invariants_phase(opt, &rt, sb, "post-mark-dirty");
	if (error != 0)
		goto out;

	if (irm != NULL && irm->nent != 0) {
		where = "inode-remap/plan-ctx-init";
		error = resize_plan_ctx_init_from_super(&pc, tfd, container_bytes,
		    opt->offset_bytes, opt->verbose, sb);
		if (error != 0)
			goto out;
		for (i = 0; i < irm->nent; i++) {
			memset(&mv, 0, sizeof(mv));
			mv.old_fsb = irm->ents[i].old_ino;
			mv.new_fsb = irm->ents[i].new_ino;
			mv.bytes = pc.inode_size;
			where = "inode-remap/journal-map-intent";
			error = resize_journal_append(&jr, RESIZE_REC_INTENT,
			    RESIZE_MUT_INODE_REMAP_MAP, &mv, 0);
			if (error != 0)
				goto out;
			where = "inode-remap/journal-map-applied";
			error = resize_journal_append(&jr, RESIZE_REC_APPLIED,
			    RESIZE_MUT_INODE_REMAP_MAP, &mv, 0);
			if (error != 0)
				goto out;
		}
		memset(&mv, 0, sizeof(mv));
		mv.old_fsb = irm->nent;
		where = "inode-remap/journal-exec-intent";
		error = resize_journal_append(&jr, RESIZE_REC_INTENT,
		    RESIZE_MUT_INODE_REMAP_EXEC, &mv, 0);
		if (error != 0)
			goto out;
		where = "inode-remap/journal-sync-before-exec";
		error = resize_journal_sync(&jr);
		if (error != 0)
			goto out;
		where = "inode-remap/apply";
		error = resize_apply_inode_remap(&pc, sb, irm);
		if (error != 0)
			goto out;
		where = "inode-remap/journal-exec-applied";
		error = resize_journal_append(&jr, RESIZE_REC_APPLIED,
		    RESIZE_MUT_INODE_REMAP_EXEC, &mv, 0);
		if (error != 0)
			goto out;
		where = "inode-remap/journal-sync-after-exec";
		error = resize_journal_sync(&jr);
		if (error != 0)
			goto out;
		where = "invariants/post-inode-remap";
		error = resize_check_invariants_phase(opt, &rt, sb,
		    "post-inode-remap");
		if (error != 0)
			goto out;
	}

	if (ml->nmoves == 0 && opt->moves_path == NULL &&
	    target_size < sb->fs_size_bytes) {
		where = "auto-plan/post-remap";
		error = resize_plan_auto_shrink_end(tfd, container_bytes, opt, sb,
		    target_size, ml);
		if (error != 0)
			goto out;
		resize_reorder_moves(ml, false);
	}

	where = "alloc/init-from-moves";
	error = resize_alloc_init_from_moves(&rt.amap, ml);
	if (error != 0)
		goto out;

	if (ml->nmoves != 0) {
		resize_vlog(opt->verbose, "phase: relocating (%zu moves)\n",
		    ml->nmoves);
		where = "phase-set/relocating";
		error = resize_journal_set_phase(&jr, RESIZE_PHASE_RELOCATING);
		if (error != 0)
			goto out;
		where = "journal-sync/relocating";
		error = resize_journal_sync(&jr);
		if (error != 0)
			goto out;
		where = "relocation/run";
		error = resize_run_relocation(&rt, ml);
		if (error != 0)
			goto out;
		where = "invariants/post-relocating";
		error = resize_check_invariants_phase(opt, &rt, sb,
		    "post-relocating");
		if (error != 0)
			goto out;
	}

	where = "phase-set/metadata";
	error = resize_journal_set_phase(&jr, RESIZE_PHASE_METADATA);
	if (error != 0)
		goto out;
	resize_vlog(opt->verbose, "phase: metadata (superblock update)\n");
	where = "journal-sync/metadata";
	error = resize_journal_sync(&jr);
	if (error != 0)
		goto out;
	where = "superblock/set-size";
	error = resize_superblock_set_size(&rt, sb, target_size);
	if (error != 0)
		goto out;
	if (target_size != old_size_bytes) {
		rt.fs = *(const struct fs *)sb->raw;
		where = "summaries/recompute";
		error = resize_recompute_free_summaries(&rt, sb);
		if (error != 0)
			goto out;
	}
	where = "invariants/post-metadata";
	error = resize_check_invariants_phase(opt, &rt, sb, "post-metadata");
	if (error != 0)
		goto out;

	if (shift_delta != 0) {
		resize_vlog(opt->verbose,
		    "phase: shifting-image (delta=%" PRIu64 ")\n",
		    shift_delta);
		where = "shift-image/journaled-copy";
		error = resize_shift_image_up_journal(&rt, opt->offset_bytes,
		    target_size, shift_delta);
		if (error != 0)
			goto out;
		where = "shift-image/verify-super";
		error = resize_shift_rebase_super(&rt, sb, shift_delta,
		    target_size);
		if (error != 0)
			goto out;
		where = "invariants/post-shifting-image";
		error = resize_check_invariants_phase(opt, &rt, sb,
		    "post-shifting-image");
		if (error != 0)
			goto out;
	}

	where = "phase-set/committing";
	error = resize_journal_set_phase(&jr, RESIZE_PHASE_COMMITTING);
	if (error != 0)
		goto out;
	resize_vlog(opt->verbose, "phase: committing\n");
	where = "commit/append";
	error = resize_journal_append(&jr, RESIZE_REC_COMMIT, 0, NULL, 0);
	if (error != 0)
		goto out;
	where = "commit/sync";
	error = resize_journal_sync(&jr);
	if (error != 0)
		goto out;

	where = "phase-set/committed";
	error = resize_journal_set_phase(&jr, RESIZE_PHASE_COMMITTED);
	if (error != 0)
		goto out;
	resize_vlog(opt->verbose, "phase: committed\n");
	where = "committed/sync";
	error = resize_journal_sync(&jr);
	if (error != 0)
		goto out;
	where = "superblock/mark-clean";
	error = resize_superblock_set_clean_state(&rt, sb, 1);
	if (error == 0) {
		where = "invariants/post-mark-clean";
		error = resize_check_invariants_phase(opt, &rt, sb,
		    "post-mark-clean");
	}
out:
	if (error != 0 && opt->verbose && where != NULL)
		fprintf(stderr, "execute: %s failed (%s)\n", where,
		    strerror(error));
	resize_alloc_free(&rt.amap);
	resize_journal_close(&jr);
	return (error);
}

static int
resize_resolve_target_size(const struct resize_options *opt, uint64_t container_bytes,
    uint64_t current_size, uint64_t *target_size)
{
	uint64_t tsize;
	int error;

	if (opt->have_size) {
		tsize = opt->size_bytes;
	} else if (container_bytes > opt->offset_bytes) {
		tsize = container_bytes - opt->offset_bytes;
	} else {
		tsize = current_size;
	}
	if (tsize == 0)
		return (EINVAL);
	error = resize_add_u64(opt->offset_bytes, tsize, &current_size);
	if (error != 0)
		return (error);
	if (current_size > container_bytes)
		return (EINVAL);
	*target_size = tsize;
	return (0);
}

static int
resize_shift_image_up_journal(struct resize_runtime *rt, uint64_t src_abs,
    uint64_t len, uint64_t delta)
{
	struct resize_move mv;
	u_int8_t *buf;
	uint64_t done, chunk, rem, from, to, end, src_end;
	int error;

	if (delta == 0 || len == 0)
		return (0);
	error = resize_add_u64(src_abs, len, &src_end);
	if (error != 0)
		return (error);
	error = resize_add_u64(src_end, delta, &end);
	if (error != 0)
		return (error);
	if (end > rt->container_bytes)
		return (EINVAL);

	chunk = 1024ULL * 1024ULL;
	if (chunk > len)
		chunk = len;
	if (chunk == 0)
		chunk = DEV_BSIZE;
	buf = malloc((size_t)chunk);
	if (buf == NULL)
		return (ENOMEM);
	resize_progress_begin(rt, "shift-copy", len);

	done = 0;
	while (done < len) {
		rem = len - done;
		if (rem < chunk)
			chunk = rem;
		from = src_abs + (len - done - chunk);
		to = from + delta;

		memset(&mv, 0, sizeof(mv));
		mv.old_fsb = from;
		mv.new_fsb = to;
		mv.bytes = (uint32_t)chunk;
		error = resize_journal_append(rt->jr, RESIZE_REC_INTENT,
		    RESIZE_MUT_SHIFT_CHUNK, &mv, 0);
		if (error != 0)
			break;
		error = resize_journal_sync(rt->jr);
		if (error != 0)
			break;

		error = resize_read_bytes_any(rt->tfd, rt->container_bytes, from, buf,
		    (size_t)chunk);
		if (error != 0)
			break;
		if (!rt->dry_run) {
			error = resize_write_bytes_any(rt->tfd, rt->container_bytes,
			    to, buf, (size_t)chunk);
			if (error != 0)
				break;
			if (fsync(rt->tfd) == -1) {
				error = errno;
				break;
			}
		}
		error = resize_journal_append(rt->jr, RESIZE_REC_APPLIED,
		    RESIZE_MUT_SHIFT_CHUNK, &mv, 0);
		if (error != 0)
			break;
		error = resize_journal_sync(rt->jr);
		if (error != 0)
			break;
		done += chunk;
		if (rt->verbose && (done % (64ULL * 1024ULL * 1024ULL) == 0 ||
		    done == len)) {
			fprintf(stderr,
			    "shift: copied %" PRIu64 "/%" PRIu64 " bytes\n",
			    done, len);
		}
		resize_progress_update(rt, done);
	}
	free(buf);
	resize_progress_end(rt, error == 0);
	return (error);
}

static int
resize_shift_rebase_super(struct resize_runtime *rt, struct resize_super *sb,
    uint64_t shift_delta, uint64_t target_size)
{
	struct resize_super nsb;
	uint64_t new_offset;
	int error;

	if (shift_delta == 0)
		return (0);
	error = resize_add_u64(rt->fs_offset, shift_delta, &new_offset);
	if (error != 0)
		return (error);
	error = resize_read_super(rt->tfd, new_offset, rt->container_bytes, &nsb);
	if (error != 0)
		return (error);
	if (nsb.fs_magic != sb->fs_magic || nsb.fs_fsize != sb->fs_fsize)
		return (EINVAL);
	if (nsb.fs_size_bytes != target_size)
		return (EINVAL);
	*sb = nsb;
	rt->fs_offset = new_offset;
	rt->fs_fsize = nsb.fs_fsize;
	rt->fs = *(const struct fs *)nsb.raw;
	return (0);
}

static void
resize_print_label_hint(FILE *fp, const struct resize_options *opt,
    const struct resize_label_info *li, int li_error, uint64_t old_size,
    uint64_t target_size)
{
	uint64_t delta, fs_old_abs, fs_new_abs, fs_new_size;
	uint64_t start_sec, size_sec;
	uint64_t start_512, size_512;

	if (target_size > old_size)
		delta = 0;
	else
		delta = old_size - target_size;

	fs_new_abs = opt->offset_bytes;
	if (opt->policy == RESIZE_POLICY_SHRINK_MOVE &&
	    target_size < old_size)
		fs_new_abs += delta;
	fs_new_size = target_size;
	fprintf(fp,
	    "layout-hint(target-relative): new_offset=%" PRIu64
	    " new_size=%" PRIu64 " bytes"
	    " (relative to start of provided target)\n",
	    fs_new_abs, fs_new_size);
	if (fs_new_abs % DEV_BSIZE == 0 && fs_new_size % DEV_BSIZE == 0) {
		start_512 = fs_new_abs / DEV_BSIZE;
		size_512 = fs_new_size / DEV_BSIZE;
		fprintf(fp,
		    "layout-hint(target-relative): 512b-start=%" PRIu64
		    " 512b-size=%" PRIu64
		    " (relative to start of provided target)\n",
		    start_512, size_512);
	}

	if (li == NULL || !li->valid) {
		if (li_error != 0) {
			fprintf(fp,
			    "disklabel-hint(absolute): unavailable (%s)\n",
			    strerror(li_error));
			if (li != NULL &&
			    (li->err_target != 0 || li->err_raw_c != 0 ||
			    li->err_block != 0 || li->err_block_c != 0)) {
				fprintf(fp,
				    "disklabel-probe: target=%s raw-c=%s block=%s block-c=%s\n",
				    li->err_target ? strerror(li->err_target) : "-",
				    li->err_raw_c ? strerror(li->err_raw_c) : "-",
				    li->err_block ? strerror(li->err_block) : "-",
				    li->err_block_c ? strerror(li->err_block_c) : "-");
			}
		} else {
			fprintf(fp,
			    "disklabel-hint(absolute): unavailable "
			    "(partition geometry query failed)\n");
		}
		return;
	}
	if (li->secsize == 0) {
		fprintf(fp,
		    "disklabel-hint(absolute): unavailable (sector size unknown)\n");
		return;
	}
	if (opt->offset_bytes % li->secsize != 0) {
		fprintf(fp,
		    "disklabel-hint(absolute): unavailable "
		    "(offset not aligned to secsize)\n");
		return;
	}
	if (target_size % li->secsize != 0) {
		fprintf(fp,
		    "disklabel-hint(absolute): unavailable "
		    "(size not aligned to secsize)\n");
		return;
	}
	fs_old_abs = li->part_offset_sec * li->secsize + opt->offset_bytes;
	fs_new_abs = fs_old_abs;
	if (opt->policy == RESIZE_POLICY_SHRINK_MOVE &&
	    target_size < old_size)
		fs_new_abs += delta;
	fs_new_size = target_size;

	start_sec = fs_new_abs / li->secsize;
	size_sec = fs_new_size / li->secsize;
	if (fs_new_abs % DEV_BSIZE == 0 && fs_new_size % DEV_BSIZE == 0) {
		start_512 = fs_new_abs / DEV_BSIZE;
		size_512 = fs_new_size / DEV_BSIZE;
		fprintf(fp,
		    "disklabel-hint(absolute): start=%" PRIu64 " size=%" PRIu64
		    " (secsize=%" PRIu64 "), 512b-start=%" PRIu64
		    " 512b-size=%" PRIu64 "\n",
		    start_sec, size_sec, li->secsize, start_512, size_512);
	} else {
		fprintf(fp,
		    "disklabel-hint(absolute): start=%" PRIu64 " size=%" PRIu64
		    " (secsize=%" PRIu64 ")\n",
		    start_sec, size_sec, li->secsize);
	}
	if (li->via_c_fallback) {
		fprintf(fp,
		    "disklabel-hint-source: geometry read from corresponding c partition\n");
	}
}

int
main(int argc, char **argv)
{
	struct resize_options opt;
	struct resize_super sb;
	struct resize_move_list ml;
	struct resize_journal jr;
	struct resize_runtime rt;
	struct resize_ino_remap irm;
	struct resize_plan_ctx ipc;
	struct resize_label_info li;
	struct stat st;
	uint64_t container_bytes, target_size, old_size_bytes;
	uint64_t begin_delta;
	const char *move_src;
	int shift_beginning_mode;
	int dryrun_irm_preview = 0;
	int defer_autoplan = 0;
	int li_error;
	int tfd = -1;
	int error;

	memset(&irm, 0, sizeof(irm));

	error = resize_parse_options(argc, argv, &opt);
	if (error != 0) {
		usage();
		return (1);
	}

	error = resize_open_target(opt.target_path, !opt.dry_run, &tfd, &st,
	    &container_bytes, opt.have_size);
	if (error != 0) {
		fprintf(stderr, "open target: %s\n", strerror(error));
		return (1);
	}
	memset(&li, 0, sizeof(li));
	li_error = resize_get_label_info_with_fallback(tfd, opt.target_path, &li);
	if (li_error != 0 && opt.verbose)
		fprintf(stderr, "disklabel-hint: %s\n", strerror(li_error));

	if (opt.recover || opt.revert || opt.resume) {
		memset(&jr, 0, sizeof(jr));
		jr.fd = -1;
		error = resize_journal_open_existing(opt.journal_path, &jr);
		if (error != 0) {
			fprintf(stderr, "open journal: %s\n", strerror(error));
			close(tfd);
			return (1);
		}
		memset(&rt, 0, sizeof(rt));
		rt.tfd = tfd;
		rt.container_bytes = container_bytes;
		rt.fs_offset = jr.hdr.fs_offset_bytes;
		rt.fs_fsize = jr.hdr.fs_fsize;
		rt.dry_run = opt.dry_run;
		rt.progress = (opt.progress && !opt.verbose &&
		    isatty(STDERR_FILENO));
		rt.verbose = opt.verbose;
		rt.jr = &jr;
		error = resize_read_super(tfd, rt.fs_offset, container_bytes, &sb);
		if (error != 0) {
			fprintf(stderr, "%s: cannot read superblock: %s\n",
			    opt.revert ? "revert" : (opt.resume ? "resume" : "recover"),
			    strerror(error));
			resize_journal_close(&jr);
			close(tfd);
			return (1);
		}
		rt.fs = *(const struct fs *)sb.raw;
		resize_vlog(opt.verbose, "%s: start phase=%u next_seq=%" PRIu64
		    "\n",
		    opt.revert ? "revert" : (opt.resume ? "resume" : "recover"),
		    jr.hdr.phase,
		    jr.hdr.next_seq);
		if (opt.revert)
			error = resize_revert_journal(&opt, &rt, &jr);
		else if (opt.resume) {
			error = resize_recover_journal(&rt, &jr);
			if (error == 0)
				error = resize_resume_journal(&opt, &rt, &jr);
		} else
			error = resize_recover_journal(&rt, &jr);
		if (error != 0) {
			fprintf(stderr, "%s failed: %s\n",
			    opt.revert ? "revert" :
			    (opt.resume ? "resume" : "recover"),
			    strerror(error));
			resize_journal_close(&jr);
			close(tfd);
			return (1);
		}
		resize_journal_close(&jr);
		close(tfd);
		return (0);
	}

	error = resize_read_super(tfd, opt.offset_bytes, container_bytes, &sb);
	if (error != 0) {
		fprintf(stderr,
		    "cannot read superblock (fs offset=%" PRIu64
		    ", probed SBOFF/SBLOCK_* and scanned early fs range)\n",
		    opt.offset_bytes);
		close(tfd);
		return (1);
	}
	old_size_bytes = sb.fs_size_bytes;

	error = resize_resolve_target_size(&opt, container_bytes, sb.fs_size_bytes,
	    &target_size);
	if (error != 0) {
		fprintf(stderr, "size resolution failed: %s\n", strerror(error));
		close(tfd);
		return (1);
	}

	if (target_size % sb.fs_fsize != 0) {
		fprintf(stderr, "target size must align to fs_fsize=%u\n",
		    sb.fs_fsize);
		close(tfd);
		return (1);
	}
	if (opt.policy == RESIZE_POLICY_PUSH_FORWARD &&
	    target_size < old_size_bytes) {
		fprintf(stderr,
		    "policy push-forward is not implemented for shrinking yet\n");
		close(tfd);
		return (1);
	}

	memset(&irm, 0, sizeof(irm));
	if (target_size < old_size_bytes && opt.moves_path == NULL) {
		memset(&ipc, 0, sizeof(ipc));
		ipc.tfd = tfd;
		ipc.container_bytes = container_bytes;
		ipc.fs_offset = opt.offset_bytes;
		ipc.fs = (const struct fs *)sb.raw;
		ipc.old_blocks = sb.fs_size_blocks;
		ipc.new_blocks = sb.fs_size_blocks;
		ipc.fs_fsize = sb.fs_fsize;
		ipc.fs_bsize = ((const struct fs *)sb.raw)->fs_bsize;
		ipc.verbose = opt.verbose;
		if (((const struct fs *)sb.raw)->fs_magic == FS_UFS1_MAGIC) {
			ipc.ptr_width = 4;
			ipc.inode_size = sizeof(struct ufs1_dinode);
			ipc.maxsymlinklen = MAXSYMLINKLEN_UFS1;
		} else {
			ipc.ptr_width = 8;
			ipc.inode_size = sizeof(struct ufs2_dinode);
			ipc.maxsymlinklen = MAXSYMLINKLEN_UFS2;
		}
		error = resize_build_inode_remap(&ipc, target_size / sb.fs_fsize,
		    &irm);
		if (error != 0 && !opt.force) {
			fprintf(stderr, "inode-remap planning failed: %s\n",
			    strerror(error));
			close(tfd);
			return (1);
		}
		if (error != 0 && opt.force)
			resize_vlog(opt.verbose,
			    "inode-remap planning failed (%s), continuing due to --force\n",
			    strerror(error));
		if (error == 0 && irm.nent != 0) {
			fprintf(stderr,
			    "inode-remap: %zu inode(s) will be relocated out of doomed inode-table blocks\n",
			    irm.nent);
			if (opt.dry_run)
				dryrun_irm_preview = 1;
			else if (opt.moves_path == NULL)
				defer_autoplan = 1;
		}
	}

	shift_beginning_mode = (opt.policy == RESIZE_POLICY_SHRINK_MOVE &&
	    target_size < old_size_bytes);
	begin_delta = shift_beginning_mode ? (old_size_bytes - target_size) : 0;

	memset(&ml, 0, sizeof(ml));
	if (opt.moves_path != NULL) {
		error = resize_load_moves(opt.moves_path, &ml);
		if (error != 0) {
			fprintf(stderr, "failed to load moves: %s\n",
			    strerror(error));
			close(tfd);
			return (1);
		}
		resize_reorder_moves(&ml, false);
		move_src = opt.moves_path;
	} else {
		move_src = "(none)";
		if (dryrun_irm_preview) {
			move_src = "(auto+inode-remap-preview)";
		} else if (defer_autoplan) {
			move_src = "(auto-post-remap)";
		} else if (target_size < sb.fs_size_bytes) {
			error = resize_plan_auto_shrink_end(tfd, container_bytes,
			    &opt, &sb, target_size, &ml);
			if (error != 0) {
				if (!opt.force) {
					if (error == ENOTSUP) {
						fprintf(stderr,
						    "auto-plan failed: %s; inode remap + relocation could not satisfy target.\n",
						    strerror(error));
					} else {
						fprintf(stderr,
						    "auto-plan failed: %s\n",
						    strerror(error));
					}
					free(ml.moves);
					close(tfd);
					return (1);
				}
				resize_vlog(opt.verbose,
				    "auto-plan failed (%s), continuing due to --force\n",
				    strerror(error));
			} else {
				move_src = "(auto)";
			}
		}
	}

	resize_vlog(opt.verbose,
	    "plan: target=%s offset=%" PRIu64 " current=%" PRIu64
	    " target=%" PRIu64 " fs_fsize=%u moves=%s policy=%s\n",
	    opt.target_path, opt.offset_bytes, sb.fs_size_bytes, target_size,
	    sb.fs_fsize, move_src, resize_policy_name(opt.policy));

	if (opt.dry_run) {
		if (opt.check_invariants) {
			memset(&rt, 0, sizeof(rt));
			rt.tfd = tfd;
			rt.container_bytes = container_bytes;
			rt.fs_offset = opt.offset_bytes;
			rt.fs_fsize = sb.fs_fsize;
			rt.fs = *(const struct fs *)sb.raw;
			rt.dry_run = 1;
			rt.verbose = opt.verbose;
			error = resize_check_invariants_phase(&opt, &rt, &sb,
			    "dry-run-preflight");
			if (error != 0) {
				fprintf(stderr, "invariant check failed: %s\n",
				    strerror(error));
				free(ml.moves);
				resize_ino_remap_free(&irm);
				close(tfd);
				return (1);
			}
		}
		fprintf(stdout,
		    "target=%s offset=%" PRIu64 " current=%" PRIu64
		    " target=%" PRIu64 " fs_fsize=%u moves=%zu policy=%s plan=%s",
		    opt.target_path, opt.offset_bytes, sb.fs_size_bytes,
		    target_size, sb.fs_fsize, ml.nmoves,
		    resize_policy_name(opt.policy),
		    move_src);
		if (shift_beginning_mode) {
			fprintf(stdout, " new_offset=%" PRIu64 " delta=%" PRIu64,
			    opt.offset_bytes + begin_delta, begin_delta);
		}
		fprintf(stdout, "\n");
		if (dryrun_irm_preview) {
			fprintf(stdout,
			    "note: inode remap preview mode; relocation move count requires non-dry-run execution path\n");
		}
		resize_print_label_hint(stdout, &opt, &li, li_error,
		    old_size_bytes, target_size);
		free(ml.moves);
		resize_ino_remap_free(&irm);
		close(tfd);
		return (0);
	}

	error = resize_execute(&opt, tfd, container_bytes, &sb, target_size, &ml,
	    &irm, shift_beginning_mode ? begin_delta : 0);
	free(ml.moves);
	if (error != 0) {
		fprintf(stderr, "resize failed: %s\n", strerror(error));
		resize_ino_remap_free(&irm);
		close(tfd);
		return (1);
	}
	resize_print_label_hint(stdout, &opt, &li, li_error, old_size_bytes,
	    target_size);
	resize_ino_remap_free(&irm);

	close(tfd);
	return (0);
}
