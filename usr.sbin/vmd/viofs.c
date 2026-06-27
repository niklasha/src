/*	$OpenBSD$	*/

/*
 * Copyright (c) 2026 Niklas Hallqvist
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * vio9p: host side of the virtio-9p (9P2000.L) filesystem-sharing transport.
 *
 * M1a: the read-only 9P2000.L server's foundation + metadata core, running in
 * the viofs device subprocess (privsep + unveil(share,"r") + pledge "rpath").
 * The server NEVER dereferences symlinks (NFS model): it reports them and the
 * guest follows them in its own namespace.  Every path the server forms is a
 * single component opened with O_NOFOLLOW relative to a FID's fd transitively
 * rooted at share_fd, so a guest can never escape the share.  See
 * plan/M1_DESIGN.md.  Directory reads (Treaddir) and the off-vcpu deferral land
 * in M1c/M1d; this servicing is synchronous.
 *
 * M3: optional read-write support.  When the share is mounted "rw"
 * (VMSHARE_WRITABLE), the subprocess unveils the share "rwc" and a wider pledge,
 * and the mutating handlers (Twrite, Tlcreate, Tmkdir, Tunlinkat, Tsetattr,
 * Trename, Trenameat, Tsymlink) are enabled.  Each mutating syscall is bracketed
 * by viofs_setcred()/viofs_restorecred(): in the shipped SQUASH mode these are
 * no-ops (the subprocess already runs as the single share-owner identity); the
 * bracket is the forward-compat seam for the M3b transparent (per-fid euid)
 * mode.  Every fid carries (parentfd,name) so an existing file can be reopened
 * read-write at Tlopen time without a second walk.  See plan/M3_DESIGN.md.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/resource.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * The protocol layer (everything up to and including viofs_handle) is pure
 * libc so the Stage-0 regress harness can #include this file with
 * -DVIOFS_STAGE0 and drive viofs_handle directly.  The vmd/virtio transport
 * glue below is excluded from that build.
 */
#ifndef VIOFS_STAGE0
#include <event.h>

#include <dev/pci/virtio_pcireg.h>
#include <dev/pv/virtioreg.h>

#include "atomicio.h"
#include "pci.h"
#include "virtio.h"
#include "vmd.h"

extern struct vmd_vm *current_vm;
#endif /* !VIOFS_STAGE0 */

/* 9P2000.L message types. */
#define P9_TSTATFS	8
#define P9_RSTATFS	9
#define P9_TLOPEN	12
#define P9_RLOPEN	13
#define P9_TREADLINK	22
#define P9_RREADLINK	23
#define P9_TGETATTR	24
#define P9_RGETATTR	25
#define P9_TREADDIR	40
#define P9_RREADDIR	41
#define P9_RLERROR	7
#define P9_TVERSION	100
#define P9_RVERSION	101
#define P9_TATTACH	104
#define P9_RATTACH	105
#define P9_TFLUSH	108
#define P9_RFLUSH	109
#define P9_TWALK	110
#define P9_RWALK	111
#define P9_TREAD	116
#define P9_RREAD	117
#define P9_TCLUNK	120
#define P9_RCLUNK	121
/* Mutating ops (enabled for RW shares in M3; still refused for RO). */
#define P9_TLCREATE	14
#define P9_RLCREATE	15
#define P9_TSYMLINK	16
#define P9_RSYMLINK	17
#define P9_TMKNOD	18
#define P9_TRENAME	20
#define P9_RRENAME	21
#define P9_TXATTRWALK	30
#define P9_TXATTRCREATE	32
#define P9_TMKDIR	72
#define P9_RMKDIR	73
#define P9_TRENAMEAT	74
#define P9_RRENAMEAT	75
#define P9_TUNLINKAT	76
#define P9_RUNLINKAT	77
#define P9_TLOCK	52
#define P9_TGETLOCK	54
#define P9_RLOCK	53
#define P9_RGETLOCK	55
#define P9_TLINK	70
#define P9_RLINK	71
#define P9_TFSYNC	50
#define P9_RFSYNC	51
#define P9_TSETATTR	26
#define P9_RSETATTR	27
#define P9_TWRITE	118
#define P9_RWRITE	119
#define P9_TAUTH	102
#define P9_TREMOVE	122

#define P9_HDRLEN	7		/* size[4] type[1] tag[2] */
#define P9_NOFID	0xffffffffU
#define P9_MAXWELEM	16		/* max Twalk components per spec */

/* qid.type values. */
#define P9_QTDIR	0x80
#define P9_QTSYMLINK	0x02
#define P9_QTFILE	0x00

/* Tgetattr request_mask bits a RO server fills (P9_GETATTR_BASIC). */
#define P9_GETATTR_BASIC	0x000007ffULL

/*
 * 9P2000.L Tsetattr valid[4] bitmask (Linux <net/9p/9p.h> P9_ATTR_*).  We honor
 * MODE/SIZE/ATIME/MTIME (+ the _SET variants that carry an explicit timespec);
 * UID/GID are parsed but ignored in squash mode (the choke point owns identity).
 */
#define P9_SETATTR_MODE		0x00000001U
#define P9_SETATTR_UID		0x00000002U
#define P9_SETATTR_GID		0x00000004U
#define P9_SETATTR_SIZE		0x00000008U
#define P9_SETATTR_ATIME	0x00000010U
#define P9_SETATTR_MTIME	0x00000020U
#define P9_SETATTR_CTIME	0x00000040U
#define P9_SETATTR_ATIME_SET	0x00000080U
#define P9_SETATTR_MTIME_SET	0x00000100U

/* Tunlinkat flags[4]: the only defined bit is Linux AT_REMOVEDIR (0x200). */
#ifndef P9_DOTL_AT_REMOVEDIR
#define P9_DOTL_AT_REMOVEDIR	0x200U
#endif

/*
 * Credential-mode value mirrored from vmd.h.  The pure-libc Stage-0 harness
 * builds this file without vmd.h, so provide the squash constant as a fallback
 * (it MUST stay numerically identical to vmd.h's VMSHARE_CRED_SQUASH == 0).
 */
#ifndef VMSHARE_CRED_SQUASH
#define VMSHARE_CRED_SQUASH	0
#endif

/*
 * Linux errno values (the wire is Linux; OpenBSD numbers diverge above 34).
 * Used both for literal refusals and as errno_xlate() outputs.
 */
#define L_EPERM		1
#define L_ENOENT	2
#define L_EIO		5
#define L_EBADF		9
#define L_ENOMEM	12
#define L_EACCES	13
#define L_EFAULT	14
#define L_EEXIST	17
#define L_EXDEV		18
#define L_ENOTDIR	20
#define L_EISDIR	21
#define L_EINVAL	22
#define L_ENFILE	23
#define L_EMFILE	24
#define L_ESPIPE	29
#define L_EROFS		30
#define L_EAGAIN	11
#define L_EDEADLK	35
#define L_ELOOP		40
#define L_ENAMETOOLONG	36
#define L_ENOTEMPTY	39
#define L_ENOLCK	37
#define L_ENOSYS	38
#define L_EOVERFLOW	75
#define L_EOPNOTSUPP	95
#define L_ENODATA	61
#define L_EMSGSIZE	90

/* Linux O_* (Tlopen flags) — hardcoded; do NOT use <fcntl.h> values. */
#define L_O_WRONLY	01
#define L_O_RDWR	02
#define L_O_CREAT	0100
#define L_O_EXCL	0200
#define L_O_TRUNC	01000
#define L_O_APPEND	02000

/* The write-intent flags that force a RW reopen at Tlopen/Tlcreate time. */
#define L_O_WRITE_MASK	(L_O_WRONLY | L_O_RDWR | L_O_TRUNC | L_O_APPEND)

#define VIOFS_MSIZE_MIN	512
#define VIOFS_MSIZE_MAX	(64 * 1024)
#define VIOFS_VERSION	"9P2000.L"

/* Treaddir: each wire dirent = qid[13] off[8] type[1] namelen[2] + name. */
#define P9_READDIR_FIXED	24
#define VIOFS_GETDENTS_BUF	4096	/* multiple of FFS DIRBLKSIZ (512) */

#define VIOFS_MAX_FIDS	1024
#define VIOFS_FD_SLACK	16
#define VIOFS_MAX_CHAIN	256		/* >= any queue size we offer */
#define FID_HASHSZ	2048		/* power of 2 */
#define FID_HASH(f)	(((uint32_t)(f) * 2654435761U) & (FID_HASHSZ - 1))

/* ---- forward declarations (transport) ---- */
#ifndef VIOFS_STAGE0
static uint32_t	viofs_read(struct virtio_dev *, struct viodev_msg *, int *);
static int	viofs_write(struct virtio_dev *, struct viodev_msg *);
static uint32_t	viofs_dev_read(struct virtio_dev *, struct viodev_msg *);
static int	viofs_notifyq(struct virtio_dev *, uint16_t);

static void	dev_dispatch_vm(int, short, void *);
static void	handle_sync_io(int, short, void *);
#endif

/* ---- little-endian helpers ---- */
static inline uint16_t
get_le16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

static inline uint32_t
get_le32(const uint8_t *p)
{
	return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
	    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t
get_le64(const uint8_t *p)
{
	return (uint64_t)get_le32(p) | ((uint64_t)get_le32(p + 4) << 32);
}

static inline void
put_le16(uint8_t *p, uint16_t v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
}

static inline void
put_le32(uint8_t *p, uint32_t v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

static inline void
put_le64(uint8_t *p, uint64_t v)
{
	put_le32(p, (uint32_t)v);
	put_le32(p + 4, (uint32_t)(v >> 32));
}

/* ---- vendored SipHash-2-4 (key need only be stable, not secret) ---- */
#define SIP_ROTL(x, b)	(((x) << (b)) | ((x) >> (64 - (b))))
#define SIP_ROUND(a, b, c, d) do {				\
	(a) += (b); (b) = SIP_ROTL((b), 13); (b) ^= (a);	\
	(a) = SIP_ROTL((a), 32);				\
	(c) += (d); (d) = SIP_ROTL((d), 16); (d) ^= (c);	\
	(a) += (d); (d) = SIP_ROTL((d), 21); (d) ^= (a);	\
	(c) += (b); (b) = SIP_ROTL((b), 17); (b) ^= (c);	\
	(c) = SIP_ROTL((c), 32);				\
} while (0)

static uint64_t
siphash24(const uint8_t *in, size_t len, uint64_t k0, uint64_t k1)
{
	uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
	uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
	uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
	uint64_t v3 = 0x7465646279746573ULL ^ k1;
	uint64_t b = (uint64_t)len << 56;
	uint64_t m;
	const uint8_t *end = in + (len & ~(size_t)7);
	int i;

	while (in != end) {
		m = get_le64(in);
		in += 8;
		v3 ^= m;
		SIP_ROUND(v0, v1, v2, v3);
		SIP_ROUND(v0, v1, v2, v3);
		v0 ^= m;
	}
	switch (len & 7) {
	case 7: b |= (uint64_t)in[6] << 48;
		/* FALLTHROUGH */
	case 6: b |= (uint64_t)in[5] << 40;
		/* FALLTHROUGH */
	case 5: b |= (uint64_t)in[4] << 32;
		/* FALLTHROUGH */
	case 4: b |= (uint64_t)in[3] << 24;
		/* FALLTHROUGH */
	case 3: b |= (uint64_t)in[2] << 16;
		/* FALLTHROUGH */
	case 2: b |= (uint64_t)in[1] << 8;
		/* FALLTHROUGH */
	case 1: b |= (uint64_t)in[0];
		break;
	}
	v3 ^= b;
	SIP_ROUND(v0, v1, v2, v3);
	SIP_ROUND(v0, v1, v2, v3);
	v0 ^= b;
	v2 ^= 0xff;
	for (i = 0; i < 4; i++)
		SIP_ROUND(v0, v1, v2, v3);
	return (v0 ^ v1 ^ v2 ^ v3);
}

/* ---- qid ---- */
struct p9_qid {
	uint8_t		type;
	uint32_t	version;
	uint64_t	path;
};

static void
qid_from(const struct stat *st, struct p9_qid *q)
{
	uint8_t buf[16];

	if (S_ISDIR(st->st_mode))
		q->type = P9_QTDIR;
	else if (S_ISLNK(st->st_mode))
		q->type = P9_QTSYMLINK;
	else
		q->type = P9_QTFILE;
	put_le64(&buf[0], (uint64_t)st->st_dev);
	put_le64(&buf[8], (uint64_t)st->st_ino);
	q->path = siphash24(buf, sizeof(buf), 0x9e3779b97f4a7c15ULL,
	    0xc2b2ae3d27d4eb4fULL);
	q->version = (uint32_t)(st->st_mtim.tv_sec ^ st->st_mtim.tv_nsec);
}

/* ---- OpenBSD errno -> Linux errno ---- */
static int
errno_xlate(int oerr)
{
	switch (oerr) {
	case 0:			return (0);
	case EPERM:		return (L_EPERM);
	case ENOENT:		return (L_ENOENT);
	case EIO:		return (L_EIO);
	case EBADF:		return (L_EBADF);
	case ENOMEM:		return (L_ENOMEM);
	case EACCES:		return (L_EACCES);
	case EFAULT:		return (L_EFAULT);
	case EEXIST:		return (L_EEXIST);
	case EXDEV:		return (L_EXDEV);
	case ENOTDIR:		return (L_ENOTDIR);
	case EISDIR:		return (L_EISDIR);
	case EINVAL:		return (L_EINVAL);
	case ENFILE:		return (L_ENFILE);
	case EMFILE:		return (L_EMFILE);
	case ESPIPE:		return (L_ESPIPE);
	case EROFS:		return (L_EROFS);
	case EAGAIN:		return (L_EAGAIN);	/* OpenBSD 35 -> 11 */
	case EDEADLK:		return (L_EDEADLK);	/* OpenBSD 11 -> 35 */
	case ELOOP:		return (L_ELOOP);	/* 62 -> 40 */
	case ENAMETOOLONG:	return (L_ENAMETOOLONG);	/* 63 -> 36 */
	case ENOTEMPTY:		return (L_ENOTEMPTY);	/* 66 -> 39 */
	case ENOLCK:		return (L_ENOLCK);	/* 77 -> 37 */
	case ENOSYS:		return (L_ENOSYS);	/* 78 -> 38 */
	case EOVERFLOW:		return (L_EOVERFLOW);	/* 87 -> 75 */
	case EMSGSIZE:		return (L_EMSGSIZE);	/* 40 -> 90 */
	case EOPNOTSUPP:	return (L_EOPNOTSUPP);	/* 45 -> 95 */
	case ENOTSUP:		return (L_EOPNOTSUPP);	/* 91 -> 95 */
	case ENOATTR:		return (L_ENODATA);	/* 83 -> 61 */
	default:		return (L_EIO);
	}
}

/* ---- FID table (file-scope: one viofs server per subprocess) ---- */
struct viofs_fid {
	uint32_t		fid;		/* P9_NOFID == free */
	int			fd;		/* -1 for a symlink FID */
	int			parentfd;	/* dir holding this object (dup) */
	uint8_t			qtype;
	uint8_t			opened;
	uint8_t			is_dir;
	uint8_t			is_share_root;	/* ".."-at-root chroot (Treaddir) */
	uint64_t		qidpath;
	uint32_t		qidversion;
	off_t			dir_off;
	uid_t			uid;		/* owning uid (squash: owner) */
	gid_t			gid;		/* owning gid (squash: owner) */
	char			name[NAME_MAX + 1];	/* leaf within parentfd */
	struct viofs_fid	*hnext;
	struct viofs_fid	*fnext;
};

static struct viofs_fid	 *fid_pool;
static struct viofs_fid	**fid_bkt;
static struct viofs_fid	 *fid_free;
static size_t		  fid_max;

/* squash identity (set by viofs_main before any fid_alloc can run) */
static uint32_t	viofs_owner_uid;
static uint32_t	viofs_owner_gid;

static int
fid_init(size_t max)
{
	size_t i;

	fid_max = max;
	if ((fid_pool = calloc(max, sizeof(*fid_pool))) == NULL)
		return (-1);
	if ((fid_bkt = calloc(FID_HASHSZ, sizeof(*fid_bkt))) == NULL)
		return (-1);
	fid_free = NULL;
	for (i = 0; i < max; i++) {
		fid_pool[i].fid = P9_NOFID;
		fid_pool[i].fd = -1;
		fid_pool[i].parentfd = -1;
		fid_pool[i].fnext = fid_free;
		fid_free = &fid_pool[i];
	}
	return (0);
}

static struct viofs_fid *
fid_lookup(uint32_t fid)
{
	struct viofs_fid *p;

	if (fid == P9_NOFID)
		return (NULL);
	for (p = fid_bkt[FID_HASH(fid)]; p != NULL; p = p->hnext)
		if (p->fid == fid)
			return (p);
	return (NULL);
}

/* Allocate a slot for an as-yet-unused fid; NULL == table full (EMFILE). */
static struct viofs_fid *
fid_alloc(uint32_t fid)
{
	struct viofs_fid *p;
	uint32_t b;

	if ((p = fid_free) == NULL)
		return (NULL);
	fid_free = p->fnext;
	p->fid = fid;
	p->fd = -1;
	p->parentfd = -1;
	p->qtype = 0;
	p->opened = 0;
	p->is_dir = 0;
	p->is_share_root = 0;
	p->qidpath = 0;
	p->qidversion = 0;
	p->dir_off = 0;
	p->uid = viofs_owner_uid;
	p->gid = viofs_owner_gid;
	p->name[0] = '\0';
	b = FID_HASH(fid);
	p->hnext = fid_bkt[b];
	fid_bkt[b] = p;
	return (p);
}

static void
fid_free_one(struct viofs_fid *p)
{
	struct viofs_fid **pp;

	for (pp = &fid_bkt[FID_HASH(p->fid)]; *pp != NULL; pp = &(*pp)->hnext) {
		if (*pp == p) {
			*pp = p->hnext;
			break;
		}
	}
	if (p->fd != -1)
		close(p->fd);
	if (p->parentfd != -1)
		close(p->parentfd);
	p->fd = -1;
	p->parentfd = -1;
	p->fid = P9_NOFID;
	p->fnext = fid_free;
	fid_free = p;
}

/* Drop the whole table (close all fds) — on re-Tversion and teardown. */
static void
fid_reset_all(void)
{
	size_t i;

	if (fid_pool == NULL)
		return;
	fid_free = NULL;
	for (i = 0; i < fid_max; i++) {
		struct viofs_fid *p = &fid_pool[i];

		if (p->fid != P9_NOFID) {
			if (p->fd != -1)
				close(p->fd);
			if (p->parentfd != -1)
				close(p->parentfd);
		}
		p->fid = P9_NOFID;
		p->fd = -1;
		p->parentfd = -1;
		p->fnext = fid_free;
		fid_free = p;
	}
	memset(fid_bkt, 0, FID_HASHSZ * sizeof(*fid_bkt));
}

/* ---- request cursor (bounds-checked) ---- */
struct p9_treq {
	const uint8_t	*buf;
	size_t		 len;
	size_t		 off;
	uint8_t		 type;
	uint16_t	 tag;
	int		 err;
};

static uint16_t
p9_get16(struct p9_treq *r)
{
	uint16_t v;

	if (r->err || r->off + 2 > r->len) {
		r->err = 1;
		return (0);
	}
	v = get_le16(&r->buf[r->off]);
	r->off += 2;
	return (v);
}

static uint32_t
p9_get32(struct p9_treq *r)
{
	uint32_t v;

	if (r->err || r->off + 4 > r->len) {
		r->err = 1;
		return (0);
	}
	v = get_le32(&r->buf[r->off]);
	r->off += 4;
	return (v);
}

static uint64_t
p9_get64(struct p9_treq *r)
{
	uint64_t v;

	if (r->err || r->off + 8 > r->len) {
		r->err = 1;
		return (0);
	}
	v = get_le64(&r->buf[r->off]);
	r->off += 8;
	return (v);
}

/* Read a 9P string[s] into out (NUL-terminated). Rejects embedded NUL. */
static void
p9_gets(struct p9_treq *r, char *out, size_t outsz)
{
	uint16_t n = p9_get16(r);

	if (r->err || r->off + n > r->len || (size_t)n >= outsz) {
		r->err = 1;
		if (outsz > 0)
			out[0] = '\0';
		return;
	}
	if (n > 0 && memchr(&r->buf[r->off], '\0', n) != NULL) {
		r->err = 1;
		out[0] = '\0';
		return;
	}
	memcpy(out, &r->buf[r->off], n);
	out[n] = '\0';
	r->off += n;
}

static int
p9_treq_init(struct p9_treq *r, const uint8_t *buf, size_t len)
{
	uint32_t declared;

	memset(r, 0, sizeof(*r));
	r->buf = buf;
	r->len = len;
	if (len < P9_HDRLEN)
		return (-1);		/* unframeable: no tag -> reset */
	r->type = buf[4];
	r->tag = get_le16(&buf[5]);
	r->off = P9_HDRLEN;
	declared = get_le32(buf);
	if (declared < P9_HDRLEN || declared > len)
		r->err = 1;		/* lying size: tag known -> Rlerror(EINVAL) */
	else
		r->len = declared;	/* trust the declared size as the bound */
	return (0);
}

/* ---- response builder (scatters across the writable iovec later) ---- */
struct p9_resp {
	uint8_t		*buf;
	size_t		 cap;
	size_t		 len;
	uint16_t	 tag;
	int		 err;
};

static void
p9_put8(struct p9_resp *r, uint8_t v)
{
	if (r->err || r->len + 1 > r->cap) {
		r->err = 1;
		return;
	}
	r->buf[r->len++] = v;
}

static void
p9_put16(struct p9_resp *r, uint16_t v)
{
	if (r->err || r->len + 2 > r->cap) {
		r->err = 1;
		return;
	}
	put_le16(&r->buf[r->len], v);
	r->len += 2;
}

static void
p9_put32(struct p9_resp *r, uint32_t v)
{
	if (r->err || r->len + 4 > r->cap) {
		r->err = 1;
		return;
	}
	put_le32(&r->buf[r->len], v);
	r->len += 4;
}

static void
p9_put64(struct p9_resp *r, uint64_t v)
{
	if (r->err || r->len + 8 > r->cap) {
		r->err = 1;
		return;
	}
	put_le64(&r->buf[r->len], v);
	r->len += 8;
}

static void
p9_putdata(struct p9_resp *r, const void *p, size_t n)
{
	if (r->err || r->len + n > r->cap) {
		r->err = 1;
		return;
	}
	memcpy(&r->buf[r->len], p, n);
	r->len += n;
}

static void
p9_puts(struct p9_resp *r, const char *s, size_t n)
{
	p9_put16(r, (uint16_t)n);
	p9_putdata(r, s, n);
}

static void
p9_putqid(struct p9_resp *r, const struct p9_qid *q)
{
	p9_put8(r, q->type);
	p9_put32(r, q->version);
	p9_put64(r, q->path);
}

/* (Re)start a response; rewrites the header, discarding any partial body. */
static void
p9_resp_start(struct p9_resp *r, uint8_t rtype)
{
	r->len = 0;
	r->err = 0;
	p9_put32(r, 0);		/* size placeholder */
	p9_put8(r, rtype);
	p9_put16(r, r->tag);
}

static void
p9_rlerror(struct p9_resp *r, int lerrno)
{
	p9_resp_start(r, P9_RLERROR);
	p9_put32(r, (uint32_t)lerrno);
}

static void
p9_resp_finish(struct p9_resp *r)
{
	if (r->len >= 4)
		put_le32(&r->buf[0], (uint32_t)r->len);
}

/* ---- path component validation ---- */
static int
name_ok(const char *n)
{
	if (n[0] == '\0')
		return (0);
	if (n[0] == '.' && (n[1] == '\0' || (n[1] == '.' && n[2] == '\0')))
		return (0);		/* "." and ".." */
	if (strchr(n, '/') != NULL)
		return (0);
	if (strlen(n) > NAME_MAX)
		return (0);
	return (1);
}

/*
 * Sanitize a guest-supplied mode word before it touches a host object: keep
 * only the 12 permission bits and strip SUID/SGID/sticky.  ONE source of truth
 * for every create/chmod path (Tlcreate, Tmkdir, Tsetattr).
 */
static mode_t
viofs_sanitize_mode(mode_t mode)
{
	return (mode & 07777 & ~(mode_t)(S_ISUID | S_ISGID | S_ISVTX));
}

/* ---- op handlers ---- */
static uint32_t	cur_msize;		/* negotiated msize */
static int	viofs_share_fd = -1;	/* share root (set by viofs_main) */
static int	viofs_writable;		/* share is RW (set by viofs_main) */
static int	viofs_credmode = VMSHARE_CRED_SQUASH;	/* M3b seam */
static uid_t	viofs_maproot = (uid_t)-1;		/* M3b seam */

/*
 * Credential choke point (forward-compat seam, single source of truth for "who
 * does this write act as").
 *
 * SQUASH (the only mode wired up in M3): NO-OP.  The subprocess already runs as
 * the single share-owner-equivalent identity, so every mutating syscall already
 * acts as that identity; there is nothing to set or restore.  Bracketing every
 * write handler now means the M3b transparent mode is a two-function change, not
 * a scatter-edit across the handlers: viofs_setcred() will setegid/seteuid to
 * the fid's carried uid/gid (honoring viofs_maproot for guest-root) and return 0
 * or an OpenBSD errno on failure; viofs_restorecred() will restore euid/egid to
 * root.  The bracket must enclose EXACTLY the filesystem syscall(s) and nothing
 * that touches the 9P wire buffers.
 */
static int
viofs_setcred(struct viofs_fid *f)
{
	(void)f;
	return (0);		/* SQUASH: no-op.  M3b fills this in. */
}

static void
viofs_restorecred(void)
{
	/* SQUASH: no-op.  M3b restores euid/egid to root here. */
}

static void
p9_version(struct p9_treq *req, struct p9_resp *resp)
{
	char ver[32];
	uint32_t msize;

	msize = p9_get32(req);
	p9_gets(req, ver, sizeof(ver));
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if (msize < VIOFS_MSIZE_MIN)
		msize = VIOFS_MSIZE_MIN;
	if (msize > VIOFS_MSIZE_MAX)
		msize = VIOFS_MSIZE_MAX;
	cur_msize = msize;

	/* A new Tversion orphans every prior fid. */
	fid_reset_all();

	p9_resp_start(resp, P9_RVERSION);
	p9_put32(resp, msize);
	if (strncmp(ver, VIOFS_VERSION, sizeof(VIOFS_VERSION)) == 0)
		p9_puts(resp, VIOFS_VERSION, strlen(VIOFS_VERSION));
	else
		p9_puts(resp, "unknown", strlen("unknown"));
}

static void
p9_attach(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f;
	struct p9_qid q;
	struct stat st;
	char uname[64], aname[256];
	uint32_t fid, afid;
	int rootfd;

	fid = p9_get32(req);
	afid = p9_get32(req);
	p9_gets(req, uname, sizeof(uname));	/* ignored (squash) */
	p9_gets(req, aname, sizeof(aname));	/* ignored (root fixed) */
	(void)p9_get32(req);			/* n_uname, ignored */
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if (afid != P9_NOFID) {
		p9_rlerror(resp, L_EACCES);	/* no auth offered */
		return;
	}
	if (fid == P9_NOFID || fid_lookup(fid) != NULL) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	rootfd = openat(viofs_share_fd, ".",
	    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (rootfd == -1) {
		p9_rlerror(resp, errno_xlate(errno));
		return;
	}
	if (fstat(rootfd, &st) == -1) {
		p9_rlerror(resp, errno_xlate(errno));
		close(rootfd);
		return;
	}
	if ((f = fid_alloc(fid)) == NULL) {
		close(rootfd);
		p9_rlerror(resp, L_EMFILE);
		return;
	}
	qid_from(&st, &q);
	f->fd = rootfd;
	f->parentfd = -1;		/* the share root is never written */
	f->qtype = q.type;
	f->qidpath = q.path;
	f->qidversion = q.version;
	f->is_dir = 1;
	f->is_share_root = 1;		/* Tattach is the only producer of the root */

	p9_resp_start(resp, P9_RATTACH);
	p9_putqid(resp, &q);
}

static void
p9_walk(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f, *nf;
	struct p9_qid wq[P9_MAXWELEM];
	struct stat st, sym_st;
	char names[P9_MAXWELEM][NAME_MAX + 1];
	char sym_name[NAME_MAX + 1];
	char last_name[NAME_MAX + 1];
	uint32_t fid, newfid;
	uint16_t nwname, i, nwq;
	int curfd, basefd, parentfd, sym_bound, sym_parentfd, lerr;

	fid = p9_get32(req);
	newfid = p9_get32(req);
	nwname = p9_get16(req);
	if (req->err || nwname > P9_MAXWELEM) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	for (i = 0; i < nwname; i++) {
		p9_gets(req, names[i], sizeof(names[i]));
		if (req->err) {
			p9_rlerror(resp, L_EINVAL);
			return;
		}
	}
	if ((f = fid_lookup(fid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (newfid == P9_NOFID) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if (newfid != fid && fid_lookup(newfid) != NULL) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}

	/* Clone (nwname == 0). */
	if (nwname == 0) {
		int nfd, pdup;

		if (f->fd == -1) {		/* symlink FID clone */
			if ((nf = (newfid == fid) ? f : fid_alloc(newfid))
			    == NULL) {
				p9_rlerror(resp, L_EMFILE);
				return;
			}
			if (nf != f) {
				pdup = dup(f->parentfd);

				if (pdup == -1) {
					fid_free_one(nf);
					p9_rlerror(resp, errno_xlate(errno));
					return;
				}
				fcntl(pdup, F_SETFD, FD_CLOEXEC);
				nf->fd = -1;
				nf->parentfd = pdup;
				strlcpy(nf->name, f->name, sizeof(nf->name));
				nf->qtype = f->qtype;
				nf->qidpath = f->qidpath;
				nf->qidversion = f->qidversion;
				nf->is_dir = 0;
			}
			p9_resp_start(resp, P9_RWALK);
			p9_put16(resp, 0);
			return;
		}
		if (f->is_dir)
			nfd = openat(f->fd, ".",
			    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		else
			nfd = fcntl(f->fd, F_DUPFD_CLOEXEC, 0);
		if (nfd == -1) {
			p9_rlerror(resp, errno_xlate(errno));
			return;
		}
		/*
		 * Carry (parentfd,name) onto the clone so it too can be reopened
		 * RW.  The base fid keeps its own (the dup is the clone's copy).
		 */
		pdup = -1;
		if (f->parentfd != -1) {
			pdup = dup(f->parentfd);
			if (pdup == -1) {
				lerr = errno_xlate(errno);
				close(nfd);
				p9_rlerror(resp, lerr);
				return;
			}
			fcntl(pdup, F_SETFD, FD_CLOEXEC);
		}
		if (newfid == fid) {
			close(f->fd);
			f->fd = nfd;
			/* parentfd/name unchanged (same object). */
			if (pdup != -1)
				close(pdup);
		} else if ((nf = fid_alloc(newfid)) == NULL) {
			close(nfd);
			if (pdup != -1)
				close(pdup);
			p9_rlerror(resp, L_EMFILE);
			return;
		} else {
			nf->fd = nfd;
			nf->parentfd = pdup;
			strlcpy(nf->name, f->name, sizeof(nf->name));
			nf->qtype = f->qtype;
			nf->qidpath = f->qidpath;
			nf->qidversion = f->qidversion;
			nf->is_dir = f->is_dir;
			nf->is_share_root = f->is_share_root;	/* clone stays root */
		}
		p9_resp_start(resp, P9_RWALK);
		p9_put16(resp, 0);
		return;
	}

	/*
	 * Walk.  curfd is the directory we resolve from; it is ours to close
	 * unless it is basefd (which belongs to f).  parentfd tracks the
	 * immediate parent of the terminal component (a dup, ours to close on
	 * partial walk) so a terminal regular/dir fid can be reopened RW.
	 */
	basefd = f->fd;
	if (basefd == -1) {		/* can't walk into a symlink FID */
		p9_rlerror(resp, L_ENOTDIR);
		return;
	}
	curfd = basefd;
	parentfd = -1;
	nwq = 0;
	sym_bound = 0;
	sym_parentfd = -1;
	sym_name[0] = '\0';
	last_name[0] = '\0';
	memset(&sym_st, 0, sizeof(sym_st));

	for (i = 0; i < nwname; i++) {
		int nfd, flags;

		if (!name_ok(names[i])) {
			if (i == 0) {
				if (curfd != basefd)
					close(curfd);
				p9_rlerror(resp, L_ENOENT);
				return;
			}
			break;
		}
		if (fstatat(curfd, names[i], &st, AT_SYMLINK_NOFOLLOW) == -1) {
			if (i == 0) {
				lerr = errno_xlate(errno);
				if (curfd != basefd)
					close(curfd);
				p9_rlerror(resp, lerr);
				return;
			}
			break;
		}
		if (S_ISLNK(st.st_mode)) {
			qid_from(&st, &wq[nwq]);
			nwq++;
			if (i + 1 == nwname) {	/* symlink is the last element */
				sym_parentfd = dup(curfd);
				if (sym_parentfd == -1) {
					lerr = errno_xlate(errno);
					if (curfd != basefd)
						close(curfd);
					p9_rlerror(resp, lerr);
					return;
				}
				fcntl(sym_parentfd, F_SETFD, FD_CLOEXEC);
				strlcpy(sym_name, names[i], sizeof(sym_name));
				sym_st = st;
				sym_bound = 1;
			}
			break;		/* report, never traverse */
		}
		flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
		    (i + 1 < nwname ? O_DIRECTORY : 0);
		nfd = openat(curfd, names[i], flags);
		if (nfd == -1) {
			if (i == 0) {
				lerr = errno_xlate(errno);
				if (curfd != basefd)
					close(curfd);
				p9_rlerror(resp, lerr);
				return;
			}
			break;
		}
		/*
		 * Capture the parent of the terminal component: if this is the
		 * last name, curfd is its parent dir.  dup it (curfd may be a
		 * walk temporary we are about to close) so the bound fid owns an
		 * independent reference for a later RW reopen.
		 */
		if (i + 1 == nwname) {
			parentfd = dup(curfd);
			if (parentfd == -1) {
				lerr = errno_xlate(errno);
				close(nfd);
				if (curfd != basefd)
					close(curfd);
				p9_rlerror(resp, lerr);
				return;
			}
			fcntl(parentfd, F_SETFD, FD_CLOEXEC);
			strlcpy(last_name, names[i], sizeof(last_name));
		}
		if (curfd != basefd)
			close(curfd);
		curfd = nfd;
		qid_from(&st, &wq[nwq]);
		nwq++;
	}

	/* Bind newfid only on a full walk. */
	if (nwq == nwname) {
		if (sym_bound) {
			if (curfd != basefd)
				close(curfd);
			if (parentfd != -1)
				close(parentfd);
			nf = (newfid == fid) ? f : fid_alloc(newfid);
			if (nf == NULL) {
				close(sym_parentfd);
				p9_rlerror(resp, L_EMFILE);
				return;
			}
			if (nf == f && f->fd != -1)
				close(f->fd);
			else if (nf == f && f->parentfd != -1)
				close(f->parentfd);
			nf->fd = -1;
			nf->parentfd = sym_parentfd;
			strlcpy(nf->name, sym_name, sizeof(nf->name));
			nf->qtype = P9_QTSYMLINK;
			nf->is_dir = 0;
			nf->is_share_root = 0;		/* descended */
			nf->opened = 0;
			{
				struct p9_qid q;

				qid_from(&sym_st, &q);
				nf->qidpath = q.path;
				nf->qidversion = q.version;
			}
		} else {
			/* curfd holds the last walked component. */
			nf = (newfid == fid) ? f : fid_alloc(newfid);
			if (nf == NULL) {
				if (curfd != basefd)
					close(curfd);
				if (parentfd != -1)
					close(parentfd);
				p9_rlerror(resp, L_EMFILE);
				return;
			}
			if (nf == f && f->fd != -1)
				close(f->fd);
			else if (nf == f && f->parentfd != -1)
				close(f->parentfd);
			nf->fd = curfd;
			nf->parentfd = parentfd;	/* dup of terminal parent */
			strlcpy(nf->name, last_name, sizeof(nf->name));
			nf->qtype = wq[nwq - 1].type;
			nf->qidpath = wq[nwq - 1].path;
			nf->qidversion = wq[nwq - 1].version;
			nf->is_dir = S_ISDIR(st.st_mode) ? 1 : 0;
			nf->is_share_root = 0;		/* descended below the root */
			nf->opened = 0;
		}
	} else {
		/* Partial walk: bind nothing, drop any held fd. */
		if (sym_parentfd != -1)
			close(sym_parentfd);
		if (parentfd != -1)
			close(parentfd);
		if (curfd != basefd)
			close(curfd);
	}

	p9_resp_start(resp, P9_RWALK);
	p9_put16(resp, nwq);
	for (i = 0; i < nwq; i++)
		p9_putqid(resp, &wq[i]);
}

static void
p9_getattr(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f;
	struct p9_qid q;
	struct stat st;
	uint32_t fid;
	uint64_t valid;
	uint32_t mode;

	fid = p9_get32(req);
	valid = p9_get64(req);		/* request_mask */
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((f = fid_lookup(fid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (f->fd == -1) {		/* symlink FID */
		if (fstatat(f->parentfd, f->name, &st, AT_SYMLINK_NOFOLLOW)
		    == -1) {
			p9_rlerror(resp, errno_xlate(errno));
			return;
		}
	} else if (fstat(f->fd, &st) == -1) {
		p9_rlerror(resp, errno_xlate(errno));
		return;
	}
	qid_from(&st, &q);

	/* Squash credentials; mask out setuid/setgid/sticky. */
	mode = (uint32_t)st.st_mode & ~(uint32_t)(S_ISUID | S_ISGID | S_ISVTX);
	valid &= P9_GETATTR_BASIC;

	p9_resp_start(resp, P9_RGETATTR);
	p9_put64(resp, valid);
	p9_putqid(resp, &q);
	p9_put32(resp, mode);
	p9_put32(resp, viofs_owner_uid);
	p9_put32(resp, viofs_owner_gid);
	p9_put64(resp, (uint64_t)st.st_nlink);
	p9_put64(resp, (uint64_t)st.st_rdev);
	p9_put64(resp, (uint64_t)st.st_size);
	p9_put64(resp, (uint64_t)st.st_blksize);
	p9_put64(resp, (uint64_t)st.st_blocks);
	p9_put64(resp, (uint64_t)st.st_atim.tv_sec);
	p9_put64(resp, (uint64_t)st.st_atim.tv_nsec);
	p9_put64(resp, (uint64_t)st.st_mtim.tv_sec);
	p9_put64(resp, (uint64_t)st.st_mtim.tv_nsec);
	p9_put64(resp, (uint64_t)st.st_ctim.tv_sec);
	p9_put64(resp, (uint64_t)st.st_ctim.tv_nsec);
	p9_put64(resp, 0);		/* btime_sec (not in valid) */
	p9_put64(resp, 0);		/* btime_nsec */
	p9_put64(resp, 0);		/* gen */
	p9_put64(resp, 0);		/* data_version */
}

/*
 * Translate a Linux Tlcreate/Tlopen open-flag word into the host open(2) flag
 * set, dropping anything we will not honor.  O_CREAT/O_EXCL are added by the
 * caller (Tlcreate always creates); here we only carry the access mode and the
 * truncate/append modifiers.  O_NOFOLLOW|O_CLOEXEC are forced on by the caller.
 */
static int
viofs_linux_oflags(uint32_t lflags)
{
	int flags;

	/*
	 * Access mode: a write-intent open needs at least write access; honor
	 * the guest's intent but guarantee write when it asked to create/write.
	 */
	if (lflags & L_O_RDWR)
		flags = O_RDWR;
	else if (lflags & L_O_WRONLY)
		flags = O_WRONLY;
	else
		flags = O_RDWR;		/* create implies the creator can write */
	if (lflags & L_O_TRUNC)
		flags |= O_TRUNC;
	if (lflags & L_O_APPEND)
		flags |= O_APPEND;
	return (flags);
}

static void
p9_lopen(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f;
	struct p9_qid q;
	uint32_t fid, flags;
	int cerr;

	fid = p9_get32(req);
	flags = p9_get32(req);
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((f = fid_lookup(fid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (f->fd == -1) {		/* symlink: cannot be opened */
		p9_rlerror(resp, L_ELOOP);
		return;
	}
	/*
	 * A write-intent open on a RO share is refused (the original RO
	 * behavior, now gated).  On a RW share a write-intent open of an
	 * existing regular file must REOPEN it read-write: p9_walk opened the
	 * fid O_RDONLY, so the held fd cannot be written.  Reopen relative to
	 * the carried parent dir under O_NOFOLLOW so the path stays confined and
	 * a symlink racily planted at the leaf is not followed.
	 */
	if (flags & L_O_WRITE_MASK) {
		if (!viofs_writable) {
			p9_rlerror(resp, L_EROFS);
			return;
		}
		if (!f->is_dir && f->parentfd != -1 && f->name[0] != '\0') {
			int nfd;

			if ((cerr = viofs_setcred(f)) != 0) {
				p9_rlerror(resp, errno_xlate(cerr));
				return;
			}
			nfd = openat(f->parentfd, f->name,
			    viofs_linux_oflags(flags) | O_NOFOLLOW |
			    O_CLOEXEC);
			if (nfd == -1) {
				cerr = errno;
				viofs_restorecred();
				p9_rlerror(resp, errno_xlate(cerr));
				return;
			}
			viofs_restorecred();
			close(f->fd);
			f->fd = nfd;
		} else if (f->is_dir) {
			/* directories are never opened for writing */
			p9_rlerror(resp, L_EISDIR);
			return;
		}
		/*
		 * Else (regular file without a carried parent — e.g. the share
		 * root can't be a regular file, so this is unreachable in
		 * practice): fall through and open the held RDONLY fd; a write
		 * will then fail with EBADF, an honest error.
		 */
	}
	f->opened = 1;
	if (f->is_dir)
		f->dir_off = 0;

	q.type = f->qtype;
	q.version = f->qidversion;
	q.path = f->qidpath;
	p9_resp_start(resp, P9_RLOPEN);
	p9_putqid(resp, &q);
	p9_put32(resp, 0);		/* iounit 0 = use msize */
}

static void
p9_read(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f;
	uint32_t fid, count;
	uint64_t offset;
	size_t avail;
	ssize_t n;
	uint8_t *dst;

	fid = p9_get32(req);
	offset = p9_get64(req);
	count = p9_get32(req);
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((f = fid_lookup(fid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (f->fd == -1) {		/* symlink FID: report, never read */
		p9_rlerror(resp, L_ELOOP);
		return;
	}
	if (!f->opened) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (f->is_dir) {
		p9_rlerror(resp, L_EISDIR);	/* dirs use Treaddir */
		return;
	}
	if (offset > (uint64_t)LLONG_MAX) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	/* Reserve the Rread header (size+type+tag+count = 11), clamp to cap. */
	if (resp->cap < P9_HDRLEN + 4) {
		resp->err = 1;		/* malformed chain -> reset */
		return;
	}
	avail = resp->cap - (P9_HDRLEN + 4);
	if (count > avail)
		count = (uint32_t)avail;

	p9_resp_start(resp, P9_RREAD);
	p9_put32(resp, 0);		/* count placeholder at resp->buf+7 */
	dst = &resp->buf[resp->len];
	n = pread(f->fd, dst, count, (off_t)offset);
	if (n == -1) {
		p9_rlerror(resp, errno_xlate(errno));
		return;
	}
	resp->len += (size_t)n;
	put_le32(&resp->buf[P9_HDRLEN], (uint32_t)n);	/* real count */
}

static void
p9_readlink(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f;
	char target[PATH_MAX];
	uint32_t fid;
	ssize_t n;

	fid = p9_get32(req);
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((f = fid_lookup(fid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (f->fd != -1 || f->qtype != P9_QTSYMLINK) {
		p9_rlerror(resp, L_EINVAL);	/* not a symlink */
		return;
	}
	n = readlinkat(f->parentfd, f->name, target, sizeof(target));
	if (n == -1) {
		p9_rlerror(resp, errno_xlate(errno));
		return;
	}
	/* Returned verbatim; never resolved. */
	p9_resp_start(resp, P9_RREADLINK);
	p9_puts(resp, target, (size_t)n);
}

static void
p9_statfs(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f;
	struct statfs sfs;
	uint32_t fid;
	int64_t bavail;

	fid = p9_get32(req);
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((f = fid_lookup(fid)) == NULL || f->fd == -1) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (fstatfs(f->fd, &sfs) == -1) {
		p9_rlerror(resp, errno_xlate(errno));
		return;
	}
	bavail = sfs.f_bavail < 0 ? 0 : sfs.f_bavail;

	p9_resp_start(resp, P9_RSTATFS);
	p9_put32(resp, 0x01021997);	/* V9FS_MAGIC */
	p9_put32(resp, (uint32_t)sfs.f_bsize);
	p9_put64(resp, (uint64_t)sfs.f_blocks);
	p9_put64(resp, (uint64_t)sfs.f_bfree);
	p9_put64(resp, (uint64_t)bavail);
	p9_put64(resp, (uint64_t)sfs.f_files);
	p9_put64(resp, (uint64_t)sfs.f_ffree);
	p9_putdata(resp, &sfs.f_fsid, 8);	/* fsid_t is exactly 8 bytes */
	p9_put32(resp, (uint32_t)sfs.f_namemax);
}

static void
p9_clunk(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f;
	uint32_t fid;

	fid = p9_get32(req);
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((f = fid_lookup(fid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	fid_free_one(f);
	p9_resp_start(resp, P9_RCLUNK);
}

static void
p9_flush(struct p9_treq *req, struct p9_resp *resp)
{
	(void)p9_get16(req);		/* oldtag — already complete */
	p9_resp_start(resp, P9_RFLUSH);
}

/*
 * Fill one Rreaddir entry's qid + wire type from a getdents record.  Uses a
 * per-entry fstatat so the qid is byte-identical to what Tgetattr/Twalk return
 * for the same file (survives sub-mounts; immune to DT_UNKNOWN).  Returns -1 to
 * skip a racily-vanished entry (don't abort the listing).  "." and ".." are
 * confined to the directory's own / the share-root's own qid so the host parent
 * identity never leaks (NFS chroot semantics).
 */
static int
readdir_qid_type(struct viofs_fid *f, struct dirent *dp, struct p9_qid *q,
    uint8_t *wtype)
{
	struct stat st;

	/*
	 * "." and (at the share root) ".." are the directory's OWN qid.  Stat
	 * f->fd FRESH — exactly as p9_getattr does — so the version (mtime) is
	 * byte-identical to a concurrent Tgetattr of this fid; the cached
	 * qidversion would drift after a host mtime bump (§4.7 invariant).
	 */
	if (dp->d_namlen == 1 && dp->d_name[0] == '.') {
		if (fstat(f->fd, &st) == -1)
			return (-1);
		qid_from(&st, q);
		*wtype = DT_DIR;
		return (0);
	}
	if (dp->d_namlen == 2 && dp->d_name[0] == '.' && dp->d_name[1] == '.') {
		if (f->is_share_root) {
			/* ".." of the root == the root; never fstatat("..") here. */
			if (fstat(f->fd, &st) == -1)
				return (-1);
		} else {
			/* below root: real parent, inside the share. */
			if (fstatat(f->fd, "..", &st, AT_SYMLINK_NOFOLLOW) == -1)
				return (-1);
		}
		qid_from(&st, q);
		*wtype = DT_DIR;
		return (0);
	}
	if (fstatat(f->fd, dp->d_name, &st, AT_SYMLINK_NOFOLLOW) == -1)
		return (-1);
	qid_from(&st, q);
	*wtype = (uint8_t)IFTODT(st.st_mode);
	return (0);
}

static void
p9_readdir(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid	*f;
	uint8_t			 dbuf[VIOFS_GETDENTS_BUF];
	uint32_t		 fid, count;
	uint64_t		 offset;
	size_t			 budget, avail, out, need;
	int			 n, bpos;

	fid = p9_get32(req);
	offset = p9_get64(req);
	count = p9_get32(req);
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if (fid == P9_NOFID) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((f = fid_lookup(fid)) == NULL || !f->opened) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (f->fd == -1 || !f->is_dir) {
		p9_rlerror(resp, L_ENOTDIR);
		return;
	}
	if (offset > (uint64_t)LLONG_MAX) {	/* cookie out of off_t range */
		p9_rlerror(resp, L_EINVAL);
		return;
	}

	if (resp->cap < P9_HDRLEN + 4) {
		resp->err = 1;			/* writable too small -> reset */
		return;
	}
	avail = resp->cap - (P9_HDRLEN + 4);
	budget = ((uint64_t)count < (uint64_t)avail) ? (size_t)count : avail;

	p9_resp_start(resp, P9_RREADDIR);
	p9_put32(resp, 0);			/* count placeholder at buf[P9_HDRLEN] */
	out = 0;

	if (lseek(f->fd, (off_t)offset, SEEK_SET) == -1) {
		p9_rlerror(resp, errno_xlate(errno));
		return;
	}

	for (;;) {
		n = getdents(f->fd, dbuf, sizeof(dbuf));
		if (n == -1) {
			if (errno == EINVAL)	/* garbage cookie -> clean stop */
				break;
			p9_rlerror(resp, errno_xlate(errno));
			return;
		}
		if (n == 0)
			break;			/* host EOF */

		bpos = 0;
		while (bpos < n) {
			struct dirent	*dp = (struct dirent *)(dbuf + bpos);
			struct p9_qid	 q;
			uint8_t		 wtype;
			int		 reclen = dp->d_reclen;
			uint16_t	 nlen;

			/* Corrupt record: reclen 0 loops forever; over-run guard. */
			if (reclen == 0 || bpos + reclen > n)
				goto done;
			bpos += reclen;
			if (dp->d_fileno == 0)		/* deleted slot */
				continue;
			nlen = dp->d_namlen;
			if (nlen == 0 || nlen > NAME_MAX)
				continue;

			need = P9_READDIR_FIXED + (size_t)nlen;
			if (out + need > budget) {
				if (out == 0) {
					/* one record can't fit even an empty
					 * reply: refuse rather than false-EOF. */
					p9_rlerror(resp, L_EINVAL);
					return;
				}
				goto done;	/* full; client resumes via cookie */
			}
			if (readdir_qid_type(f, dp, &q, &wtype) == -1)
				continue;	/* racy vanish: skip */

			p9_putqid(resp, &q);			/* 13 */
			p9_put64(resp, (uint64_t)dp->d_off);	/* 8: next-entry cookie */
			p9_put8(resp, wtype);			/* 1 */
			p9_puts(resp, dp->d_name, nlen);	/* 2 + nlen */
			out += need;
		}
	}
done:
	put_le32(&resp->buf[P9_HDRLEN], (uint32_t)out);
}

/* ====================================================================== *
 * M3 write (mutating) handlers.  Each self-gates on viofs_writable and
 * returns L_EROFS for a read-only share, so the dispatch can call them
 * unconditionally.  Every filesystem syscall is bracketed by the credential
 * choke point viofs_setcred()/viofs_restorecred() (no-ops in squash mode).
 * Path safety is preserved exactly as in the RO server: name_ok() rejects
 * "", ".", "..", "/" and over-long leaves, and every syscall is *at-relative
 * to a fid fd transitively rooted at share_fd with O_NOFOLLOW where a leaf
 * could be a symlink.
 * ====================================================================== */

/*
 * Twrite fid[4] offset[8] count[4] data[count]  ->  Rwrite count[4]
 *
 * Mirrors p9_read: the fid must be an opened, non-dir, non-symlink regular fd.
 * data lives in the request buffer at req->off; we pwrite it at the guest
 * offset.  A short host write is reported faithfully (the guest retries the
 * tail).  Symlink fids (fd == -1) and directories are rejected, matching read.
 */
static void
p9_write(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f;
	const uint8_t	*src;
	uint32_t	 fid, count;
	uint64_t	 offset;
	ssize_t		 n;
	int		 cerr;

	fid = p9_get32(req);
	offset = p9_get64(req);
	count = p9_get32(req);
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	/* The payload must be fully present in the (size-bounded) request. */
	if (req->off + count > req->len) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	src = &req->buf[req->off];

	if (!viofs_writable) {
		p9_rlerror(resp, L_EROFS);
		return;
	}
	if ((f = fid_lookup(fid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (f->fd == -1) {			/* symlink fid: never written */
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (!f->opened) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (f->is_dir) {
		p9_rlerror(resp, L_EISDIR);
		return;
	}
	if (offset > (uint64_t)LLONG_MAX) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}

	if ((cerr = viofs_setcred(f)) != 0) {
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	n = pwrite(f->fd, src, count, (off_t)offset);
	if (n == -1)
		cerr = errno;
	viofs_restorecred();
	if (n == -1) {
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}

	p9_resp_start(resp, P9_RWRITE);
	p9_put32(resp, (uint32_t)n);
}

/*
 * Tlcreate fid[4] name[s] flags[4] mode[4] gid[4]  ->  Rlcreate qid[13] iounit[4]
 *
 * Per 9P2000.L the fid (a directory) is REPLACED in place by the newly created
 * regular file: we openat(dirfd, name, ...|O_CREAT) and, on success, close the
 * directory fd and adopt the new fd into the SAME fid slot (now an opened file).
 * The new fid carries (parentfd = dup(dirfd), name) so the just-created file is
 * itself reopenable / renameable.  Mode is sanitized to the 12 permission bits
 * with SUID/SGID/sticky stripped.  gid is parsed and ignored in squash mode.
 */
static void
p9_lcreate(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f;
	struct p9_qid	 q;
	struct stat	 st;
	char		 name[NAME_MAX + 1];
	uint32_t	 fid, lflags, mode, gid;
	int		 oflags, newfd, pdup, cerr;

	fid = p9_get32(req);
	p9_gets(req, name, sizeof(name));
	lflags = p9_get32(req);
	mode = p9_get32(req);
	gid = p9_get32(req);
	(void)gid;				/* squash: identity via choke point */
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if (!viofs_writable) {
		p9_rlerror(resp, L_EROFS);
		return;
	}
	if (!name_ok(name)) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((f = fid_lookup(fid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (f->fd == -1 || !f->is_dir) {	/* must be a directory fid */
		p9_rlerror(resp, L_ENOTDIR);
		return;
	}

	oflags = viofs_linux_oflags(lflags) |
	    O_CREAT | O_NOFOLLOW | O_CLOEXEC;
	if (lflags & L_O_EXCL)
		oflags |= O_EXCL;

	if ((cerr = viofs_setcred(f)) != 0) {
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	newfd = openat(f->fd, name, oflags, viofs_sanitize_mode((mode_t)mode));
	if (newfd == -1) {
		cerr = errno;
		viofs_restorecred();
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	if (fstat(newfd, &st) == -1) {
		cerr = errno;
		viofs_restorecred();
		close(newfd);
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	viofs_restorecred();

	/*
	 * Carry the parent dir + leaf onto the (now file) fid before we replace
	 * the directory fd, so the new file is reopenable / renameable.  A dup
	 * failure is non-fatal: the file still works for write via the held fd.
	 */
	pdup = dup(f->fd);
	if (pdup != -1)
		(void)fcntl(pdup, F_SETFD, FD_CLOEXEC);

	/* Replace the directory fd with the new file fd, in place. */
	qid_from(&st, &q);
	close(f->fd);
	if (f->parentfd != -1)
		close(f->parentfd);
	f->fd = newfd;
	f->parentfd = pdup;
	strlcpy(f->name, name, sizeof(f->name));
	f->qtype = q.type;
	f->qidpath = q.path;
	f->qidversion = q.version;
	f->is_dir = 0;
	f->is_share_root = 0;
	f->opened = 1;				/* Tlcreate leaves the fid open */
	f->dir_off = 0;

	p9_resp_start(resp, P9_RLCREATE);
	p9_putqid(resp, &q);
	p9_put32(resp, 0);			/* iounit 0 = use msize */
}

/*
 * Tmkdir dfid[4] name[s] mode[4] gid[4]  ->  Rmkdir qid[13]
 *
 * dfid is the parent directory and is NOT consumed (unlike Tlcreate): the new
 * directory gets its own qid, fetched via fstatat under O_NOFOLLOW semantics.
 */
static void
p9_mkdir(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f;
	struct p9_qid	 q;
	struct stat	 st;
	char		 name[NAME_MAX + 1];
	uint32_t	 dfid, mode, gid;
	int		 cerr;

	dfid = p9_get32(req);
	p9_gets(req, name, sizeof(name));
	mode = p9_get32(req);
	gid = p9_get32(req);
	(void)gid;
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if (!viofs_writable) {
		p9_rlerror(resp, L_EROFS);
		return;
	}
	if (!name_ok(name)) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((f = fid_lookup(dfid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (f->fd == -1 || !f->is_dir) {
		p9_rlerror(resp, L_ENOTDIR);
		return;
	}

	if ((cerr = viofs_setcred(f)) != 0) {
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	if (mkdirat(f->fd, name, viofs_sanitize_mode((mode_t)mode)) == -1) {
		cerr = errno;
		viofs_restorecred();
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	/* O_NOFOLLOW: a symlink racily planted at name is not followed. */
	if (fstatat(f->fd, name, &st, AT_SYMLINK_NOFOLLOW) == -1) {
		cerr = errno;
		viofs_restorecred();
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	viofs_restorecred();

	qid_from(&st, &q);
	p9_resp_start(resp, P9_RMKDIR);
	p9_putqid(resp, &q);
}

/*
 * Tunlinkat dirfd[4] name[s] flags[4]  ->  Runlinkat
 *
 * flags carries only Linux AT_REMOVEDIR (rmdir vs unlink); we translate it to
 * the host AT_REMOVEDIR.  No fid is created or destroyed (the victim has its own
 * fid clunked separately by the guest).
 */
static void
p9_unlinkat(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f;
	char		 name[NAME_MAX + 1];
	uint32_t	 dfid, flags;
	int		 atflags, cerr;

	dfid = p9_get32(req);
	p9_gets(req, name, sizeof(name));
	flags = p9_get32(req);
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if (!viofs_writable) {
		p9_rlerror(resp, L_EROFS);
		return;
	}
	if (!name_ok(name)) {		/* forbids "", ".", "..", "/", over-long */
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((f = fid_lookup(dfid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (f->fd == -1 || !f->is_dir) {
		p9_rlerror(resp, L_ENOTDIR);
		return;
	}
	atflags = (flags & P9_DOTL_AT_REMOVEDIR) ? AT_REMOVEDIR : 0;

	if ((cerr = viofs_setcred(f)) != 0) {
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	if (unlinkat(f->fd, name, atflags) == -1) {
		cerr = errno;
		viofs_restorecred();
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	viofs_restorecred();

	p9_resp_start(resp, P9_RUNLINKAT);
}

/*
 * Tsetattr fid[4] valid[4] mode[4] uid[4] gid[4] size[8]
 *          atime_sec[8] atime_nsec[8] mtime_sec[8] mtime_nsec[8]  ->  Rsetattr
 *
 * We honor MODE (fchmod, SUID/SGID/sticky stripped), SIZE (ftruncate), and
 * ATIME/MTIME (futimens; UTIME_NOW when the *_SET bit is clear, else the
 * supplied timespec).  UID/GID changes are PARSED AND IGNORED in squash mode —
 * the credential choke point owns ownership; transparent mode (M3b) will route
 * a chown through viofs_setcred-style logic, not by reintroducing fchown here.
 * Symlink fids cannot be the target of fchmod/ftruncate (no fd); we reject them
 * with EINVAL, matching the RO server's symlink stance.
 */
static void
p9_setattr(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f;
	struct timespec	 times[2];
	uint32_t	 fid, valid, mode, uid, gid;
	uint64_t	 size;
	uint64_t	 atime_sec, atime_nsec, mtime_sec, mtime_nsec;
	int		 cerr, did_times;

	fid = p9_get32(req);
	valid = p9_get32(req);
	mode = p9_get32(req);
	uid = p9_get32(req);
	gid = p9_get32(req);
	size = p9_get64(req);
	atime_sec = p9_get64(req);
	atime_nsec = p9_get64(req);
	mtime_sec = p9_get64(req);
	mtime_nsec = p9_get64(req);
	(void)uid;
	(void)gid;				/* squash: choke point owns identity */
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if (!viofs_writable) {
		p9_rlerror(resp, L_EROFS);
		return;
	}
	if ((f = fid_lookup(fid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (f->fd == -1) {		/* symlink fid: no fd to fchmod/ftruncate */
		p9_rlerror(resp, L_EINVAL);
		return;
	}

	if ((cerr = viofs_setcred(f)) != 0) {
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}

	if (valid & P9_SETATTR_MODE) {
		if (fchmod(f->fd, viofs_sanitize_mode((mode_t)mode)) == -1) {
			cerr = errno;
			viofs_restorecred();
			p9_rlerror(resp, errno_xlate(cerr));
			return;
		}
	}
	/* UID/GID deliberately not honored in squash mode (no fchown). */

	if (valid & P9_SETATTR_SIZE) {
		if (size > (uint64_t)LLONG_MAX) {
			viofs_restorecred();
			p9_rlerror(resp, L_EINVAL);
			return;
		}
		if (ftruncate(f->fd, (off_t)size) == -1) {
			cerr = errno;
			viofs_restorecred();
			p9_rlerror(resp, errno_xlate(cerr));
			return;
		}
	}

	did_times = 0;
	times[0].tv_sec = 0;
	times[0].tv_nsec = UTIME_OMIT;
	times[1].tv_sec = 0;
	times[1].tv_nsec = UTIME_OMIT;
	if (valid & P9_SETATTR_ATIME) {
		if (valid & P9_SETATTR_ATIME_SET) {
			times[0].tv_sec = (time_t)atime_sec;
			times[0].tv_nsec = (long)atime_nsec;
		} else
			times[0].tv_nsec = UTIME_NOW;
		did_times = 1;
	}
	if (valid & P9_SETATTR_MTIME) {
		if (valid & P9_SETATTR_MTIME_SET) {
			times[1].tv_sec = (time_t)mtime_sec;
			times[1].tv_nsec = (long)mtime_nsec;
		} else
			times[1].tv_nsec = UTIME_NOW;
		did_times = 1;
	}
	if (did_times) {
		if (futimens(f->fd, times) == -1) {
			cerr = errno;
			viofs_restorecred();
			p9_rlerror(resp, errno_xlate(cerr));
			return;
		}
	}

	viofs_restorecred();
	p9_resp_start(resp, P9_RSETATTR);
}

/*
 * Trename fid[4] newdirfid[4] name[s]  ->  Rrename
 *
 * Rename the object held by `fid` into directory `newdirfid` under `name`.  Both
 * fids are already confined under the share (every fid is transitively rooted at
 * share_fd), so the rename is host-side renameat(oldparent, oldname, newdir,
 * name).  Every fid now carries (parentfd,name), so the source (parentdir,leaf)
 * is available for any fid (regular/dir/symlink); only the share-root fid lacks
 * a parent and cannot be renamed.  The in-kernel M2 guest mainly uses Trenameat
 * (which carries both parents + both names); Trename is supported here for the
 * legacy single-name path.
 */
static void
p9_rename(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f, *nd;
	char		 name[NAME_MAX + 1];
	uint32_t	 fid, newdirfid;
	int		 cerr;

	fid = p9_get32(req);
	newdirfid = p9_get32(req);
	p9_gets(req, name, sizeof(name));
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if (!viofs_writable) {
		p9_rlerror(resp, L_EROFS);
		return;
	}
	if (!name_ok(name)) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((f = fid_lookup(fid)) == NULL ||
	    (nd = fid_lookup(newdirfid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (nd->fd == -1 || !nd->is_dir) {	/* destination must be a dir */
		p9_rlerror(resp, L_ENOTDIR);
		return;
	}
	/*
	 * Need the source (parentdir,leaf).  Every walked/created fid carries it;
	 * only the share-root fid (parentfd == -1) lacks one and cannot move.
	 */
	if (f->parentfd == -1 || f->name[0] == '\0') {
		p9_rlerror(resp, L_EINVAL);
		return;
	}

	if ((cerr = viofs_setcred(f)) != 0) {
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	if (renameat(f->parentfd, f->name, nd->fd, name) == -1) {
		cerr = errno;
		viofs_restorecred();
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	viofs_restorecred();

	/* The fid now names the object at its new location. */
	if (f->parentfd != -1)
		close(f->parentfd);
	f->parentfd = dup(nd->fd);
	if (f->parentfd != -1)
		(void)fcntl(f->parentfd, F_SETFD, FD_CLOEXEC);
	strlcpy(f->name, name, sizeof(f->name));

	p9_resp_start(resp, P9_RRENAME);
}

/*
 * Trenameat olddirfid[4] oldname[s] newdirfid[4] newname[s]  ->  Rrenameat
 *
 * The general, fid-complete rename: both parents are directory fids confined
 * under the share, both leaves are validated single components.  This is the
 * path the in-kernel guest uses for every rename.  No fid is consumed (the moved
 * object's own fid, if any, is the guest's to refresh).
 */
static void
p9_renameat(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *od, *nd;
	char		 oldname[NAME_MAX + 1], newname[NAME_MAX + 1];
	uint32_t	 olddirfid, newdirfid;
	int		 cerr;

	olddirfid = p9_get32(req);
	p9_gets(req, oldname, sizeof(oldname));
	newdirfid = p9_get32(req);
	p9_gets(req, newname, sizeof(newname));
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if (!viofs_writable) {
		p9_rlerror(resp, L_EROFS);
		return;
	}
	if (!name_ok(oldname) || !name_ok(newname)) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((od = fid_lookup(olddirfid)) == NULL ||
	    (nd = fid_lookup(newdirfid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (od->fd == -1 || !od->is_dir || nd->fd == -1 || !nd->is_dir) {
		p9_rlerror(resp, L_ENOTDIR);
		return;
	}

	if ((cerr = viofs_setcred(od)) != 0) {
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	if (renameat(od->fd, oldname, nd->fd, newname) == -1) {
		cerr = errno;
		viofs_restorecred();
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	viofs_restorecred();

	p9_resp_start(resp, P9_RRENAMEAT);
}

/*
 * Tsymlink dfid[4] name[s] target[s] gid[4]  ->  Rsymlink qid[13]
 *
 * Create symlink `name` in directory `dfid` pointing at `target`.  target is
 * stored VERBATIM (NFS model — the server never resolves it; the guest follows
 * it in its own namespace, so a target escaping the share is harmless: it just
 * fails to resolve on the guest, or resolves within the guest's own tree).  We
 * never O_NOFOLLOW-open the new link; symlinkat does not follow.  We fstatat the
 * link itself (AT_SYMLINK_NOFOLLOW) for the qid, which must be P9_QTSYMLINK.
 */
static void
p9_symlink(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *f;
	struct p9_qid	 q;
	struct stat	 st;
	char		 name[NAME_MAX + 1];
	char		 target[PATH_MAX];
	uint32_t	 dfid, gid;
	int		 cerr;

	dfid = p9_get32(req);
	p9_gets(req, name, sizeof(name));
	p9_gets(req, target, sizeof(target));
	gid = p9_get32(req);
	(void)gid;
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if (!viofs_writable) {
		p9_rlerror(resp, L_EROFS);
		return;
	}
	if (!name_ok(name) || target[0] == '\0') {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((f = fid_lookup(dfid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (f->fd == -1 || !f->is_dir) {
		p9_rlerror(resp, L_ENOTDIR);
		return;
	}

	if ((cerr = viofs_setcred(f)) != 0) {
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	if (symlinkat(target, f->fd, name) == -1) {
		cerr = errno;
		viofs_restorecred();
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	if (fstatat(f->fd, name, &st, AT_SYMLINK_NOFOLLOW) == -1) {
		cerr = errno;
		viofs_restorecred();
		p9_rlerror(resp, errno_xlate(cerr));
		return;
	}
	viofs_restorecred();

	qid_from(&st, &q);		/* must be P9_QTSYMLINK */
	p9_resp_start(resp, P9_RSYMLINK);
	p9_putqid(resp, &q);
}

/*
 * Tlink dfid[4] fid[4] name[s]  ->  Rlink
 *
 * Hard-link the object held by `fid` into directory `dfid` under `name`.
 * linkat() needs the SOURCE as a (dirfd, pathname) pair OR an fd plus
 * AT_EMPTY_PATH.  OpenBSD's linkat(2) does NOT implement AT_EMPTY_PATH; a fid
 * carries (parentfd,name), but hard-linking via the carried name re-resolves the
 * leaf and (for a symlink leaf) would need AT_SYMLINK_FOLLOW semantics OpenBSD
 * does not offer per-fd cleanly.  Linux v9fs does not rely on Tlink, so we
 * refuse it with L_EOPNOTSUPP — a correct, honest failure for a filesystem that
 * cannot express fd-relative hard links.
 */
static void
p9_link(struct p9_treq *req, struct p9_resp *resp)
{
	struct viofs_fid *nd, *f;
	char		 name[NAME_MAX + 1];
	uint32_t	 dfid, fid;

	dfid = p9_get32(req);
	fid = p9_get32(req);
	p9_gets(req, name, sizeof(name));
	if (req->err) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if (!viofs_writable) {
		p9_rlerror(resp, L_EROFS);
		return;
	}
	if (!name_ok(name)) {
		p9_rlerror(resp, L_EINVAL);
		return;
	}
	if ((nd = fid_lookup(dfid)) == NULL || (f = fid_lookup(fid)) == NULL) {
		p9_rlerror(resp, L_EBADF);
		return;
	}
	if (nd->fd == -1 || !nd->is_dir) {
		p9_rlerror(resp, L_ENOTDIR);
		return;
	}
	/* Not expressible from a fid without AT_EMPTY_PATH (OpenBSD lacks it). */
	p9_rlerror(resp, L_EOPNOTSUPP);
}

/*
 * The single dispatch entry, callable without a vring (so the Stage-0 harness
 * frames a treq buffer and reads the rbuf directly).  Returns 0 with a built
 * response (incl. Rlerror) in rbuf, or -1 for a transport-fatal condition
 * (malformed framing / response cannot fit) -> the caller resets the device.
 * Pure (no vmd/virtio types): the Stage-0 harness #includes this file and
 * calls it directly.
 */
static int
viofs_handle(const uint8_t *treq, size_t treq_len,
    uint8_t *rbuf, size_t rbuf_cap, size_t *rlen)
{
	struct p9_treq req;
	struct p9_resp resp;

	memset(&resp, 0, sizeof(resp));
	resp.buf = rbuf;
	resp.cap = rbuf_cap;

	if (p9_treq_init(&req, treq, treq_len) == -1)
		return (-1);		/* malformed header -> reset */
	resp.tag = req.tag;

	switch (req.type) {
	case P9_TVERSION:
		p9_version(&req, &resp);
		break;
	case P9_TATTACH:
		p9_attach(&req, &resp);
		break;
	case P9_TWALK:
		p9_walk(&req, &resp);
		break;
	case P9_TGETATTR:
		p9_getattr(&req, &resp);
		break;
	case P9_TLOPEN:
		p9_lopen(&req, &resp);
		break;
	case P9_TREAD:
		p9_read(&req, &resp);
		break;
	case P9_TREADLINK:
		p9_readlink(&req, &resp);
		break;
	case P9_TSTATFS:
		p9_statfs(&req, &resp);
		break;
	case P9_TCLUNK:
		p9_clunk(&req, &resp);
		break;
	case P9_TFLUSH:
		p9_flush(&req, &resp);
		break;
	case P9_TREADDIR:
		p9_readdir(&req, &resp);
		break;
	/*
	 * Mutating ops.  Each handler self-gates on viofs_writable and returns
	 * L_EROFS for a read-only share, so the switch calls them
	 * unconditionally; a binary with write support still serves RO shares
	 * as strictly RO.
	 */
	case P9_TWRITE:
		p9_write(&req, &resp);
		break;
	case P9_TLCREATE:
		p9_lcreate(&req, &resp);
		break;
	case P9_TMKDIR:
		p9_mkdir(&req, &resp);
		break;
	case P9_TUNLINKAT:
		p9_unlinkat(&req, &resp);
		break;
	case P9_TSETATTR:
		p9_setattr(&req, &resp);
		break;
	case P9_TRENAME:
		p9_rename(&req, &resp);
		break;
	case P9_TRENAMEAT:
		p9_renameat(&req, &resp);
		break;
	case P9_TSYMLINK:
		p9_symlink(&req, &resp);
		break;
	case P9_TLINK:
		p9_link(&req, &resp);
		break;
	case P9_TREMOVE:		/* legacy remove+clunk: guest uses Tunlinkat */
	case P9_TXATTRCREATE:		/* no xattr write support */
		p9_rlerror(&resp, L_EROFS);
		break;
	case P9_TMKNOD:
		p9_rlerror(&resp, L_EPERM);	/* no device nodes (security) */
		break;
	case P9_TFSYNC:
		p9_resp_start(&resp, P9_RFSYNC);
		break;
	case P9_TXATTRWALK:
		p9_rlerror(&resp, L_ENODATA);
		break;
	case P9_TLOCK:
		p9_resp_start(&resp, P9_RLOCK);
		p9_put8(&resp, 0);		/* status: success */
		break;
	case P9_TGETLOCK:
		p9_rlerror(&resp, L_EOPNOTSUPP);	/* M1+ if needed */
		break;
	case P9_TAUTH:
		p9_rlerror(&resp, L_EACCES);
		break;
	default:
		p9_rlerror(&resp, L_EOPNOTSUPP);
		break;
	}

	if (resp.err)
		return (-1);		/* response did not fit -> reset */
	p9_resp_finish(&resp);
	*rlen = resp.len;
	return (0);
}

/* ======================================================================
 * Transport glue (vmd/virtio): excluded from the Stage-0 harness build.
 * ====================================================================== */
#ifndef VIOFS_STAGE0

/* ---- per-device staging buffers ---- */
static uint8_t treqbuf[VIOFS_MSIZE_MAX];
static uint8_t respbuf[VIOFS_MSIZE_MAX];

/* ---- descriptor-chain scatter/gather ---- */
struct p9_seg {
	uint64_t	gpa;
	uint32_t	len;
};
struct p9_iov {
	struct p9_seg	seg[VIOFS_MAX_CHAIN];
	unsigned int	nseg;
	size_t		total;
};

static int
p9_chain_split(struct vring_desc *table, uint16_t head, uint32_t mask,
    uint32_t qs, struct p9_iov *rd, struct p9_iov *wr)
{
	struct vring_desc *desc;
	uint16_t idx = head;
	unsigned int hops = 0;

	rd->nseg = wr->nseg = 0;
	rd->total = wr->total = 0;
	for (;;) {
		desc = &table[idx & mask];
		if (DESC_WRITABLE(desc)) {
			if (wr->nseg >= VIOFS_MAX_CHAIN)
				return (-1);
			wr->seg[wr->nseg].gpa = desc->addr;
			wr->seg[wr->nseg].len = desc->len;
			wr->nseg++;
			wr->total += desc->len;
		} else {
			if (wr->nseg != 0)	/* readable after writable */
				return (-1);
			if (rd->nseg >= VIOFS_MAX_CHAIN)
				return (-1);
			rd->seg[rd->nseg].gpa = desc->addr;
			rd->seg[rd->nseg].len = desc->len;
			rd->nseg++;
			rd->total += desc->len;
		}
		if ((desc->flags & VRING_DESC_F_NEXT) == 0)
			break;
		idx = desc->next;
		if (++hops >= qs)
			return (-1);
	}
	return (0);
}

static ssize_t
p9_gather_readable(struct p9_iov *rd, uint8_t *dst, size_t cap)
{
	size_t off = 0;
	unsigned int i;

	for (i = 0; i < rd->nseg; i++) {
		if (off + rd->seg[i].len > cap)
			return (-1);
		if (rd->seg[i].len > 0 &&
		    read_mem(rd->seg[i].gpa, dst + off, rd->seg[i].len))
			return (-1);
		off += rd->seg[i].len;
	}
	return ((ssize_t)off);
}

static int
p9_scatter(struct p9_iov *wr, const uint8_t *src, size_t len)
{
	size_t off = 0, n;
	unsigned int i;

	for (i = 0; i < wr->nseg && off < len; i++) {
		n = len - off;
		if (n > wr->seg[i].len)
			n = wr->seg[i].len;
		if (n > 0 && write_mem(wr->seg[i].gpa, src + off, n))
			return (-1);
		off += n;
	}
	return (off == len ? 0 : -1);
}

/*
 * Process request virtqueue notifications: for each available chain, gather
 * the T-message, dispatch it, scatter the R-message, publish to the used ring.
 * Returns 1 if an IRQ should be asserted.
 */
static int
viofs_notifyq(struct virtio_dev *dev, uint16_t vq_idx)
{
	struct virtio_vq_info	*vq_info;
	struct vring_desc	*table;
	struct vring_avail	*avail;
	struct vring_used	*used;
	struct p9_iov		 rd, wr;
	char			*vr;
	uint16_t		 idx, head;
	uint32_t		 mask, qs;
	size_t			 cap, rlen;
	ssize_t			 tlen;
	int			 notify = 0;

	if (vq_idx >= dev->num_queues)
		return (0);

	vq_info = &dev->vq[vq_idx];
	idx = vq_info->last_avail;
	vr = vq_info->q_hva;
	if (vr == NULL)
		fatalx("%s: null vring", __func__);
	mask = vq_info->mask;
	qs = vq_info->qs;

	table = (struct vring_desc *)(vr);
	avail = (struct vring_avail *)(vr + vq_info->vq_availoffset);
	used = (struct vring_used *)(vr + vq_info->vq_usedoffset);

	while (idx != avail->idx) {
		__sync_synchronize();
		head = avail->ring[idx & mask];

		if (p9_chain_split(table, head, mask, qs, &rd, &wr) == -1)
			goto reset;

		tlen = p9_gather_readable(&rd, treqbuf, sizeof(treqbuf));
		if (tlen < 0)
			goto reset;

		/* The clamp for response building: msize and the writable iovec. */
		cap = wr.total;
		if (cur_msize != 0 && cap > cur_msize)
			cap = cur_msize;
		if (cap > sizeof(respbuf))
			cap = sizeof(respbuf);

		if (viofs_handle(treqbuf, (size_t)tlen, respbuf, cap,
		    &rlen) == -1)
			goto reset;

		if (p9_scatter(&wr, respbuf, rlen) == -1)
			goto reset;

		dev->isr |= 1;
		notify = 1;
		used->ring[used->idx & mask].id = head;
		used->ring[used->idx & mask].len = (uint32_t)rlen;
		__sync_synchronize();
		used->idx++;
		idx++;
	}

	vq_info->last_avail = idx;
	return (notify);

reset:
	dev->status |= DEVICE_NEEDS_RESET;
	dev->isr |= VIRTIO_CONFIG_ISR_CONFIG_CHANGE;
	return (1);
}

__dead void
viofs_main(int fd, int fd_vmm)
{
	struct virtio_dev	 dev;
	struct viofs_dev	*viofs = NULL;
	struct viodev_msg	 msg;
	struct vmd_vm		 vm;
	struct rlimit		 rlim;
	size_t			 maxfids;
	ssize_t			 sz;
	int			 ret;

	/*
	 * The broad initial set; pledge(2) can only narrow it.
	 * stdio  - channels + reading the share.
	 * vmm + proc - remap_guest_mem.
	 * recvfd - device channels are passed to us.
	 * unveil - confine to the share subtree, then drop.
	 * rpath  - open/stat/read the (unveiled) share.
	 * wpath cpath fattr - writable shares (M3): write/truncate, create/
	 *   unlink/rename/mkdir/symlink, fchmod/futimens.  The narrowing pledge
	 *   below drops them again for read-only shares.
	 */
	if (pledge("stdio recvfd vmm proc unveil rpath wpath cpath fattr",
	    NULL) == -1)
		fatal("pledge");

	memset(&dev, 0, sizeof(dev));
	sz = atomicio(read, fd, &dev, sizeof(dev));
	if (sz != sizeof(dev)) {
		ret = errno;
		log_warn("failed to receive viofs");
		goto fail;
	}
	if (dev.dev_type != VMD_DEVTYPE_VIOFS) {
		ret = EINVAL;
		log_warnx("received invalid device type");
		goto fail;
	}
	dev.sync_fd = fd;
	viofs = &dev.viofs;

	log_debug("%s: got viofs dev. tag = \"%s\", share = \"%s\"", __func__,
	    viofs->tag, viofs->path);

	viofs_writable = (viofs->flags & VMSHARE_WRITABLE) ? 1 : 0;
	viofs_credmode = viofs->credmode;
	viofs_maproot = viofs->maproot;

	/*
	 * SQUASH is the only credential mode wired up in M3.  A config that
	 * requested transparent/maproot must fail loudly, never silently squash
	 * — the privilege-drop launch below is squash-shaped and would be unsafe
	 * to run under a transparent request.  (M3b replaces this guard with the
	 * seteuid-per-op machinery + pledge "id".)
	 */
	if (viofs_credmode != VMSHARE_CRED_SQUASH) {
		ret = EINVAL;
		log_warnx("%s: share \"%s\": credmode %d not supported "
		    "(M3 is squash-only)", __func__, viofs->tag,
		    viofs_credmode);
		goto fail;
	}

	memset(&vm, 0, sizeof(vm));
	sz = atomicio(read, dev.sync_fd, &vm, sizeof(vm));
	if (sz != sizeof(vm)) {
		ret = EIO;
		log_warnx("failed to receive vm details");
		goto fail;
	}
	current_vm = &vm;

	setproctitle("%s/vio9p%u", vm.vm_params.vmc_name, viofs->idx);
	log_procinit("vm/%s/vio9p%u", vm.vm_params.vmc_name, viofs->idx);

	ret = remap_guest_mem(&vm, fd_vmm);
	if (ret) {
		log_warnx("failed to remap guest memory");
		goto fail;
	}

	close_fd(fd_vmm);
	/*
	 * "rwc" for a writable share (read + write + create), scoped to the
	 * share subtree only — no "x": the server never execs share content.
	 * The unveil lock + the O_NOFOLLOW/openat-from-share_fd containment in
	 * every handler still bound every path to the subtree, so "rwc" cannot
	 * escape the share.  RO shares unveil "r" exactly as before.
	 */
	if (unveil(viofs->path, viofs_writable ? "rwc" : "r") == -1)
		fatal("unveil %s", viofs->path);
	if (unveil(NULL, NULL) == -1)
		fatal("unveil lock");
	/*
	 * Narrow the pledge.  RO shares end up exactly as the M1/M2 path (no
	 * wpath/cpath/fattr).  RW shares keep wpath (pwrite/ftruncate), cpath
	 * (openat O_CREAT, mkdirat, symlinkat, unlinkat, renameat) and fattr
	 * (fchmod/futimens in Tsetattr).
	 */
	if (pledge(viofs_writable ? "stdio recvfd rpath wpath cpath fattr"
	    : "stdio recvfd rpath", NULL) == -1)
		fatal("pledge2");

	viofs->share_fd = open(viofs->path, O_DIRECTORY | O_RDONLY);
	if (viofs->share_fd == -1) {
		ret = errno;
		log_warn("%s: can't open share %s", __func__, viofs->path);
		goto fail;
	}
	viofs_share_fd = viofs->share_fd;
	viofs_owner_uid = current_vm->vm_params.vmc_owner.uid;
	viofs_owner_gid = (uint32_t)current_vm->vm_params.vmc_owner.gid;

	/*
	 * Bound the FID table to the host fd budget so a flood plateaus at the
	 * cap (and the kernel's existing RLIMIT_NOFILE is the hard backstop).
	 * Only getrlimit() is used — setrlimit needs pledge "proc"/"id", which
	 * we deliberately do not hold; lowering the limit is unnecessary since
	 * the table cap already keeps us under it.
	 */
	maxfids = VIOFS_MAX_FIDS;
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0 &&
	    rlim.rlim_cur > VIOFS_FD_SLACK &&
	    (rlim_t)(VIOFS_MAX_FIDS + VIOFS_FD_SLACK) > rlim.rlim_cur)
		maxfids = (size_t)(rlim.rlim_cur - VIOFS_FD_SLACK);
	if (fid_init(maxfids) == -1)
		fatal("fid_init");

	event_init();

	if (vm_device_pipe(&dev, dev_dispatch_vm, NULL)) {
		ret = EIO;
		log_warnx("vm_device_pipe");
		goto fail;
	}

	if (imsgbuf_init(&dev.sync_iev.ibuf, dev.sync_fd) == -1) {
		log_warn("imsgbuf_init");
		goto fail;
	}
	imsgbuf_allow_fdpass(&dev.sync_iev.ibuf);
	dev.sync_iev.handler = handle_sync_io;
	dev.sync_iev.data = &dev;
	dev.sync_iev.events = EV_READ;
	imsg_event_add(&dev.sync_iev);

	memset(&msg, 0, sizeof(msg));
	msg.type = VIODEV_MSG_READY;
	imsg_compose_event(&dev.sync_iev, IMSG_DEVOP_MSG, 0, 0, -1, &msg,
	    sizeof(msg));

	ret = imsg_compose_event(&dev.async_iev, IMSG_DEVOP_MSG, 0, 0, -1,
	    &msg, sizeof(msg));
	if (ret == -1) {
		log_warnx("%s: failed to send async ready message!", __func__);
		goto fail;
	}

	ret = event_dispatch();

	if (ret == 0) {
		fid_reset_all();
		close_fd(dev.sync_fd);
		close_fd(dev.async_fd);
		close_fd(viofs->share_fd);
		_exit(0);
		/* NOTREACHED */
	}

fail:
	memset(&msg, 0, sizeof(msg));
	msg.type = VIODEV_MSG_ERROR;
	msg.data = ret;
	imsg_compose(&dev.sync_iev.ibuf, IMSG_DEVOP_MSG, 0, 0, -1, &msg,
	    sizeof(msg));
	imsgbuf_flush(&dev.sync_iev.ibuf);

	fid_reset_all();
	close_fd(dev.sync_fd);
	close_fd(dev.async_fd);
	if (viofs != NULL)
		close_fd(viofs->share_fd);
	_exit(ret);
	/* NOTREACHED */
}

static void
dev_dispatch_vm(int fd, short event, void *arg)
{
	struct virtio_dev	*dev = (struct virtio_dev *)arg;
	struct imsgev		*iev = &dev->async_iev;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	ssize_t			 n = 0;
	int			 verbose;
	uint32_t		 type;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("%s: imsgbuf_read", __func__);
		if (n == 0) {
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1) {
			if (errno == EPIPE) {
				event_del(&iev->ev);
				event_loopexit(NULL);
				return;
			}
			fatal("%s: imsgbuf_write", __func__);
		}
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)
			break;

		type = imsg_get_type(&imsg);
		switch (type) {
		case IMSG_VMDOP_PAUSE_VM:
			break;
		case IMSG_VMDOP_UNPAUSE_VM:
			break;
		case IMSG_CTL_VERBOSE:
			verbose = imsg_int_read(&imsg);
			log_setverbose(verbose);
			break;
		default:
			log_warnx("%s: unhandled imsg type %d", __func__, type);
			break;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

static void
handle_sync_io(int fd, short event, void *arg)
{
	struct virtio_dev *dev = (struct virtio_dev *)arg;
	struct imsgev *iev = &dev->sync_iev;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct viodev_msg msg;
	struct imsg imsg;
	ssize_t n;
	int deassert = 0;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("%s: imsgbuf_read", __func__);
		if (n == 0) {
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1) {
			if (errno == EPIPE) {
				event_del(&iev->ev);
				event_loopexit(NULL);
				return;
			}
			fatal("%s: imsgbuf_write", __func__);
		}
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatalx("%s: imsg_get (n=%ld)", __func__, n);
		if (n == 0)
			break;

		viodev_msg_read(&imsg, &msg);
		imsg_free(&imsg);

		switch (msg.type) {
		case VIODEV_MSG_IO_READ:
			deassert = 0;
			msg.data = viofs_read(dev, &msg, &deassert);
			msg.data_valid = 1;
			imsg_compose_event(iev, IMSG_DEVOP_MSG, 0, 0, -1, &msg,
			    sizeof(msg));
			if (deassert)
				virtio_deassert_irq(dev, 0);
			break;
		case VIODEV_MSG_IO_WRITE:
			if (viofs_write(dev, &msg))
				virtio_assert_irq(dev, 0);
			break;
		case VIODEV_MSG_SHUTDOWN:
			event_del(&dev->sync_iev.ev);
			event_loopbreak();
			return;
		default:
			fatalx("%s: invalid msg type %d", __func__, msg.type);
		}
	}
	imsg_event_add(iev);
}

static int
viofs_write(struct virtio_dev *dev, struct viodev_msg *msg)
{
	uint32_t data = msg->data;
	uint16_t reg = msg->reg;
	uint8_t sz = msg->io_sz;
	int intr = 0;

	switch (reg & 0xFF00) {
	case VIO1_CFG_BAR_OFFSET:
		(void)virtio_io_cfg(dev, VEI_DIR_OUT, (reg & 0x00FF), data, sz);
		break;
	case VIO1_DEV_BAR_OFFSET:
		/* Device configuration is read-only. */
		break;
	case VIO1_NOTIFY_BAR_OFFSET:
		intr = viofs_notifyq(dev, (uint16_t)(msg->data));
		break;
	case VIO1_ISR_BAR_OFFSET:
		/* Ignore writes to ISR. */
		break;
	default:
		log_debug("%s: no handler for reg 0x%04x", __func__, reg);
	}

	return (intr);
}

static uint32_t
viofs_read(struct virtio_dev *dev, struct viodev_msg *msg, int *deassert)
{
	uint32_t data = 0;
	uint16_t reg = msg->reg;
	uint8_t sz = msg->io_sz;

	switch (reg & 0xFF00) {
	case VIO1_CFG_BAR_OFFSET:
		data = virtio_io_cfg(dev, VEI_DIR_IN, (uint8_t)reg, 0, sz);
		break;
	case VIO1_DEV_BAR_OFFSET:
		data = viofs_dev_read(dev, msg);
		break;
	case VIO1_NOTIFY_BAR_OFFSET:
		/* Reads of notify register return all 1's. */
		break;
	case VIO1_ISR_BAR_OFFSET:
		data = dev->isr;
		dev->isr = 0;
		*deassert = 1;
		break;
	default:
		log_debug("%s: no handler for reg 0x%04x", __func__, reg);
	}

	return (data);
}

/*
 * The virtio-9p device configuration space is { le16 tag_len; u8 tag[] }.
 * Return up to io_sz bytes starting at the requested offset.
 */
static uint32_t
viofs_dev_read(struct virtio_dev *dev, struct viodev_msg *msg)
{
	struct viofs_dev *viofs = &dev->viofs;
	uint8_t cfg[2 + VIO9P_TAG_MAX];
	uint16_t tag_len;
	uint16_t off = msg->reg & 0xFF;
	uint8_t sz = msg->io_sz;
	uint32_t data = 0;
	size_t i;

	tag_len = (uint16_t)strnlen(viofs->tag, VIO9P_TAG_MAX);
	memset(cfg, 0, sizeof(cfg));
	put_le16(cfg, tag_len);
	memcpy(cfg + 2, viofs->tag, tag_len);

	if (sz > sizeof(data))
		sz = sizeof(data);
	for (i = 0; i < sz; i++) {
		if ((size_t)off + i >= sizeof(cfg))
			break;
		data |= (uint32_t)cfg[off + i] << (8 * i);
	}

	return (data);
}

#endif /* !VIOFS_STAGE0 */
