/*	$OpenBSD$	*/

/*
 * Copyright (c) 2026 Niklas Hallqvist <niklas@appli.se>
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
 * Damage an FFS image in controlled ways for the fsck_ffs regress tests.
 *
 *	ffsedit image info		print the geometry of the last cg
 *	ffsedit image tail N		fs_size = cgbase(ncg - 1) + N
 *	ffsedit image size N		fs_size = N
 *	ffsedit image db INO N		di_db[0] of inode INO = N
 *	ffsedit image nlink INO N	di_nlink of inode INO = N
 *	ffsedit image mode INO N	di_mode of inode INO = N (0 prefix: octal)
 *	ffsedit image getdb INO		print di_db[0] of inode INO
 *	ffsedit image sbncg N		fs_ncg = N in the primary super block only
 *	ffsedit image unclean		clear fs_clean in the primary super block
 *
 * fs_size is written to the primary and all alternate super blocks,
 * as resize_ffs does when it grows a file system.
 */

#include <sys/param.h>
#include <sys/time.h>

#include <ufs/ufs/dinode.h>
#include <ufs/ffs/fs.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static union {
	struct fs fs;
	char buf[SBLOCKSIZE];
} u;
static struct fs *fs = &u.fs;

static off_t sbloc;

static void
usage(void)
{
	fprintf(stderr, "usage: ffsedit image info | tail n | size n | "
	    "db ino n | nlink ino n | mode ino n |\n"
	    "\tgetdb ino | sbncg n | unclean\n");
	exit(1);
}

static long long
num(const char *s)
{
	long long n;
	char *ep;

	errno = 0;
	n = strtoll(s, &ep, 0);
	if (*s == '\0' || *ep != '\0' || n < 0 || errno == ERANGE)
		errx(1, "%s: invalid number", s);
	return (n);
}

static void
readsb(int fd)
{
	static const off_t try[] = { SBLOCK_UFS2, SBLOCK_UFS1 };
	size_t i;

	for (i = 0; i < nitems(try); i++) {
		if (pread(fd, u.buf, SBLOCKSIZE, try[i]) != SBLOCKSIZE)
			err(1, "pread super block");
		if ((fs->fs_magic == FS_UFS2_MAGIC &&
		    fs->fs_sblockloc == try[i]) ||
		    (fs->fs_magic == FS_UFS1_MAGIC && try[i] == SBLOCK_UFS1)) {
			sbloc = try[i];
			return;
		}
	}
	errx(1, "no super block");
}

static void
setsize(int fd, int64_t size)
{
	u_int32_t c;

	fs->fs_size = size;
	if (fs->fs_magic == FS_UFS1_MAGIC)
		fs->fs_ffs1_size = size;
	if (pwrite(fd, u.buf, SBLOCKSIZE, sbloc) != SBLOCKSIZE)
		err(1, "pwrite super block");
	/* Like resize_ffs, update the alternates too. */
	for (c = 0; c < fs->fs_ncg; c++)
		if (pwrite(fd, u.buf, fs->fs_sbsize,
		    (off_t)cgsblock(fs, c) * fs->fs_fsize) != fs->fs_sbsize)
			err(1, "pwrite alternate super block %u", c);
}

/*
 * Set field (db, nlink or mode) of inode ino to val, or print di_db[0]
 * for getdb.
 */
static void
setino(int fd, ino_t ino, const char *field, int64_t val)
{
	struct ufs1_dinode d1;
	struct ufs2_dinode d2;
	off_t off;

	off = (off_t)ino_to_fsba(fs, ino) * fs->fs_fsize;
	if (fs->fs_magic == FS_UFS1_MAGIC) {
		off += ino_to_fsbo(fs, ino) * sizeof(d1);
		if (pread(fd, &d1, sizeof(d1), off) != sizeof(d1))
			err(1, "pread inode");
		if (strcmp(field, "getdb") == 0) {
			printf("%lld\n", (long long)d1.di_db[0]);
			return;
		} else if (strcmp(field, "db") == 0)
			d1.di_db[0] = val;
		else if (strcmp(field, "mode") == 0)
			d1.di_mode = val;
		else
			d1.di_nlink = val;
		if (pwrite(fd, &d1, sizeof(d1), off) != sizeof(d1))
			err(1, "pwrite inode");
	} else {
		off += ino_to_fsbo(fs, ino) * sizeof(d2);
		if (pread(fd, &d2, sizeof(d2), off) != sizeof(d2))
			err(1, "pread inode");
		if (strcmp(field, "getdb") == 0) {
			printf("%lld\n", (long long)d2.di_db[0]);
			return;
		} else if (strcmp(field, "db") == 0)
			d2.di_db[0] = val;
		else if (strcmp(field, "mode") == 0)
			d2.di_mode = val;
		else
			d2.di_nlink = val;
		if (pwrite(fd, &d2, sizeof(d2), off) != sizeof(d2))
			err(1, "pwrite inode");
	}
}

int
main(int argc, char *argv[])
{
	int64_t size;
	u_int32_t last;
	int fd;

	if (argc < 3)
		usage();
	if ((fd = open(argv[1], O_RDWR)) == -1)
		err(1, "%s", argv[1]);
	readsb(fd);
	size = fs->fs_magic == FS_UFS1_MAGIC ? fs->fs_ffs1_size : fs->fs_size;
	last = fs->fs_ncg - 1;

	if (strcmp(argv[2], "info") == 0 && argc == 3) {
		printf("magic %s ncg %u fpg %d frag %d fsize %d size %lld "
		    "lastcgbase %lld lastcgimin %lld lastcgdmin %lld\n",
		    fs->fs_magic == FS_UFS1_MAGIC ? "FFS1" : "FFS2",
		    fs->fs_ncg, fs->fs_fpg, fs->fs_frag, fs->fs_fsize,
		    (long long)size,
		    (long long)cgbase(fs, last), (long long)cgimin(fs, last),
		    (long long)cgdmin(fs, last));
	} else if (strcmp(argv[2], "tail") == 0 && argc == 4) {
		setsize(fd, cgbase(fs, last) + num(argv[3]));
	} else if (strcmp(argv[2], "size") == 0 && argc == 4) {
		setsize(fd, num(argv[3]));
	} else if ((strcmp(argv[2], "db") == 0 ||
	    strcmp(argv[2], "nlink") == 0 ||
	    strcmp(argv[2], "mode") == 0) && argc == 5) {
		setino(fd, num(argv[3]), argv[2], num(argv[4]));
	} else if (strcmp(argv[2], "getdb") == 0 && argc == 4) {
		setino(fd, num(argv[3]), argv[2], 0);
	} else if (strcmp(argv[2], "sbncg") == 0 && argc == 4) {
		/* Primary only: the alternates keep the real value. */
		fs->fs_ncg = num(argv[3]);
		if (pwrite(fd, u.buf, SBLOCKSIZE, sbloc) != SBLOCKSIZE)
			err(1, "pwrite super block");
	} else if (strcmp(argv[2], "unclean") == 0 && argc == 3) {
		fs->fs_clean = 0;
		if (pwrite(fd, u.buf, SBLOCKSIZE, sbloc) != SBLOCKSIZE)
			err(1, "pwrite super block");
	} else
		usage();
	close(fd);
	return (0);
}
