/*	$OpenBSD: scan_ffs.c,v 1.23 2019/06/28 13:32:46 deraadt Exp $	*/

/*
 * Copyright (c) 1998 Niklas Hallqvist, Tobias Weingartner
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <ufs/ffs/fs.h>

#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <util.h>

#define SBCOUNT 64		/* XXX - Should be configurable */
#define SBCHUNK (SBCOUNT * SBSIZE)
#define SBCHUNKBLKS (SBCHUNK / DEV_BSIZE)

/* Flags to control ourselves... */
#define FLAG_VERBOSE		1
#define FLAG_SMART		2
#define FLAG_LABELS		4

static int found_partition(struct fs *, int, int64_t, daddr_t, char *, time_t,
    daddr_t *, int *);
static void scanbuf(u_int8_t *, daddr_t *, daddr_t *);
static int ufsscan(int, daddr_t, daddr_t);
static void usage(void);

static int flags = 0;

static int
ufsscan(int fd, daddr_t beg, daddr_t end)
{
	/* Allocate with an overlap, so we can scan over the SBCHUNK border */
	static u_int8_t buf[SBCHUNK + SBSIZE - DEV_BSIZE];
	daddr_t blk, lastblk = -1;

	for (blk = beg; blk <= (end < 0 ? blk : end); blk += SBCHUNKBLKS) {
		memset(buf, 0, sizeof buf);
		if (lseek(fd, (off_t)blk * DEV_BSIZE, SEEK_SET) == -1)
			err(1, "lseek");
		if (read(fd, buf, sizeof buf) == -1)
			err(1, "read");
		scanbuf(buf, &blk, &lastblk);
	}
	return(0);
}

static void
scanbuf(u_int8_t *buf, daddr_t *chunk, daddr_t *lastblk)
{       
	static char lastmount[MAXMNTLEN];
	struct fs *sb;
	daddr_t sblock, sbdiff, blk = *chunk;
	int n;
	int64_t fs_size;
	time_t time;
	int version, bailout = 0;

	for (n = 0; !bailout && n < SBCHUNKBLKS; n++, blk++) {
       		sb = (struct fs *)(&buf[n * DEV_BSIZE]);
		switch (sb->fs_magic) {
		case FS_UFS1_MAGIC:
			fs_size = sb->fs_ffs1_size;
			sblock = SBLOCK_UFS1 / DEV_BSIZE;
			time = sb->fs_ffs1_time;
			version = 1;
			break;
		case FS_UFS2_MAGIC:
			fs_size = sb->fs_size;
			sblock = SBLOCK_UFS2 / DEV_BSIZE;
			time = sb->fs_time;
			version = 2;
			break;
		default:
			continue;
		}
		/* Compute the offset between the main SB and the first alternate. */
		sbdiff = fsbtodb(sb, cgsblock(sb, 0)) - sblock;
		if (flags & FLAG_VERBOSE)
			printf("block %lld version %d id %x,%x size %lld "
			    "fsize %d\n",
			    (long long)blk, version, sb->fs_id[0], sb->fs_id[1],
			    (long long)fs_size, sb->fs_fsize);
		/*
		 * Use the distance between the main SB and the 1st alternate as
		 * a hueristic for having found the start of a partition.
		 */
		if (*lastblk != -1 && blk - *lastblk == sbdiff)
			bailout = found_partition(sb, version, fs_size,
			    *lastblk - sblock, lastmount, time, chunk, &n);

		/* Update last potential SB seen. */
		*lastblk = blk;
		memcpy(lastmount, sb->fs_fsmnt, MAXMNTLEN);
	}
}

/*
 * Report a potential partition, and optionally compute a block where
 * to continue scanning.  Return 1 if this block will be outside the
 * currently scanned buffer, 0 otherwise.
 */
static int
found_partition(struct fs *sb, int version, int64_t fs_size, daddr_t offset,
    char *lastmount, time_t time, daddr_t *chunk, int *n)
{
	if (flags & FLAG_LABELS ) {
		printf("X: %lld %lld 4.2BSD %d %d %d # %s\n",
		       (long long)fsbtodb(sb, fs_size),
		       (long long)offset, sb->fs_fsize, sb->fs_bsize,
		       sb->fs_cpg, lastmount);
	} else {
		printf("ffs%d at %lld size %lld mount %s time %s",
		       version, (long long)offset,
		       (long long)(fs_size * sb->fs_fsize),
		       lastmount, ctime(&time));
	}

	if (flags & FLAG_SMART) {
		daddr_t nextblk = offset + fsbtodb(sb, fs_size);
		if (flags & FLAG_VERBOSE)
			printf("skipping to %lld\n", (long long)nextblk);
		if (nextblk - *chunk < SBCHUNKBLKS) {
			*n = (int)(nextblk - *chunk - 1);
		} else {
			*chunk = nextblk - SBCHUNKBLKS;
			return(1);
		}
	}
	return(0);
}

static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-lsv] [-b begin] [-e end] device\n",
	    __progname);
	exit(1);
}


int
main(int argc, char *argv[])
{
	int ch, fd;
	daddr_t beg = 0, end = -1;
	const char *errstr;

	if (pledge("stdio rpath disklabel", NULL) == -1)
		err(1, "pledge");

	while ((ch = getopt(argc, argv, "lsvb:e:")) != -1)
		switch(ch) {
		case 'b':
			beg = strtonum(optarg, 0, LLONG_MAX, &errstr);
			if (errstr)
				errx(1, "%s: %s", optarg, errstr);
			break;
		case 'e':
			end = strtonum(optarg, 0, LLONG_MAX, &errstr);
			if (errstr)
				errx(1, "%s: %s", optarg, errstr);
			break;
		case 'v':
			flags |= FLAG_VERBOSE;
			break;
		case 's':
			flags |= FLAG_SMART;
			break;
		case 'l':
			flags |= FLAG_LABELS;
			break;
		default:
			usage();
			/* NOTREACHED */
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	fd = opendev(argv[0], O_RDONLY, OPENDEV_PART, NULL);
	if (fd == -1)
		err(1, "%s", argv[0]);

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	return (ufsscan(fd, beg, end));
}
