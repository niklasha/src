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
 * mount_vio9p -- mount(8) helper for the in-kernel vio9p 9P2000.L guest VFS
 * client.
 *
 * Unlike mount_tmpfs, the first non-option argument is a 9P mount tag
 * (matched against the vio9p(4) device's exported tag), NOT a path: it
 * is never resolved with realpath().  Only the mountpoint is adjusted.
 * The helper does not open a device fd; the kernel vio9p driver already
 * owns the device.
 *
 * The mount defaults to read-only (MNT_RDONLY set before getmntopts); an
 * explicit `-o rw` clears MNT_RDONLY (MOPT_STDOPTS handles the ro/rw keywords)
 * and is reported to the kernel via args.va_rw.  The HOST viofs server remains
 * the authority on whether the share is actually writable.
 */

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>


#include <err.h>
#include <errno.h>
#include <limits.h>
#include <mntopts.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* --------------------------------------------------------------------- */

static const struct mntopt mopts[] = {
	MOPT_STDOPTS,
	{ NULL },
};

/* --------------------------------------------------------------------- */

static void	usage(void) __dead;
static int	a_num(const char *, const char *);
static void	pathadj(const char *, char *);

/* --------------------------------------------------------------------- */

int
main(int argc, char *argv[])
{
	struct vio9p_args args;
	char canon_dir[PATH_MAX];
	int ch, mntflags, unit;

	memset(&args, 0, sizeof(args));
	args.va_version = VIO9P_ARGS_VERSION;
	args.va_rdonly = 1;
	args.va_rw = 0;
	mntflags = MNT_RDONLY;			/* RO unless -o rw clears it */
	unit = 0;

	while ((ch = getopt(argc, argv, "o:u:")) != -1) {
		switch (ch) {
		case 'o':
			getmntopts(optarg, mopts, &mntflags);
			break;

		case 'u':
			unit = a_num(optarg, "unit");
			break;

		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2)
		usage();

	/* argv[0] is a 9P tag, not a path: do not realpath it. */
	if (strlcpy(args.va_tag, argv[0], sizeof(args.va_tag)) >=
	    sizeof(args.va_tag))
		errx(1, "tag too long: %s", argv[0]);
	args.va_unit = unit;

	pathadj(argv[1], canon_dir);

	/*
	 * Default read-only.  `-o rw` cleared MNT_RDONLY via MOPT_STDOPTS;
	 * honor that and tell the kernel via va_rw.  The host server still
	 * enforces whether the share is actually writable.
	 */
	if (mntflags & MNT_RDONLY) {
		args.va_rw = 0;
		args.va_rdonly = 1;
	} else {
		args.va_rw = 1;
		args.va_rdonly = 0;
	}

	if (mount(MOUNT_VIO9P, canon_dir, mntflags, &args) == -1)
		err(1, "%s on %s", args.va_tag, canon_dir);

	return (0);
}

/* --------------------------------------------------------------------- */

static void
usage(void)
{
	extern char *__progname;

	(void)fprintf(stderr,
	    "usage: %s [-o options] [-u unit] tag mount_point\n"
	    "       (default read-only; use -o rw for a writable mount)\n",
	    __progname);
	exit(1);
}

static int
a_num(const char *s, const char *id_type)
{
	int id;
	char *ep;

	id = strtol(s, &ep, 0);
	if (*ep || s == ep || id < 0)
		errx(1, "unknown %s: %s", id_type, s);
	return (id);
}

static void
pathadj(const char *input, char *adjusted)
{

	if (realpath(input, adjusted) == NULL)
		err(1, "realpath %s", input);
	if (strncmp(input, adjusted, PATH_MAX)) {
		warnx("\"%s\" is a relative path.", input);
		warnx("using \"%s\" instead.", adjusted);
	}
}
