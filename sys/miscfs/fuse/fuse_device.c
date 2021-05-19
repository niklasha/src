/* $OpenBSD: fuse_device.c,v 1.36 2021/03/11 13:31:35 jsg Exp $ */
/*
 * Copyright (c) 2012-2013 Sylvestre Gallon <ccna.syl@gmail.com>
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vnode.h>
#include <sys/fuse_kernel.h>

#include "fusebuf.h"
#include "fusefs_node.h"
#include "fusefs.h"

SIMPLEQ_HEAD(fusebuf_head, fusebuf);

struct fuse_d {
	struct fusefs_mnt *fd_fmp;
	int fd_unit;

	/*fusebufs queues*/
	struct fusebuf_head fd_fbufs_in;
	struct fusebuf_head fd_fbufs_wait;

	LIST_ENTRY(fuse_d) fd_list;
};

int stat_fbufs_in = 0;
int stat_fbufs_wait = 0;
int stat_opened_fusedev = 0;

LIST_HEAD(, fuse_d) fuse_d_list;
struct fuse_d *fuse_lookup(int);

void	fuseattach(int);
int	fuseopen(dev_t, int, int, struct proc *);
int	fuseclose(dev_t, int, int, struct proc *);
int	fuseioctl(dev_t, u_long, caddr_t, int, struct proc *);
int	fuseread(dev_t, struct uio *, int);
int	fusewrite(dev_t, struct uio *, int);
int	fusepoll(dev_t, int, struct proc *);
int	fusekqfilter(dev_t dev, struct knote *kn);
int	filt_fuse_read(struct knote *, long);
void	filt_fuse_rdetach(struct knote *);

struct fuse_d *
fuse_lookup(int unit)
{
	struct fuse_d *fd;

	LIST_FOREACH(fd, &fuse_d_list, fd_list)
		if (fd->fd_unit == unit)
			return (fd);
	return (NULL);
}

/*
 * Cleanup all msgs from fd_fbufs_in and fd_fbufs_wait.
 */
void
fuse_device_cleanup(dev_t dev)
{
	struct fuse_d *fd;
	struct fusebuf *f, *ftmp, *lprev;

	fd = fuse_lookup(minor(dev));
	if (fd == NULL)
		return;

	/* clear FIFO IN */
	lprev = NULL;
	SIMPLEQ_FOREACH_SAFE(f, &fd->fd_fbufs_in, fb_next, ftmp) {
		if (lprev == NULL)
			SIMPLEQ_REMOVE_HEAD(&fd->fd_fbufs_in, fb_next);
		else
			SIMPLEQ_REMOVE_AFTER(&fd->fd_fbufs_in, lprev,
			    fb_next);

		stat_fbufs_in--;
		f->fb_err = -ENXIO;
		wakeup(f);
		lprev = f;
	}

	/* clear FIFO WAIT*/
	lprev = NULL;
	SIMPLEQ_FOREACH_SAFE(f, &fd->fd_fbufs_wait, fb_next, ftmp) {
		if (lprev == NULL)
			SIMPLEQ_REMOVE_HEAD(&fd->fd_fbufs_wait, fb_next);
		else
			SIMPLEQ_REMOVE_AFTER(&fd->fd_fbufs_wait, lprev,
			    fb_next);

		stat_fbufs_wait--;
		f->fb_err = -ENXIO;
		wakeup(f);
		lprev = f;
	}
}

void
fuse_device_queue_fbuf(dev_t dev, struct fusebuf *fbuf)
{
	struct fuse_d *fd;

	fd = fuse_lookup(minor(dev));
	if (fd == NULL)
		return;

	SIMPLEQ_INSERT_TAIL(&fd->fd_fbufs_in, fbuf, fb_next);
	stat_fbufs_in++;
	wakeup_one(&fd->fd_fbufs_in);
}

void
fuse_device_set_fmp(struct fusefs_mnt *fmp, int set)
{
	struct fuse_d *fd;

	fd = fuse_lookup(minor(fmp->dev));
	if (fd == NULL)
		return;

	if (set)
		fd->fd_fmp = fmp;
	else {
		fd->fd_fmp = NULL;

		/* Let sleeping daemons know the device is dead */
		wakeup(&fd->fd_fbufs_in);
	}
}

void
fuseattach(int num)
{
	LIST_INIT(&fuse_d_list);
}

int
fuseopen(dev_t dev, int flags, int fmt, struct proc * p)
{
	struct fuse_d *fd;
	int unit = minor(dev);

	if (flags & O_EXCL)
		return (EBUSY); /* No exclusive opens */

	if ((fd = fuse_lookup(unit)) != NULL)
		return (EBUSY);

	fd = malloc(sizeof(*fd), M_DEVBUF, M_WAITOK | M_ZERO);
	fd->fd_unit = unit;
	SIMPLEQ_INIT(&fd->fd_fbufs_in);
	SIMPLEQ_INIT(&fd->fd_fbufs_wait);
	LIST_INSERT_HEAD(&fuse_d_list, fd, fd_list);

	stat_opened_fusedev++;
	return (0);
}

int
fuseclose(dev_t dev, int flags, int fmt, struct proc *p)
{
	struct fuse_d *fd;

	fd = fuse_lookup(minor(dev));
	if (fd == NULL)
		return (EINVAL);

	if (fd->fd_fmp) {
		/*
		 * Device closed without umount. This is OK but don't
		 * automatically unmount the file system since it may be
		 * unmounted later. Worst case, it can be unmounted manually
		 * with umount(2).
		 */
		fd->fd_fmp->sess_init = 0;
		fuse_device_cleanup(dev);
		fuse_device_set_fmp(fd->fd_fmp, 0);
	}

	LIST_REMOVE(fd, fd_list);
	free(fd, M_DEVBUF, sizeof(*fd));
	stat_opened_fusedev--;
	return (0);
}

int
fuseread(dev_t dev, struct uio *uio, int ioflag)
{
	struct fuse_d *fd;
	struct fusebuf *fbuf;
	int error = 0;

	fd = fuse_lookup(minor(dev));
	if (fd == NULL)
		return (ENXIO);

	if (fd->fd_fmp == NULL)
		return (ENODEV);

	/* Loop to avoid a race condition with multithreaded daemons. */
	fbuf = SIMPLEQ_FIRST(&fd->fd_fbufs_in);
	while (fbuf == NULL) {
		if (ioflag & O_NONBLOCK)
			return (EAGAIN);

		error = tsleep_nsec(&fd->fd_fbufs_in, PWAIT | PCATCH,
		    "fbread", INFSLP);

		if (fd->fd_fmp == NULL)
			return (ENODEV);

		if (error == EINTR || error == ERESTART)
			return (EINTR);

		fbuf = SIMPLEQ_FIRST(&fd->fd_fbufs_in);
	}

	/* The whole fusebuf must be read at once */
	if (uio->uio_resid < FUSEBUF_INSIZE(fbuf)) {
		printf("fuse: invalid read: %zu opcode=%d fb_len=%llu\n",
		    uio->uio_resid, fbuf->fb_type, fbuf->fb_len);
		return (EINVAL);
	}

	error = uiomove(&fbuf->hdr, sizeof(fbuf->hdr), uio);
	if (error)
		goto end;
	error = uiomove(&fbuf->op, fbuf->op_in_len, uio);
	if (error)
		goto end;
	error = uiomove(fbuf->fb_dat, fbuf->fb_len, uio);
	if (error)
		goto end;

	SIMPLEQ_REMOVE_HEAD(&fd->fd_fbufs_in, fb_next);
	stat_fbufs_in--;
	if (fbuf->fb_type == FUSE_FORGET) {
		/* FUSE_FORGET has no response */
		fb_delete(fbuf);
		goto end;
	}
	SIMPLEQ_INSERT_TAIL(&fd->fd_fbufs_wait, fbuf, fb_next);
	stat_fbufs_wait++;

end:
	return (error);
}

int
fusewrite(dev_t dev, struct uio *uio, int ioflag)
{
	struct fusebuf *lastfbuf;
	struct fuse_d *fd;
	struct fusebuf *fbuf;
	struct fuse_out_header hdr;
	int error = 0;

	fd = fuse_lookup(minor(dev));
	if (fd == NULL)
		return (ENXIO);

	if (uio->uio_resid < sizeof(hdr)) {
		printf("fuse: invalid fusebuf write\n");
		return (EINVAL);
	}

	/* Read the header */
	if ((error = uiomove(&hdr, sizeof(hdr), uio)) != 0)
		return (error);

	/* Validate the userland provided fbuf size */
	if (hdr.len < sizeof(hdr)) {
		printf("fuse: invalid fusebuf header length\n");
		return (EINVAL);
	}

	/*
	 * A unique value of zero means daemon is notifying us and hdr.error
	 * contains notification type. Currently unsupported.
	 */
	if (hdr.unique == 0) {
		printf("fuse: Ignoring FUSE_NOTIFY_");
		switch (hdr.error) {
			case FUSE_NOTIFY_POLL:
				printf("POLL\n");
				return (0);
			case FUSE_NOTIFY_INVAL_INODE:
				printf("INODE\n");
				return (0);
			case FUSE_NOTIFY_INVAL_ENTRY:
				printf("ENTRY\n");
				return (0);
			case FUSE_NOTIFY_STORE:
				printf("STORE\n");
				return (0);
			case FUSE_NOTIFY_RETRIEVE:
				printf("RETRIEVE\n");
				return (0);
			case FUSE_NOTIFY_DELETE:
				printf("DELETE\n");
				return (0);
			default:
				printf("?: %d\n", hdr.error);
				return (EINVAL);
		}
	}

	/* Find matching fbuf in wait list */
	SIMPLEQ_FOREACH(fbuf, &fd->fd_fbufs_wait, fb_next) {
		if (fbuf->fb_uuid == hdr.unique)
			break;

		lastfbuf = fbuf;
	}
	if (fbuf == NULL) {
		printf("fuse: cannot find fusebuf in wait list\n");
		return (EINVAL);
	}

	fbuf->fb_err = hdr.error;

	/* Don't expect output or data if there was an error */
	if (fbuf->fb_err) {
		if (uio->uio_resid > 0) {
			printf("fuse: invalid fusebuf\n");
			return (EINVAL);
		}
		goto end;
	}

	/* Calculate the length of the data buffer to expect */
	if (fbuf->op_out_buf) {
		fbuf->fb_len = hdr.len - sizeof(hdr) - fbuf->op_out_len;
		if (fbuf->fb_len > fd->fd_fmp->max_read || fbuf->fb_len < 0) {
			printf("fuse: invalid fusebuf read size: %llu "
			    "opcode=%d\n", fbuf->fb_len, fbuf->fb_type);
			return (EINVAL);
		}
	} else
		fbuf->fb_len = 0;

	/* We get the whole fusebuf or nothing */
	if (FUSEBUF_OUTSIZE(fbuf) != uio->uio_resid + sizeof(hdr)) {
		printf("fuse: invalid fusebuf size\n");
		return (EINVAL);
	}

	if ((error = uiomove(&fbuf->op, fbuf->op_out_len, uio)) != 0)
		return (error);

	if (fbuf->fb_len > 0) {
		fbuf->fb_dat = malloc(fbuf->fb_len, M_FUSEFS,
			M_WAITOK | M_ZERO);
		if ((error = uiomove(fbuf->fb_dat, fbuf->fb_len, uio)) != 0) {
			free(fbuf->fb_dat, M_FUSEFS, fbuf->fb_len);
			return (error);
		}
	}

	if (fbuf->fb_type == FUSE_INIT) {
		/*
		 * We don't support userspace with a smaller major version and
		 * it's up to userspace implementations to fall back to our
	 	 * version if they are capable of a later version.
	 	 */
		if (fbuf->op.out.init.major != FUSE_KERNEL_VERSION) {
			printf("fuse: unsupported major version: %d.%d\n",
 			    fbuf->op.out.init.major, fbuf->op.out.init.minor);
			return (EINVAL);
		}

		/*
		 * If the major versions match then both shall use the smallest
 		 * of the two minor versions for communication. 7.9 is the 
		 * smallest version less than what we support where the ABI has
		 * not changed. Supporting an earlier version would require
		 * conditional handling of some FUSE input arguments. If the 
		 * daemon supports a later version then it must fall back to
		 * ours.
		 */
		if (fbuf->op.out.init.minor < 9) {
			printf("fuse: unsupported minor version: %d.%d\n",
 			    fbuf->op.out.init.major, fbuf->op.out.init.minor);
			return (EINVAL);
		}

		/*
		 * max_write determines the size of buffer to send to the file
		 * system daemon when writing so ensure that it's sane.
		 */
		fd->fd_fmp->max_write = MIN(fbuf->op.out.init.max_write,
		    FUSEBUFMAXSIZE);
		if (fd->fd_fmp->max_write == 0)
			fd->fd_fmp->max_write = FUSEBUFMAXSIZE;

		fd->fd_fmp->sess_init = 1;
	}

end: 
	/* Remove the fbuf now that it's been successfully received */
	if (fbuf == SIMPLEQ_FIRST(&fd->fd_fbufs_wait))
		SIMPLEQ_REMOVE_HEAD(&fd->fd_fbufs_wait, fb_next);
	else
		SIMPLEQ_REMOVE_AFTER(&fd->fd_fbufs_wait, lastfbuf, fb_next);
	stat_fbufs_wait--;

	/* The kernel doesn't wait for a response to FUSE_INIT */
	if (fbuf->fb_type == FUSE_INIT)
		fb_delete(fbuf);
	else
		wakeup(fbuf);

	return (error);
}
