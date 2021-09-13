/* $OpenBSD: fusebuf.c,v 1.18 2021/03/11 13:31:35 jsg Exp $ */
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
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/pool.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/fuse_kernel.h>

#include "fusebuf.h"
#include "fusefs_node.h"
#include "fusefs.h"

struct fusebuf *
fb_setup(size_t len, ino_t ino, int op, struct proc *p)
{
	struct fusebuf *fbuf;

	KASSERT(len <= FUSEBUFMAXSIZE);

	fbuf = pool_get(&fusefs_fbuf_pool, PR_WAITOK | PR_ZERO);

	fbuf->op_in_len = 0;
	fbuf->op_out_len = 0;
	fbuf->op_out_buf = 0;
	switch(op) {
		case FUSE_GETATTR:
			fbuf->op_in_len = sizeof(struct fuse_getattr_in);
			fbuf->op_out_len = sizeof(struct fuse_attr_out);
			break;
		case FUSE_SETATTR:
			fbuf->op_in_len = sizeof(struct fuse_setattr_in);
			fbuf->op_out_len = sizeof(struct fuse_attr_out);
			break;
		case FUSE_READLINK:
			fbuf->op_out_buf = 1;
			break;
		case FUSE_FLUSH:
			fbuf->op_in_len = sizeof(struct fuse_flush_in);
			break;
		case FUSE_INIT:
			fbuf->op_in_len = sizeof(struct fuse_init_in);
			fbuf->op_out_len = sizeof(struct fuse_init_out);
			break;
		case FUSE_OPEN:
		case FUSE_OPENDIR:
			fbuf->op_in_len = sizeof(struct fuse_open_in);
			fbuf->op_out_len = sizeof(struct fuse_open_out);
			break;
		case FUSE_READ:
		case FUSE_READDIR:
			fbuf->op_in_len = sizeof(struct fuse_read_in);
			fbuf->op_out_buf = 1;
			break;
		case FUSE_MKDIR:
			fbuf->op_in_len = sizeof(struct fuse_mkdir_in);
			fbuf->op_out_len = sizeof(struct fuse_entry_out);
			break;
		case FUSE_MKNOD:
			fbuf->op_in_len = sizeof(struct fuse_mknod_in);
			fbuf->op_out_len = sizeof(struct fuse_entry_out);
			break;
		case FUSE_FSYNC:
			fbuf->op_in_len = sizeof(struct fuse_fsync_in);
			break;
		case FUSE_RENAME:
			fbuf->op_in_len = sizeof(struct fuse_rename_in);
			break;
		case FUSE_LINK:
			fbuf->op_in_len = sizeof(struct fuse_link_in);
			fbuf->op_out_len = sizeof(struct fuse_entry_out);
			break;
		case FUSE_SYMLINK:
			fbuf->op_out_len = sizeof(struct fuse_entry_out);
			break;
		case FUSE_RELEASE:
		case FUSE_RELEASEDIR:
			fbuf->op_in_len = sizeof(struct fuse_release_in);
			break;
		case FUSE_WRITE:
			fbuf->op_in_len = sizeof(struct fuse_write_in);
			fbuf->op_out_len = sizeof(struct fuse_write_out);
			break;
		case FUSE_ACCESS:
			fbuf->op_in_len = sizeof(struct fuse_access_in);
			break;
		case FUSE_FORGET:
			fbuf->op_in_len = sizeof(struct fuse_forget_in);
			break;
		case FUSE_LOOKUP:
			fbuf->op_out_len = sizeof(struct fuse_entry_out);
			break;
		case FUSE_STATFS:
			fbuf->op_out_len = sizeof(struct fuse_statfs_out);
			break;
	}
	fbuf->hdr.len = sizeof(fbuf->hdr) + fbuf->op_in_len + len;
	fbuf->fb_len = len;
	fbuf->fb_err = 0;
	arc4random_buf(&fbuf->fb_uuid, sizeof fbuf->fb_uuid);
	fbuf->fb_type = op;
	fbuf->fb_ino = ino;
	/*
	 * When exposed to userspace, thread IDs have THREAD_PID_OFFSET added
	 * to keep them from overlapping the PID range.
	 */
	fbuf->fb_tid = p->p_tid + THREAD_PID_OFFSET;
	fbuf->fb_uid = p->p_ucred->cr_uid;
	fbuf->fb_gid = p->p_ucred->cr_gid;
	if (len == 0)
		fbuf->fb_dat = NULL;
	else
		fbuf->fb_dat = (uint8_t *)malloc(len, M_FUSEFS,
		    M_WAITOK | M_ZERO);

	return (fbuf);
}

/*
 * Puts the fbuf on the queue and waits for the file system to process
 * it. The current process will block indefinitely and cannot be
 * interrupted or killed. This is consistent with how VFS system calls
 * should behave. nfs supports the -ointr or -i mount option and FUSE
 * can too but this is non-trivial. The file system daemon must be
 * multi-threaded and also support being interrupted. Note that
 * libfuse currently only supports single-threaded daemons.
 *
 * Why not timeout similar to mount_nfs -osoft?
 * It introduces another point of failure and a possible mount option
 * (to specify the timeout) that users need to understand and tune to
 * avoid premature timeouts for slow file systems. More complexity,
 * less reliability.
 *
 * In the case where the daemon has become unresponsive the daemon
 * will have to be killed in order for the current process to
 * wakeup. The FUSE device is automatically closed when the daemon
 * terminates and any waiting fbuf is woken up.
 */
int
fb_queue(dev_t dev, struct fusebuf *fbuf)
{
	fuse_device_queue_fbuf(dev, fbuf);
	tsleep_nsec(fbuf, PWAIT, "fbwrite", INFSLP);

	return -(fbuf->fb_err);
}

void
fb_delete(struct fusebuf *fbuf)
{
	if (fbuf != NULL) {
		free(fbuf->fb_dat, M_FUSEFS, fbuf->fb_len);
		pool_put(&fusefs_fbuf_pool, fbuf);
	}
}
