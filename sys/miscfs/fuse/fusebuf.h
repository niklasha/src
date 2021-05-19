/* $OpenBSD: fusebuf.h,v 1.13 2018/06/19 11:27:54 helg Exp $ */
/*
 * Copyright (c) 2013 Sylvestre Gallon
 * Copyright (c) 2013 Martin Pieuchot
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

#ifndef _SYS_FUSEBUF_H_
#define _SYS_FUSEBUF_H_

#include <sys/fuse_kernel.h>

/*
 * Fusebufs vary in size depending on the operation up to a maximum sane
 * size for the data used in read, readdir, write etc.
 */
#define	FUSEBUF_INSIZE(fbuf) \
    (sizeof(struct fuse_in_header) + (fbuf)->op_in_len + (fbuf)->dat_len)
#define	FUSEBUF_OUTSIZE(fbuf) \
    (sizeof(struct fuse_out_header) + (fbuf)->op_out_len + \
    ((fbuf)->op_out_buf ? (fbuf)->dat_len : 0))
/*
 * Maximum size for fb_dat.
 */
#define FUSEBUFMAXSIZE	(4096*1024)

/*
 * An operation is issued by the kernel through fuse(4) when the
 * userland file system needs to execute an action (mkdir(2),
 * link(2), etc).
 *
 * When the userland file system answers to this operation it uses
 * the same ID (fb_uuid).
 */
struct fusebuf {
	SIMPLEQ_ENTRY(fusebuf)	next;		/* next buffer in chain */
	int32_t			error;		/* error returned by daemon */
	struct fuse_in_header	hdr;
	size_t			op_in_len;	/* size of input */
	size_t			op_out_len;	/* size of output */
	uint8_t			op_out_buf;	/* whether to expect data */
	union {
		union {
			struct fuse_forget_in	forget;
			struct fuse_getattr_in	getattr;
			struct fuse_setattr_in	setattr;
			struct fuse_mknod_in	mknod;
			struct fuse_mkdir_in	mkdir;
			struct fuse_rename_in	rename;
			struct fuse_link_in	link;
			struct fuse_open_in	open;
			struct fuse_read_in	read;
			struct fuse_write_in	write;
			struct fuse_release_in	release;
			struct fuse_fsync_in	fsync;
			struct fuse_flush_in	flush;
			struct fuse_init_in	init;
			struct fuse_access_in	access;
		} in;
		union {
			struct fuse_entry_out	entry;
			struct fuse_attr_out	attr;
			struct fuse_open_out	open;
			struct fuse_write_out	write;
			struct fuse_statfs_out	statfs;
			struct fuse_init_out	init;
		} out;
	} op;
	uint64_t dat_len;
	uint8_t *dat;
};

#define fb_dat		dat
#define fb_next		next
#define fb_err		error
#define fb_len		dat_len
#define fb_type		hdr.opcode
#define fb_uuid		hdr.unique
#define fb_ino		hdr.nodeid
#define fb_tid		hdr.pid
#define fb_uid		hdr.uid
#define fb_gid		hdr.gid

/* fusebuf prototypes */
struct	fusebuf *fb_setup(size_t, ino_t, int, struct proc *);
int	fb_queue(dev_t, struct fusebuf *);
void	fb_delete(struct fusebuf *);

#endif /* _SYS_FUSEBUF_H_ */
