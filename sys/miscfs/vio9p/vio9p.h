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
 * vio9p in-kernel 9P2000.L guest VFS client.  Shared types/constants for the
 * VFS (vfsops/vnops/node), the 9P client (p9c_*), and the mount(2) helper.
 * Mirrors the host server's wire contract (usr.sbin/vmd/viofs.c).
 */

#ifndef _MISCFS_VIO9P_VIO9P_H_
#define _MISCFS_VIO9P_VIO9P_H_

/*
 * struct vio9p_args + VIO9P_ARGS_VERSION live in <sys/mount.h>, beside the
 * other per-filesystem mount-args structs (the mount(2) helper and vfs_init.c
 * both see them via <sys/mount.h>).
 */

#ifdef _KERNEL

/* ---- 9P2000.L message types (viofs.c:65-88) ---- */
#define P9_RLERROR	7
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

#define P9_HDRLEN	7		/* size[4] type[1] tag[2] */
#define P9_NOFID	0xffffffffU
#define P9_NOTAG	0xffff
#define P9_MAXWELEM	16
#define P9_READ_IOHDRSZ	(P9_HDRLEN + 4)	/* Rread/Rreaddir hdr = 11 */
#define P9_READDIR_FIXED 24		/* qid13 off8 type1 namelen2 */

#define P9_QTDIR	0x80
#define P9_QTSYMLINK	0x02
#define P9_QTFILE	0x00

#define P9_GETATTR_BASIC 0x000007ffULL	/* request_mask a RO server fills */
#define L_O_RDONLY	0		/* Linux O_RDONLY for Tlopen */

#define VIO9P_VERSION_STR "9P2000.L"
#define VIO9P_FID_ROOT	0		/* attach-root fid */
#define VIO9P_MAX_FIDS	1024		/* = VIOFS_MAX_FIDS (viofs.c:171) */
#define VIO9P_NOFID	0xffffffffU
#define VIO9P_ROOTINO	((ino_t)1)

struct p9_qid {
	uint8_t		type;
	uint32_t	version;
	uint64_t	path;
};

/* Subset of Rgetattr we consume (P9_GETATTR_BASIC). */
struct p9_attr {
	struct p9_qid	qid;
	uint32_t	mode;
	uint32_t	uid;
	uint32_t	gid;
	uint64_t	nlink;
	uint64_t	rdev;
	uint64_t	size;
	uint64_t	blksize;
	uint64_t	blocks;
	int64_t		atime_sec;
	int64_t		mtime_sec;
	int64_t		ctime_sec;
	uint32_t	atime_nsec;
	uint32_t	mtime_nsec;
	uint32_t	ctime_nsec;
};

struct p9_statfs {
	uint32_t	type;
	uint32_t	bsize;
	uint64_t	blocks;
	uint64_t	bfree;
	uint64_t	bavail;
	uint64_t	files;
	uint64_t	ffree;
	uint64_t	fsid;
	uint32_t	namelen;
};

struct vio9p_softc;	/* dev/pv/vio9pvar.h */
struct vnode;
struct mount;

/* ---- per-mount state (mnt_data) ---- */
struct vio9p_mnt {
	struct mount		*vm_mp;
	struct vio9p_softc	*vm_sc;		/* rendezvous result */
	uint32_t		 vm_rootfid;	/* fid from Tattach */
	struct p9_qid		 vm_rootqid;
	uint32_t		 vm_msize;
	uint32_t		 vm_iomax;	/* msize - 11 */
	uint64_t		 vm_rootpath;	/* root qid.path (VROOT test) */
	int			 vm_rdonly;	/* always 1 */
};
#define VFSTOVIO9P(mp)	((struct vio9p_mnt *)((mp)->mnt_data))

/* ---- in-core inode ---- */
LIST_HEAD(vio9p_node_head, vio9p_node);
struct vio9p_node {
	LIST_ENTRY(vio9p_node)	 n_hash;	/* qid.path hash chain */
	struct vnode		*n_vnode;
	struct vio9p_mnt	*n_mnt;
	uint64_t		 n_qidpath;	/* HASH KEY = host inode id */
	uint64_t		 n_parentpath;	/* parent's qid.path (for "..") */
	uint32_t		 n_qidvers;	/* attr-cache stamp */
	uint8_t			 n_qtype;	/* P9_QT* -> v_type */
	uint32_t		 n_fid;		/* owned fid; VIO9P_NOFID=none */
	uint8_t			 n_fid_opened;	/* Tlopen issued? */
	uint64_t		 n_dir_off;	/* readdir cookie */
	off_t			 n_size;
	struct rrwlock		 n_lock;
};
#define VTON(vp)	((struct vio9p_node *)(vp)->v_data)

/* ---- 9P client API (vio9p_client.c) ---- */
int	p9c_version(struct vio9p_softc *);
int	p9c_attach(struct vio9p_softc *, uint32_t, struct p9_qid *);
int	p9c_clunk(struct vio9p_softc *, uint32_t);
int	p9c_getattr(struct vio9p_softc *, uint32_t, struct p9_attr *);
int	p9c_statfs(struct vio9p_softc *, uint32_t, struct p9_statfs *);
int	p9c_errno(uint32_t);

/* M2c: the file-I/O ops */
int	p9c_walk(struct vio9p_softc *, uint32_t, uint32_t, const char *,
	    struct p9_qid *, int *);
int	p9c_lopen(struct vio9p_softc *, uint32_t, uint32_t, uint32_t *);
int	p9c_read(struct vio9p_softc *, uint32_t, uint64_t, void *, uint32_t,
	    uint32_t *);
int	p9c_readdir(struct vio9p_softc *, uint32_t, uint64_t, void *, uint32_t,
	    uint32_t *);
int	p9c_readlink(struct vio9p_softc *, uint32_t, char *, size_t, size_t *);

/* fid pool (vio9p_node.c) */
uint32_t vio9p_fid_alloc(struct vio9p_mnt *);
void	 vio9p_fid_free(struct vio9p_mnt *, uint32_t);

/* ---- node layer (vio9p_node.c) ---- */
void	vio9p_ihashinit(void);
int	vio9p_vget(struct mount *, struct p9_qid *, uint32_t, struct vnode **);
struct vnode *vio9p_ihashget(uint64_t);
void	vio9p_ihashrem(struct vio9p_node *);

/* ---- vfsops / vnops tables ---- */
extern const struct vfsops vio9p_vfsops;
extern const struct vops vio9p_vops;

#endif /* _KERNEL */
#endif /* _MISCFS_VIO9P_VIO9P_H_ */
