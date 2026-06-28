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
/* ---- M3 read-write message types (mirror the host p9_* write handlers) ---- */
#define P9_TLCREATE	14
#define P9_RLCREATE	15
#define P9_TSYMLINK	16
#define P9_RSYMLINK	17
#define P9_TRENAME	20
#define P9_RRENAME	21
#define P9_TSETATTR	26
#define P9_RSETATTR	27
#define P9_TLINK	70
#define P9_RLINK	71
#define P9_TMKDIR	72
#define P9_RMKDIR	73
#define P9_TRENAMEAT	74
#define P9_RRENAMEAT	75
#define P9_TUNLINKAT	76
#define P9_RUNLINKAT	77
#define P9_TWRITE	118
#define P9_RWRITE	119

#define P9_HDRLEN	7		/* size[4] type[1] tag[2] */
#define P9_NOFID	0xffffffffU
#define P9_NOTAG	0xffff
#define P9_MAXWELEM	16
#define P9_READ_IOHDRSZ	(P9_HDRLEN + 4)	/* Tread req hdr: +offset? no: count fits in 11 */
/*
 * Twrite carries fid[4] offset[8] count[4] BEFORE the data, so its per-message
 * header is larger than Tread's.  The writable payload per Twrite is therefore
 * msize - P9_WRITE_IOHDRSZ (23), which is SMALLER than the read budget
 * (msize - 11).  vio9p_write MUST size its chunks by this, else it asks
 * p9c_write for more than fits, p9c_write silently clamps, and the vop
 * mis-reads the clamp as a short server write -> a short VOP_WRITE that
 * single-write callers (cp's mmap copy) treat as a hard error.
 */
#define P9_WRITE_IOHDRSZ (P9_HDRLEN + 4 + 8 + 4)	/* hdr+fid+offset+count = 23 */
#define P9_READDIR_FIXED 24		/* qid13 off8 type1 namelen2 */

#define P9_QTDIR	0x80
#define P9_QTSYMLINK	0x02
#define P9_QTFILE	0x00

#define P9_GETATTR_BASIC 0x000007ffULL	/* request_mask a RO server fills */

/* ---- Linux open flags for Tlopen/Tlcreate (mirror viofs.c:156-161) ----
 * HARDCODED Linux numbers -- NEVER from the host <fcntl.h>, which differs.
 */
#define L_O_RDONLY	0		/* Linux O_RDONLY */
#define L_O_WRONLY	01		/* Linux O_WRONLY */
#define L_O_RDWR	02		/* Linux O_RDWR */
#define L_O_CREAT	0100		/* Linux O_CREAT */
#define L_O_EXCL	0200		/* Linux O_EXCL */
#define L_O_TRUNC	01000		/* Linux O_TRUNC */
#define L_O_APPEND	02000		/* Linux O_APPEND */

/* Tsetattr valid[4] bits (9P2000.L canonical). */
#define P9_SETATTR_MODE		0x00000001U
#define P9_SETATTR_UID		0x00000002U
#define P9_SETATTR_GID		0x00000004U
#define P9_SETATTR_SIZE		0x00000008U
#define P9_SETATTR_ATIME	0x00000010U
#define P9_SETATTR_MTIME	0x00000020U
#define P9_SETATTR_CTIME	0x00000040U
#define P9_SETATTR_ATIME_SET	0x00000080U
#define P9_SETATTR_MTIME_SET	0x00000100U

/* Tunlinkat flags[4]: Linux AT_REMOVEDIR (rmdir vs unlink). */
#define P9_AT_REMOVEDIR		0x200

#define VIO9P_VERSION_STR "9P2000.L"
/*
 * M3b: the appli extended dialect.  When BOTH ends agree on this version string
 * in the Tversion/Rversion exchange, every T-message EXCEPT Tversion carries,
 * immediately after the 7-byte header (size[4] type[1] tag[2]) and BEFORE the
 * type-specific body, the caller identity as two little-endian uint32 fields:
 * uid[4] then gid[4].  R-messages never carry it; Tversion never carries it (it
 * is sent before negotiation).  size[4] (the whole message length) includes the
 * 8 prefix bytes automatically because it is computed from the encoder length.
 * When the server is plain "9P2000.L" the prefix is NOT emitted and behavior is
 * byte-identical to M3 (squash).
 */
#define VIO9P_VERSION_EXT "9P2000.L.appli"
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
	uint32_t		 vm_iomax;	/* read budget:  msize - 11 */
	uint32_t		 vm_womax;	/* write budget: msize - 23 */
	uint64_t		 vm_rootpath;	/* root qid.path (VROOT test) */
	int			 vm_rdonly;	/* legacy; see vm_rw */
	int			 vm_rw;		/* M3: write ops permitted */
	gid_t			 vm_owner_gid;	/* squash gid for create/mkdir */
	/*
	 * M3b: the mount owner identity, captured from the mounting process's
	 * cred at mount time.  This is the SENTINEL uid/gid threaded into every
	 * cred-less p9c_* wrapper (version, attach, statfs-at-mount, the
	 * reclaim/redundant clunk) so the extended uid/gid prefix is always a
	 * coherent identity; under squash the host ignores it.  vm_owner_gid is
	 * the gid half (kept for the create/mkdir gid argument too).
	 */
	uid_t			 vm_owner_uid;	/* sentinel uid (mount owner) */
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
	uint8_t			 n_fid_write;	/* fid opened RDWR (vs RDONLY)? */
	uint64_t		 n_dir_off;	/* readdir cookie */
	off_t			 n_size;
	struct rrwlock		 n_lock;
};
#define VTON(vp)	((struct vio9p_node *)(vp)->v_data)

/*
 * ---- 9P client API (vio9p_client.c) ----
 *
 * M3b: every wrapper takes a trailing (uint32_t uid, uint32_t gid) caller
 * identity.  When the extended dialect is negotiated (sc->sc_extended), p9c_rpc
 * threads it into p9c_enc_start, which emits it as the uid[4] gid[4] prefix on
 * every T-message except Tversion; when it is NOT negotiated the identity is
 * ignored and no prefix is emitted (byte-identical to M3).  User-issued VOPs
 * pass cred->cr_uid/cr_gid; cred-less wrappers (version, attach, the
 * reclaim/redundant clunk, statfs at mount) pass the mount-owner sentinel
 * (vm_owner_uid/vm_owner_gid).  p9c_version is special: it is sent BEFORE
 * negotiation so it never emits the prefix, but it still takes the sentinel for
 * signature uniformity.
 */
int	p9c_version(struct vio9p_softc *, uint32_t, uint32_t);
int	p9c_attach(struct vio9p_softc *, uint32_t, uint32_t, uint32_t,
	    struct p9_qid *);
int	p9c_clunk(struct vio9p_softc *, uint32_t, uint32_t, uint32_t);
int	p9c_getattr(struct vio9p_softc *, uint32_t, uint32_t, uint32_t,
	    struct p9_attr *);
int	p9c_statfs(struct vio9p_softc *, uint32_t, uint32_t, uint32_t,
	    struct p9_statfs *);
int	p9c_errno(uint32_t);

/* M2c: the file-I/O ops */
int	p9c_walk(struct vio9p_softc *, uint32_t, uint32_t, const char *,
	    uint32_t, uint32_t, struct p9_qid *, int *);
int	p9c_lopen(struct vio9p_softc *, uint32_t, uint32_t, uint32_t, uint32_t,
	    uint32_t *);
int	p9c_read(struct vio9p_softc *, uint32_t, uint64_t, void *, uint32_t,
	    uint32_t, uint32_t, uint32_t *);
int	p9c_readdir(struct vio9p_softc *, uint32_t, uint64_t, void *, uint32_t,
	    uint32_t, uint32_t, uint32_t *);
int	p9c_readlink(struct vio9p_softc *, uint32_t, uint32_t, uint32_t, char *,
	    size_t, size_t *);

/* M3: the write/mutate ops (mirror the host p9_* write handlers) */
int	p9c_write(struct vio9p_softc *, uint32_t, uint64_t, const void *,
	    uint32_t, uint32_t, uint32_t, uint32_t *);
int	p9c_lcreate(struct vio9p_softc *, uint32_t, const char *, uint32_t,
	    uint32_t, uint32_t, uint32_t, uint32_t, struct p9_qid *, uint32_t *);
int	p9c_mkdir(struct vio9p_softc *, uint32_t, const char *, uint32_t,
	    uint32_t, uint32_t, uint32_t, struct p9_qid *);
int	p9c_unlinkat(struct vio9p_softc *, uint32_t, const char *, uint32_t,
	    uint32_t, uint32_t);
int	p9c_setattr(struct vio9p_softc *, uint32_t, uint32_t, uint32_t,
	    uint32_t, uint32_t, uint64_t, int64_t, int64_t, int64_t, int64_t,
	    uint32_t, uint32_t);
int	p9c_renameat(struct vio9p_softc *, uint32_t, const char *, uint32_t,
	    const char *, uint32_t, uint32_t);
int	p9c_symlink(struct vio9p_softc *, uint32_t, const char *,
	    const char *, uint32_t, uint32_t, uint32_t, struct p9_qid *);
int	p9c_link(struct vio9p_softc *, uint32_t, uint32_t, const char *,
	    uint32_t, uint32_t);

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
