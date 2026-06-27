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
 * vio9p vnode operations.  Clones fuse_vnops.c / fuse_lookup.c, keeps
 * lock/unlock/islocked (rrwlock) and inactive/reclaim real, and implements the
 * full file-I/O path against the host server:
 *
 *   lookup   -- Twalk-clone a fresh per-vnode fid one component at a time
 *   open     -- lazy Tlopen of the vnode's owned fid (RDWR for a writable reg)
 *   read     -- Tread loop, chunked by msize, into the uio
 *   write    -- Twrite loop, chunked by msize, from the uio (M3)
 *   readdir  -- Treaddir cookie stream -> struct dirent (uio_offset = 9P cookie)
 *   readlink -- Treadlink, target verbatim (guest resolves; NFS model)
 *
 * M3 read-write: create/mkdir/remove/rmdir/setattr/rename/symlink/link become
 * real, each mirroring a host p9_* write handler.  The guest is mode-agnostic
 * (it stops refusing write ops on a RW mount); the HOST server still enforces
 * RO/RW and squash identity.  mknod, bmap, strategy and advlock stay refused
 * (vio9p_erofs): no device/special files, no buffer cache, no advisory locks.
 *
 * The fid/vnode lifecycle (M2_DESIGN.md section 7) is the load-bearing invariant:
 * every vnode OWNS one Twalk-cloned fid backed by its own host fd; that fid is
 * Tclunk'd in vop_reclaim and ONLY there (the unique free site), except the one
 * redundant just-walked fid that a hash-hit in vio9p_vget makes superfluous.
 * The M3 create/mkdir/symlink paths preserve this EXACTLY: they bind a fresh
 * fid via an RPC the server backs with its own host fd (Tlcreate REPLACES the
 * clone; Tmkdir/Tsymlink + a follow-up Twalk-clone), then vio9p_vget becomes
 * the sole owner -- the new node owns one fid, clunked only in its reclaim.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/dirent.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/lock.h>
#include <sys/unistd.h>
#include <sys/pool.h>			/* namei_pool, pool_put */

#include <uvm/uvm_extern.h>		/* uvm_vnp_setsize, uvm_vnp_uncache */

#include <dev/pv/vio9preg.h>
#include <dev/pv/vio9pvar.h>

#include <miscfs/vio9p/vio9p.h>

/*
 * Little-endian readers for parsing a raw Rreaddir body (the 9P wire is LE,
 * mirror viofs.c:189-229).  The client's get_le* are file-static there, so
 * vio9p_readdir carries its own; they read from a bounds-checked window
 * (pos + P9_READDIR_FIXED already verified by the caller before each access).
 */
static inline uint16_t
vio9p_le16(const uint8_t *p)
{
	return ((uint16_t)(p[0] | (p[1] << 8)));
}

static inline uint64_t
vio9p_le64(const uint8_t *p)
{
	return ((uint64_t)p[0] | ((uint64_t)p[1] << 8) |
	    ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
	    ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
	    ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56));
}

/* Prototypes for vio9p vnode ops */
int	vio9p_lookup(void *);
int	vio9p_open(void *);
int	vio9p_close(void *);
int	vio9p_access(void *);
int	vio9p_getattr(void *);
int	vio9p_read(void *);
int	vio9p_readdir(void *);
int	vio9p_readlink(void *);
int	vio9p_inactive(void *);
int	vio9p_reclaim(void *);
int	vio9p_print(void *);
int	vio9p_pathconf(void *);
int	vio9p_lock(void *);
int	vio9p_unlock(void *);
int	vio9p_islocked(void *);
int	vio9p_ioctl(void *);
int	vio9p_erofs(void *);

/* M3 read-write vops */
int	vio9p_write(void *);
int	vio9p_create(void *);
int	vio9p_mkdir(void *);
int	vio9p_remove(void *);
int	vio9p_rmdir(void *);
int	vio9p_setattr(void *);
int	vio9p_rename(void *);
int	vio9p_symlink(void *);
int	vio9p_link(void *);

/* node layer (vio9p_node.c) -- not in vio9p.h yet */

const struct vops vio9p_vops = {
	.vop_lookup	= vio9p_lookup,
	.vop_create	= vio9p_create,		/* M3 (was vio9p_erofs) */
	.vop_mknod	= vio9p_erofs,		/* refused: no device/special */
	.vop_open	= vio9p_open,
	.vop_close	= vio9p_close,
	.vop_access	= vio9p_access,
	.vop_getattr	= vio9p_getattr,
	.vop_setattr	= vio9p_setattr,	/* M3 (was vio9p_erofs) */
	.vop_read	= vio9p_read,
	.vop_write	= vio9p_write,		/* M3 (was vio9p_erofs) */
	.vop_ioctl	= vio9p_ioctl,
	.vop_kqfilter	= vio9p_erofs,
	.vop_revoke	= NULL,
	.vop_fsync	= nullop,
	.vop_remove	= vio9p_remove,		/* M3 (was vio9p_erofs) */
	.vop_link	= vio9p_link,		/* M3 (was vio9p_erofs) */
	.vop_rename	= vio9p_rename,		/* M3 (was vio9p_erofs) */
	.vop_mkdir	= vio9p_mkdir,		/* M3 (was vio9p_erofs) */
	.vop_rmdir	= vio9p_rmdir,		/* M3 (was vio9p_erofs) */
	.vop_symlink	= vio9p_symlink,	/* M3 (was vio9p_erofs) */
	.vop_readdir	= vio9p_readdir,
	.vop_readlink	= vio9p_readlink,
	.vop_abortop	= vop_generic_abortop,
	.vop_inactive	= vio9p_inactive,
	.vop_reclaim	= vio9p_reclaim,
	.vop_lock	= vio9p_lock,
	.vop_unlock	= vio9p_unlock,
	.vop_bmap	= vio9p_erofs,
	.vop_strategy	= vio9p_erofs,
	.vop_print	= vio9p_print,
	.vop_islocked	= vio9p_islocked,
	.vop_pathconf	= vio9p_pathconf,
	.vop_advlock	= vio9p_erofs,
	.vop_bwrite	= nullop,
};

/*
 * Catch-all for operations vio9p never supports (mknod, bmap, strategy,
 * advlock).  On a RO mount the host server also refuses any write flag, so the
 * real mutating ops short-circuit on !vm_rw too; this remains the wall for the
 * ops that are unsupported regardless of mode.
 */
int
vio9p_erofs(void *v)
{
	return (EROFS);
}

int
vio9p_ioctl(void *v)
{
	return (ENOTTY);
}

/*
 * vop_getattr: fetch a fresh Rgetattr for the vnode's fid and translate it to
 * a struct vattr.  The host server has already squashed creds and masked out
 * setuid/setgid/sticky (viofs.c:1060-1069); we surface those values verbatim.
 */
int
vio9p_getattr(void *v)
{
	struct vop_getattr_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct vio9p_node *np = VTON(vp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(vp->v_mount);
	struct p9_attr a;
	int error;

	error = p9c_getattr(vmp->vm_sc, np->n_fid, &a);
	if (error)
		return (error);

	/* qid.version is the advisory attr-cache stamp. */
	np->n_qidvers = a.qid.version;

	vattr_null(vap);
	vap->va_type = vp->v_type;
	vap->va_mode = a.mode & ALLPERMS;
	vap->va_nlink = a.nlink;
	vap->va_uid = a.uid;
	vap->va_gid = a.gid;
	vap->va_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];
	vap->va_fileid = a.qid.path;
	vap->va_size = a.size;
	vap->va_blocksize = vmp->vm_iomax;
	vap->va_atime.tv_sec = a.atime_sec;
	vap->va_atime.tv_nsec = a.atime_nsec;
	vap->va_mtime.tv_sec = a.mtime_sec;
	vap->va_mtime.tv_nsec = a.mtime_nsec;
	vap->va_ctime.tv_sec = a.ctime_sec;
	vap->va_ctime.tv_nsec = a.ctime_nsec;
	vap->va_rdev = a.rdev;
	vap->va_flags = 0;
	vap->va_gen = 0;
	vap->va_bytes = a.blocks * S_BLKSIZE;

	/* Keep n_size warm for diagnostics / future getpages. */
	np->n_size = (off_t)a.size;

	return (0);
}

/*
 * vop_access: enforce read-only at the mount wall, then run a plain vaccess(9)
 * against the squashed mode/uid/gid the host reports.  No owner-only policy is
 * imposed -- the server already squashed (viofs.c:1068).
 */
int
vio9p_access(void *v)
{
	struct vop_access_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct proc *p = ap->a_p;
	struct ucred *cred = p->p_ucred;
	struct vattr vattr;
	int error;

	/*
	 * Disallow write attempts on filesystems mounted read-only; unless the
	 * file is a socket, fifo, or a block or character device.
	 */
	if ((ap->a_mode & VWRITE) && (vp->v_mount->mnt_flag & MNT_RDONLY)) {
		switch (vp->v_type) {
		case VREG:
		case VDIR:
		case VLNK:
			return (EROFS);
		default:
			break;
		}
	}

	if ((error = VOP_GETATTR(vp, &vattr, cred, p)) != 0)
		return (error);

	return (vaccess(vp->v_type, vattr.va_mode & ALLPERMS, vattr.va_uid,
	    vattr.va_gid, ap->a_mode, ap->a_cred));
}

/*
 * vop_lookup: resolve one path component.  Cloned from fuse_lookup.c
 * (fusefs_lookup), RO-pruned (M2_DESIGN.md section 6.1).
 *
 * The fid-lifecycle crux: a real component is resolved by allocating a fresh
 * fid and Twalk-CLONING it off the parent fid one component at a time; the
 * child vnode then OWNS that fid (vio9p_vget stores it on a miss).  On a Twalk
 * failure the freshly-allocated newfid was never bound server-side
 * (viofs.c:964), so it is returned to the pool WITHOUT a Tclunk.  On a Twalk
 * SUCCESS, vio9p_vget becomes the sole owner of newfid (installs it on a miss,
 * or clunk+frees the redundant one on a hash hit -- the one Tclunk outside
 * vop_reclaim, M2_DESIGN.md section 7.3); the caller never touches it again.
 *
 * Lock discipline: dvp enters locked.  For a normal child the parent lock is
 * held across the Twalk then the child is vget'd (parent-then-child order, no
 * deadlock).  For ".." the parent lock is dropped FIRST (PDIRUNLOCK) to avoid
 * the classic ".." lock inversion, and relocked per LOCKPARENT|ISLASTCN.
 */
int
vio9p_lookup(void *v)
{
	struct vop_lookup_args *ap = v;
	struct vnode *dvp = ap->a_dvp;		/* directory being searched */
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct proc *p = cnp->cn_proc;
	struct ucred *cred = cnp->cn_cred;
	struct vio9p_node *dnp = VTON(dvp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(dvp->v_mount);
	struct vio9p_softc *sc = vmp->vm_sc;
	struct vnode *tdp;
	struct p9_qid q;
	char name[NAME_MAX + 1];
	uint32_t cfid;
	int nwq;
	int flags = cnp->cn_flags;
	int nameiop = cnp->cn_nameiop;
	int lockparent = flags & LOCKPARENT;
	int error;

	*vpp = NULL;

	if ((error = VOP_ACCESS(dvp, VEXEC, cred, p)) != 0)
		return (error);

	/*
	 * On a RO mount, refuse a name op that would mutate the directory on the
	 * last component before any RPC (fuse_lookup.c:65).  On a RW mount let it
	 * through; the create/rename/delete vop (and the host) enforce.
	 */
	if (!vmp->vm_rw && (flags & ISLASTCN) &&
	    (nameiop == CREATE || nameiop == RENAME || nameiop == DELETE))
		return (EROFS);

	/*
	 * No VFS name cache (cache_lookup/cache_enter): fusefs deliberately uses
	 * none, and neither do we.  A name-cache NEGATIVE entry created by an
	 * lstat() miss (e.g. mv/mkdir/cp probing the destination) survived the
	 * subsequent create and made a later rm/rmdir/open return a stale ENOENT.
	 * The per-mount qid hash (vio9p_ihashget) still coalesces vnodes; every
	 * name resolution simply walks, which is always correct.
	 */

	/* "." -- the directory itself. */
	if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') {
		vref(dvp);
		*vpp = dvp;
		return (0);
	}

	/* Reject an overlong component before touching the wire. */
	if (cnp->cn_namelen > NAME_MAX)
		return (ENAMETOOLONG);
	memcpy(name, cnp->cn_nameptr, cnp->cn_namelen);
	name[cnp->cn_namelen] = '\0';

	if (flags & ISDOTDOT) {
		/*
		 * ".." at the share root resolves to the root itself: the
		 * server confines the share and refuses Twalk("..") at the
		 * root, and the VFS layer intercepts ".." across the mount
		 * boundary above us.  Return dvp without an RPC.  (Mirrors the
		 * server's is_share_root ".."-confinement, viofs.c:1303.)
		 */
		if (dvp->v_flag & VROOT) {
			vref(dvp);
			*vpp = dvp;
			return (0);
		}

		/*
		 * ".." for a non-root dir.  The M1 server refuses Twalk(fid,
		 * "..") (name_ok(), viofs.c:687), so resolve it LOCALLY from the
		 * cached parent vnode, keyed by the parent qid.path recorded on
		 * this node when it was looked up.  Drop the parent lock first to
		 * avoid the classic ".." lock inversion (fuse_lookup.c:168-171);
		 * vio9p_ihashget returns the parent LOCKED; relock dvp per
		 * LOCKPARENT|ISLASTCN.  If the parent has fallen out of the vnode
		 * cache we cannot reach it without a walk -> ENOENT.
		 */
		VOP_UNLOCK(dvp);
		cnp->cn_flags |= PDIRUNLOCK;

		tdp = vio9p_ihashget(dnp->n_parentpath);
		if (tdp == NULL) {
			if (vn_lock(dvp, LK_EXCLUSIVE | LK_RETRY) == 0)
				cnp->cn_flags &= ~PDIRUNLOCK;
			return (ENOENT);
		}

		if (lockparent && (flags & ISLASTCN)) {
			if ((error = vn_lock(dvp, LK_EXCLUSIVE))) {
				vput(tdp);
				return (error);
			}
			cnp->cn_flags &= ~PDIRUNLOCK;
		}
		*vpp = tdp;
		return (0);
	}

	/*
	 * A real component: the parent stays LOCKED across the RPC.  Twalk-clone
	 * a fresh fid one component deep off the parent fid.
	 */
	cfid = vio9p_fid_alloc(vmp);
	if (cfid == VIO9P_NOFID)
		return (EMFILE);

	error = p9c_walk(sc, dnp->n_fid, cfid, name, &q, &nwq);
	if (error == 0 && nwq < 1)
		error = ENOENT;			/* short walk: server bound nothing */
	if (error) {
		vio9p_fid_free(vmp, cfid);	/* never bound (viofs.c:964) */
		if (error == ENOENT) {
			/*
			 * A not-yet-existing last component being created or
			 * renamed-onto: tell the VFS the name is absent but
			 * creation is intended (EJUSTRETURN) so it calls
			 * vop_create/etc.  Write access to the dir = create
			 * permission (fuse_lookup.c:99-116).  The !vm_rw case
			 * already returned EROFS above.
			 */
			if ((nameiop == CREATE || nameiop == RENAME) &&
			    (flags & ISLASTCN)) {
				if ((error = VOP_ACCESS(dvp, VWRITE, cred,
				    p)) != 0)
					return (error);
				cnp->cn_flags |= SAVENAME;
				if (!lockparent) {
					VOP_UNLOCK(dvp);
					cnp->cn_flags |= PDIRUNLOCK;
				}
				return (EJUSTRETURN);
			}
			return (ENOENT);
		}
		return (error);
	}

	/*
	 * vio9p_vget is the sole owner of cfid from here on: on a miss it
	 * installs cfid on the new node (clunked later in reclaim); on a hash
	 * hit it clunk+frees the now-redundant cfid; on any error it clunk+frees
	 * it.  So we never touch cfid after a successful Twalk.
	 */
	error = vio9p_vget(vmp->vm_mp, &q, cfid, &tdp);
	if (error)
		return (error);

	VTON(tdp)->n_parentpath = dnp->n_qidpath;	/* enables ".." resolution */
	*vpp = tdp;

	/*
	 * DELETE/RENAME of an EXISTING last component (fuse_lookup.c:136-163):
	 * the matching vop (vio9p_remove/rmdir/rename) dereferences
	 * cnp->cn_nameptr AFTER namei returns.  Without SAVENAME the namei layer
	 * frees cn_pnbuf first, so the vop reads freed memory and ships a GARBAGE
	 * name in Tunlinkat/Trenameat -> the host can't find it -> spurious
	 * ENOENT (rm/rmdir of files that demonstrably exist).  Require VWRITE on
	 * the directory, exactly like fuse_lookup and ufs_lookup.
	 */
	if ((nameiop == DELETE || nameiop == RENAME) && (flags & ISLASTCN)) {
		if ((error = VOP_ACCESS(dvp, VWRITE, cred, p)) != 0) {
			vput(tdp);
			*vpp = NULL;
			return (error);
		}
		cnp->cn_flags |= SAVENAME;
	}

	/*
	 * Release the parent lock unless the caller wants it held on the last
	 * component (fuse_lookup.c:214-217).
	 */
	if (!lockparent || !(flags & ISLASTCN)) {
		VOP_UNLOCK(dvp);
		cnp->cn_flags |= PDIRUNLOCK;
	}

	return (0);
}

/*
 * vop_open: lazily Tlopen the vnode's owned fid.  The server flips f->opened in
 * place on the FIRST Tlopen (viofs.c -- no second fid), so a vnode owns at most
 * one fid for its whole life and we cannot widen the access of an already-open
 * fid.  Therefore the first open requests the WIDEST access this vnode may need:
 * on a RW mount a regular file opens RDWR (so a later FWRITE needs no re-open);
 * directories, symlinks, and everything on a RO mount open RDONLY.  A write open
 * on a RO mount is refused before any RPC.  Idempotent: a second open is a no-op.
 */
int
vio9p_open(void *v)
{
	struct vop_open_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vio9p_node *np = VTON(vp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(vp->v_mount);
	uint32_t iounit, oflags;
	int error;

	/* Write open on a RO mount: refuse before any RPC. */
	if ((ap->a_mode & FWRITE) && !vmp->vm_rw)
		return (EROFS);

	if (np->n_fid_opened)
		return (0);

	if (vmp->vm_rw && vp->v_type == VREG)
		oflags = L_O_RDWR;
	else
		oflags = L_O_RDONLY;

	error = p9c_lopen(vmp->vm_sc, np->n_fid, oflags, &iounit);
	if (error)
		return (error);

	np->n_fid_opened = 1;
	if (vp->v_type == VDIR)
		np->n_dir_off = 0;

	return (0);
}

/*
 * vop_close: read-only no-op.  The fid lives with the vnode and is clunked only
 * in vop_reclaim (never here, never in inactive).
 */
int
vio9p_close(void *v)
{
	return (0);
}

/*
 * vop_read: straight uiomove of host bytes, chunked by the negotiated msize
 * (vm_iomax = msize - 11).  Cloned from fuse_vnops.c (fusefs_read).  No buffer
 * cache, no bmap (M2 known gap; mmap(MAP_SHARED)/exec-off-share need M3).
 */
int
vio9p_read(void *v)
{
	struct vop_read_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct vio9p_node *np = VTON(vp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(vp->v_mount);
	struct vio9p_softc *sc = vmp->vm_sc;
	uint8_t *buf;
	uint32_t want, got;
	int error = 0;

	if (vp->v_type == VDIR)
		return (EISDIR);
	if (vp->v_type == VLNK)
		return (EINVAL);
	if (uio->uio_resid == 0)
		return (0);
	if (uio->uio_offset < 0)
		return (EINVAL);

	/* Lazily open the fid for reading. */
	if (!np->n_fid_opened) {
		error = p9c_lopen(sc, np->n_fid, L_O_RDONLY, &got);
		if (error)
			return (error);
		np->n_fid_opened = 1;
	}

	buf = malloc(vmp->vm_iomax, M_MISCFSMNT, M_WAITOK);

	while (uio->uio_resid > 0) {
		want = (uint32_t)ulmin((size_t)uio->uio_resid, vmp->vm_iomax);

		error = p9c_read(sc, np->n_fid, (uint64_t)uio->uio_offset,
		    buf, want, &got);
		if (error)
			break;
		if (got == 0)			/* EOF */
			break;
		if (got > want) {		/* defensive: server overran */
			error = EIO;
			break;
		}

		error = uiomove(buf, got, uio);
		if (error)
			break;

		if (got < want)			/* short read: EOF/no more now */
			break;
	}

	free(buf, M_MISCFSMNT, vmp->vm_iomax);
	return (error);
}

/*
 * vop_write: msize-chunked Twrite from the uio (the inverse of vio9p_read).
 * The vnode is exclusively locked by the caller (VOP_WRITE contract), so n_size
 * and the uvm size are updated without further locking.  IO_APPEND seeks to EOF
 * first.  The server enforces RO/identity; the guest just streams bytes.
 */
int
vio9p_write(void *v)
{
	struct vop_write_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct vio9p_node *np = VTON(vp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(vp->v_mount);
	struct vio9p_softc *sc = vmp->vm_sc;
	int ioflag = ap->a_ioflag;
	uint8_t *buf;
	uint32_t want, put;
	off_t off;
	int error = 0;

	if (vp->v_type == VDIR)
		return (EISDIR);
	if (vp->v_type == VLNK)
		return (EINVAL);
	if (!vmp->vm_rw)
		return (EROFS);
	if (uio->uio_resid == 0)
		return (0);

	if (ioflag & IO_APPEND)
		uio->uio_offset = np->n_size;

	if (uio->uio_offset < 0)
		return (EINVAL);

	/* Lazily open the fid for writing (RDWR so reads on it still work). */
	if (!np->n_fid_opened) {
		error = p9c_lopen(sc, np->n_fid, L_O_RDWR, &put);
		if (error)
			return (error);
		np->n_fid_opened = 1;
	}

	buf = malloc(vmp->vm_womax, M_MISCFSMNT, M_WAITOK);

	while (uio->uio_resid > 0) {
		/*
		 * Size by the WRITE budget (vm_womax = msize - 23), not the read
		 * budget (vm_iomax = msize - 11): p9c_write can only carry
		 * vm_womax data bytes per Twrite.  Asking for more makes p9c_write
		 * clamp and return a short count, which this loop would misread as
		 * a short server write and stop -> a short VOP_WRITE that breaks
		 * single-write callers (cp).  With vm_womax, put == want always.
		 */
		want = (uint32_t)ulmin((size_t)uio->uio_resid, vmp->vm_womax);

		/*
		 * Capture the write offset BEFORE uiomove advances uio_offset
		 * by `want` -- p9c_write must use the pre-advance offset, else
		 * every chunk lands `want` bytes too far (a hole).
		 */
		off = uio->uio_offset;
		error = uiomove(buf, want, uio);
		if (error)
			break;

		error = p9c_write(sc, np->n_fid, (uint64_t)off,
		    buf, want, &put);
		if (error)
			break;
		if (put == 0) {		/* server accepted nothing: avoid spin */
			error = EIO;
			break;
		}
		if (put > want) {	/* defensive: server overran */
			error = EIO;
			break;
		}

		/*
		 * uiomove already advanced uio_offset/uio_resid by `want`.  If
		 * the server took a SHORT write (put < want), rewind the
		 * unwritten tail so the loop re-ships it from the right offset
		 * (mirrors the fuse short-write fixup).
		 */
		if (put < want) {
			size_t diff = (size_t)(want - put);

			uio->uio_resid += diff;
			uio->uio_offset -= diff;
		}

		if (uio->uio_offset > np->n_size) {
			np->n_size = uio->uio_offset;
			uvm_vnp_setsize(vp, np->n_size);
		}
		uvm_vnp_uncache(vp);

		if (put < want)		/* short write: stop (re-issue next call) */
			break;
	}

	free(buf, M_MISCFSMNT, vmp->vm_womax);
	return (error);
}

/*
 * vop_create: create a regular file and return it, preserving the
 * per-vnode-owned-fid single-owner contract (M2_DESIGN.md section 7).
 *
 * Fid crux: allocate a fresh fid, Twalk-CLONE it off the (locked) parent's fid,
 * then Tlcreate on the clone.  Per 9P2000.L the server REPLACES the cloned dir
 * fid with the newly-created, opened FILE fid -- so the clone now refers to the
 * new file (backed by its own host fd) and is handed to vio9p_vget, which
 * becomes its sole owner exactly like a walk fid.
 *
 * Error fid disposition: a failed Twalk never bound the clone (no Tclunk).  A
 * failed Tlcreate leaves the DIRECTORY fid still bound server-side (the host
 * p9_lcreate does not touch the slot on an openat() error), so we MUST
 * p9c_clunk(cfid) before vio9p_fid_free(cfid) (FIX D4) -- otherwise the host
 * leaks a bound dir fid.
 */
int
vio9p_create(void *v)
{
	struct vop_create_args *ap = v;
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct vattr *vap = ap->a_vap;
	struct vio9p_node *dnp = VTON(dvp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(dvp->v_mount);
	struct vio9p_softc *sc = vmp->vm_sc;
	struct vnode *tdp;
	struct p9_qid q;
	char name[NAME_MAX + 1];
	uint32_t cfid, iounit, mode;
	int nwq, error;

	*vpp = NULL;

	/*
	 * VOP_CREATE contract (OpenBSD): the CALLER releases dvp -- vn_open and
	 * uipc_usrreq both do "VOP_CREATE(...); vput(ni_dvp);" unconditionally.
	 * So this vop must NEVER vput(dvp) (doing so double-frees the parent dir
	 * vnode -> refcount underflow panic on the FIRST create).  On error we
	 * VOP_ABORTOP(dvp, cnp) (vop_generic_abortop frees cn_pnbuf); on success
	 * we free cn_pnbuf ourselves (the caller frees neither).  dvp stays
	 * locked+referenced on return; the caller drops it.  Mirrors ufs_create.
	 */
	if (!vmp->vm_rw) {
		VOP_ABORTOP(dvp, cnp);
		return (EROFS);
	}
	if (cnp->cn_namelen > NAME_MAX) {
		VOP_ABORTOP(dvp, cnp);
		return (ENAMETOOLONG);
	}
	memcpy(name, cnp->cn_nameptr, cnp->cn_namelen);
	name[cnp->cn_namelen] = '\0';

	/* Squash SUID/SGID/sticky guest-side too (server masks again). */
	mode = MAKEIMODE(vap->va_type, vap->va_mode) & 0777;

	/* Fresh fid, cloned off the (locked) parent: clone => nwname 0. */
	cfid = vio9p_fid_alloc(vmp);
	if (cfid == VIO9P_NOFID) {
		VOP_ABORTOP(dvp, cnp);
		return (EMFILE);
	}
	error = p9c_walk(sc, dnp->n_fid, cfid, NULL, &q, &nwq);
	if (error) {
		vio9p_fid_free(vmp, cfid);	/* clone never bound */
		VOP_ABORTOP(dvp, cnp);
		return (error);
	}

	/*
	 * Tlcreate REPLACES cfid (the dir clone) with the new opened file fid.
	 * O_EXCL: vfs_lookup already proved the name absent (CREATE path), and
	 * the server adds O_CREAT|O_EXCL|O_NOFOLLOW to refuse a pre-placed
	 * symlink/file race.
	 */
	/*
	 * Open the new fid L_O_RDWR (not WRONLY): the created vnode keeps this one
	 * fid for its whole life (n_fid_opened=1, no reopen), and the same vnode
	 * is commonly READ back while still cached (e.g. cp then cksum), where
	 * vio9p_open is a no-op -- a WRONLY host fd would then EBADF the read.
	 * RDWR matches vio9p_open's "widest access" policy for VREG on a RW mount.
	 */
	error = p9c_lcreate(sc, cfid, name,
	    L_O_RDWR | L_O_CREAT | L_O_EXCL, mode, vmp->vm_owner_gid,
	    &q, &iounit);
	if (error) {
		/*
		 * FIX D4: the host left the cloned DIR fid bound on the error
		 * path, so clunk it before returning the slot to the pool.
		 */
		p9c_clunk(sc, cfid);
		vio9p_fid_free(vmp, cfid);
		VOP_ABORTOP(dvp, cnp);
		return (error);
	}

	/* vio9p_vget is sole owner of cfid from here (installs or drops it). */
	error = vio9p_vget(vmp->vm_mp, &q, cfid, &tdp);
	if (error) {
		VOP_ABORTOP(dvp, cnp);
		return (error);
	}

	/* The fid is already opened (Tlcreate opened it) -> mark it. */
	VTON(tdp)->n_fid_opened = 1;
	VTON(tdp)->n_parentpath = dnp->n_qidpath;
	VTON(tdp)->n_size = 0;

	*vpp = tdp;
	VN_KNOTE(dvp, NOTE_WRITE);
	pool_put(&namei_pool, cnp->cn_pnbuf);
	return (0);
}

/*
 * vop_mkdir: Tmkdir on the parent fid (no fid replacement), then Twalk-clone a
 * fresh owned fid for the new directory vnode (the lookup-after-create pattern)
 * and vio9p_vget it (sole owner).
 */
int
vio9p_mkdir(void *v)
{
	struct vop_mkdir_args *ap = v;
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct vattr *vap = ap->a_vap;
	struct vio9p_node *dnp = VTON(dvp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(dvp->v_mount);
	struct vio9p_softc *sc = vmp->vm_sc;
	struct vnode *tdp;
	struct p9_qid q, wq;
	char name[NAME_MAX + 1];
	uint32_t cfid, mode;
	int nwq, error;

	*vpp = NULL;

	if (!vmp->vm_rw) {
		error = EROFS;
		goto bad;
	}
	if (cnp->cn_namelen > NAME_MAX) {
		error = ENAMETOOLONG;
		goto bad;
	}
	memcpy(name, cnp->cn_nameptr, cnp->cn_namelen);
	name[cnp->cn_namelen] = '\0';
	mode = MAKEIMODE(vap->va_type, vap->va_mode) & 0777;

	error = p9c_mkdir(sc, dnp->n_fid, name, mode, vmp->vm_owner_gid, &q);
	if (error)
		goto bad;

	/* Resolve the new dir to its own owned fid (lookup-after-create). */
	cfid = vio9p_fid_alloc(vmp);
	if (cfid == VIO9P_NOFID) {
		error = EMFILE;
		goto bad;
	}
	error = p9c_walk(sc, dnp->n_fid, cfid, name, &wq, &nwq);
	if (error == 0 && nwq < 1)
		error = ENOENT;
	if (error) {
		vio9p_fid_free(vmp, cfid);	/* clone never bound */
		goto bad;
	}

	error = vio9p_vget(vmp->vm_mp, &wq, cfid, &tdp);
	if (error)
		goto bad;

	VTON(tdp)->n_parentpath = dnp->n_qidpath;
	*vpp = tdp;
	VN_KNOTE(dvp, NOTE_WRITE | NOTE_LINK);
bad:
	pool_put(&namei_pool, cnp->cn_pnbuf);
	vput(dvp);
	return (error);
}

/*
 * vop_remove: unlink `cnp->cn_nameptr` from dir dvp via Tunlinkat (flags 0).
 * Both dvp and vp enter locked+referenced; both are released here.  The removed
 * vnode's own fid is still clunked in ITS vop_reclaim (the file fid is
 * independent of the dir fid -- the D41844 separation), so unlink does not touch
 * vp->n_fid.
 */
int
vio9p_remove(void *v)
{
	struct vop_remove_args *ap = v;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = ap->a_vp;
	struct componentname *cnp = ap->a_cnp;
	struct vio9p_node *dnp = VTON(dvp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(dvp->v_mount);
	char name[NAME_MAX + 1];
	int error;

	if (!vmp->vm_rw) {
		error = EROFS;
		goto out;
	}
	if (cnp->cn_namelen > NAME_MAX) {
		error = ENAMETOOLONG;
		goto out;
	}
	memcpy(name, cnp->cn_nameptr, cnp->cn_namelen);
	name[cnp->cn_namelen] = '\0';

	error = p9c_unlinkat(vmp->vm_sc, dnp->n_fid, name, 0);
	if (error == 0) {
		VN_KNOTE(vp, NOTE_DELETE);
		VN_KNOTE(dvp, NOTE_WRITE);
		cache_purge(vp);
	}
out:
	/*
	 * UNLIKE every other create-family op, the VOP_REMOVE wrapper
	 * (kern/vfs_vops.c) releases BOTH vnodes itself after we return:
	 *	error = vop_remove(&a);
	 *	if (dvp == vp) vrele(vp); else vput(vp);
	 *	vput(dvp);
	 * so this vop must NOT release them (ufs_remove does not either).
	 * Doing our own vput(vp) double-freed vp -> "vput: bad ref count,
	 * use 0" panic in dounlinkat.  (VOP_RMDIR's wrapper does NOT release,
	 * so vio9p_rmdir DOES vput both -- the asymmetry is real.)
	 */
	return (error);
}

/*
 * vop_rmdir: remove dir `cnp` from dvp via Tunlinkat(AT_REMOVEDIR).  Same
 * contract as remove, plus refuse ".." (would corrupt the tree; the server also
 * rejects it via name_ok).
 */
int
vio9p_rmdir(void *v)
{
	struct vop_rmdir_args *ap = v;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = ap->a_vp;
	struct componentname *cnp = ap->a_cnp;
	struct vio9p_node *dnp = VTON(dvp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(dvp->v_mount);
	char name[NAME_MAX + 1];
	int error;

	if (!vmp->vm_rw) {
		error = EROFS;
		goto out;
	}
	/* Don't try to rmdir "..". */
	if (cnp->cn_namelen == 2 && cnp->cn_nameptr[0] == '.' &&
	    cnp->cn_nameptr[1] == '.') {
		error = ENOTEMPTY;
		goto out;
	}
	if (cnp->cn_namelen > NAME_MAX) {
		error = ENAMETOOLONG;
		goto out;
	}
	memcpy(name, cnp->cn_nameptr, cnp->cn_namelen);
	name[cnp->cn_namelen] = '\0';

	error = p9c_unlinkat(vmp->vm_sc, dnp->n_fid, name, P9_AT_REMOVEDIR);
	if (error == 0) {
		VN_KNOTE(dvp, NOTE_WRITE | NOTE_LINK);
		VN_KNOTE(vp, NOTE_DELETE);
		cache_purge(vp);
	}
out:
	vput(dvp);
	vput(vp);
	return (error);
}

/*
 * vop_setattr: build the Tsetattr valid mask from the supplied vattr and apply
 * mode/size/atime/mtime.  uid/gid are IGNORED in squash mode (the host owns
 * identity); va_flags are unsupported.  SUID/SGID/sticky are masked guest-side
 * (the server masks again).  After a successful truncate, sync n_size + uvm.
 * The vnode enters EXCLUSIVELY locked.
 */
int
vio9p_setattr(void *v)
{
	struct vop_setattr_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct vio9p_node *np = VTON(vp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(vp->v_mount);
	uint32_t valid = 0, mode = 0;
	uint64_t size = 0;
	int64_t at_s = 0, at_ns = 0, mt_s = 0, mt_ns = 0;
	int error;

	/* Flag changes are not supported. */
	if (vap->va_flags != VNOVAL)
		return (EOPNOTSUPP);
	/* Reject unsettable attributes (mirror fuse). */
	if (vap->va_type != VNON || vap->va_nlink != VNOVAL ||
	    vap->va_fsid != VNOVAL || vap->va_fileid != VNOVAL ||
	    vap->va_blocksize != VNOVAL || vap->va_rdev != VNOVAL ||
	    (int)vap->va_bytes != VNOVAL || vap->va_gen != VNOVAL)
		return (EINVAL);

	if (!vmp->vm_rw)
		return (EROFS);

	/* uid/gid: silently ignored in squash (NOT an error -- chown(-1) noop). */

	if (vap->va_mode != (mode_t)VNOVAL) {
		mode = vap->va_mode & 0777;	/* drop SUID/SGID/sticky */
		valid |= P9_SETATTR_MODE;
	}
	if (vap->va_size != VNOVAL) {
		if (vp->v_type == VDIR)
			return (EISDIR);
		if (vp->v_type != VREG && vp->v_type != VLNK)
			return (EINVAL);
		size = vap->va_size;
		valid |= P9_SETATTR_SIZE;
	}
	if (vap->va_atime.tv_nsec != VNOVAL) {
		at_s = vap->va_atime.tv_sec;
		at_ns = vap->va_atime.tv_nsec;
		valid |= P9_SETATTR_ATIME | P9_SETATTR_ATIME_SET;
	}
	if (vap->va_mtime.tv_nsec != VNOVAL) {
		mt_s = vap->va_mtime.tv_sec;
		mt_ns = vap->va_mtime.tv_nsec;
		valid |= P9_SETATTR_MTIME | P9_SETATTR_MTIME_SET;
	}

	if (valid == 0)
		return (0);		/* nothing to do */

	error = p9c_setattr(vmp->vm_sc, np->n_fid, valid, mode, 0, 0, size,
	    at_s, at_ns, mt_s, mt_ns);
	if (error)
		return (error);

	if (valid & P9_SETATTR_SIZE) {
		np->n_size = (off_t)size;
		uvm_vnp_setsize(vp, np->n_size);
		uvm_vnp_uncache(vp);
	}
	VN_KNOTE(vp, NOTE_ATTRIB);
	return (0);
}

/*
 * vop_rename: rename fvp (in fdvp) to tcnp name in tdvp via a single
 * Trenameat(fdvp->n_fid, fromname, tdvp->n_fid, toname).  FIX D1: the host
 * refuses the legacy Trename for a non-symlink fid (it holds only a host fd to
 * the object, not a (parentdir,leaf) it can renameat() from), so we always emit
 * Trenameat, which carries BOTH parents + BOTH leaf names.  Cross-mount is
 * refused (EXDEV); "."/".." and same-source-dest are refused.  All four vnodes
 * are released per the VOP_RENAME contract; the moved vnode and any clobbered
 * target have their name caches purged.
 */
int
vio9p_rename(void *v)
{
	struct vop_rename_args *ap = v;
	struct vnode *fdvp = ap->a_fdvp;
	struct vnode *fvp = ap->a_fvp;
	struct vnode *tdvp = ap->a_tdvp;
	struct vnode *tvp = ap->a_tvp;
	struct componentname *tcnp = ap->a_tcnp;
	struct componentname *fcnp = ap->a_fcnp;
	struct vio9p_mnt *vmp = VFSTOVIO9P(fdvp->v_mount);
	struct vio9p_node *fdnp = VTON(fdvp);
	struct vio9p_node *tdnp = VTON(tdvp);
	char fromname[NAME_MAX + 1];
	char toname[NAME_MAX + 1];
	int error = 0;

	/* Cross-device (cross-mount) rename. */
	if (fvp->v_mount != tdvp->v_mount ||
	    (tvp != NULL && fvp->v_mount != tvp->v_mount)) {
		error = EXDEV;
abortit:
		VOP_ABORTOP(tdvp, tcnp);
		if (tdvp == tvp)
			vrele(tdvp);
		else
			vput(tdvp);
		if (tvp != NULL)
			vput(tvp);
		VOP_ABORTOP(fdvp, fcnp);
		vrele(fdvp);
		vrele(fvp);
		return (error);
	}

	/* Nothing to do if source == dest. */
	if (tvp == fvp) {
		error = 0;
		goto abortit;
	}
	if (!vmp->vm_rw) {
		error = EROFS;
		goto abortit;
	}

	if ((error = vn_lock(fvp, LK_EXCLUSIVE | LK_RETRY)) != 0)
		goto abortit;

	/* Refuse "."/".." and aliases of "." that would cripple the tree. */
	if (fvp->v_type == VDIR) {
		if ((fcnp->cn_namelen == 1 && fcnp->cn_nameptr[0] == '.') ||
		    fdnp == VTON(fvp) ||
		    (fcnp->cn_flags & ISDOTDOT) ||
		    (tcnp->cn_flags & ISDOTDOT)) {
			VOP_UNLOCK(fvp);
			error = EINVAL;
			goto abortit;
		}
	}
	if (fcnp->cn_namelen > NAME_MAX || tcnp->cn_namelen > NAME_MAX) {
		VOP_UNLOCK(fvp);
		error = ENAMETOOLONG;
		goto abortit;
	}
	memcpy(fromname, fcnp->cn_nameptr, fcnp->cn_namelen);
	fromname[fcnp->cn_namelen] = '\0';
	memcpy(toname, tcnp->cn_nameptr, tcnp->cn_namelen);
	toname[tcnp->cn_namelen] = '\0';

	/*
	 * FIX D1: Trenameat carries the SOURCE-parent fid + source name and the
	 * DEST-dir fid + dest name (the host renameat()s between the two dir
	 * fds).  This works for every fid type, unlike legacy Trename.
	 */
	error = p9c_renameat(vmp->vm_sc, fdnp->n_fid, fromname, tdnp->n_fid,
	    toname);

	if (error == 0) {
		VN_KNOTE(fvp, NOTE_RENAME);
		VN_KNOTE(fdvp, NOTE_WRITE);
		VN_KNOTE(tdvp, NOTE_WRITE);
		if (tvp != NULL)
			VN_KNOTE(tvp, NOTE_DELETE);
		/*
		 * The moved node's n_parentpath is now stale (it pointed at the
		 * old parent's qid.path); fix it so a later ".." on the moved
		 * vnode resolves correctly.  qid.path itself is stable across a
		 * rename (the host inode id is unchanged), so the qid hash key
		 * stays valid and no re-keying is needed.
		 */
		VTON(fvp)->n_parentpath = tdnp->n_qidpath;
		cache_purge(fvp);
		if (tvp != NULL)
			cache_purge(tvp);
	}

	VOP_UNLOCK(fvp);
	if (tdvp == tvp)
		vrele(tdvp);
	else
		vput(tdvp);
	if (tvp != NULL)
		vput(tvp);
	vrele(fdvp);
	vrele(fvp);
	return (error);
}

/*
 * vop_symlink: create a symlink with body a_target via Tsymlink on the parent
 * fid, then Twalk-clone a fresh owned fid for the new link vnode and
 * vio9p_vget it (sole owner).  The target is stored verbatim (NFS model).
 */
int
vio9p_symlink(void *v)
{
	struct vop_symlink_args *ap = v;
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	char *target = ap->a_target;
	struct vio9p_node *dnp = VTON(dvp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(dvp->v_mount);
	struct vio9p_softc *sc = vmp->vm_sc;
	struct vnode *tdp;
	struct p9_qid q, wq;
	char name[NAME_MAX + 1];
	uint32_t cfid;
	int nwq, error;

	*vpp = NULL;

	if (!vmp->vm_rw) {
		error = EROFS;
		goto bad;
	}
	if (cnp->cn_namelen > NAME_MAX) {
		error = ENAMETOOLONG;
		goto bad;
	}
	memcpy(name, cnp->cn_nameptr, cnp->cn_namelen);
	name[cnp->cn_namelen] = '\0';

	error = p9c_symlink(sc, dnp->n_fid, name, target, vmp->vm_owner_gid,
	    &q);
	if (error)
		goto bad;

	cfid = vio9p_fid_alloc(vmp);
	if (cfid == VIO9P_NOFID) {
		error = EMFILE;
		goto bad;
	}
	error = p9c_walk(sc, dnp->n_fid, cfid, name, &wq, &nwq);
	if (error == 0 && nwq < 1)
		error = ENOENT;
	if (error) {
		vio9p_fid_free(vmp, cfid);	/* clone never bound */
		goto bad;
	}

	error = vio9p_vget(vmp->vm_mp, &wq, cfid, &tdp);
	if (error)
		goto bad;

	VTON(tdp)->n_parentpath = dnp->n_qidpath;
	tdp->v_type = VLNK;
	*vpp = tdp;
	VN_KNOTE(dvp, NOTE_WRITE);
	/*
	 * VOP_SYMLINK contract (OpenBSD): the caller (sys_symlinkat) ignores
	 * ni_vp on success and never releases it, so the vop owns the new vnode
	 * end to end -- vput it here (mirrors ufs_symlink's "vput(vp)").  Leaving
	 * it referenced+locked would strand it and deadlock the next lookup
	 * (e.g. the readlink that follows ln -s).  *vpp is left dangling by
	 * design; the caller does not dereference it.
	 */
	vput(tdp);
bad:
	pool_put(&namei_pool, cnp->cn_pnbuf);
	vput(dvp);
	return (error);
}

/*
 * vop_link: create hard link `cnp` in dvp to vp via Tlink(dvp->n_fid,
 * vp->n_fid, name).  NOTE: OpenBSD linkat(2) lacks AT_EMPTY_PATH, so the HOST
 * may be unable to express link-by-fid and reply EOPNOTSUPP; we surface it.
 * vp is same-mount (the VFS guarantees it for VOP_LINK).
 */
int
vio9p_link(void *v)
{
	struct vop_link_args *ap = v;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = ap->a_vp;
	struct componentname *cnp = ap->a_cnp;
	struct vio9p_node *dnp = VTON(dvp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(dvp->v_mount);
	char name[NAME_MAX + 1];
	int error = 0;

	if (!vmp->vm_rw) {
		VOP_ABORTOP(dvp, cnp);
		error = EROFS;
		goto out2;
	}
	if (vp->v_type == VDIR) {
		VOP_ABORTOP(dvp, cnp);
		error = EPERM;		/* no hardlinks to dirs */
		goto out2;
	}
	if (cnp->cn_namelen > NAME_MAX) {
		VOP_ABORTOP(dvp, cnp);
		error = ENAMETOOLONG;
		goto out2;
	}
	if (dvp != vp && (error = vn_lock(vp, LK_EXCLUSIVE))) {
		VOP_ABORTOP(dvp, cnp);
		goto out2;
	}
	memcpy(name, cnp->cn_nameptr, cnp->cn_namelen);
	name[cnp->cn_namelen] = '\0';

	error = p9c_link(vmp->vm_sc, dnp->n_fid, VTON(vp)->n_fid, name);
	if (error == 0) {
		VN_KNOTE(vp, NOTE_LINK);
		VN_KNOTE(dvp, NOTE_WRITE);
	}

	pool_put(&namei_pool, cnp->cn_pnbuf);
	if (dvp != vp)
		VOP_UNLOCK(vp);
out2:
	vput(dvp);
	return (error);
}

/*
 * vop_readdir: cookie-driven dirent stream (M2_DESIGN.md section 6.7, THE
 * careful one).  The dir fid is opened lazily once (left open until reclaim --
 * never Tlopen/Tclunk per getdents).  Treaddir resumes at uio_offset, which
 * carries the OPAQUE 9P cookie (the off[8] of the previous entry), NOT a byte
 * position; we OVERWRITE uio_offset with each entry's cookie after emitting it.
 * Getting this wrong yields infinite or truncated listings.
 *
 * Each wire entry is qid[13] off[8] type[1] namelen[2] name[] (P9_READDIR_FIXED
 * == 24; viofs.c:1415-1418).  off is the resume cookie for the NEXT entry; type
 * is already a DT_* (viofs.c:1319) so it passes through unremapped; qid.path is
 * the host inode id, surfaced as d_fileno to keep readdir/getattr/VFS_VGET
 * inode numbers coherent.
 */
int
vio9p_readdir(void *v)
{
	struct vop_readdir_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct vio9p_node *np = VTON(vp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(vp->v_mount);
	struct vio9p_softc *sc = vmp->vm_sc;
	struct dirent dent;
	uint8_t *raw;
	uint64_t cookie;
	uint32_t got, junk;
	size_t pos;
	int error = 0, eof = 0;

	if (vp->v_type != VDIR)
		return (ENOTDIR);
	if (uio->uio_offset < 0)
		return (EINVAL);
	/* Need room for at least one maximal dirent. */
	if (uio->uio_resid < sizeof(struct dirent))
		return (EINVAL);

	/* Lazily open the dir fid (idempotent for the vnode's lifetime). */
	if (!np->n_fid_opened) {
		error = p9c_lopen(sc, np->n_fid, L_O_RDONLY, &junk);
		if (error)
			return (error);
		np->n_fid_opened = 1;
		np->n_dir_off = 0;
	}

	raw = malloc(vmp->vm_iomax, M_MISCFSMNT, M_WAITOK);
	cookie = (uint64_t)uio->uio_offset;

	while (uio->uio_resid > 0) {
		error = p9c_readdir(sc, np->n_fid, cookie, raw, vmp->vm_iomax,
		    &got);
		if (error)
			break;
		if (got == 0) {			/* server EOF */
			eof = 1;
			break;
		}
		if (got > vmp->vm_iomax) {	/* defensive */
			error = EIO;
			break;
		}

		pos = 0;
		while (pos + P9_READDIR_FIXED <= (size_t)got) {
			/*
			 * Wire entry: qid[13] off[8] type[1] namelen[2] name[].
			 * qid.path is at off 5 (after type[1] version[4]); the
			 * resume cookie is the off[8] at off 13; d_type is the
			 * DT_* the server already computed, at off 21.
			 */
			uint64_t qpath = vio9p_le64(&raw[pos + 5]);
			uint64_t ecookie = vio9p_le64(&raw[pos + 13]);
			uint8_t  dtype = raw[pos + 21];
			uint16_t nlen = vio9p_le16(&raw[pos + 22]);
			char    *nm = (char *)&raw[pos + 24];

			/* Truncated tail: resume from this cookie next round. */
			if (pos + P9_READDIR_FIXED + nlen > (size_t)got)
				break;
			/* Skip a degenerate/oversized record but advance. */
			if (nlen == 0 || nlen > MAXNAMLEN) {
				pos += P9_READDIR_FIXED + nlen;
				cookie = ecookie;
				continue;
			}

			memset(&dent, 0, sizeof(dent));
			dent.d_fileno = qpath;		/* == va_fileid, VFS_VGET key */
			dent.d_reclen = DIRENT_RECSIZE(nlen);
			dent.d_type = dtype;		/* DT_* passes through */
			dent.d_namlen = nlen;
			dent.d_off = (off_t)ecookie;
			memcpy(dent.d_name, nm, nlen);
			dent.d_name[nlen] = '\0';

			/* Won't fit: stop and resume here next call. */
			if (uio->uio_resid < dent.d_reclen)
				goto done;

			error = uiomove(&dent, dent.d_reclen, uio);
			if (error)
				goto done;

			/*
			 * CRITICAL: uio_offset is the opaque 9P cookie, NOT the
			 * byte count uiomove just added.  Overwrite it with this
			 * entry's off[8] so the next Treaddir resumes at the
			 * server lseek target (viofs.c:1368).
			 */
			cookie = ecookie;
			uio->uio_offset = (off_t)ecookie;
			pos += P9_READDIR_FIXED + nlen;
		}

		/*
		 * If we consumed nothing from a non-empty reply (e.g. the very
		 * first record could not fit), bail rather than spin.
		 */
		if (pos == 0)
			break;
	}
done:
	free(raw, M_MISCFSMNT, vmp->vm_iomax);

	if (!error)
		np->n_dir_off = cookie;
	if (!error && ap->a_eofflag != NULL)
		*ap->a_eofflag = eof;

	return (error);
}

/*
 * vop_readlink: return the symlink target verbatim, unresolved (NFS model;
 * the guest namei resolves it).  VLNK only.  Cloned from fuse_vnops.c
 * (fusefs_readlink).  The client decode already rejects an embedded NUL in the
 * 9P string, but we re-check defensively before handing bytes to the uio.
 */
int
vio9p_readlink(void *v)
{
	struct vop_readlink_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct vio9p_node *np = VTON(vp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(vp->v_mount);
	char target[PATH_MAX];
	size_t len = 0;
	int error;

	if (vp->v_type != VLNK)
		return (EINVAL);
	if (uio->uio_resid == 0)
		return (0);
	if (uio->uio_offset < 0)
		return (EINVAL);

	error = p9c_readlink(vmp->vm_sc, np->n_fid, target, sizeof(target),
	    &len);
	if (error)
		return (error);

	/* Reject an embedded NUL in the link text. */
	if (len > 0 && memchr(target, '\0', len) != NULL)
		return (EIO);

	return (uiomove(target, len, uio));
}

/*
 * vop_inactive: read-only, nothing to flush.  VOP_UNLOCK is mandatory or
 * vclean(9) panics.  DO NOT clunk here -- the fid is freed in reclaim.
 */
int
vio9p_inactive(void *v)
{
	struct vop_inactive_args *ap = v;
	struct vnode *vp = ap->a_vp;

	VOP_UNLOCK(vp);

	/* Don't return error to prevent kernel panic in vclean(9). */
	return (0);
}

/*
 * vop_reclaim: the unique fid-free site.  Clunk and free the vnode's owned fid
 * (unless it is the root fid, which the mount owns and clunks at unmount), drop
 * the node from the qid-path hash, purge the name cache, and free the node.
 */
int
vio9p_reclaim(void *v)
{
	struct vop_reclaim_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vio9p_node *np = VTON(vp);
	struct vio9p_mnt *vmp = np->n_mnt;

	if (np->n_fid != VIO9P_NOFID && !(vp->v_flag & VROOT)) {
		p9c_clunk(vmp->vm_sc, np->n_fid);
		vio9p_fid_free(np->n_mnt, np->n_fid);
		np->n_fid = VIO9P_NOFID;
	}

	/* Remove the node from its hash chain. */
	vio9p_ihashrem(np);
	cache_purge(vp);

	free(np, M_MISCFSMNT, sizeof(*np));
	vp->v_data = NULL;

	/* Must return success otherwise kernel panic in vclean(9). */
	return (0);
}

int
vio9p_print(void *v)
{
#if defined(DEBUG) || defined(DIAGNOSTIC) || defined(VFSLCKDEBUG)
	struct vop_print_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vio9p_node *np = VTON(vp);

	/* Complete the information given by vprint(). */
	printf("tag VT_VIO9P, qid.path %llu fid %u\n",
	    (unsigned long long)np->n_qidpath, np->n_fid);
#endif
	return (0);
}

int
vio9p_pathconf(void *v)
{
	struct vop_pathconf_args *ap = v;
	int error = 0;

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = LINK_MAX;
		break;
	case _PC_NAME_MAX:
		*ap->a_retval = NAME_MAX;
		break;
	case _PC_PATH_MAX:
		*ap->a_retval = PATH_MAX;
		break;
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		break;
	case _PC_NO_TRUNC:
		*ap->a_retval = 1;
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}

int
vio9p_lock(void *v)
{
	struct vop_lock_args *ap = v;
	struct vnode *vp = ap->a_vp;

	return (rrw_enter(&VTON(vp)->n_lock, ap->a_flags & LK_RWFLAGS));
}

int
vio9p_unlock(void *v)
{
	struct vop_unlock_args *ap = v;
	struct vnode *vp = ap->a_vp;

	rrw_exit(&VTON(vp)->n_lock);
	return (0);
}

int
vio9p_islocked(void *v)
{
	struct vop_islocked_args *ap = v;

	return (rrw_status(&VTON(ap->a_vp)->n_lock));
}
