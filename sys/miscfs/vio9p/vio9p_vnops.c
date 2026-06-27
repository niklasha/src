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
 * vio9p RO vnode operations (M2c).  Clones fuse_vnops.c / fuse_lookup.c, routes
 * every mutating op to vio9p_erofs (EROFS), keeps lock/unlock/islocked (rrwlock)
 * and inactive/reclaim real, and implements the full RO file-I/O path against
 * the host server:
 *
 *   lookup   -- Twalk-clone a fresh per-vnode fid one component at a time
 *   open     -- lazy Tlopen of the vnode's owned fid (RO)
 *   read     -- Tread loop, chunked by msize, into the uio
 *   readdir  -- Treaddir cookie stream -> struct dirent (uio_offset = 9P cookie)
 *   readlink -- Treadlink, target verbatim (guest resolves; NFS model)
 *
 * The fid/vnode lifecycle (M2_DESIGN.md section 7) is the load-bearing invariant:
 * every vnode OWNS one Twalk-cloned fid backed by its own host fd; that fid is
 * Tclunk'd in vop_reclaim and ONLY there (the unique free site), except the one
 * redundant just-walked fid that a hash-hit in vio9p_vget makes superfluous.
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

/* node layer (vio9p_node.c) -- not in vio9p.h yet */

const struct vops vio9p_vops = {
	.vop_lookup	= vio9p_lookup,
	.vop_create	= vio9p_erofs,
	.vop_mknod	= vio9p_erofs,
	.vop_open	= vio9p_open,
	.vop_close	= vio9p_close,
	.vop_access	= vio9p_access,
	.vop_getattr	= vio9p_getattr,
	.vop_setattr	= vio9p_erofs,
	.vop_read	= vio9p_read,
	.vop_write	= vio9p_erofs,
	.vop_ioctl	= vio9p_ioctl,
	.vop_kqfilter	= vio9p_erofs,
	.vop_revoke	= NULL,
	.vop_fsync	= nullop,
	.vop_remove	= vio9p_erofs,
	.vop_link	= vio9p_erofs,
	.vop_rename	= vio9p_erofs,
	.vop_mkdir	= vio9p_erofs,
	.vop_rmdir	= vio9p_erofs,
	.vop_symlink	= vio9p_erofs,
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
 * Catch-all for every mutating operation on a read-only mount.  The mount is
 * forced MNT_RDONLY and the host server also refuses any write flag, so this
 * is purely a fast-path wall.
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
	 * RO gate: any name operation that would mutate the directory on the
	 * last component is refused before any RPC (fuse_lookup.c:65).
	 */
	if ((flags & ISLASTCN) &&
	    (nameiop == CREATE || nameiop == RENAME || nameiop == DELETE))
		return (EROFS);

	/*
	 * cache_lookup returns 0 on a name-cache hit (with *vpp set / locked
	 * per the cache rules), or a positive errno (ENOENT on a negative-cache
	 * hit).  A return of -1 means "not cached" -> fall through and walk.
	 */
	if ((error = cache_lookup(dvp, vpp, cnp)) >= 0)
		return (error);

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
		if (flags & MAKEENTRY)
			cache_enter(dvp, *vpp, cnp);
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
			 * Negative-cache the miss for a plain lookup.  RENAME
			 * is excluded so a later create-by-rename still walks.
			 */
			if ((flags & MAKEENTRY) && nameiop != CREATE &&
			    nameiop != RENAME)
				cache_enter(dvp, NULL, cnp);
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
	 * Release the parent lock unless the caller wants it held on the last
	 * component (fuse_lookup.c:214-217).
	 */
	if (!lockparent || !(flags & ISLASTCN)) {
		VOP_UNLOCK(dvp);
		cnp->cn_flags |= PDIRUNLOCK;
	}
	if (flags & MAKEENTRY)
		cache_enter(dvp, *vpp, cnp);

	return (0);
}

/*
 * vop_open: lazily Tlopen the vnode's owned fid read-only.  RO -- a write open
 * is refused before the wire.  The Tlopen reuses the walk fid in place (the
 * server flips f->opened, viofs.c:1113 -- no second fid), so a vnode owns at
 * most one fid for its whole life.  Idempotent: a second open is a no-op.
 */
int
vio9p_open(void *v)
{
	struct vop_open_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vio9p_node *np = VTON(vp);
	struct vio9p_mnt *vmp = VFSTOVIO9P(vp->v_mount);
	uint32_t iounit;
	int error;

	if (ap->a_mode & FWRITE)
		return (EROFS);

	if (np->n_fid_opened)
		return (0);

	error = p9c_lopen(vmp->vm_sc, np->n_fid, L_O_RDONLY, &iounit);
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
