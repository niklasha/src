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
 * vio9p VFS operations + the mount(2) path for the in-kernel, read-only
 * 9P2000.L guest client (M2).  This is the VFS-side analog of fuse_vfsops.c:
 * a filesystem that forwards to an external server.  Here the "server" is the
 * host vmd viofs subprocess, reached through the vio9p(4) virtio transport.
 *
 * The mount-syscall reaches the transport softc that owns the virtqueue via
 * the cfdriver global registry (device_lookup(&vio9p_cd, unit)); no /dev node
 * and no new global are needed because the client is wholly in-kernel.  See
 * M2_DESIGN.md sections 5.1-5.5.
 *
 * M2b scope: mount + root vnode + statfs + getattr-root.  lookup/open/read/
 * readdir/readlink live in vio9p_vnops.c (M2c).
 *
 * M3: the mount honors the helper's RW request (args.va_rw); a RO mount is
 * still forced MNT_RDONLY (so the VFS write barriers engage) and MNT_UPDATE is
 * always refused (no ro<->rw remount).  The mutating vfsops (sync, etc.) stay
 * no-ops; the write path is entirely in the vnops layer + the host server.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

#include <sys/device.h>

#include <miscfs/vio9p/vio9p.h>
#include <dev/pv/vio9preg.h>
#include <dev/pv/vio9pvar.h>

int	vio9p_mount(struct mount *, const char *, void *, struct nameidata *,
	    struct proc *);
int	vio9p_start(struct mount *, int, struct proc *);
int	vio9p_unmount(struct mount *, int, struct proc *);
int	vio9p_root(struct mount *, struct vnode **);
int	vio9p_quotactl(struct mount *, int, uid_t, caddr_t, struct proc *);
int	vio9p_statfs(struct mount *, struct statfs *, struct proc *);
int	vio9p_sync(struct mount *, int, int, struct ucred *, struct proc *);
int	vio9p_vfs_vget(struct mount *, ino_t, struct vnode **);
int	vio9p_fhtovp(struct mount *, struct fid *, struct vnode **);
int	vio9p_vptofh(struct vnode *, struct fid *);
int	vio9p_init(struct vfsconf *);
int	vio9p_sysctl(int *, u_int, void *, size_t *, void *, size_t,
	    struct proc *);
int	vio9p_checkexp(struct mount *, struct mbuf *, int *, struct ucred **);

const struct vfsops vio9p_vfsops = {
	.vfs_mount	= vio9p_mount,
	.vfs_start	= vio9p_start,
	.vfs_unmount	= vio9p_unmount,
	.vfs_root	= vio9p_root,
	.vfs_quotactl	= vio9p_quotactl,
	.vfs_statfs	= vio9p_statfs,
	.vfs_sync	= vio9p_sync,
	.vfs_vget	= vio9p_vfs_vget,
	.vfs_fhtovp	= vio9p_fhtovp,
	.vfs_vptofh	= vio9p_vptofh,
	.vfs_init	= vio9p_init,
	.vfs_sysctl	= vio9p_sysctl,
	.vfs_checkexp	= vio9p_checkexp,
};

/*
 * Mount a vio9p share.  The mount(2) argument is a struct vio9p_args copied in
 * from userland (the /sbin/mount_vio9p helper).  We rendezvous with the
 * transport instance the helper selected by unit, cross-check the mount tag
 * against the device's config-space tag, then run the 9P session bring-up:
 * Tversion (msize negotiation) and Tattach (root fid + root qid).
 */
int
vio9p_mount(struct mount *mp, const char *path, void *data,
    struct nameidata *ndp, struct proc *p)
{
	struct vio9p_args	 args;
	struct vio9p_mnt	*vmp;
	struct vio9p_softc	*sc;
	int			 error;

	if (mp->mnt_flag & MNT_UPDATE)		/* no remount (incl. ro<->rw) */
		return (EOPNOTSUPP);

	/* sys_mount() already copied the args into kernel space (vfc_datasize). */
	memcpy(&args, data, sizeof(args));
	if (args.va_version != VIO9P_ARGS_VERSION)
		return (EINVAL);

	/*
	 * Rendezvous with the transport softc the helper selected, then
	 * cross-check the mount tag against the device's config-space tag.
	 */
	sc = (struct vio9p_softc *)device_lookup(&vio9p_cd, args.va_unit);
	if (sc == NULL)
		return (ENXIO);
	if (strncmp(sc->sc_tag, args.va_tag, VIO9P_TAG_MAX) != 0)
		return (EINVAL);

	/*
	 * Honor the helper's RW request (args.va_rw).  The HOST server remains
	 * the authority -- a guest RW mount over a RO share still gets EROFS per
	 * op -- but the guest stops self-vetoing.  When the mount is RO, force
	 * MNT_RDONLY so the VFS-layer write barriers (and vio9p_access) engage.
	 */
	vmp = malloc(sizeof(*vmp), M_MISCFSMNT, M_WAITOK | M_ZERO);
	vmp->vm_mp = mp;
	vmp->vm_sc = sc;
	vmp->vm_rw = args.va_rw ? 1 : 0;
	vmp->vm_rdonly = vmp->vm_rw ? 0 : 1;
	if (!vmp->vm_rw)
		mp->mnt_flag |= MNT_RDONLY;	/* belt: VFS-level RO wall */
	vmp->vm_owner_gid = 0;			/* host owns identity (squash) */

	/*
	 * 9P session bring-up.  Unlike fuse, the server is the host (not the
	 * mounting process), so it is safe to block on the virtqueue here.
	 */
	error = p9c_version(sc);
	if (error != 0)
		goto bad;
	vmp->vm_msize = sc->sc_msize;
	vmp->vm_iomax = sc->sc_msize - P9_READ_IOHDRSZ;
	vmp->vm_womax = sc->sc_msize - P9_WRITE_IOHDRSZ;
	vmp->vm_rootfid = VIO9P_FID_ROOT;

	error = p9c_attach(sc, vmp->vm_rootfid, &vmp->vm_rootqid);
	if (error != 0)
		goto bad;
	vmp->vm_rootpath = vmp->vm_rootqid.path;

	mp->mnt_data = vmp;
	vfs_getnewfsid(mp);

	memset(mp->mnt_stat.f_mntonname, 0, MNAMELEN);
	strlcpy(mp->mnt_stat.f_mntonname, path, MNAMELEN);
	memset(mp->mnt_stat.f_mntfromname, 0, MNAMELEN);
	strlcpy(mp->mnt_stat.f_mntfromname, args.va_tag, MNAMELEN);
	memset(mp->mnt_stat.f_mntfromspec, 0, MNAMELEN);
	strlcpy(mp->mnt_stat.f_mntfromspec, args.va_tag, MNAMELEN);

	return (vio9p_statfs(mp, &mp->mnt_stat, p));
bad:
	free(vmp, M_MISCFSMNT, sizeof(*vmp));
	return (error);
}

int
vio9p_start(struct mount *mp, int flags, struct proc *p)
{
	return (0);
}

/*
 * Unmount.  vflush() first, so every child vnode's vop_reclaim runs and clunks
 * its own owned fid; only then clunk the root fid.  Clunking the root before
 * the children would orphan still-referenced child fids host-side (the D41844
 * ordering hazard, M2_DESIGN.md section 7).
 */
int
vio9p_unmount(struct mount *mp, int mntflags, struct proc *p)
{
	struct vio9p_mnt	*vmp;
	int			 flags = 0;
	int			 error;

	vmp = VFSTOVIO9P(mp);

	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	error = vflush(mp, NULL, flags);
	if (error != 0)
		return (error);

	/* Swallow the error: the host may already have torn the session down. */
	(void)p9c_clunk(vmp->vm_sc, vmp->vm_rootfid);

	free(vmp, M_MISCFSMNT, sizeof(*vmp));
	mp->mnt_data = NULL;

	return (0);
}

/*
 * Return the root vnode.  The node layer special-cases the root qid/fid and
 * sets VROOT; here we only have to ensure the type is VDIR.
 */
int
vio9p_root(struct mount *mp, struct vnode **vpp)
{
	struct vio9p_mnt	*vmp;
	struct vnode		*nvp;
	int			 error;

	vmp = VFSTOVIO9P(mp);

	error = vio9p_vget(mp, &vmp->vm_rootqid, vmp->vm_rootfid, &nvp);
	if (error != 0)
		return (error);

	nvp->v_type = VDIR;
	*vpp = nvp;

	return (0);
}

int
vio9p_quotactl(struct mount *mp, int cmds, uid_t uid, caddr_t arg,
    struct proc *p)
{
	return (EOPNOTSUPP);
}

/*
 * statfs.  Ask the host with Tstatfs against the root fid and translate the
 * Rstatfs body into struct statfs.  On any error, fill zeros and still return
 * success so statfs(2)/df do not fail (mirrors fuse_statfs).
 */
int
vio9p_statfs(struct mount *mp, struct statfs *sbp, struct proc *p)
{
	struct vio9p_mnt	*vmp;
	struct p9_statfs	 s;
	int			 error;

	vmp = VFSTOVIO9P(mp);

	copy_statfs_info(sbp, mp);

	error = p9c_statfs(vmp->vm_sc, vmp->vm_rootfid, &s);
	if (error != 0) {
		sbp->f_bsize = 0;
		sbp->f_iosize = 0;
		sbp->f_blocks = 0;
		sbp->f_bfree = 0;
		sbp->f_bavail = 0;
		sbp->f_files = 0;
		sbp->f_ffree = 0;
		sbp->f_favail = 0;
		sbp->f_namemax = 0;
		return (0);
	}

	sbp->f_bsize = s.bsize;
	sbp->f_iosize = vmp->vm_iomax;
	sbp->f_blocks = s.blocks;
	sbp->f_bfree = s.bfree;
	sbp->f_bavail = s.bavail;
	sbp->f_files = s.files;
	sbp->f_ffree = s.ffree;
	sbp->f_favail = s.ffree;
	sbp->f_namemax = s.namelen;

	return (0);
}

int
vio9p_sync(struct mount *mp, int waitfor, int stall, struct ucred *cred,
    struct proc *p)
{
	return (0);
}

/*
 * The vfs_vget vfsop (by inode number).  Distinct from the node-layer
 * vio9p_vget(mp, qid, fid, vpp), which builds a vnode from a known qid.  For
 * M2b only the root is reachable here; the general by-ino path is M2c and a
 * 9P fid cannot be reconstructed from an inode number alone.
 */
int
vio9p_vfs_vget(struct mount *mp, ino_t ino, struct vnode **vpp)
{
	struct vio9p_mnt	*vmp;

	if (ino != VIO9P_ROOTINO)
		return (EOPNOTSUPP);

	vmp = VFSTOVIO9P(mp);

	return (vio9p_vget(mp, &vmp->vm_rootqid, vmp->vm_rootfid, vpp));
}

int
vio9p_fhtovp(struct mount *mp, struct fid *fhp, struct vnode **vpp)
{
	return (EINVAL);
}

int
vio9p_vptofh(struct vnode *vp, struct fid *fhp)
{
	return (EINVAL);
}

int
vio9p_init(struct vfsconf *vfc)
{
	vio9p_ihashinit();

	return (0);
}

int
vio9p_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp,
    size_t newlen, struct proc *p)
{
	return (EOPNOTSUPP);
}

int
vio9p_checkexp(struct mount *mp, struct mbuf *nam, int *extflagsp,
    struct ucred **credanonp)
{
	return (EOPNOTSUPP);
}
