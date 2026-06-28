/*	$OpenBSD$	*/
/*	$NetBSD: ufs_ihash.c,v 1.3 1996/02/09 22:36:04 christos Exp $	*/

/*
 * Copyright (c) 2026 Niklas Hallqvist <niklas@appli.se>
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * vio9p in-kernel 9P2000.L guest VFS client: node/inode layer (DIM 5).
 *
 * A qid.path-keyed in-core inode hash (cloned from sys/miscfs/fuse/fuse_ihash.c),
 * the vnode birth path (vio9p_vget, cloned from fusefs_vget), and a per-mount fid
 * pool.  The hash key is the 9P qid.path -- the host inode id the M1 server hands
 * back (usr.sbin/vmd/viofs.c) -- so one host inode == one vnode == one owned fid
 * (the EEXIST collapse), which is the property that defeats the FreeBSD D41844
 * premature-clunk hazard (M2_DESIGN.md sections 7.2/7.6).
 *
 * M2c adds the file-I/O caller: vio9p_lookup() Twalk-CLONEs a fresh fid off the
 * parent and hands it to vio9p_vget(), which TAKES OWNERSHIP of that fid on a
 * cache miss (bound 1:1 to the new vnode, clunked only in vop_reclaim, the unique
 * free site).  On a cache hit -- another vnode already owns a fid for this host
 * inode (the EEXIST collapse: hardlinks/dedup/", ".."/concurrent lookups) -- the
 * just-walked fid is REDUNDANT and is the single spot a walk fid is clunked
 * outside reclaim (M2_DESIGN.md section 7.3; the most common 9p fid-leak trap).
 * The mount root fid (VIO9P_FID_ROOT) is owned by the mount, not by a vnode, so
 * vio9p_root()/vfs_vget() pass it in and it is never clunked here.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/lock.h>
#include <sys/rwlock.h>

#include <crypto/siphash.h>

#include <miscfs/vio9p/vio9p.h>
#include <dev/pv/vio9pvar.h>

/*
 * In-core inode cache keyed on the 9P qid.path.
 */
LIST_HEAD(vio9p_ihashhead, vio9p_node)	*vio9p_ihashtbl;
u_long		vio9p_ihashsz;		/* size of hash table - 1 */
SIPHASH_KEY	vio9p_ihashkey;

struct vio9p_ihashhead	*vio9p_ihash(uint64_t);
int			 vio9p_ihashins(struct vio9p_node *);

/*
 * Per-device fid pool.  A single mount per virtio-9p device (the single-mount
 * invariant, M2_DESIGN.md section 5.1), so a file-scope bitmap suffices for v1;
 * the struct vio9p_mnt argument is accepted for API stability but unused.  Fid 0
 * (VIO9P_FID_ROOT) is reserved for the attach-root fid and is never handed out
 * here.  vio9p_fid_alloc() returns a fid in [1, VIO9P_MAX_FIDS) or VIO9P_NOFID
 * on exhaustion.
 */
#define VIO9P_FIDMAP_WORDS	(VIO9P_MAX_FIDS / (sizeof(uint32_t) * NBBY))

uint32_t	vio9p_fidmap[VIO9P_FIDMAP_WORDS];
struct rwlock	vio9p_fidlock = RWLOCK_INITIALIZER("vio9pfid");

struct vio9p_ihashhead *
vio9p_ihash(uint64_t qidpath)
{
	SIPHASH_CTX ctx;

	SipHash24_Init(&ctx, &vio9p_ihashkey);
	SipHash24_Update(&ctx, &qidpath, sizeof(qidpath));

	return (&vio9p_ihashtbl[SipHash24_End(&ctx) & vio9p_ihashsz]);
}

/*
 * Initialize the inode hash table and the fid pool.  Called from vfs_init via
 * the vfsops vfs_init hook.
 */
void
vio9p_ihashinit(void)
{
	vio9p_ihashtbl = hashinit(initialvnodes, M_MISCFSMNT, M_WAITOK,
	    &vio9p_ihashsz);
	arc4random_buf(&vio9p_ihashkey, sizeof(vio9p_ihashkey));

	rw_enter_write(&vio9p_fidlock);
	memset(vio9p_fidmap, 0, sizeof(vio9p_fidmap));
	rw_exit_write(&vio9p_fidlock);
}

/*
 * Use the qid.path to find the in-core inode and return its vnode.  If it is in
 * core but locked, wait for it.  Mirrors fuse_ihashget(): the vget(LK_EXCLUSIVE)
 * + goto-loop serializes against a concurrent vop_reclaim of the same vnode.
 */
struct vnode *
vio9p_ihashget(uint64_t qidpath)
{
	struct vio9p_ihashhead	*ipp;
	struct vio9p_node	*ip;
	struct vnode		*vp;
loop:
	/* XXXLOCKING lock hash list */
	ipp = vio9p_ihash(qidpath);
	LIST_FOREACH(ip, ipp, n_hash) {
		if (qidpath == ip->n_qidpath) {
			vp = ip->n_vnode;
			/* XXXLOCKING unlock hash list? */
			if (vget(vp, LK_EXCLUSIVE))
				goto loop;

			return (vp);
		}
	}
	/* XXXLOCKING unlock hash list? */
	return (NULL);
}

/*
 * Insert the inode into the hash table and return it locked.  Returns EEXIST if
 * a racing thread already installed a node for the same qid.path (the EEXIST
 * collapse: two concurrent lookups of one host inode converge on one vnode).
 *
 * Contract (mirrors fuse_ihashins): on success the vnode is returned LOCKED
 * (VOP_LOCK held); on EEXIST it is returned UNLOCKED (VOP_UNLOCK already done),
 * so the caller must vrele() -- never vput() -- the loser vnode.
 */
int
vio9p_ihashins(struct vio9p_node *ip)
{
	struct vio9p_node	*curip;
	struct vio9p_ihashhead	*ipp;
	uint64_t		 qidpath = ip->n_qidpath;

	/* lock the inode, then put it on the appropriate hash list */
	VOP_LOCK(ip->n_vnode, LK_EXCLUSIVE);

	/* XXXLOCKING lock hash list */

	ipp = vio9p_ihash(qidpath);
	LIST_FOREACH(curip, ipp, n_hash) {
		if (qidpath == curip->n_qidpath) {
			/* XXXLOCKING unlock hash list? */
			VOP_UNLOCK(ip->n_vnode);
			return (EEXIST);
		}
	}

	LIST_INSERT_HEAD(ipp, ip, n_hash);
	/* XXXLOCKING unlock hash list? */

	return (0);
}

/*
 * Remove the inode from the hash table.  Called from vop_reclaim (the unique fid
 * clunk site, M2_DESIGN.md section 7.4) after the fid has been clunked.
 */
void
vio9p_ihashrem(struct vio9p_node *ip)
{
	/* XXXLOCKING lock hash list */

	if (ip->n_hash.le_prev == NULL)
		return;
	LIST_REMOVE(ip, n_hash);
#ifdef DIAGNOSTIC
	ip->n_hash.le_next = NULL;
	ip->n_hash.le_prev = NULL;
#endif
	/* XXXLOCKING unlock hash list? */
}

/*
 * Drop a REDUNDANT just-walked fid on a cache HIT.  Called from vio9p_vget when
 * vio9p_lookup's freshly Twalk-cloned `fid` turned out to alias a host inode that
 * a vnode in the hash already owns (the EEXIST collapse: hardlinks/dedup/"."/
 * ".."/a winning concurrent lookup).  The redundant fid was bound by the server's
 * Twalk but was never installed on a hashed node, so clunking it here is sound and
 * preserves FID-1 (every hashed node's owned fid is still clunked only in its own
 * vop_reclaim).  This is the single spot a walk fid is clunked outside reclaim
 * (M2_DESIGN.md section 7.3); the EEXIST-race arm of vio9p_vget does NOT use this
 * helper -- there the loser node still owns the fid and its own reclaim clunks it.
 *
 * The mount root fid (VIO9P_FID_ROOT) is owned by the mount, not by any vnode;
 * vio9p_root()/vfs_vget() pass it to vio9p_vget and on the (always-hit) revisit
 * it MUST NOT be clunked -- p9c_clunk would orphan the live session root.  Both
 * VIO9P_FID_ROOT and VIO9P_NOFID are therefore skipped here (vio9p_fid_free
 * already ignores them, but p9c_clunk must be skipped too).
 */
static void
vio9p_fid_drop(struct vio9p_mnt *vmp, uint32_t fid)
{
	if (fid == VIO9P_NOFID || fid == VIO9P_FID_ROOT)
		return;

	/* M3b: Tclunk carries no identity; use the mount-owner sentinel. */
	(void)p9c_clunk(vmp->vm_sc, fid, vmp->vm_owner_uid, vmp->vm_owner_gid);
	vio9p_fid_free(vmp, fid);
}

/*
 * Look up (or create) the vnode for a 9P qid, taking ownership of the caller's
 * just-walked `fid` on a cache miss.  Clone of fusefs_vget (fuse_vfsops.c:266).
 *
 * On a hash HIT another vnode already owns a fid for this host inode (the EEXIST
 * collapse).  The caller's `fid` is REDUNDANT: clunk+free it (vio9p_fid_drop,
 * skipping the mount root fid) and return the cached, locked vnode.
 *
 * On a MISS create a fresh vnode + struct vio9p_node that OWNS `fid`, set v_type
 * from the qid type, mark VROOT when qid.path == vm_rootpath, and ihashins under
 * an EEXIST-retry loop.  vio9p_vget is the SOLE owner of `fid` on every path:
 * on a hit it clunk+frees the redundant fid; on a miss it installs it on the new
 * node (clunked later in that node's vop_reclaim, the unique steady-state site);
 * on getnewvnode failure or a lost insert race it clunk+frees it inline exactly
 * once (taking it off the loser node first so the deferred reclaim cannot touch
 * it, and clearing the local copy so an EEXIST retry's hit cannot re-drop it).
 * The caller therefore NEVER clunks/frees `fid` after a successful Twalk.
 *
 * The returned vnode is LOCKED (VFS_VGET / vio9p_lookup contract).
 */
int
vio9p_vget(struct mount *mp, struct p9_qid *q, uint32_t fid, struct vnode **vpp)
{
	struct vio9p_mnt	*vmp;
	struct vio9p_node	*np;
	struct vnode		*nvp;
	int			 error;
retry:
	vmp = VFSTOVIO9P(mp);

	/*
	 * Check the hash.  On a hit the redundant walk fid is clunked+freed
	 * here -- the one spot a walk fid is clunked outside reclaim (the root
	 * fid is skipped, it belongs to the mount).
	 */
	if ((*vpp = vio9p_ihashget(q->path)) != NULL) {
		vio9p_fid_drop(vmp, fid);
		return (0);
	}

	if ((error = getnewvnode(VT_VIO9P, mp, &vio9p_vops, &nvp)) != 0) {
		printf("vio9p: getnewvnode error\n");
		vio9p_fid_drop(vmp, fid);	/* vget owns fid on every path */
		*vpp = NULL;
		return (error);
	}

	np = malloc(sizeof(*np), M_MISCFSMNT, M_WAITOK | M_ZERO);
	rrw_init_flags(&np->n_lock, "vio9pnode", RWL_DUPOK | RWL_IS_VNODE);
	nvp->v_data = np;
	np->n_vnode = nvp;
	np->n_mnt = vmp;
	np->n_fid = fid;		/* TAKE OWNERSHIP: clunked in reclaim */
	np->n_fid_opened = 0;
	np->n_qidpath = q->path;
	np->n_qidvers = q->version;
	np->n_qtype = q->type;

	switch (q->type) {
	case P9_QTDIR:
		nvp->v_type = VDIR;
		break;
	case P9_QTSYMLINK:
		nvp->v_type = VLNK;
		break;
	default:
		nvp->v_type = VREG;
		break;
	}

	if (q->path == vmp->vm_rootpath)
		nvp->v_flag |= VROOT;

	error = vio9p_ihashins(np);
	if (error) {
		/*
		 * Lost the insert race (EEXIST) or a hard insert error.
		 * ihashins returned the loser UNLOCKED (VOP_UNLOCK before
		 * EEXIST), so release with vrele(), not vput().
		 *
		 * Single-owner fid discipline (the D41844 crux): take the
		 * redundant walk fid OFF the loser node (n_fid = VIO9P_NOFID)
		 * so the loser's deferred vop_reclaim will NOT clunk it, then
		 * drop it explicitly here exactly once.  Clearing the local
		 * `fid` keeps a subsequent EEXIST-retry hash hit from dropping
		 * the same number a second time.  This makes vio9p_vget the
		 * sole owner of `fid` on every path, so the caller never
		 * clunks/frees it after a successful Twalk.
		 */
		np->n_fid = VIO9P_NOFID;
		vrele(nvp);
		vio9p_fid_drop(vmp, fid);
		fid = VIO9P_NOFID;

		if (error == EEXIST)
			goto retry;

		*vpp = NULL;
		return (error);
	}

	*vpp = nvp;
	return (0);
}

/*
 * Allocate a free fid in [1, VIO9P_MAX_FIDS).  Fid 0 (VIO9P_FID_ROOT) is
 * reserved.  Returns VIO9P_NOFID on exhaustion.  The mnt argument is unused for
 * now (single mount per device).
 */
uint32_t
vio9p_fid_alloc(struct vio9p_mnt *vmp)
{
	uint32_t fid;

	rw_enter_write(&vio9p_fidlock);
	for (fid = 1; fid < VIO9P_MAX_FIDS; fid++) {
		if ((vio9p_fidmap[fid / 32] & (1U << (fid % 32))) == 0) {
			vio9p_fidmap[fid / 32] |= (1U << (fid % 32));
			rw_exit_write(&vio9p_fidlock);
			return (fid);
		}
	}
	rw_exit_write(&vio9p_fidlock);
	return (VIO9P_NOFID);
}

/*
 * Return a fid to the pool.  VIO9P_NOFID and VIO9P_FID_ROOT are ignored.
 */
void
vio9p_fid_free(struct vio9p_mnt *vmp, uint32_t fid)
{
	if (fid == VIO9P_NOFID || fid == VIO9P_FID_ROOT || fid >= VIO9P_MAX_FIDS)
		return;

	rw_enter_write(&vio9p_fidlock);
	vio9p_fidmap[fid / 32] &= ~(1U << (fid % 32));
	rw_exit_write(&vio9p_fidlock);
}
