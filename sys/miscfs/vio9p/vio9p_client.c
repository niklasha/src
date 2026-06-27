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
 * vio9p 9P2000.L client protocol layer.  Builds T-messages, frames and
 * submits them through the vio9p(4) transport (vio9p_submit), validates the
 * reply envelope, then parses the typed R-body or translates an Rlerror.
 *
 * This is the exact inverse of the host server's wire contract
 * (usr.sbin/vmd/viofs.c): the encode/decode primitives mirror the server's
 * little-endian put/get and 9P request/response cursors, and p9c_errno is the
 * reverse of viofs.c errno_xlate().  Every decode bounds-checks the reply
 * length, so a truncated or hostile reply yields EIO, never an OOB read.
 *
 * M2c scope: version, attach, clunk, getattr, statfs (M2b) plus the file-I/O
 * path -- walk, lopen, read, readdir and readlink.
 *
 * M3 scope: the write/mutate RPCs -- write, lcreate, mkdir, unlinkat, setattr,
 * renameat, symlink and link.  Each is the exact inverse of a host p9_* write
 * handler and reuses the same encode/decode/p9c_rpc machinery, so a hostile or
 * truncated reply still yields EIO, never an OOB.  The host (not the guest) is
 * the security boundary: it re-checks viofs_writable and per-op identity.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <machine/bus.h>
#include <sys/device.h>
#include <sys/rwlock.h>
#include <sys/vnode.h>
#include <sys/mount.h>

#include <dev/pv/virtiovar.h>
#include <dev/pv/vio9preg.h>
#include <dev/pv/vio9pvar.h>

#include <miscfs/vio9p/vio9p.h>

/*
 * Linux errno values carried in Rlerror{ecode[4]}.  These are the WIRE
 * numbers (mirror viofs.c:127-153), NOT the host <sys/errno.h> values.  Only
 * the names that diverge from the OpenBSD numbers are listed; below 35 (and
 * outside the swap pair) the numbers coincide.
 */
#define L_EAGAIN	11
#define L_EDEADLK	35
#define L_ENAMETOOLONG	36
#define L_ENOLCK	37
#define L_ENOSYS	38
#define L_ENOTEMPTY	39
#define L_ELOOP		40
#define L_ENODATA	61
#define L_EOVERFLOW	75
#define L_EMSGSIZE	90
#define L_EOPNOTSUPP	95

/*
 * One RPC at a time uses these file-scope scratch buffers.  vio9p_submit()
 * serializes per softc, but the buffers below are shared across every mount/
 * softc, so a dedicated lock guards the framing-to-parse window.
 */
static uint8_t		p9c_txbuf[VIO9P_MSIZE_MAX];
static uint8_t		p9c_rxbuf[VIO9P_MSIZE_MAX];
static struct rwlock	p9c_lock = RWLOCK_INITIALIZER("vio9prpc");

/* The single tag used by the steady-state single-outstanding model. */
#define P9C_TAG		0

/* ---- little-endian byte helpers (mirror viofs.c:189-229) ---- */
static inline uint16_t
get_le16(const uint8_t *p)
{
	return ((uint16_t)(p[0] | (p[1] << 8)));
}

static inline uint32_t
get_le32(const uint8_t *p)
{
	return (((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
	    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static inline uint64_t
get_le64(const uint8_t *p)
{
	return ((uint64_t)get_le32(p) | ((uint64_t)get_le32(p + 4) << 32));
}

static inline void
put_le16(uint8_t *p, uint16_t v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
}

static inline void
put_le32(uint8_t *p, uint32_t v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

static inline void
put_le64(uint8_t *p, uint64_t v)
{
	put_le32(p, (uint32_t)v);
	put_le32(p + 4, (uint32_t)(v >> 32));
}

/* ---- request builder (bounds-checked, mirrors viofs.c struct p9_resp) ---- */
struct p9c_enc {
	uint8_t		*buf;
	size_t		 cap;
	size_t		 len;
	int		 err;
};

static void
p9c_put8(struct p9c_enc *e, uint8_t v)
{
	if (e->err || e->len + 1 > e->cap) {
		e->err = 1;
		return;
	}
	e->buf[e->len++] = v;
}

static void
p9c_put16(struct p9c_enc *e, uint16_t v)
{
	if (e->err || e->len + 2 > e->cap) {
		e->err = 1;
		return;
	}
	put_le16(&e->buf[e->len], v);
	e->len += 2;
}

static void
p9c_put32(struct p9c_enc *e, uint32_t v)
{
	if (e->err || e->len + 4 > e->cap) {
		e->err = 1;
		return;
	}
	put_le32(&e->buf[e->len], v);
	e->len += 4;
}

static void
p9c_put64(struct p9c_enc *e, uint64_t v)
{
	if (e->err || e->len + 8 > e->cap) {
		e->err = 1;
		return;
	}
	put_le64(&e->buf[e->len], v);
	e->len += 8;
}

/* Write a 9P string[s]: count[2] then bytes (no terminator). */
static void
p9c_puts(struct p9c_enc *e, const char *s, size_t n)
{
	p9c_put16(e, (uint16_t)n);
	if (e->err || e->len + n > e->cap) {
		e->err = 1;
		return;
	}
	if (n > 0)
		memcpy(&e->buf[e->len], s, n);
	e->len += n;
}

/*
 * Begin a T-message: reserve the header (size placeholder, type, tag).  The
 * size[0..3] field is patched at submit time once the body length is known.
 */
static void
p9c_enc_start(struct p9c_enc *e, uint8_t *buf, size_t cap, uint8_t ttype)
{
	e->buf = buf;
	e->cap = cap;
	e->len = 0;
	e->err = 0;
	p9c_put32(e, 0);		/* size placeholder */
	p9c_put8(e, ttype);
	p9c_put16(e, P9C_TAG);
}

/* ---- reply cursor (bounds-checked, mirrors viofs.c struct p9_treq) ---- */
struct p9c_dec {
	const uint8_t	*buf;
	size_t		 len;
	size_t		 off;
	int		 err;
};

static void
p9c_dec_init(struct p9c_dec *d, const uint8_t *buf, size_t len)
{
	d->buf = buf;
	d->len = len;
	d->off = P9_HDRLEN;		/* skip size[4] type[1] tag[2] */
	d->err = 0;
}

static uint8_t
p9c_get8(struct p9c_dec *d)
{
	uint8_t v;

	if (d->err || d->off + 1 > d->len) {
		d->err = 1;
		return (0);
	}
	v = d->buf[d->off];
	d->off += 1;
	return (v);
}

static uint16_t
p9c_get16(struct p9c_dec *d)
{
	uint16_t v;

	if (d->err || d->off + 2 > d->len) {
		d->err = 1;
		return (0);
	}
	v = get_le16(&d->buf[d->off]);
	d->off += 2;
	return (v);
}

static uint32_t
p9c_get32(struct p9c_dec *d)
{
	uint32_t v;

	if (d->err || d->off + 4 > d->len) {
		d->err = 1;
		return (0);
	}
	v = get_le32(&d->buf[d->off]);
	d->off += 4;
	return (v);
}

static uint64_t
p9c_get64(struct p9c_dec *d)
{
	uint64_t v;

	if (d->err || d->off + 8 > d->len) {
		d->err = 1;
		return (0);
	}
	v = get_le64(&d->buf[d->off]);
	d->off += 8;
	return (v);
}

/*
 * Copy n raw bytes out of the reply at the cursor into dst, bounds-checked
 * against the validated reply length.  Used for the opaque Rread/Rreaddir
 * payloads, where the count[4] just read bounds how many data bytes follow;
 * a hostile or truncated reply (count claims more than arrived) sets err and
 * copies nothing, so the caller surfaces EIO rather than reading past rxlen.
 */
static void
p9c_getdata(struct p9c_dec *d, void *dst, size_t n)
{
	if (d->err || d->off + n > d->len) {
		d->err = 1;
		return;
	}
	if (n > 0)
		memcpy(dst, &d->buf[d->off], n);
	d->off += n;
}

/* Read a 9P string[s] into out (NUL-terminated); rejects embedded NUL. */
static void
p9c_gets(struct p9c_dec *d, char *out, size_t outsz)
{
	uint16_t n;

	if (d->err || d->off + 2 > d->len) {
		d->err = 1;
		if (outsz > 0)
			out[0] = '\0';
		return;
	}
	n = get_le16(&d->buf[d->off]);
	d->off += 2;
	if (d->off + n > d->len || (size_t)n >= outsz) {
		d->err = 1;
		if (outsz > 0)
			out[0] = '\0';
		return;
	}
	if (n > 0 && memchr(&d->buf[d->off], '\0', n) != NULL) {
		d->err = 1;
		out[0] = '\0';
		return;
	}
	if (n > 0)
		memcpy(out, &d->buf[d->off], n);
	out[n] = '\0';
	d->off += n;
}

/* Parse qid[13] = type[1] version[4] path[8]. */
static void
p9c_getqid(struct p9c_dec *d, struct p9_qid *q)
{
	q->type = p9c_get8(d);
	q->version = p9c_get32(d);
	q->path = p9c_get64(d);
}

/*
 * Reverse of viofs.c:313-349 errno_xlate(): a Linux errno on the wire to an
 * OpenBSD errno.  Switch on the LINUX value only -- never round-trip through
 * an OpenBSD number, because Linux 40 (ELOOP) and Linux 90 (EMSGSIZE) both
 * map onto OpenBSD number 40, and Linux 11/35 are a swap of OpenBSD 35/11.
 * Values below 35, except the 11/35 swap, are identity.
 */
int
p9c_errno(uint32_t lerr)
{
	switch (lerr) {
	case 0:
		return (0);
	case L_EAGAIN:			/* Linux 11 -> OpenBSD 35 */
		return (EAGAIN);
	case L_EDEADLK:			/* Linux 35 -> OpenBSD 11 */
		return (EDEADLK);
	case L_ENAMETOOLONG:		/* Linux 36 -> OpenBSD 63 */
		return (ENAMETOOLONG);
	case L_ENOLCK:			/* Linux 37 -> OpenBSD 77 */
		return (ENOLCK);
	case L_ENOSYS:			/* Linux 38 -> OpenBSD 78 */
		return (ENOSYS);
	case L_ENOTEMPTY:		/* Linux 39 -> OpenBSD 66 */
		return (ENOTEMPTY);
	case L_ELOOP:			/* Linux 40 -> OpenBSD 62 */
		return (ELOOP);
	case L_ENODATA:			/* Linux 61 -> OpenBSD 83 */
		return (ENOATTR);
	case L_EOVERFLOW:		/* Linux 75 -> OpenBSD 87 */
		return (EOVERFLOW);
	case L_EMSGSIZE:		/* Linux 90 -> OpenBSD 40 */
		return (EMSGSIZE);
	case L_EOPNOTSUPP:		/* Linux 95 -> OpenBSD 45 */
		return (EOPNOTSUPP);
	default:
		/*
		 * 1..34 (EPERM..ERANGE), minus the 11/35 swap handled above,
		 * coincide between Linux and OpenBSD.  Anything else (incl.
		 * unmapped high Linux numbers) is EIO, mirroring the server's
		 * default (viofs.c:347).
		 */
		if (lerr >= 1 && lerr <= 34)
			return ((int)lerr);
		return (EIO);
	}
}

/*
 * Frame, submit, and validate one RPC.  enc carries the already-built body;
 * its size[0..3] and the transport tag are patched here.  On return *rxlenp
 * holds the validated reply length and rxbuf the reply bytes; the caller may
 * then parse the typed body starting at offset P9_HDRLEN.
 *
 * Validation order (before any typed parse, symmetric to viofs.c:565-574):
 *   - the encoder did not overflow;
 *   - the transport returned a reply of at least the 7-byte header;
 *   - the declared size[0..3] equals the returned length and is within
 *     [P9_HDRLEN, sc_msize];
 *   - the echoed tag matches;
 *   - the type is the expected R-type, or P9_RLERROR (translated), else EIO.
 */
static int
p9c_rpc(struct vio9p_softc *sc, struct p9c_enc *enc, uint8_t rtype,
    uint8_t *rxbuf, size_t rxcap, size_t *rxlenp)
{
	struct p9c_dec dec;
	size_t rxlen = 0;
	uint32_t declared, ecode;
	uint16_t tag;
	uint8_t type;
	int error;

	if (enc->err)
		return (EIO);

	/* Patch the framed size now that the body length is final. */
	put_le32(&enc->buf[0], (uint32_t)enc->len);

	if (enc->len < P9_HDRLEN || enc->len > sc->sc_msize)
		return (EIO);

	error = vio9p_submit(sc, enc->buf, enc->len, rxbuf, rxcap, &rxlen);
	if (error != 0)
		return (error);

	if (rxlen < P9_HDRLEN)
		return (EIO);
	declared = get_le32(rxbuf);
	if (declared != rxlen || declared < P9_HDRLEN ||
	    declared > sc->sc_msize)
		return (EIO);
	type = rxbuf[4];
	tag = get_le16(&rxbuf[5]);
	if (tag != P9C_TAG)
		return (EIO);

	if (type == P9_RLERROR) {
		p9c_dec_init(&dec, rxbuf, rxlen);
		ecode = p9c_get32(&dec);
		if (dec.err)
			return (EIO);
		return (p9c_errno(ecode));
	}
	if (type != rtype)
		return (EIO);

	*rxlenp = rxlen;
	return (0);
}

/*
 * Tversion: propose msize=VIO9P_MSIZE_MAX and version "9P2000.L"; store the
 * server's returned (clamped) msize in sc->sc_msize.  Sent once at mount,
 * before any fid exists (a new Tversion orphans every server fid).
 * Tversion[msize[4] version[s]] -> Rversion[msize[4] version[s]].
 */
int
p9c_version(struct vio9p_softc *sc)
{
	struct p9c_enc enc;
	struct p9c_dec dec;
	char ver[32];
	size_t rxlen = 0;
	uint32_t msize;
	int error;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TVERSION);
	/*
	 * The proposal must fit the static scratch buffers; the negotiated
	 * msize bounds every later RPC.  Tversion itself uses NOTAG, but the
	 * server echoes whatever tag it receives, so P9C_TAG is consistent.
	 */
	p9c_put32(&enc, VIO9P_MSIZE_MAX);
	p9c_puts(&enc, VIO9P_VERSION_STR, strlen(VIO9P_VERSION_STR));

	/*
	 * sc_msize is the transport's max (VIO9P_MSIZE_MAX) until we lower it
	 * below, so p9c_rpc's size bound holds for this first exchange.
	 */
	error = p9c_rpc(sc, &enc, P9_RVERSION, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);
	if (error != 0)
		goto out;

	p9c_dec_init(&dec, p9c_rxbuf, rxlen);
	msize = p9c_get32(&dec);
	p9c_gets(&dec, ver, sizeof(ver));
	if (dec.err) {
		error = EIO;
		goto out;
	}
	if (msize < VIO9P_MSIZE_MIN || msize > VIO9P_MSIZE_MAX) {
		error = EIO;
		goto out;
	}
	if (strncmp(ver, VIO9P_VERSION_STR, sizeof(VIO9P_VERSION_STR)) != 0) {
		error = EINVAL;
		goto out;
	}
	sc->sc_msize = msize;
out:
	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Tattach: bind fid to the share root, afid=NOFID (no auth), uname/aname
 * empty (server squashes and the root is fixed), n_uname=NOFID.
 * Tattach[fid[4] afid[4] uname[s] aname[s] n_uname[4]] -> Rattach[qid[13]].
 */
int
p9c_attach(struct vio9p_softc *sc, uint32_t fid, struct p9_qid *root_qid)
{
	struct p9c_enc enc;
	struct p9c_dec dec;
	size_t rxlen = 0;
	int error;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TATTACH);
	p9c_put32(&enc, fid);
	p9c_put32(&enc, P9_NOFID);		/* afid: no auth */
	p9c_puts(&enc, "", 0);			/* uname (squashed) */
	p9c_puts(&enc, "", 0);			/* aname (root fixed) */
	p9c_put32(&enc, P9_NOFID);		/* n_uname */

	error = p9c_rpc(sc, &enc, P9_RATTACH, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);
	if (error != 0)
		goto out;

	p9c_dec_init(&dec, p9c_rxbuf, rxlen);
	p9c_getqid(&dec, root_qid);
	if (dec.err)
		error = EIO;
out:
	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Tclunk: forget fid server-side.  After Rclunk (or even on an error -- the
 * server fid is gone either way) the caller returns the fid to the pool.
 * Tclunk[fid[4]] -> Rclunk[] (header only).
 */
int
p9c_clunk(struct vio9p_softc *sc, uint32_t fid)
{
	struct p9c_enc enc;
	size_t rxlen = 0;
	int error;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TCLUNK);
	p9c_put32(&enc, fid);

	error = p9c_rpc(sc, &enc, P9_RCLUNK, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);

	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Tgetattr: fetch the basic attribute set.  The Rgetattr body is built by the
 * server at viofs.c:1064-1084 and is parsed here field-for-field; trailing
 * btime/gen/data_version come back zeroed (masked) and are ignored.
 * Tgetattr[fid[4] request_mask[8]] ->
 *   Rgetattr[valid[8] qid[13] mode[4] uid[4] gid[4] nlink[8] rdev[8] size[8]
 *            blksize[8] blocks[8] atime_sec[8] atime_nsec[8] mtime_sec[8]
 *            mtime_nsec[8] ctime_sec[8] ctime_nsec[8] btime_sec[8]
 *            btime_nsec[8] gen[8] data_version[8]].
 */
int
p9c_getattr(struct vio9p_softc *sc, uint32_t fid, struct p9_attr *a)
{
	struct p9c_enc enc;
	struct p9c_dec dec;
	size_t rxlen = 0;
	int error;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TGETATTR);
	p9c_put32(&enc, fid);
	p9c_put64(&enc, P9_GETATTR_BASIC);	/* request_mask */

	error = p9c_rpc(sc, &enc, P9_RGETATTR, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);
	if (error != 0)
		goto out;

	p9c_dec_init(&dec, p9c_rxbuf, rxlen);
	(void)p9c_get64(&dec);			/* valid mask (ignored) */
	p9c_getqid(&dec, &a->qid);
	a->mode = p9c_get32(&dec);
	a->uid = p9c_get32(&dec);
	a->gid = p9c_get32(&dec);
	a->nlink = p9c_get64(&dec);
	a->rdev = p9c_get64(&dec);
	a->size = p9c_get64(&dec);
	a->blksize = p9c_get64(&dec);
	a->blocks = p9c_get64(&dec);
	a->atime_sec = (int64_t)p9c_get64(&dec);
	a->atime_nsec = (uint32_t)p9c_get64(&dec);
	a->mtime_sec = (int64_t)p9c_get64(&dec);
	a->mtime_nsec = (uint32_t)p9c_get64(&dec);
	a->ctime_sec = (int64_t)p9c_get64(&dec);
	a->ctime_nsec = (uint32_t)p9c_get64(&dec);
	/* btime_sec/btime_nsec/gen/data_version trailing -- masked, ignored. */
	if (dec.err)
		error = EIO;
out:
	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Tstatfs: filesystem statistics for the (root) fid.  The Rstatfs body is
 * built by the server at viofs.c:1237-1246; type[4] (V9FS_MAGIC) is consumed
 * and surfaced but typically ignored by the caller.
 * Tstatfs[fid[4]] ->
 *   Rstatfs[type[4] bsize[4] blocks[8] bfree[8] bavail[8] files[8] ffree[8]
 *           fsid[8] namelen[4]].
 */
int
p9c_statfs(struct vio9p_softc *sc, uint32_t fid, struct p9_statfs *s)
{
	struct p9c_enc enc;
	struct p9c_dec dec;
	size_t rxlen = 0;
	int error;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TSTATFS);
	p9c_put32(&enc, fid);

	error = p9c_rpc(sc, &enc, P9_RSTATFS, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);
	if (error != 0)
		goto out;

	p9c_dec_init(&dec, p9c_rxbuf, rxlen);
	s->type = p9c_get32(&dec);
	s->bsize = p9c_get32(&dec);
	s->blocks = p9c_get64(&dec);
	s->bfree = p9c_get64(&dec);
	s->bavail = p9c_get64(&dec);
	s->files = p9c_get64(&dec);
	s->ffree = p9c_get64(&dec);
	s->fsid = p9c_get64(&dec);
	s->namelen = p9c_get32(&dec);
	if (dec.err)
		error = EIO;
out:
	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Twalk: clone or descend a fid by ONE component.  This mirrors the server's
 * p9_walk (viofs.c:786) restricted to the two shapes the in-kernel client
 * ever needs: a fid-clone (name == NULL -> nwname=0) and a single-component
 * descent (name != NULL -> nwname=1).  Multi-component walks are deliberately
 * not exposed; vop_lookup resolves one path element per call.
 *
 *   Twalk[fid[4] newfid[4] nwname[2] (wname[s])*nwname] ->
 *     Rwalk[nwqid[2] (qid[13])*nwqid].
 *
 * Caller contract (M2_DESIGN.md sections 4.6/6.1):
 *   - newfid must be a freshly allocated, server-unbound fid (vio9p_fid_alloc).
 *   - On success (return 0) the server has BOUND newfid to the walked target;
 *     the caller (vio9p_vget) takes ownership and the fid is clunked only in
 *     vop_reclaim.  *wqid receives the LAST walked qid (the target); *nwqid
 *     receives the number of qids the server returned.
 *   - A short Rwalk (nwqid < nwname) means the server bound NOTHING
 *     (viofs.c:964 binds newfid only on a full walk) -> ENOENT, and the caller
 *     returns newfid to the pool WITHOUT a Tclunk (the server never bound it).
 *   - On any transport/protocol error (return != 0) the server likewise bound
 *     nothing (it only replies Rwalk on a full walk); caller frees newfid
 *     without Tclunk.
 *   - If the returned *wqid.type is P9_QTSYMLINK the server stopped AT a
 *     symlink and bound newfid as a symlink-fid (viofs.c:978); the caller must
 *     not Twalk through it -- it issues p9c_readlink and resolves in the guest
 *     namespace (NFS model).
 */
int
p9c_walk(struct vio9p_softc *sc, uint32_t fid, uint32_t newfid,
    const char *name, struct p9_qid *wqid, int *nwqid)
{
	struct p9c_enc enc;
	struct p9c_dec dec;
	struct p9_qid q;
	size_t rxlen = 0;
	uint16_t nwname, nwq, i;
	int error;

	nwname = (name != NULL) ? 1 : 0;
	*nwqid = 0;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TWALK);
	p9c_put32(&enc, fid);
	p9c_put32(&enc, newfid);
	p9c_put16(&enc, nwname);
	if (nwname == 1)
		p9c_puts(&enc, name, strlen(name));

	error = p9c_rpc(sc, &enc, P9_RWALK, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);
	if (error != 0)
		goto out;

	p9c_dec_init(&dec, p9c_rxbuf, rxlen);
	nwq = p9c_get16(&dec);
	if (dec.err || nwq > P9_MAXWELEM) {
		error = EIO;
		goto out;
	}
	/*
	 * Read every returned qid so the cursor stays consistent and the last
	 * one (the target) lands in *wqid.  On a clone (nwname==0) the server
	 * returns nwq==0 and *wqid is left untouched (clone reuses the source
	 * qid -- the caller already has it).
	 */
	for (i = 0; i < nwq; i++) {
		p9c_getqid(&dec, &q);
		if (dec.err) {
			error = EIO;
			goto out;
		}
	}
	if (nwq < nwname) {
		/* Server bound nothing (viofs.c:964): component absent. */
		error = ENOENT;
		goto out;
	}
	if (nwname == 1)
		*wqid = q;
	*nwqid = nwq;
out:
	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Tlopen: open the file the fid refers to with Linux open flags.  The server
 * (viofs.c:1087) flips its per-fid "opened" flag IN PLACE -- no second fid is
 * created -- so the same walk fid that vop_lookup bound becomes the I/O fid.
 * RO callers pass flags=0 (L_O_RDONLY); any write bit makes the server reply
 * L_EROFS, a symlink-fid L_ELOOP.
 *   Tlopen[fid[4] flags[4]] -> Rlopen[qid[13] iounit[4]].
 * The qid is consumed but not surfaced (the caller already cached it from the
 * walk/getattr); *iounit receives the server's per-op transfer hint, 0 meaning
 * "use msize" (viofs.c:1122) -- the caller falls back to vm_iomax.
 */
int
p9c_lopen(struct vio9p_softc *sc, uint32_t fid, uint32_t flags,
    uint32_t *iounit)
{
	struct p9c_enc enc;
	struct p9c_dec dec;
	struct p9_qid q;
	size_t rxlen = 0;
	uint32_t iu;
	int error;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TLOPEN);
	p9c_put32(&enc, fid);
	p9c_put32(&enc, flags);

	error = p9c_rpc(sc, &enc, P9_RLOPEN, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);
	if (error != 0)
		goto out;

	p9c_dec_init(&dec, p9c_rxbuf, rxlen);
	p9c_getqid(&dec, &q);			/* qid (cached elsewhere) */
	iu = p9c_get32(&dec);
	if (dec.err) {
		error = EIO;
		goto out;
	}
	if (iounit != NULL)
		*iounit = iu;
out:
	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Tread: read up to len bytes of a regular file at byte offset off into buf.
 * count is clamped to the negotiated payload budget (msize - 11, the Rread
 * header) so the reply always fits the scratch buffer; the caller loops to
 * satisfy a larger request.  *got receives the bytes returned; *got==0 is EOF.
 * The server refuses a dir fid (L_EISDIR), a symlink-fid (L_ELOOP), and an
 * unopened fid (L_EBADF -- a client bug).
 *   Tread[fid[4] offset[8] count[4]] -> Rread[count[4] data[count]].
 */
int
p9c_read(struct vio9p_softc *sc, uint32_t fid, uint64_t off, void *buf,
    uint32_t len, uint32_t *got)
{
	struct p9c_enc enc;
	struct p9c_dec dec;
	size_t rxlen = 0;
	uint32_t count, n;
	int error;

	*got = 0;

	count = len;
	if (count > sc->sc_msize - P9_READ_IOHDRSZ)
		count = sc->sc_msize - P9_READ_IOHDRSZ;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TREAD);
	p9c_put32(&enc, fid);
	p9c_put64(&enc, off);
	p9c_put32(&enc, count);

	error = p9c_rpc(sc, &enc, P9_RREAD, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);
	if (error != 0)
		goto out;

	p9c_dec_init(&dec, p9c_rxbuf, rxlen);
	n = p9c_get32(&dec);
	if (dec.err || n > count) {	/* server must not exceed what we asked */
		error = EIO;
		goto out;
	}
	p9c_getdata(&dec, buf, n);	/* bounds-checks n against rxlen */
	if (dec.err) {
		error = EIO;
		goto out;
	}
	*got = n;
out:
	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Treaddir: fetch a chunk of the directory stream for an opened dir fid at the
 * opaque 9P cookie off (NOT a byte offset -- the server lseek()s to it,
 * viofs.c:1368; the first call passes 0).  The raw per-entry wire stream
 *   (qid[13] off[8] type[1] namelen[2] name[namelen])*
 * is copied verbatim into buf; *got receives its byte length (0 == end of
 * directory).  The vnops layer (vio9p_dirents_to_uio) parses the entries and,
 * critically, carries each entry's off[8] forward as the next cookie.  count
 * is clamped to the payload budget so the reply fits the scratch buffer.
 *   Treaddir[fid[4] offset[8] count[4]] -> Rreaddir[count[4] data[count]].
 */
int
p9c_readdir(struct vio9p_softc *sc, uint32_t fid, uint64_t off, void *buf,
    uint32_t len, uint32_t *got)
{
	struct p9c_enc enc;
	struct p9c_dec dec;
	size_t rxlen = 0;
	uint32_t count, n;
	int error;

	*got = 0;

	count = len;
	if (count > sc->sc_msize - P9_READ_IOHDRSZ)
		count = sc->sc_msize - P9_READ_IOHDRSZ;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TREADDIR);
	p9c_put32(&enc, fid);
	p9c_put64(&enc, off);
	p9c_put32(&enc, count);

	error = p9c_rpc(sc, &enc, P9_RREADDIR, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);
	if (error != 0)
		goto out;

	p9c_dec_init(&dec, p9c_rxbuf, rxlen);
	n = p9c_get32(&dec);
	if (dec.err || n > count) {
		error = EIO;
		goto out;
	}
	p9c_getdata(&dec, buf, n);	/* bounds-checks n against rxlen */
	if (dec.err) {
		error = EIO;
		goto out;
	}
	*got = n;
out:
	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Treadlink: read a symlink target for a symlink-fid.  The server only honors
 * this on a fid it bound as a symlink (viofs.c:1200, else L_EINVAL) and
 * returns the target VERBATIM, unresolved (viofs.c:1209) -- guest-side
 * resolution is the caller's job (NFS model).  The decoded string is copied
 * into buf (NUL-terminated; embedded NUL is rejected by p9c_gets, surfacing
 * EIO) and *lenp receives its length (excluding the terminator).  bufsz must
 * be large enough (PATH_MAX) or the server's reply overflows it -> EIO.
 *   Treadlink[fid[4]] -> Rreadlink[target[s]].
 */
int
p9c_readlink(struct vio9p_softc *sc, uint32_t fid, char *buf, size_t bufsz,
    size_t *lenp)
{
	struct p9c_enc enc;
	struct p9c_dec dec;
	size_t rxlen = 0;
	int error;

	if (lenp != NULL)
		*lenp = 0;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TREADLINK);
	p9c_put32(&enc, fid);

	error = p9c_rpc(sc, &enc, P9_RREADLINK, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);
	if (error != 0)
		goto out;

	p9c_dec_init(&dec, p9c_rxbuf, rxlen);
	p9c_gets(&dec, buf, bufsz);	/* rejects embedded NUL + overflow */
	if (dec.err) {
		error = EIO;
		goto out;
	}
	if (lenp != NULL)
		*lenp = strlen(buf);
out:
	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Twrite: write up to len bytes at byte offset off from buf.  count is clamped
 * to the negotiated payload budget so the request fits the static scratch
 * buffer (the Twrite header beyond P9_HDRLEN is fid[4] offset[8] count[4] = 16
 * bytes, so the budget is msize - P9_WRITE_HDR).  The caller loops for a larger
 * request.  *put receives bytes accepted; a short write is normal (the vnops
 * layer re-issues from the new offset).  The server refuses a dir fid
 * (L_EISDIR), a symlink fid (L_ELOOP), an unopened/!writable fid (L_EBADF/
 * L_EROFS), and a RO share (L_EROFS).
 *   Twrite[fid[4] offset[8] count[4] data[count]] -> Rwrite[count[4]].
 */
#define P9_WRITE_HDR	(P9_HDRLEN + 4 + 8 + 4)	/* hdr+fid+offset+count = 23 */
int
p9c_write(struct vio9p_softc *sc, uint32_t fid, uint64_t off, const void *buf,
    uint32_t len, uint32_t *put)
{
	struct p9c_enc enc;
	struct p9c_dec dec;
	size_t rxlen = 0;
	uint32_t count, n;
	int error;

	*put = 0;

	count = len;
	if (count > sc->sc_msize - P9_WRITE_HDR)
		count = sc->sc_msize - P9_WRITE_HDR;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TWRITE);
	p9c_put32(&enc, fid);
	p9c_put64(&enc, off);
	p9c_put32(&enc, count);
	/* Append the data bytes; bounds-check against the encoder cap. */
	if (!enc.err && enc.len + count <= enc.cap) {
		if (count > 0)
			memcpy(&enc.buf[enc.len], buf, count);
		enc.len += count;
	} else
		enc.err = 1;

	error = p9c_rpc(sc, &enc, P9_RWRITE, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);
	if (error != 0)
		goto out;

	p9c_dec_init(&dec, p9c_rxbuf, rxlen);
	n = p9c_get32(&dec);
	if (dec.err || n > count) {	/* server must not claim more than asked */
		error = EIO;
		goto out;
	}
	*put = n;
out:
	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Tlcreate: create a regular file `name` in the directory `fid` and OPEN it.
 * Per 9P2000.L the server REPLACES `fid` (the dir fid) with the new, opened
 * file fid -- so the caller MUST pass a freshly Twalk-cloned, dir-derived fid
 * it is willing to convert into the file fid (vop_create owns that contract).
 * flags are Linux O_* (the caller passes L_O_WRONLY|L_O_CREAT|L_O_EXCL etc.;
 * the server adds O_CREAT|O_NOFOLLOW|O_CLOEXEC and masks SUID/SGID/sticky from
 * mode).  *qid receives the new file's qid; *iounit the transfer hint (0 ==
 * use msize -- the caller falls back to vm_iomax).
 *
 * Fid disposition on ERROR (host_handlers.c p9_lcreate): an openat() failure
 * leaves the directory fid STILL BOUND server-side (the slot's fd/is_dir are
 * untouched), so the caller MUST p9c_clunk(fid) before returning it to the
 * pool -- it is not implicitly freed (FIX D4).
 *   Tlcreate[fid[4] name[s] flags[4] mode[4] gid[4]] -> Rlcreate[qid[13] iounit[4]].
 */
int
p9c_lcreate(struct vio9p_softc *sc, uint32_t fid, const char *name,
    uint32_t flags, uint32_t mode, uint32_t gid, struct p9_qid *qid,
    uint32_t *iounit)
{
	struct p9c_enc enc;
	struct p9c_dec dec;
	size_t rxlen = 0;
	uint32_t iu;
	int error;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TLCREATE);
	p9c_put32(&enc, fid);
	p9c_puts(&enc, name, strlen(name));
	p9c_put32(&enc, flags);
	p9c_put32(&enc, mode);
	p9c_put32(&enc, gid);

	error = p9c_rpc(sc, &enc, P9_RLCREATE, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);
	if (error != 0)
		goto out;

	p9c_dec_init(&dec, p9c_rxbuf, rxlen);
	p9c_getqid(&dec, qid);
	iu = p9c_get32(&dec);
	if (dec.err) {
		error = EIO;
		goto out;
	}
	if (iounit != NULL)
		*iounit = iu;
out:
	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Tmkdir: create directory `name` in dir `dfid` (mode masked server-side).
 * Unlike Tlcreate the fid is NOT replaced; only the new qid comes back.  The
 * caller then Twalk-clones a fresh fid for the child vnode (lookup-after-create).
 *   Tmkdir[dfid[4] name[s] mode[4] gid[4]] -> Rmkdir[qid[13]].
 */
int
p9c_mkdir(struct vio9p_softc *sc, uint32_t dfid, const char *name,
    uint32_t mode, uint32_t gid, struct p9_qid *qid)
{
	struct p9c_enc enc;
	struct p9c_dec dec;
	size_t rxlen = 0;
	int error;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TMKDIR);
	p9c_put32(&enc, dfid);
	p9c_puts(&enc, name, strlen(name));
	p9c_put32(&enc, mode);
	p9c_put32(&enc, gid);

	error = p9c_rpc(sc, &enc, P9_RMKDIR, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);
	if (error != 0)
		goto out;

	p9c_dec_init(&dec, p9c_rxbuf, rxlen);
	p9c_getqid(&dec, qid);
	if (dec.err)
		error = EIO;
out:
	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Tunlinkat: remove `name` from dir `dfid`.  flags carries P9_AT_REMOVEDIR for
 * rmdir, 0 for unlink (the vnops layer sets it by op).  Runlinkat is header-only.
 *   Tunlinkat[dfid[4] name[s] flags[4]] -> Runlinkat[].
 */
int
p9c_unlinkat(struct vio9p_softc *sc, uint32_t dfid, const char *name,
    uint32_t flags)
{
	struct p9c_enc enc;
	size_t rxlen = 0;
	int error;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TUNLINKAT);
	p9c_put32(&enc, dfid);
	p9c_puts(&enc, name, strlen(name));
	p9c_put32(&enc, flags);

	error = p9c_rpc(sc, &enc, P9_RUNLINKAT, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);

	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Tsetattr: apply the attributes selected by `valid` to `fid`.  In squash mode
 * the caller never sets P9_SETATTR_UID/GID, but the wire fields are always sent
 * (the server ignores uid/gid in squash).  Rsetattr is header-only.
 *   Tsetattr[fid[4] valid[4] mode[4] uid[4] gid[4] size[8]
 *            atime_sec[8] atime_nsec[8] mtime_sec[8] mtime_nsec[8]] -> Rsetattr[].
 */
int
p9c_setattr(struct vio9p_softc *sc, uint32_t fid, uint32_t valid, uint32_t mode,
    uint32_t uid, uint32_t gid, uint64_t size, int64_t atime_sec,
    int64_t atime_nsec, int64_t mtime_sec, int64_t mtime_nsec)
{
	struct p9c_enc enc;
	size_t rxlen = 0;
	int error;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TSETATTR);
	p9c_put32(&enc, fid);
	p9c_put32(&enc, valid);
	p9c_put32(&enc, mode);
	p9c_put32(&enc, uid);
	p9c_put32(&enc, gid);
	p9c_put64(&enc, size);
	p9c_put64(&enc, (uint64_t)atime_sec);
	p9c_put64(&enc, (uint64_t)atime_nsec);
	p9c_put64(&enc, (uint64_t)mtime_sec);
	p9c_put64(&enc, (uint64_t)mtime_nsec);

	error = p9c_rpc(sc, &enc, P9_RSETATTR, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);

	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Trenameat: rename `oldname` in directory `olddirfid` to `newname` in
 * directory `newdirfid` -- the general, fid-complete rename that carries BOTH
 * parents and BOTH leaf names.  This is the ONLY rename shape the in-kernel
 * guest emits: the host refuses the legacy Trename for a non-symlink fid
 * (it has only a host fd to the object, not a (parentdir,leaf) it can
 * renameat() from), so vop_rename always uses Trenameat (FIX D1).  Both dir
 * fids are already bound under the share; the server confines the operation and
 * blocks cross-mount before the RPC.  Rrenameat is header-only; no fid is
 * consumed (the moved object's own fid stays valid host-side, POSIX-unlink
 * style).
 *   Trenameat[olddirfid[4] oldname[s] newdirfid[4] newname[s]] -> Rrenameat[].
 */
int
p9c_renameat(struct vio9p_softc *sc, uint32_t olddirfid, const char *oldname,
    uint32_t newdirfid, const char *newname)
{
	struct p9c_enc enc;
	size_t rxlen = 0;
	int error;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TRENAMEAT);
	p9c_put32(&enc, olddirfid);
	p9c_puts(&enc, oldname, strlen(oldname));
	p9c_put32(&enc, newdirfid);
	p9c_puts(&enc, newname, strlen(newname));

	error = p9c_rpc(sc, &enc, P9_RRENAMEAT, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);

	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Tsymlink: create symlink `name` in dir `dfid` with body `target` (stored
 * verbatim -- NFS model, the guest resolves on read).  *qid receives the new
 * link's qid.  The caller Twalk-clones a fresh fid for the child afterward.
 *   Tsymlink[dfid[4] name[s] target[s] gid[4]] -> Rsymlink[qid[13]].
 */
int
p9c_symlink(struct vio9p_softc *sc, uint32_t dfid, const char *name,
    const char *target, uint32_t gid, struct p9_qid *qid)
{
	struct p9c_enc enc;
	struct p9c_dec dec;
	size_t rxlen = 0;
	int error;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TSYMLINK);
	p9c_put32(&enc, dfid);
	p9c_puts(&enc, name, strlen(name));
	p9c_puts(&enc, target, strlen(target));
	p9c_put32(&enc, gid);

	error = p9c_rpc(sc, &enc, P9_RSYMLINK, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);
	if (error != 0)
		goto out;

	p9c_dec_init(&dec, p9c_rxbuf, rxlen);
	p9c_getqid(&dec, qid);
	if (dec.err)
		error = EIO;
out:
	rw_exit_write(&p9c_lock);
	return (error);
}

/*
 * Tlink: create hard link `name` in dir `dfid` to the existing object `fid`.
 * Rlink is header-only.  NOTE: OpenBSD's linkat(2) has no AT_EMPTY_PATH, so the
 * host may not be able to express link-by-fid and may reply L_EOPNOTSUPP; the
 * guest surfaces that to the caller unchanged.
 *   Tlink[dfid[4] fid[4] name[s]] -> Rlink[].
 */
int
p9c_link(struct vio9p_softc *sc, uint32_t dfid, uint32_t fid, const char *name)
{
	struct p9c_enc enc;
	size_t rxlen = 0;
	int error;

	rw_enter_write(&p9c_lock);

	p9c_enc_start(&enc, p9c_txbuf, sizeof(p9c_txbuf), P9_TLINK);
	p9c_put32(&enc, dfid);
	p9c_put32(&enc, fid);
	p9c_puts(&enc, name, strlen(name));

	error = p9c_rpc(sc, &enc, P9_RLINK, p9c_rxbuf, sizeof(p9c_rxbuf),
	    &rxlen);

	rw_exit_write(&p9c_lock);
	return (error);
}
