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
 * Interface between the vio9p(4) virtio transport driver (sys/dev/pv/vio9p.c)
 * and the vio9p VFS client (sys/miscfs/vio9p/).  The VFS reaches a transport
 * instance via device_lookup(&vio9p_cd, unit), reads sc_tag/sc_msize, borrows
 * a request context with vio9p_get(), frames a 9P T-message in its req_tbuf,
 * and issues the RPC with vio9p_rpc().
 *
 * Include order in a consumer: <dev/pv/virtiovar.h>, <dev/pv/vio9preg.h>,
 * <sys/mutex.h>, <sys/queue.h>, <machine/bus.h> before this header.
 */

#ifndef _DEV_PV_VIO9PVAR_H_
#define _DEV_PV_VIO9PVAR_H_

#include <sys/queue.h>			/* TAILQ */
#include <sys/mutex.h>			/* struct mutex */
#include <machine/bus.h>		/* bus_dmamap_t, bus_dma_segment_t */
#include <dev/pv/virtiovar.h>		/* struct virtqueue, virtio_softc */
#include <dev/pv/vio9preg.h>		/* VIO9P_TAG_MAX, VIO9P_MSIZE_* */

/*
 * One outstanding 9P request: its own device-readable T buffer and
 * device-writable R buffer, both DMA-mapped, plus completion state.  The 9P
 * tag is the pool index, so it is unique among the requests currently in
 * flight -- that is what lets vio9p_vq_done() (and the client) demultiplex
 * replies that may arrive out of order.
 */
struct vio9p_req {
	uint8_t			*req_tbuf;	/* request (device-readable) */
	uint8_t			*req_rbuf;	/* reply   (device-writable) */
	bus_dmamap_t		 req_tmap;
	bus_dmamap_t		 req_rmap;
	bus_dma_segment_t	 req_tseg;
	bus_dma_segment_t	 req_rseg;
	uint16_t		 req_tag;	/* 9P tag == pool index */
	int			 req_slot;	/* virtqueue slot while in flight */
	volatile int		 req_done;	/* set by vq_done (IPL_BIO) */
	int			 req_rlen;	/* bytes device wrote to R */
	TAILQ_ENTRY(vio9p_req)	 req_link;	/* free list linkage */
};

struct vio9p_softc {
	struct device		 sc_dev;
	struct virtio_softc	*sc_virtio;
	struct virtqueue	 sc_vq[1];	/* one request queue */

	char			 sc_tag[VIO9P_TAG_MAX + 1];
	uint16_t		 sc_taglen;
	uint32_t		 sc_msize;	/* negotiated by Tversion */
	/*
	 * M3b: set by p9c_version iff the host echoed the extended version
	 * string ("9P2000.L.appli").  When set, every T-message except Tversion
	 * carries a uid[4] gid[4] caller-identity prefix right after the 7-byte
	 * header (see miscfs/vio9p/vio9p.h).  One 9P session per transport, so
	 * one negotiated flag per softc is correct.
	 */
	int			 sc_extended;	/* extended dialect negotiated */

	/*
	 * Pool of outstanding-request contexts.  Each carries its own DMA T/R
	 * buffers and a tag equal to its index, so several may be in flight at
	 * once.  sc_slot_req maps a virtqueue slot back to its req for the
	 * completion demux.  sc_mtx (IPL_BIO) guards sc_free, sc_slot_req and
	 * the req_done/req_rlen completion fields shared with vio9p_vq_done().
	 */
	struct vio9p_req	*sc_reqs;	/* array[sc_nreq] */
	int			 sc_nreq;
	TAILQ_HEAD(, vio9p_req)	 sc_free;	/* available contexts */
	struct vio9p_req       **sc_slot_req;	/* array[vq_num]: slot -> req */
	struct mutex		 sc_mtx;
};

extern struct cfdriver vio9p_cd;

/*
 * Borrow a request context (blocks until one is free), submit the
 * already-framed 9P T-message of tlen bytes built in req->req_tbuf, and wait
 * for its reply (copied by the device into req->req_rbuf, length in *rlenp).
 * Several contexts may be in flight concurrently; vio9p_rpc() blocks in
 * process context (msleep) or polls when cold.  Return req with vio9p_put().
 * vio9p_rpc() returns 0 or an errno.
 */
struct vio9p_req *vio9p_get(struct vio9p_softc *);
int	vio9p_rpc(struct vio9p_softc *, struct vio9p_req *, size_t, size_t *);
void	vio9p_put(struct vio9p_softc *, struct vio9p_req *);

#endif /* _DEV_PV_VIO9PVAR_H_ */
