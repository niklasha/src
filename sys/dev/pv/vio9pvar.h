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
 * instance via device_lookup(&vio9p_cd, unit), reads sc_tag/sc_msize, and
 * issues 9P RPCs with vio9p_submit().
 *
 * Include order in a consumer: <dev/pv/virtiovar.h>, <dev/pv/vio9preg.h>,
 * <sys/rwlock.h>, <machine/bus.h> before this header.
 */

#ifndef _DEV_PV_VIO9PVAR_H_
#define _DEV_PV_VIO9PVAR_H_

#include <machine/bus.h>		/* bus_dmamap_t, bus_dma_segment_t */
#include <dev/pv/virtiovar.h>		/* struct virtqueue, virtio_softc */
#include <dev/pv/vio9preg.h>		/* VIO9P_TAG_MAX, VIO9P_MSIZE_* */

struct vio9p_softc {
	struct device		 sc_dev;
	struct virtio_softc	*sc_virtio;
	struct virtqueue	 sc_vq[1];	/* one request queue */

	char			 sc_tag[VIO9P_TAG_MAX + 1];
	uint16_t		 sc_taglen;
	uint32_t		 sc_msize;	/* negotiated by Tversion */

	uint8_t			*sc_tbuf;	/* request (device-readable) */
	uint8_t			*sc_rbuf;	/* reply   (device-writable) */
	bus_dmamap_t		 sc_tmap;
	bus_dmamap_t		 sc_rmap;
	bus_dma_segment_t	 sc_tseg;
	bus_dma_segment_t	 sc_rseg;

	struct rwlock		 sc_lock;	/* one submit() at a time */
	volatile int		 sc_done;	/* set by vq_done (IPL_BIO) */
	int			 sc_rlen;	/* bytes device wrote to R */
};

extern struct cfdriver vio9p_cd;

/*
 * Submit one already-framed 9P T-message (tbuf/tlen) and copy the reply into
 * rbuf (<= rcap), returning its length in *rlenp.  Serialized; blocks in
 * process context (tsleep) or polls when cold.  Returns 0 or an errno.
 */
int	vio9p_submit(struct vio9p_softc *, const void *, size_t, void *,
	    size_t, size_t *);

#endif /* _DEV_PV_VIO9PVAR_H_ */
