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
 * virtio-9p transport driver: owns the PCI virtio-9p device and the request
 * virtqueue, reads the mount tag from configuration space, and exposes one
 * synchronous primitive, vio9p_submit(), that the in-kernel 9P client
 * (sys/miscfs/vio9p/) builds T-messages on.  The guest mounts a host
 * bind-mount share served by the M1 host server (usr.sbin/vmd/viofs.c).
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <machine/bus.h>
#include <sys/device.h>
#include <sys/rwlock.h>
#include <sys/time.h>

#include <dev/pv/virtioreg.h>
#include <dev/pv/virtiovar.h>
#include <dev/pv/vio9preg.h>
#include <dev/pv/vio9pvar.h>

#define P9_HDRLEN	7		/* size[4] type[1] tag[2] */

int	vio9p_match(struct device *, void *, void *);
void	vio9p_attach(struct device *, struct device *, void *);
int	vio9p_vq_done(struct virtqueue *);
int	vio9p_buf_alloc(struct vio9p_softc *, bus_size_t, int,
	    bus_dma_segment_t *, bus_dmamap_t *, uint8_t **);
void	vio9p_buf_free(struct vio9p_softc *, bus_dma_segment_t *,
	    bus_dmamap_t, uint8_t *);

const struct cfattach vio9p_ca = {
	sizeof(struct vio9p_softc),
	vio9p_match,
	vio9p_attach,
	NULL
};

struct cfdriver vio9p_cd = {
	NULL, "vio9p", DV_DULL, CD_COCOVM
};

/*
 * Allocate one DMA-coherent staging buffer, mapped and loaded.  dmaflags is
 * BUS_DMA_WRITE for a device-readable buffer (T), BUS_DMA_READ for a
 * device-writable buffer (R).
 */
int
vio9p_buf_alloc(struct vio9p_softc *sc, bus_size_t size, int dmaflags,
    bus_dma_segment_t *seg, bus_dmamap_t *mapp, uint8_t **kvap)
{
	bus_dma_tag_t dmat = sc->sc_virtio->sc_dmat;
	caddr_t kva;
	int rsegs;

	if (bus_dmamem_alloc(dmat, size, 0, 0, seg, 1, &rsegs,
	    BUS_DMA_NOWAIT | BUS_DMA_64BIT) != 0)
		return (1);
	if (bus_dmamem_map(dmat, seg, 1, size, &kva, BUS_DMA_NOWAIT) != 0)
		goto free;
	if (bus_dmamap_create(dmat, size, 1, size, 0,
	    BUS_DMA_NOWAIT | BUS_DMA_ALLOCNOW | BUS_DMA_64BIT, mapp) != 0)
		goto unmap;
	if (bus_dmamap_load(dmat, *mapp, kva, size, NULL,
	    BUS_DMA_NOWAIT | dmaflags) != 0)
		goto destroy;

	memset(kva, 0, size);
	*kvap = (uint8_t *)kva;
	return (0);

destroy:
	bus_dmamap_destroy(dmat, *mapp);
unmap:
	bus_dmamem_unmap(dmat, kva, size);
free:
	bus_dmamem_free(dmat, seg, 1);
	return (1);
}

void
vio9p_buf_free(struct vio9p_softc *sc, bus_dma_segment_t *seg,
    bus_dmamap_t map, uint8_t *kva)
{
	bus_dma_tag_t dmat = sc->sc_virtio->sc_dmat;

	bus_dmamap_unload(dmat, map);
	bus_dmamap_destroy(dmat, map);
	bus_dmamem_unmap(dmat, (caddr_t)kva, VIO9P_MSIZE_MAX);
	bus_dmamem_free(dmat, seg, 1);
}

int
vio9p_match(struct device *parent, void *match, void *aux)
{
	struct virtio_attach_args *va = aux;

	if (va->va_devid == PCI_PRODUCT_VIRTIO_9P)
		return (1);
	return (0);
}

void
vio9p_attach(struct device *parent, struct device *self, void *aux)
{
	struct vio9p_softc *sc = (struct vio9p_softc *)self;
	struct virtio_softc *vsc = (struct virtio_softc *)parent;
	struct virtio_attach_args *va = aux;
	uint16_t i;

	if (vsc->sc_child != NULL)
		panic("%s: parent already has a child", sc->sc_dev.dv_xname);
	vsc->sc_child = self;
	vsc->sc_vqs = &sc->sc_vq[0];
	vsc->sc_nvqs = 1;
	vsc->sc_ipl = IPL_BIO;
	sc->sc_virtio = vsc;

	vsc->sc_driver_features = VIRTIO_9P_F_MOUNT_TAG;
	if (virtio_negotiate_features(vsc, NULL) != 0) {
		printf(": feature negotiation failed\n");
		goto err;
	}
	if (!virtio_has_feature(vsc, VIRTIO_9P_F_MOUNT_TAG)) {
		printf(": no mount tag\n");
		goto err;
	}

	/* Config space: { le16 tag_len; u8 tag[] } (viofs_dev_read). */
	sc->sc_taglen = virtio_read_device_config_2(vsc,
	    VIRTIO_9P_CONFIG_TAG_LEN);
	if (sc->sc_taglen == 0 || sc->sc_taglen > VIO9P_TAG_MAX) {
		printf(": bad tag length %u\n", sc->sc_taglen);
		goto err;
	}
	for (i = 0; i < sc->sc_taglen; i++)
		sc->sc_tag[i] = virtio_read_device_config_1(vsc,
		    VIRTIO_9P_CONFIG_TAG + i);
	sc->sc_tag[sc->sc_taglen] = '\0';

	if (vio9p_buf_alloc(sc, VIO9P_MSIZE_MAX, BUS_DMA_WRITE,
	    &sc->sc_tseg, &sc->sc_tmap, &sc->sc_tbuf) != 0) {
		printf(": cannot allocate request buffer\n");
		goto err;
	}
	if (vio9p_buf_alloc(sc, VIO9P_MSIZE_MAX, BUS_DMA_READ,
	    &sc->sc_rseg, &sc->sc_rmap, &sc->sc_rbuf) != 0) {
		printf(": cannot allocate reply buffer\n");
		goto err_tbuf;
	}

	/* Two descriptors per request: readable T then writable R. */
	if (virtio_alloc_vq(vsc, &sc->sc_vq[0], 0, 2, "9p request") != 0) {
		printf(": cannot allocate virtqueue\n");
		goto err_rbuf;
	}
	sc->sc_vq[0].vq_done = vio9p_vq_done;

	rw_init(&sc->sc_lock, "vio9p");
	sc->sc_msize = VIO9P_MSIZE_MAX;
	sc->sc_done = 0;

	virtio_start_vq_intr(vsc, &sc->sc_vq[0]);

	printf(": tag \"%s\"\n", sc->sc_tag);

	if (virtio_attach_finish(vsc, va) != 0)
		goto err_vq;
	return;

err_vq:
	virtio_free_vq(vsc, &sc->sc_vq[0]);
err_rbuf:
	vio9p_buf_free(sc, &sc->sc_rseg, sc->sc_rmap, sc->sc_rbuf);
err_tbuf:
	vio9p_buf_free(sc, &sc->sc_tseg, sc->sc_tmap, sc->sc_tbuf);
err:
	vsc->sc_child = VIRTIO_CHILD_ERROR;
}

int
vio9p_vq_done(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct vio9p_softc *sc = (struct vio9p_softc *)vsc->sc_child;
	int slot, len;

	if (virtio_dequeue(vsc, vq, &slot, &len) != 0)
		return (0);
	bus_dmamap_sync(vsc->sc_dmat, sc->sc_tmap, 0, VIO9P_MSIZE_MAX,
	    BUS_DMASYNC_POSTWRITE);
	bus_dmamap_sync(vsc->sc_dmat, sc->sc_rmap, 0, VIO9P_MSIZE_MAX,
	    BUS_DMASYNC_POSTREAD);
	virtio_dequeue_commit(vq, slot);

	if (len < 0 || len > VIO9P_MSIZE_MAX)
		len = 0;		/* defensive; the client rejects short */
	sc->sc_rlen = len;
	sc->sc_done = 1;
	wakeup_one(&sc->sc_done);
	return (1);
}

/*
 * Submit one 9P request and wait for its reply.  Serialized: one request is
 * outstanding at a time.  During autoconf (cold) the used ring is polled, as
 * sleeping is not permitted; otherwise the queue interrupt wakes us.
 */
int
vio9p_submit(struct vio9p_softc *sc, const void *tbuf, size_t tlen,
    void *rbuf, size_t rcap, size_t *rlenp)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = &sc->sc_vq[0];
	int slot, s, error = 0;

	if (tlen < P9_HDRLEN || tlen > VIO9P_MSIZE_MAX)
		return (EINVAL);
	if (rcap > VIO9P_MSIZE_MAX)
		rcap = VIO9P_MSIZE_MAX;

	rw_enter_write(&sc->sc_lock);
	memcpy(sc->sc_tbuf, tbuf, tlen);

	s = splbio();
	sc->sc_done = 0;
	sc->sc_rlen = 0;
	bus_dmamap_sync(vsc->sc_dmat, sc->sc_tmap, 0, tlen,
	    BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(vsc->sc_dmat, sc->sc_rmap, 0, rcap,
	    BUS_DMASYNC_PREREAD);

	if (virtio_enqueue_prep(vq, &slot) != 0 ||
	    virtio_enqueue_reserve(vq, slot, 2) != 0) {
		splx(s);
		rw_exit_write(&sc->sc_lock);
		return (EAGAIN);	/* single-outstanding: not in steady state */
	}
	/* Device reads the request (write=1), then writes the reply (write=0). */
	virtio_enqueue_p(vq, slot, sc->sc_tmap, 0, tlen, 1);
	virtio_enqueue_p(vq, slot, sc->sc_rmap, 0, rcap, 0);
	virtio_enqueue_commit(vsc, vq, slot, 1);

	if (cold) {
		int timo;

		for (timo = 1500000; timo > 0 && !sc->sc_done; timo--) {
			virtio_check_vq(vsc, vq);
			if (!sc->sc_done)
				delay(10);	/* up to ~15s total */
		}
		if (!sc->sc_done)
			error = EIO;
	} else {
		while (!sc->sc_done) {
			if (tsleep_nsec(&sc->sc_done, PRIBIO, "vio9p",
			    SEC_TO_NSEC(15)) == EWOULDBLOCK && !sc->sc_done) {
				error = EIO;	/* host wedged */
				break;
			}
		}
	}
	splx(s);

	if (error == 0 &&
	    (sc->sc_rlen < P9_HDRLEN || (size_t)sc->sc_rlen > rcap))
		error = EIO;
	if (error == 0) {
		memcpy(rbuf, sc->sc_rbuf, sc->sc_rlen);
		*rlenp = sc->sc_rlen;
	}
	rw_exit_write(&sc->sc_lock);
	return (error);
}
