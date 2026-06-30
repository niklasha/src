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
 * virtqueue, reads the mount tag from configuration space, and exposes a small
 * primitive set, vio9p_get()/vio9p_rpc()/vio9p_put(), that the in-kernel 9P
 * client (sys/miscfs/vio9p/) builds T-messages on.  Several requests may be in
 * flight at once: each borrows a request context (its own DMA T/R buffers and
 * a unique 9P tag), and replies are demultiplexed back to the waiting context
 * by virtqueue slot.  The guest mounts a host bind-mount share served by the
 * M1 host server (usr.sbin/vmd/viofs.c).
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <machine/bus.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/time.h>

#include <dev/pv/virtioreg.h>
#include <dev/pv/virtiovar.h>
#include <dev/pv/vio9preg.h>
#include <dev/pv/vio9pvar.h>

#define P9_HDRLEN	7		/* size[4] type[1] tag[2] */
#define VIO9P_NREQ	16		/* desired outstanding requests */

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

/* Free the first nreq request contexts' buffers (cleanup helper). */
static void
vio9p_reqs_free(struct vio9p_softc *sc, int nreq)
{
	struct vio9p_req *req;
	int i;

	for (i = 0; i < nreq; i++) {
		req = &sc->sc_reqs[i];
		if (req->req_rbuf != NULL)
			vio9p_buf_free(sc, &req->req_rseg, req->req_rmap,
			    req->req_rbuf);
		if (req->req_tbuf != NULL)
			vio9p_buf_free(sc, &req->req_tseg, req->req_tmap,
			    req->req_tbuf);
	}
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
	struct vio9p_req *req;
	int i, nreq;
	uint16_t t;

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
	for (t = 0; t < sc->sc_taglen; t++)
		sc->sc_tag[t] = virtio_read_device_config_1(vsc,
		    VIRTIO_9P_CONFIG_TAG + t);
	sc->sc_tag[sc->sc_taglen] = '\0';

	/* Two descriptors per request: readable T then writable R. */
	if (virtio_alloc_vq(vsc, &sc->sc_vq[0], 0, 2, "9p request") != 0) {
		printf(": cannot allocate virtqueue\n");
		goto err;
	}
	sc->sc_vq[0].vq_done = vio9p_vq_done;

	/*
	 * Size the request pool so at most vq_num/2 requests (two descriptors
	 * each) are ever outstanding, and never fewer than one.
	 */
	nreq = sc->sc_vq[0].vq_num / 2;
	if (nreq > VIO9P_NREQ)
		nreq = VIO9P_NREQ;
	if (nreq < 1)
		nreq = 1;

	sc->sc_reqs = mallocarray(nreq, sizeof(struct vio9p_req), M_DEVBUF,
	    M_NOWAIT | M_ZERO);
	sc->sc_slot_req = mallocarray(sc->sc_vq[0].vq_num,
	    sizeof(struct vio9p_req *), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (sc->sc_reqs == NULL || sc->sc_slot_req == NULL) {
		printf(": cannot allocate request pool\n");
		goto err_vq;
	}

	TAILQ_INIT(&sc->sc_free);
	for (i = 0; i < nreq; i++) {
		req = &sc->sc_reqs[i];
		req->req_tag = (uint16_t)i;
		if (vio9p_buf_alloc(sc, VIO9P_MSIZE_MAX, BUS_DMA_WRITE,
		    &req->req_tseg, &req->req_tmap, &req->req_tbuf) != 0) {
			printf(": cannot allocate request buffers\n");
			vio9p_reqs_free(sc, i);
			goto err_pool;
		}
		if (vio9p_buf_alloc(sc, VIO9P_MSIZE_MAX, BUS_DMA_READ,
		    &req->req_rseg, &req->req_rmap, &req->req_rbuf) != 0) {
			printf(": cannot allocate reply buffers\n");
			vio9p_reqs_free(sc, i);	/* frees this req's tbuf too */
			goto err_pool;
		}
		TAILQ_INSERT_TAIL(&sc->sc_free, req, req_link);
	}
	sc->sc_nreq = nreq;

	mtx_init(&sc->sc_mtx, IPL_BIO);
	sc->sc_msize = VIO9P_MSIZE_MAX;

	virtio_start_vq_intr(vsc, &sc->sc_vq[0]);

	printf(": tag \"%s\", %d outstanding\n", sc->sc_tag, nreq);

	if (virtio_attach_finish(vsc, va) != 0)
		goto err_reqs;
	return;

err_reqs:
	vio9p_reqs_free(sc, nreq);
err_pool:
	free(sc->sc_reqs, M_DEVBUF, 0);
	free(sc->sc_slot_req, M_DEVBUF, 0);
err_vq:
	virtio_free_vq(vsc, &sc->sc_vq[0]);
err:
	vsc->sc_child = VIRTIO_CHILD_ERROR;
}

/*
 * Reply completion (IPL_BIO).  Demultiplex every finished slot back to its
 * request context, record the reply length, and wake that context's waiter.
 */
int
vio9p_vq_done(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct vio9p_softc *sc = (struct vio9p_softc *)vsc->sc_child;
	struct vio9p_req *req;
	int slot, len, handled = 0;

	mtx_enter(&sc->sc_mtx);
	while (virtio_dequeue(vsc, vq, &slot, &len) == 0) {
		req = sc->sc_slot_req[slot];
		sc->sc_slot_req[slot] = NULL;
		if (req != NULL) {
			bus_dmamap_sync(vsc->sc_dmat, req->req_tmap, 0,
			    VIO9P_MSIZE_MAX, BUS_DMASYNC_POSTWRITE);
			bus_dmamap_sync(vsc->sc_dmat, req->req_rmap, 0,
			    VIO9P_MSIZE_MAX, BUS_DMASYNC_POSTREAD);
		}
		virtio_dequeue_commit(vq, slot);
		if (req != NULL) {
			if (len < 0 || len > VIO9P_MSIZE_MAX)
				len = 0;	/* defensive; client rejects */
			req->req_rlen = len;
			req->req_done = 1;
			wakeup(req);
		}
		handled = 1;
	}
	mtx_leave(&sc->sc_mtx);
	return (handled);
}

/*
 * Borrow a request context, blocking until one of the sc_nreq contexts is
 * free.  Callers run in process context (mount/VFS), so sleeping is fine; the
 * autoconf (cold) path uses the pool single-threaded, so it never blocks here.
 */
struct vio9p_req *
vio9p_get(struct vio9p_softc *sc)
{
	struct vio9p_req *req;

	mtx_enter(&sc->sc_mtx);
	while ((req = TAILQ_FIRST(&sc->sc_free)) == NULL)
		msleep_nsec(&sc->sc_free, &sc->sc_mtx, PRIBIO, "vio9pq",
		    INFSLP);
	TAILQ_REMOVE(&sc->sc_free, req, req_link);
	mtx_leave(&sc->sc_mtx);
	return (req);
}

/* Return a borrowed context to the free pool and wake one waiter. */
void
vio9p_put(struct vio9p_softc *sc, struct vio9p_req *req)
{
	mtx_enter(&sc->sc_mtx);
	TAILQ_INSERT_TAIL(&sc->sc_free, req, req_link);
	mtx_leave(&sc->sc_mtx);
	wakeup_one(&sc->sc_free);
}

/*
 * Submit req's T-message (tlen bytes in req->req_tbuf) and wait for its reply,
 * copied by the device into req->req_rbuf with length stored in *rlenp.
 * During autoconf (cold) the used ring is polled; otherwise the queue
 * interrupt wakes us.  Other contexts may be in flight concurrently.
 */
int
vio9p_rpc(struct vio9p_softc *sc, struct vio9p_req *req, size_t tlen,
    size_t *rlenp)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = &sc->sc_vq[0];
	int slot, error = 0;

	if (tlen < P9_HDRLEN || tlen > VIO9P_MSIZE_MAX)
		return (EINVAL);

	bus_dmamap_sync(vsc->sc_dmat, req->req_tmap, 0, tlen,
	    BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(vsc->sc_dmat, req->req_rmap, 0, sc->sc_msize,
	    BUS_DMASYNC_PREREAD);

	mtx_enter(&sc->sc_mtx);
	req->req_done = 0;
	req->req_rlen = 0;
	if (virtio_enqueue_prep(vq, &slot) != 0 ||
	    virtio_enqueue_reserve(vq, slot, 2) != 0) {
		mtx_leave(&sc->sc_mtx);
		return (EAGAIN);	/* pool <= vq_num/2, so should not happen */
	}
	/* Device reads the request (write=1), then writes the reply (write=0). */
	virtio_enqueue_p(vq, slot, req->req_tmap, 0, tlen, 1);
	virtio_enqueue_p(vq, slot, req->req_rmap, 0, sc->sc_msize, 0);
	req->req_slot = slot;
	sc->sc_slot_req[slot] = req;
	virtio_enqueue_commit(vsc, vq, slot, 1);

	if (cold) {
		int timo;

		/*
		 * No interrupts during autoconf: poll the used ring.  Release
		 * the mutex first so vio9p_vq_done() (called from
		 * virtio_check_vq) can take it.
		 */
		mtx_leave(&sc->sc_mtx);
		for (timo = 1500000; timo > 0 && !req->req_done; timo--) {
			virtio_check_vq(vsc, vq);
			if (!req->req_done)
				delay(10);	/* up to ~15s total */
		}
		if (!req->req_done)
			error = EIO;
	} else {
		while (!req->req_done) {
			if (msleep_nsec(req, &sc->sc_mtx, PRIBIO, "vio9p",
			    SEC_TO_NSEC(15)) == EWOULDBLOCK && !req->req_done) {
				error = EIO;	/* host wedged */
				break;
			}
		}
		mtx_leave(&sc->sc_mtx);
	}

	if (error == 0 &&
	    (req->req_rlen < P9_HDRLEN || (size_t)req->req_rlen > sc->sc_msize))
		error = EIO;
	if (error == 0)
		*rlenp = req->req_rlen;
	return (error);
}
