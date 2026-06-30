/*	$OpenBSD: virtio.c,v 1.137 2026/04/14 21:41:19 dv Exp $	*/

/*
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
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

#include <sys/param.h>	/* PAGE_SIZE */
#include <sys/socket.h>
#include <sys/wait.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcidevs.h>
#include <dev/pv/virtioreg.h>
#include <dev/pci/virtio_pcireg.h>
#include <dev/pv/vioblkreg.h>
#include <dev/vmm/vmm.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <errno.h>
#include <event.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "atomicio.h"
#include "mmio.h"
#include "pci.h"
#include "vioscsi.h"
#include "virtio.h"
#include "vmd.h"

/*
 * MSI-X prototype for viofs.  When 1, the viofs PCI device advertises an
 * MSI-X capability (SMP guests only) so the guest negotiates MSI-X and
 * the completion interrupt is delivered as an edge MSI directly to the
 * target vcpu's LAPIC -- eliminating the legacy-INTx ISR-read round-trip.
 * When 0, the MMIO BAR is still added but no capability is advertised, so
 * the guest stays on INTx and all the new MSI-X paths remain dormant.
 */
#define VIOFS_MSIX_ENABLE	1

/* MSI-X capability id (PCI 3.0). */
#ifndef PCI_CAP_MSIX
#define PCI_CAP_MSIX		0x11
#endif

/*
 * Layout of the MSI-X table + PBA within the device's MSI-X MMIO BAR.
 * The BAR is a single 4 KiB page -- the size vmd reports to the guest's
 * BAR size-probe (pci.c hardcodes 0xfffff000) -- so the table (offset 0)
 * and the PBA (offset 0x800) both fit, and a relocated handler never
 * overlaps the adjacent emulated IOAPIC.
 */
#define VIOFS_MSIX_BAR_SIZE	0x1000
#define VIOFS_MSIX_TABLE_OFFSET	0x0000
#define VIOFS_MSIX_PBA_OFFSET	0x0800

#define VIRTIO_DEBUG	0
#ifdef DPRINTF
#undef DPRINTF
#endif
#if VIRTIO_DEBUG
#define DPRINTF		log_debug
#else
#define DPRINTF(x...)	do {} while(0)
#endif	/* VIRTIO_DEBUG */

extern struct vmd *env;

struct virtio_dev viornd;
struct virtio_dev *vioscsi = NULL;
struct virtio_dev vmmci;

/* Devices emulated in subprocesses are inserted into this list. */
SLIST_HEAD(virtio_dev_head, virtio_dev) virtio_devs;

#define MAXPHYS	(64 * 1024)	/* max raw I/O transfer size */

#define VIRTIO_NET_F_MAC	(1<<5)

#define VMMCI_F_TIMESYNC	(1<<0)
#define VMMCI_F_ACK		(1<<1)
#define VMMCI_F_SYNCRTC		(1<<2)

#define RXQ	0
#define TXQ	1

/*
 * Virtio 9p (vio9p).  The modern virtio PCI product id 0x1049 (0x1040 + virtio
 * device id 9) is not yet in pcidevs(5); define it here for now (move to
 * sys/dev/pci/pcidevs for upstream).
 */
#define PCI_PRODUCT_QUMRANET_VIO1_9P	0x1049
#define VIRTIO_9P_F_MOUNT_TAG		(1ULL << 0)
#define VIRTIO_9P_QUEUES		1
#define VIOFS_QUEUE_SIZE_DEFAULT	128

static void virtio_dev_init(struct vmd_vm *, struct virtio_dev *, uint8_t,
    uint16_t, uint16_t, uint64_t);
static int virtio_dev_launch(struct vmd_vm *, struct virtio_dev *);
static int virtio_dev_launch_await_parent(struct vmd_vm *, struct virtio_dev *,
    int, int);
static void virtio_dispatch_dev(int, short, void *);
static int handle_dev_msg(struct viodev_msg *, struct virtio_dev *);
static int virtio_dev_closefds(struct virtio_dev *);
static void virtio_pci_add_cap(uint8_t, uint8_t, uint8_t, uint32_t);
static void virtio_add_msix_cap(uint8_t, uint8_t, uint16_t);
static int virtio_msix_mmio_read(uint64_t, uint8_t, uint64_t *, void *);
static int virtio_msix_mmio_write(uint64_t, uint8_t, uint64_t, void *);
static void virtio_deliver_msix(struct virtio_dev *, uint16_t);
static void vmmci_pipe_dispatch(int, short, void *);

static int virtio_io_dispatch(int, uint16_t, uint32_t *, uint8_t *, void *,
    uint8_t);
static int virtio_io_isr(int, uint16_t, uint32_t *, uint8_t *, void *, uint8_t);
static int virtio_io_notify(int, uint16_t, uint32_t *, uint8_t *, void *,
    uint8_t);
static int viornd_notifyq(struct virtio_dev *, uint16_t);

static void vmmci_ack(struct virtio_dev *, unsigned int);

#if VIRTIO_DEBUG
static const char *
virtio1_reg_name(uint16_t reg)
{
	switch (reg) {
	case VIO1_PCI_DEVICE_FEATURE_SELECT: return "DEVICE_FEATURE_SELECT";
	case VIO1_PCI_DEVICE_FEATURE: return "DEVICE_FEATURE";
	case VIO1_PCI_DRIVER_FEATURE_SELECT: return "DRIVER_FEATURE_SELECT";
	case VIO1_PCI_DRIVER_FEATURE: return "DRIVER_FEATURE";
	case VIO1_PCI_CONFIG_MSIX_VECTOR: return "CONFIG_MSIX_VECTOR";
	case VIO1_PCI_NUM_QUEUES: return "NUM_QUEUES";
	case VIO1_PCI_DEVICE_STATUS: return "DEVICE_STATUS";
	case VIO1_PCI_CONFIG_GENERATION: return "CONFIG_GENERATION";
	case VIO1_PCI_QUEUE_SELECT: return "QUEUE_SELECT";
	case VIO1_PCI_QUEUE_SIZE: return "QUEUE_SIZE";
	case VIO1_PCI_QUEUE_MSIX_VECTOR: return "QUEUE_MSIX_VECTOR";
	case VIO1_PCI_QUEUE_ENABLE: return "QUEUE_ENABLE";
	case VIO1_PCI_QUEUE_NOTIFY_OFF: return "QUEUE_NOTIFY_OFF";
	case VIO1_PCI_QUEUE_DESC: return "QUEUE_DESC";
	case VIO1_PCI_QUEUE_DESC + 4: return "QUEUE_DESC (HIGH)";
	case VIO1_PCI_QUEUE_AVAIL: return "QUEUE_AVAIL";
	case VIO1_PCI_QUEUE_AVAIL + 4: return "QUEUE_AVAIL (HIGH)";
	case VIO1_PCI_QUEUE_USED: return "QUEUE_USED";
	case VIO1_PCI_QUEUE_USED + 4: return "QUEUE_USED (HIGH)";
	default: return "UNKNOWN";
	}
}
#endif	/* VIRTIO_DEBUG */

const char *
virtio_reg_name(uint8_t reg)
{
	switch (reg) {
	case VIRTIO_CONFIG_DEVICE_FEATURES: return "device feature";
	case VIRTIO_CONFIG_GUEST_FEATURES: return "guest feature";
	case VIRTIO_CONFIG_QUEUE_PFN: return "queue address";
	case VIRTIO_CONFIG_QUEUE_SIZE: return "queue size";
	case VIRTIO_CONFIG_QUEUE_SELECT: return "queue select";
	case VIRTIO_CONFIG_QUEUE_NOTIFY: return "queue notify";
	case VIRTIO_CONFIG_DEVICE_STATUS: return "device status";
	case VIRTIO_CONFIG_ISR_STATUS: return "isr status";
	case VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI...VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI + 3:
		return "device config 0";
	case VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI + 4:
	case VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI + 5:
		return "device config 1";
	case VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI + 8: return "device config 2";
	case VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI + 12: return "device config 3";
	case VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI + 16: return "device config 4";
	default: return "unknown";
	}
}

uint32_t
vring_size(uint32_t vq_size)
{
	uint32_t allocsize1, allocsize2;

	/* allocsize1: descriptor table + avail ring + pad */
	allocsize1 = VIRTQUEUE_ALIGN(sizeof(struct vring_desc) * vq_size
	    + sizeof(uint16_t) * (2 + vq_size));
	/* allocsize2: used ring + pad */
	allocsize2 = VIRTQUEUE_ALIGN(sizeof(uint16_t) * 2
	    + sizeof(struct vring_used_elem) * vq_size);

	return allocsize1 + allocsize2;
}

/* Update queue select */
void
virtio_update_qs(struct virtio_dev *dev)
{
	struct virtio_vq_info *vq_info = NULL;

	if (dev->driver_feature & VIRTIO_F_VERSION_1) {
		/* Invalid queue */
		if (dev->pci_cfg.queue_select >= dev->num_queues) {
			dev->pci_cfg.queue_size = 0;
			dev->pci_cfg.queue_enable = 0;
			return;
		}
		vq_info = &dev->vq[dev->pci_cfg.queue_select];
		dev->pci_cfg.queue_size = vq_info->qs;
		dev->pci_cfg.queue_desc = vq_info->q_gpa;
		dev->pci_cfg.queue_avail = vq_info->q_gpa + vq_info->vq_availoffset;
		dev->pci_cfg.queue_used = vq_info->q_gpa + vq_info->vq_usedoffset;
		dev->pci_cfg.queue_enable = vq_info->vq_enabled;
	} else {
		/* Invalid queue? */
		if (dev->cfg.queue_select >= dev->num_queues) {
			dev->cfg.queue_size = 0;
			return;
		}
		vq_info = &dev->vq[dev->cfg.queue_select];
		dev->cfg.queue_pfn = vq_info->q_gpa >> 12;
		dev->cfg.queue_size = vq_info->qs;
	}
}

/* Update queue address. */
void
virtio_update_qa(struct virtio_dev *dev)
{
	struct virtio_vq_info *vq_info = NULL;
	void *hva = NULL;

	if (dev->driver_feature & VIRTIO_F_VERSION_1) {
		if (dev->pci_cfg.queue_select >= dev->num_queues) {
			log_warnx("%s: invalid queue index", __func__);
			return;
		}
		vq_info = &dev->vq[dev->pci_cfg.queue_select];
		vq_info->q_gpa = dev->pci_cfg.queue_desc;

		/*
		 * Queue size is adjustable by the guest in Virtio 1.x.
		 * We validate the max size at time of write and not here.
		 */
		vq_info->qs = dev->pci_cfg.queue_size;
		vq_info->mask = vq_info->qs - 1;

		if (vq_info->qs > 0 && vq_info->qs % 2 == 0) {
			vq_info->vq_availoffset = dev->pci_cfg.queue_avail -
			    dev->pci_cfg.queue_desc;
			vq_info->vq_usedoffset = dev->pci_cfg.queue_used -
			    dev->pci_cfg.queue_desc;
			vq_info->vq_enabled = (dev->pci_cfg.queue_enable == 1);
		} else {
			vq_info->vq_availoffset = 0;
			vq_info->vq_usedoffset = 0;
			vq_info->vq_enabled = 0;
		}
	} else {
		/* Invalid queue? */
		if (dev->cfg.queue_select >= dev->num_queues) {
			log_warnx("%s: invalid queue index", __func__);
			return;
		}
		vq_info = &dev->vq[dev->cfg.queue_select];
		vq_info->q_gpa = (uint64_t)dev->cfg.queue_pfn *
		    VIRTIO_PAGE_SIZE;

		/* Queue size is immutable in Virtio 0.9. */
		vq_info->vq_availoffset = sizeof(struct vring_desc) *
		    vq_info->qs;
		vq_info->vq_usedoffset = VIRTQUEUE_ALIGN(
			sizeof(struct vring_desc) * vq_info->qs +
			sizeof(uint16_t) * (2 + vq_info->qs));
	}

	/* Update any host va mappings. */
	if (vq_info->q_gpa > 0) {
		hva = hvaddr_mem(vq_info->q_gpa, vring_size(vq_info->qs));
		if (hva == NULL)
			fatalx("%s: failed to translate gpa to hva", __func__);
		vq_info->q_hva = hva;
	} else {
		vq_info->q_hva = NULL;
		vq_info->last_avail = 0;
		vq_info->notified_avail = 0;
	}
}

static int
viornd_notifyq(struct virtio_dev *dev, uint16_t idx)
{
	size_t sz;
	int dxx, ret = 0;
	uint16_t aidx, uidx;
	char *vr, *rnd_data;
	struct vring_desc *desc = NULL;
	struct vring_avail *avail = NULL;
	struct vring_used *used = NULL;
	struct virtio_vq_info *vq_info = NULL;

	if (dev->device_id != PCI_PRODUCT_VIRTIO_ENTROPY)
		fatalx("%s: device is not an entropy device", __func__);

	if (idx >= dev->num_queues) {
		log_warnx("%s: invalid virtqueue index", __func__);
		return (0);
	}
	vq_info = &dev->vq[idx];

	if (!vq_info->vq_enabled) {
		log_warnx("%s: virtqueue not enabled", __func__);
		return (0);
	}

	vr = vq_info->q_hva;
	if (vr == NULL)
		fatalx("%s: null vring", __func__);

	desc = (struct vring_desc *)(vr);
	avail = (struct vring_avail *)(vr + vq_info->vq_availoffset);
	used = (struct vring_used *)(vr + vq_info->vq_usedoffset);

	aidx = avail->idx & vq_info->mask;
	uidx = used->idx & vq_info->mask;

	/*
	 * virtio device read barrier: observe avail->idx before reading
	 * the ring slot/descriptor (SMP stale-read guard).
	 */
	__sync_synchronize();
	dxx = avail->ring[aidx] & vq_info->mask;

	sz = desc[dxx].len;
	if (sz > MAXPHYS)
		fatalx("viornd descriptor size too large (%zu)", sz);

	rnd_data = malloc(sz);
	if (rnd_data == NULL)
		fatal("memory allocaiton error for viornd data");

	arc4random_buf(rnd_data, sz);
	if (write_mem(desc[dxx].addr, rnd_data, sz)) {
		log_warnx("viornd: can't write random data @ 0x%llx",
		    desc[dxx].addr);
	} else {
		/* ret == 1 -> interrupt needed */
		/* XXX check VIRTIO_F_NO_INTR */
		ret = 1;
		viornd.isr = 1;
		used->ring[uidx].id = dxx;
		used->ring[uidx].len = sz;
		__sync_synchronize();
		used->idx++;
	}
	free(rnd_data);

	return (ret);
}

static int
virtio_io_dispatch(int dir, uint16_t reg, uint32_t *data, uint8_t *intr,
    void *arg, uint8_t sz)
{
	struct virtio_dev *dev = (struct virtio_dev *)arg;
	uint8_t actual = (uint8_t)reg;

	switch (reg & 0xFF00) {
	case VIO1_CFG_BAR_OFFSET:
		*data = virtio_io_cfg(dev, dir, actual, *data, sz);
		break;
	case VIO1_DEV_BAR_OFFSET:
		if (dir == VEI_DIR_IN) {
			log_debug("%s: no device specific handler", __func__);
			*data = (uint32_t)(-1);
		}
		break;
	case VIO1_NOTIFY_BAR_OFFSET:
		return virtio_io_notify(dir, actual, data, intr, arg, sz);
	case VIO1_ISR_BAR_OFFSET:
		return virtio_io_isr(dir, actual, data, intr, arg, sz);
	default:
		DPRINTF("%s: no handler for reg 0x%04x", __func__, reg);
		if (dir == VEI_DIR_IN)
			*data = (uint32_t)(-1);
	}
	return (0);
}

/*
 * virtio 1.x PCI config register io. If a register is read, returns the value.
 * Otherwise returns 0.
 */
uint32_t
virtio_io_cfg(struct virtio_dev *dev, int dir, uint8_t reg, uint32_t data,
    uint8_t sz)
{
	struct virtio_pci_common_cfg *pci_cfg = &dev->pci_cfg;
	uint32_t res = 0;
	uint16_t i;

	if (dir == VEI_DIR_OUT) {
		switch (reg) {
		case VIO1_PCI_DEVICE_FEATURE_SELECT:
			if (sz != 4)
				log_warnx("%s: unaligned write to device "
				    "feature select (sz=%u)", __func__, sz);
			else
				pci_cfg->device_feature_select = data;
			break;
		case VIO1_PCI_DEVICE_FEATURE:
			log_warnx("illegal write to device feature register");
			break;
		case VIO1_PCI_DRIVER_FEATURE_SELECT:
			if (sz != 4)
				log_warnx("%s: unaligned write to driver "
				    "feature select register (sz=%u)", __func__,
				    sz);
			else
				pci_cfg->driver_feature_select = data;
			break;
		case VIO1_PCI_DRIVER_FEATURE:
			if (sz != 4) {
				log_warnx("%s: unaligned write to driver "
				    "feature register (sz=%u)", __func__, sz);
				break;
			}
			if (pci_cfg->driver_feature_select > 1) {
				/* We only support a 64-bit feature space. */
				DPRINTF("%s: ignoring driver feature write",
				    __func__);
				break;
			}
			pci_cfg->driver_feature = data;
			if (pci_cfg->driver_feature_select == 0)
				dev->driver_feature |= pci_cfg->driver_feature;
			else
				dev->driver_feature |=
				    ((uint64_t)pci_cfg->driver_feature << 32);
			dev->driver_feature &= dev->device_feature;
			DPRINTF("%s: driver features 0x%llx", __func__,
			    dev->driver_feature);
			break;
		case VIO1_PCI_CONFIG_MSIX_VECTOR:
			/* Config-change interrupt vector (subprocess). */
			dev->config_msix_vector = (uint16_t)data;
			break;
		case VIO1_PCI_NUM_QUEUES:
			log_warnx("illegal write to num queues register");
			break;
		case VIO1_PCI_DEVICE_STATUS:
			if (sz != 1) {
				log_warnx("%s: unaligned write to device "
				    "status register (sz=%u)", __func__, sz);
				break;
			}
			dev->status = data;
			if (dev->status == 0) {
				/* Reset device and virtqueues (if any). */
				dev->driver_feature = 0;
				dev->isr = 0;
				dev->config_msix_vector = VIRTIO_MSI_NO_VECTOR;

				/*
				 * A reset must lower the interrupt line.
				 * After reset the guest will not read the ISR
				 * register, so without an explicit deassert
				 * the level line would stay asserted if a
				 * completion was in service, presenting as a
				 * false interrupt source.  Mirror vionet's
				 * reset deassert.  Only multi-process devices
				 * (vioblk/vioscsi reach this shared path) own
				 * an async KICK channel; in-process devices
				 * (entropy, vmmci) keep async_fd == -1 and
				 * raise no level line here, so scope the
				 * deassert to them.
				 */
				if (dev->async_fd != -1)
					virtio_deassert_irq(dev, 0);

				pci_cfg->queue_select = 0;
				virtio_update_qs(dev);

				if (dev->num_queues > 0) {
					/*
					 * Reset virtqueues to initial state and
					 * set to disabled status. Clear PCI
					 * configuration registers.
					 */
					for (i = 0; i < dev->num_queues; i++)
						virtio_vq_init(dev, i);
				}
			}

			DPRINTF("%s: dev %u status [%s%s%s%s%s%s]", __func__,
			    dev->pci_id,
			    (data & VIRTIO_CONFIG_DEVICE_STATUS_ACK) ?
			    "[ack]" : "",
			    (data & VIRTIO_CONFIG_DEVICE_STATUS_DRIVER) ?
			    "[driver]" : "",
			    (data & VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK) ?
			    "[driver ok]" : "",
			    (data & VIRTIO_CONFIG_DEVICE_STATUS_FEATURES_OK) ?
			    "[features ok]" : "",
			    (data &
				VIRTIO_CONFIG_DEVICE_STATUS_DEVICE_NEEDS_RESET)
			    ? "[needs reset]" : "",
			    (data & VIRTIO_CONFIG_DEVICE_STATUS_FAILED) ?
			    "[failed]" : "");

			break;
		case VIO1_PCI_CONFIG_GENERATION:
			log_warnx("illegal write to config generation "
			    "register");
			break;
		case VIO1_PCI_QUEUE_SELECT:
			pci_cfg->queue_select = data;
			virtio_update_qs(dev);
			break;
		case VIO1_PCI_QUEUE_SIZE:
			if (data <= VIRTIO_QUEUE_SIZE_MAX)
				pci_cfg->queue_size = data;
			else {
				log_warnx("%s: clamping queue size", __func__);
				pci_cfg->queue_size = VIRTIO_QUEUE_SIZE_MAX;
			}
			virtio_update_qa(dev);
			break;
		case VIO1_PCI_QUEUE_MSIX_VECTOR:
			/*
			 * Assign an MSI-X table index to the selected
			 * virtqueue (subprocess).  Stamped into the KICK
			 * message by virtio_assert_irq() so the VM process
			 * delivers the right vector.
			 */
			if (pci_cfg->queue_select < dev->num_queues)
				dev->vq[pci_cfg->queue_select].msix_vector =
				    (uint16_t)data;
			break;
		case VIO1_PCI_QUEUE_ENABLE:
			pci_cfg->queue_enable = data;
			virtio_update_qa(dev);
			break;
		case VIO1_PCI_QUEUE_NOTIFY_OFF:
			log_warnx("illegal write to queue notify offset "
			    "register");
			break;
		case VIO1_PCI_QUEUE_DESC:
			if (sz != 4) {
				log_warnx("%s: unaligned write to queue "
				    "desc. register (sz=%u)", __func__, sz);
				break;
			}
			pci_cfg->queue_desc &= 0xffffffff00000000;
			pci_cfg->queue_desc |= (uint64_t)data;
			virtio_update_qa(dev);
			break;
		case VIO1_PCI_QUEUE_DESC + 4:
			if (sz != 4) {
				log_warnx("%s: unaligned write to queue "
				    "desc. register (sz=%u)", __func__, sz);
				break;
			}
			pci_cfg->queue_desc &= 0x00000000ffffffff;
			pci_cfg->queue_desc |= ((uint64_t)data << 32);
			virtio_update_qa(dev);
			break;
		case VIO1_PCI_QUEUE_AVAIL:
			if (sz != 4) {
				log_warnx("%s: unaligned write to queue "
				    "available register (sz=%u)", __func__, sz);
				break;
			}
			pci_cfg->queue_avail &= 0xffffffff00000000;
			pci_cfg->queue_avail |= (uint64_t)data;
			virtio_update_qa(dev);
			break;
		case VIO1_PCI_QUEUE_AVAIL + 4:
			if (sz != 4) {
				log_warnx("%s: unaligned write to queue "
				    "available register (sz=%u)", __func__, sz);
				break;
			}
			pci_cfg->queue_avail &= 0x00000000ffffffff;
			pci_cfg->queue_avail |= ((uint64_t)data << 32);
			virtio_update_qa(dev);
			break;
		case VIO1_PCI_QUEUE_USED:
			if (sz != 4) {
				log_warnx("%s: unaligned write to queue used "
				    "register (sz=%u)", __func__, sz);
				break;
			}
			pci_cfg->queue_used &= 0xffffffff00000000;
			pci_cfg->queue_used |= (uint64_t)data;
			virtio_update_qa(dev);
			break;
		case VIO1_PCI_QUEUE_USED + 4:
			if (sz != 4) {
				log_warnx("%s: unaligned write to queue used "
				    "register (sz=%u)", __func__, sz);
				break;
			}
			pci_cfg->queue_used &= 0x00000000ffffffff;
			pci_cfg->queue_used |= ((uint64_t)data << 32);
			virtio_update_qa(dev);
			break;
		default:
			log_warnx("%s: invalid register 0x%04x", __func__, reg);
		}
	} else {
		switch (reg) {
		case VIO1_PCI_DEVICE_FEATURE_SELECT:
			res = pci_cfg->device_feature_select;
			break;
		case VIO1_PCI_DEVICE_FEATURE:
			if (pci_cfg->device_feature_select == 0)
				res = dev->device_feature & (uint32_t)(-1);
			else if (pci_cfg->device_feature_select == 1)
				res = dev->device_feature >> 32;
			else {
				DPRINTF("%s: ignoring device feature read",
				    __func__);
			}
			break;
		case VIO1_PCI_DRIVER_FEATURE_SELECT:
			res = pci_cfg->driver_feature_select;
			break;
		case VIO1_PCI_DRIVER_FEATURE:
			if (pci_cfg->driver_feature_select == 0)
				res = dev->driver_feature & (uint32_t)(-1);
			else if (pci_cfg->driver_feature_select == 1)
				res = dev->driver_feature >> 32;
			else {
				DPRINTF("%s: ignoring driver feature read",
				    __func__);
			}
			break;
		case VIO1_PCI_CONFIG_MSIX_VECTOR:
			res = dev->config_msix_vector;
			break;
		case VIO1_PCI_NUM_QUEUES:
			res = dev->num_queues;
			break;
		case VIO1_PCI_DEVICE_STATUS:
			res = dev->status;
			break;
		case VIO1_PCI_CONFIG_GENERATION:
			res = pci_cfg->config_generation;
			break;
		case VIO1_PCI_QUEUE_SELECT:
			res = pci_cfg->queue_select;
			break;
		case VIO1_PCI_QUEUE_SIZE:
			res = pci_cfg->queue_size;
			break;
		case VIO1_PCI_QUEUE_MSIX_VECTOR:
			if (pci_cfg->queue_select < dev->num_queues)
				res = dev->vq[pci_cfg->queue_select].msix_vector;
			else
				res = VIRTIO_MSI_NO_VECTOR;
			break;
		case VIO1_PCI_QUEUE_ENABLE:
			res = pci_cfg->queue_enable;
			break;
		case VIO1_PCI_QUEUE_NOTIFY_OFF:
			res = pci_cfg->queue_notify_off;
			break;
		case VIO1_PCI_QUEUE_DESC:
			res = (uint32_t)(0xFFFFFFFF & pci_cfg->queue_desc);
			break;
		case VIO1_PCI_QUEUE_DESC + 4:
			res = (uint32_t)(pci_cfg->queue_desc >> 32);
			break;
		case VIO1_PCI_QUEUE_AVAIL:
			res = (uint32_t)(0xFFFFFFFF & pci_cfg->queue_avail);
			break;
		case VIO1_PCI_QUEUE_AVAIL + 4:
			res = (uint32_t)(pci_cfg->queue_avail >> 32);
			break;
		case VIO1_PCI_QUEUE_USED:
			res = (uint32_t)(0xFFFFFFFF & pci_cfg->queue_used);
			break;
		case VIO1_PCI_QUEUE_USED + 4:
			res = (uint32_t)(pci_cfg->queue_used >> 32);
			break;
		default:
			log_warnx("%s: invalid register 0x%04x", __func__, reg);
		}
	}

	DPRINTF("%s: dev=%u %s sz=%u dir=%s data=0x%04x", __func__, dev->pci_id,
	    virtio1_reg_name(reg), sz, (dir == VEI_DIR_OUT) ? "w" : "r",
	    (dir == VEI_DIR_OUT) ? data : res);

	return (res);
}

static int
virtio_io_isr(int dir, uint16_t reg, uint32_t *data, uint8_t *intr,
    void *arg, uint8_t sz)
{
	struct virtio_dev *dev = (struct virtio_dev *)arg;
	*intr = 0xFF;

	DPRINTF("%s: dev=%u, reg=0x%04x, sz=%u, dir=%s", __func__,
	    dev->pci_id, reg, sz,
	    (dir == VEI_DIR_OUT) ? "write" : "read");

	/* Limit to in-process devices. */
	if (dev->device_id == PCI_PRODUCT_VIRTIO_BLOCK ||
	    dev->device_id == PCI_PRODUCT_VIRTIO_NETWORK ||
	    dev->device_id == PCI_PRODUCT_VIRTIO_SCSI)
		fatalx("%s: cannot use on multi-process virtio dev", __func__);

	if (dir == VEI_DIR_IN) {
		*data = dev->isr;
		dev->isr = 0;
		vcpu_deassert_irq(dev->vmm_id, 0, dev->irq);
	}

	return (0);
}

static int
virtio_io_notify(int dir, uint16_t reg, uint32_t *data, uint8_t *intr,
    void *arg, uint8_t sz)
{
	int raise_intr = 0;
	struct virtio_dev *dev = (struct virtio_dev *)arg;
	uint16_t vq_idx = (uint16_t)(0x0000ffff & *data);

	*intr = 0xFF;

	DPRINTF("%s: reg=0x%04x, sz=%u, vq_idx=%u, dir=%s", __func__, reg, sz,
	    vq_idx, (dir == VEI_DIR_OUT) ? "write" : "read");

	/* Limit this handler to in-process devices */
	if (dev->device_id == PCI_PRODUCT_VIRTIO_BLOCK ||
	    dev->device_id == PCI_PRODUCT_VIRTIO_NETWORK ||
	    dev->device_id == PCI_PRODUCT_VIRTIO_SCSI)
		fatalx("%s: cannot use on multi-process virtio dev", __func__);

	if (vq_idx >= dev->num_queues) {
		log_warnx("%s: invalid virtqueue index %u", __func__, vq_idx);
		return (0);
	}

	if (dir == VEI_DIR_IN) {
		/* Behavior is undefined. */
		*data = 0;
		return (0);
	}

	switch (dev->device_id) {
	case PCI_PRODUCT_VIRTIO_ENTROPY:
		raise_intr = viornd_notifyq(dev, vq_idx);
		break;
	case PCI_PRODUCT_VIRTIO_VMMCI:
		/* Does not use a virtqueue. */
		break;
	default:
		log_warnx("%s: invalid device type %u", __func__,
		    dev->device_id);
	}

	if (raise_intr)
		*intr = 1;

	return (0);
}

/*
 * vmmci_ctl
 *
 * Inject a command into the vmmci device, potentially delivering interrupt.
 *
 * Called by the vm process's event(3) loop.
 */
int
vmmci_ctl(struct virtio_dev *dev, unsigned int cmd)
{
	int ret = 0;
	struct timeval tv = { 0, 0 };
	struct vmmci_dev *v = NULL;

	if (dev->device_id != PCI_PRODUCT_VIRTIO_VMMCI)
		fatalx("%s: device is not a vmmci device", __func__);
	v = &dev->vmmci;

	mutex_lock(&v->mutex);

	if ((dev->status & VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK) == 0) {
		ret = -1;
		goto unlock;
	}

	if (cmd == v->cmd)
		goto unlock;

	switch (cmd) {
	case VMMCI_NONE:
		break;
	case VMMCI_SHUTDOWN:
	case VMMCI_REBOOT:
		/* Update command */
		v->cmd = cmd;

		/*
		 * vmm VMs do not support powerdown, send a reboot request
		 * instead and turn it off after the triple fault.
		 */
		if (cmd == VMMCI_SHUTDOWN)
			cmd = VMMCI_REBOOT;

		/* Trigger interrupt */
		dev->isr = VIRTIO_CONFIG_ISR_CONFIG_CHANGE;
		vcpu_assert_irq(dev->vmm_id, 0, dev->irq);

		/* Add ACK timeout */
		tv.tv_sec = VMMCI_TIMEOUT_SHORT;
		evtimer_add(&v->timeout, &tv);
		break;
	case VMMCI_SYNCRTC:
		if (vmmci.cfg.guest_feature & VMMCI_F_SYNCRTC) {
			/* RTC updated, request guest VM resync of its RTC */
			v->cmd = cmd;

			dev->isr = VIRTIO_CONFIG_ISR_CONFIG_CHANGE;
			vcpu_assert_irq(dev->vmm_id, 0, dev->irq);
		} else {
			log_debug("%s: RTC sync skipped (guest does not "
			    "support RTC sync)\n", __func__);
		}
		break;
	default:
		fatalx("invalid vmmci command: %d", cmd);
	}

unlock:
	mutex_unlock(&v->mutex);

	return (ret);
}

/*
 * vmmci_ack
 *
 * Process a write to the command register.
 *
 * Called by the vcpu thread. Must be called with the mutex held.
 */
static void
vmmci_ack(struct virtio_dev *dev, unsigned int cmd)
{
	struct vmmci_dev *v = NULL;

	if (dev->device_id != PCI_PRODUCT_VIRTIO_VMMCI)
		fatalx("%s: device is not a vmmci device", __func__);
	v = &dev->vmmci;

	switch (cmd) {
	case VMMCI_NONE:
		break;
	case VMMCI_SHUTDOWN:
		/*
		 * The shutdown was requested by the VM if we don't have
		 * a pending shutdown request.  In this case add a short
		 * timeout to give the VM a chance to reboot before the
		 * timer is expired.
		 */
		if (v->cmd == 0) {
			log_debug("%s: vm %u requested shutdown", __func__,
			    dev->vmm_id);
			vm_pipe_send(&v->dev_pipe, VMMCI_SET_TIMEOUT_SHORT);
			return;
		}
		/* FALLTHROUGH */
	case VMMCI_REBOOT:
		/*
		 * If the VM acknowledged our shutdown request, give it
		 * enough time to shutdown or reboot gracefully.  This
		 * might take a considerable amount of time (running
		 * rc.shutdown on the VM), so increase the timeout before
		 * killing it forcefully.
		 */
		if (cmd == v->cmd) {
			log_debug("%s: vm %u acknowledged shutdown request",
			    __func__, dev->vmm_id);
			vm_pipe_send(&v->dev_pipe, VMMCI_SET_TIMEOUT_LONG);
		}
		break;
	case VMMCI_SYNCRTC:
		log_debug("%s: vm %u acknowledged RTC sync request",
		    __func__, dev->vmm_id);
		v->cmd = VMMCI_NONE;
		break;
	default:
		log_warnx("%s: illegal request %u", __func__, cmd);
		break;
	}
}

void
vmmci_timeout(int fd, short type, void *arg)
{
	struct virtio_dev *dev = (struct virtio_dev *)arg;
	struct vmmci_dev *v = NULL;

	if (dev->device_id != PCI_PRODUCT_VIRTIO_VMMCI)
		fatalx("%s: device is not a vmmci device", __func__);
	v = &dev->vmmci;

	log_debug("vm %u shutdown", dev->vmm_id);
	vm_shutdown(v->cmd == VMMCI_REBOOT ? VMMCI_REBOOT : VMMCI_SHUTDOWN);
}

int
vmmci_io(int dir, uint16_t reg, uint32_t *data, uint8_t *intr,
    void *arg, uint8_t sz)
{
	struct virtio_dev	*dev = (struct virtio_dev *)arg;
	struct vmmci_dev	*v = NULL;

	if (dev->device_id != PCI_PRODUCT_VIRTIO_VMMCI)
		fatalx("%s: device is not a vmmci device (%u)",
		    __func__, dev->device_id);
	v = &dev->vmmci;

	*intr = 0xFF;

	mutex_lock(&v->mutex);
	if (dir == 0) {
		switch (reg) {
		case VIRTIO_CONFIG_DEVICE_FEATURES:
		case VIRTIO_CONFIG_QUEUE_SIZE:
		case VIRTIO_CONFIG_ISR_STATUS:
			log_warnx("illegal write %x to %s", *data,
			    virtio_reg_name(reg));
			break;
		case VIRTIO_CONFIG_GUEST_FEATURES:
			dev->cfg.guest_feature = *data;
			break;
		case VIRTIO_CONFIG_QUEUE_PFN:
			dev->cfg.queue_pfn = *data;
			break;
		case VIRTIO_CONFIG_QUEUE_SELECT:
			dev->cfg.queue_select = *data;
			break;
		case VIRTIO_CONFIG_QUEUE_NOTIFY:
			dev->cfg.queue_notify = *data;
			break;
		case VIRTIO_CONFIG_DEVICE_STATUS:
			dev->status = *data;
			break;
		case VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI:
			vmmci_ack(dev, *data);
			break;
		}
	} else {
		switch (reg) {
		case VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI:
			*data = v->cmd;
			break;
		case VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI + 4:
			/* Update time once when reading the first register */
			gettimeofday(&v->time, NULL);
			*data = (uint64_t)v->time.tv_sec;
			break;
		case VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI + 8:
			*data = (uint64_t)v->time.tv_sec << 32;
			break;
		case VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI + 12:
			*data = (uint64_t)v->time.tv_usec;
			break;
		case VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI + 16:
			*data = (uint64_t)v->time.tv_usec << 32;
			break;
		case VIRTIO_CONFIG_DEVICE_FEATURES:
			*data = dev->cfg.device_feature;
			break;
		case VIRTIO_CONFIG_GUEST_FEATURES:
			*data = dev->cfg.guest_feature;
			break;
		case VIRTIO_CONFIG_QUEUE_PFN:
			*data = dev->cfg.queue_pfn;
			break;
		case VIRTIO_CONFIG_QUEUE_SIZE:
			*data = dev->cfg.queue_size;
			break;
		case VIRTIO_CONFIG_QUEUE_SELECT:
			*data = dev->cfg.queue_select;
			break;
		case VIRTIO_CONFIG_QUEUE_NOTIFY:
			*data = dev->cfg.queue_notify;
			break;
		case VIRTIO_CONFIG_DEVICE_STATUS:
			*data = dev->status;
			break;
		case VIRTIO_CONFIG_ISR_STATUS:
			*data = dev->isr;
			dev->isr = 0;
			vcpu_deassert_irq(dev->vmm_id, 0, dev->irq);
			break;
		}
	}
	mutex_unlock(&v->mutex);

	return (0);
}

enum vm_disk_fmt
virtio_get_disktype(int fd)
{
	char	 buf[sizeof(VM_MAGIC_QCOW) - 1];
	ssize_t	 len;

	len = pread(fd, buf, sizeof(buf), 0);
	if (len >= (ssize_t)sizeof(buf) &&
	    memcmp(buf, VM_MAGIC_QCOW, sizeof(buf)) == 0)
		return (VMDF_QCOW2);

	return (VMDF_RAW);
}

static void
vmmci_pipe_dispatch(int fd, short event, void *arg)
{
	struct virtio_dev	*dev = (struct virtio_dev *)arg;
	struct vmmci_dev 	*v = &dev->vmmci;
	struct timeval		 tv = { 0, 0 };
	enum pipe_msg_type	 msg;

	msg = vm_pipe_recv(&v->dev_pipe);
	switch (msg) {
	case VMMCI_SET_TIMEOUT_SHORT:
		tv.tv_sec = VMMCI_TIMEOUT_SHORT;
		evtimer_add(&v->timeout, &tv);
		break;
	case VMMCI_SET_TIMEOUT_LONG:
		tv.tv_sec = VMMCI_TIMEOUT_LONG;
		evtimer_add(&v->timeout, &tv);
		break;
	default:
		log_warnx("%s: invalid pipe message type %d", __func__, msg);
	}
}

/*
 * Initialize virtio devices, launching subprocesses if needed.
 *
 * Returns 0 on success, 1 on failure.
 */
int
virtio_init(struct vmd_vm *vm, int child_cdrom,
    int child_disks[][VM_MAX_BASE_PER_DISK], int *child_taps)
{
	struct vmop_create_params *vmc = &vm->vm_params;
	struct virtio_dev *dev;
	uint8_t id, i, j;
	int bar_id, ret = 0;

	SLIST_INIT(&virtio_devs);

	/* Virtio 1.x Entropy Device */
	if (pci_add_device(&id, PCI_VENDOR_QUMRANET,
	    PCI_PRODUCT_QUMRANET_VIO1_RNG, PCI_CLASS_SYSTEM,
	    PCI_SUBCLASS_SYSTEM_MISC, PCI_VENDOR_OPENBSD,
	    PCI_PRODUCT_VIRTIO_ENTROPY, 1, 1, NULL)) {
		log_warnx("can't add PCI virtio rng device");
		return (1);
	}
	virtio_dev_init(vm, &viornd, id, VIORND_QUEUE_SIZE_DEFAULT,
	    VIRTIO_RND_QUEUES, VIRTIO_F_VERSION_1);

	bar_id = pci_add_bar(id, PCI_MAPREG_TYPE_IO, virtio_io_dispatch,
	    &viornd);
	if (bar_id == -1 || bar_id > 0xff) {
		log_warnx("can't add bar for virtio rng device");
		return (1);
	}
	virtio_pci_add_cap(id, VIRTIO_PCI_CAP_COMMON_CFG, bar_id, 0);
	virtio_pci_add_cap(id, VIRTIO_PCI_CAP_ISR_CFG, bar_id, 0);
	virtio_pci_add_cap(id, VIRTIO_PCI_CAP_NOTIFY_CFG, bar_id, 0);

	/* Virtio 1.x Network Devices */
	if (vmc->vmc_nnics > 0) {
		for (i = 0; i < vmc->vmc_nnics; i++) {
			dev = malloc(sizeof(struct virtio_dev));
			if (dev == NULL) {
				log_warn("calloc failure allocating vionet");
				return (1);
			}
			if (pci_add_device(&id, PCI_VENDOR_QUMRANET,
				PCI_PRODUCT_QUMRANET_VIO1_NET, PCI_CLASS_SYSTEM,
				PCI_SUBCLASS_SYSTEM_MISC, PCI_VENDOR_OPENBSD,
				PCI_PRODUCT_VIRTIO_NETWORK, 1, 1, NULL)) {
				log_warnx("can't add PCI virtio net device");
				return (1);
			}
			virtio_dev_init(vm, dev, id, VIONET_QUEUE_SIZE_DEFAULT,
			    VIRTIO_NET_QUEUES,
			    (VIRTIO_NET_F_MAC | VIRTIO_F_VERSION_1));

			if (pci_add_bar(id, PCI_MAPREG_TYPE_IO, virtio_pci_io,
			    dev) == -1) {
				log_warnx("can't add bar for virtio net "
				    "device");
				return (1);
			}
			virtio_pci_add_cap(id, VIRTIO_PCI_CAP_COMMON_CFG,
			    bar_id, 0);
			virtio_pci_add_cap(id, VIRTIO_PCI_CAP_DEVICE_CFG,
			    bar_id, 8);
			virtio_pci_add_cap(id, VIRTIO_PCI_CAP_ISR_CFG, bar_id,
			    0);
			virtio_pci_add_cap(id, VIRTIO_PCI_CAP_NOTIFY_CFG,
			    bar_id, 0);

			/* Device specific initializiation. */
			dev->dev_type = VMD_DEVTYPE_NET;
			dev->vmm_id = vm->vm_vmmid;
			dev->vionet.data_fd = child_taps[i];

			/* MAC address has been assigned by the parent */
			memcpy(&dev->vionet.mac, &vmc->vmc_macs[i], 6);
			dev->vionet.lockedmac =
			    vmc->vmc_ifflags[i] & VMIFF_LOCKED ? 1 : 0;
			dev->vionet.local =
			    vmc->vmc_ifflags[i] & VMIFF_LOCAL ? 1 : 0;
			if (i == 0 && vmc->vmc_bootdevice & VMBOOTDEV_NET)
				dev->vionet.pxeboot = 1;
			memcpy(&dev->vionet.local_prefix,
			    &env->vmd_cfg.cfg_localprefix,
			    sizeof(dev->vionet.local_prefix));
			log_debug("%s: vm \"%s\" vio%u lladdr %s%s%s%s",
			    __func__, vm->vm_params.vmc_name, i,
			    ether_ntoa((void *)dev->vionet.mac),
			    dev->vionet.lockedmac ? ", locked" : "",
			    dev->vionet.local ? ", local" : "",
			    dev->vionet.pxeboot ? ", pxeboot" : "");

			/* Add the vionet to our device list. */
			dev->vionet.idx = i;
			SLIST_INSERT_HEAD(&virtio_devs, dev, dev_next);
		}
	}

	/* Virtio 1.x Block Devices */
	if (vmc->vmc_ndisks > 0) {
		for (i = 0; i < vmc->vmc_ndisks; i++) {
			dev = malloc(sizeof(struct virtio_dev));
			if (dev == NULL) {
				log_warn("%s: failure allocating vioblk",
				    __func__);
				return (1);
			}
			if (pci_add_device(&id, PCI_VENDOR_QUMRANET,
			    PCI_PRODUCT_QUMRANET_VIO1_BLOCK,
			    PCI_CLASS_MASS_STORAGE,
			    PCI_SUBCLASS_MASS_STORAGE_SCSI, PCI_VENDOR_OPENBSD,
			    PCI_PRODUCT_VIRTIO_BLOCK, 1, 1, NULL)) {
				log_warnx("can't add PCI virtio block "
				    "device");
				return (1);
			}
			virtio_dev_init(vm, dev, id, VIOBLK_QUEUE_SIZE_DEFAULT,
			    VIRTIO_BLK_QUEUES,
			    (VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_SEG_MAX |
			    VIRTIO_BLK_F_FLUSH));

			bar_id = pci_add_bar(id, PCI_MAPREG_TYPE_IO, virtio_pci_io,
			    dev);
			if (bar_id == -1 || bar_id > 0xff) {
				log_warnx("can't add bar for virtio block "
				    "device");
				return (1);
			}
			virtio_pci_add_cap(id, VIRTIO_PCI_CAP_COMMON_CFG,
			    bar_id, 0);
			virtio_pci_add_cap(id, VIRTIO_PCI_CAP_DEVICE_CFG,
			    bar_id, 24);
			virtio_pci_add_cap(id, VIRTIO_PCI_CAP_ISR_CFG, bar_id,
			    0);
			virtio_pci_add_cap(id, VIRTIO_PCI_CAP_NOTIFY_CFG,
			    bar_id, 0);

			/* Device specific initialization. */
			dev->dev_type = VMD_DEVTYPE_DISK;
			dev->vmm_id = vm->vm_vmmid;
			dev->vioblk.seg_max = VIOBLK_SEG_MAX_DEFAULT;

			/*
			 * Initialize disk fds to an invalid fd (-1), then
			 * set any child disk fds.
			 */
			memset(&dev->vioblk.disk_fd, -1,
			    sizeof(dev->vioblk.disk_fd));
			dev->vioblk.ndisk_fd = vmc->vmc_diskbases[i];
			for (j = 0; j < dev->vioblk.ndisk_fd; j++)
				dev->vioblk.disk_fd[j] = child_disks[i][j];

			dev->vioblk.idx = i;
			SLIST_INSERT_HEAD(&virtio_devs, dev, dev_next);
		}
	}

	/* Virtio 1.x SCSI CD-ROM */
	if (strlen(vmc->vmc_cdrom)) {
		dev = malloc(sizeof(struct virtio_dev));
		if (dev == NULL) {
			log_warn("calloc failure allocating vioscsi");
			return (1);
		}
		if (pci_add_device(&id, PCI_VENDOR_QUMRANET,
		    PCI_PRODUCT_QUMRANET_VIO1_SCSI, PCI_CLASS_MASS_STORAGE,
		    PCI_SUBCLASS_MASS_STORAGE_SCSI, PCI_VENDOR_OPENBSD,
		    PCI_PRODUCT_VIRTIO_SCSI, 1, 1, NULL)) {
			log_warnx("can't add PCI vioscsi device");
			return (1);
		}
		virtio_dev_init(vm, dev, id, VIOSCSI_QUEUE_SIZE_DEFAULT,
		    VIRTIO_SCSI_QUEUES, VIRTIO_F_VERSION_1);
		if (pci_add_bar(id, PCI_MAPREG_TYPE_IO, virtio_pci_io, dev)
		    == -1) {
			log_warnx("can't add bar for vioscsi device");
			return (1);
		}
		virtio_pci_add_cap(id, VIRTIO_PCI_CAP_COMMON_CFG, bar_id, 0);
		virtio_pci_add_cap(id, VIRTIO_PCI_CAP_DEVICE_CFG, bar_id, 36);
		virtio_pci_add_cap(id, VIRTIO_PCI_CAP_ISR_CFG, bar_id, 0);
		virtio_pci_add_cap(id, VIRTIO_PCI_CAP_NOTIFY_CFG, bar_id, 0);

		/* Device specific initialization. */
		dev->dev_type = VMD_DEVTYPE_SCSI;
		dev->vmm_id = vm->vm_vmmid;
		dev->vioscsi.cdrom_fd = child_cdrom;
		dev->vioscsi.locked = 0;
		dev->vioscsi.lba = 0;
		dev->vioscsi.max_xfer = VIOSCSI_BLOCK_SIZE_CDROM;
		SLIST_INSERT_HEAD(&virtio_devs, dev, dev_next);
	}

	/* Virtio 1.x Shared Filesystems (vio9p) */
	if (vmc->vmc_nshares > 0) {
		for (i = 0; i < vmc->vmc_nshares; i++) {
			dev = malloc(sizeof(struct virtio_dev));
			if (dev == NULL) {
				log_warn("%s: failure allocating viofs",
				    __func__);
				return (1);
			}
			if (pci_add_device(&id, PCI_VENDOR_QUMRANET,
			    PCI_PRODUCT_QUMRANET_VIO1_9P, PCI_CLASS_SYSTEM,
			    PCI_SUBCLASS_SYSTEM_MISC, PCI_VENDOR_OPENBSD,
			    PCI_PRODUCT_VIRTIO_9P, 1, 1, NULL)) {
				log_warnx("can't add PCI virtio 9p device");
				return (1);
			}
			virtio_dev_init(vm, dev, id, VIOFS_QUEUE_SIZE_DEFAULT,
			    VIRTIO_9P_QUEUES,
			    (VIRTIO_F_VERSION_1 | VIRTIO_9P_F_MOUNT_TAG));

			bar_id = pci_add_bar(id, PCI_MAPREG_TYPE_IO,
			    virtio_pci_io, dev);
			if (bar_id == -1 || bar_id > 0xff) {
				log_warnx("can't add bar for virtio 9p device");
				return (1);
			}
			virtio_pci_add_cap(id, VIRTIO_PCI_CAP_COMMON_CFG,
			    bar_id, 0);
			virtio_pci_add_cap(id, VIRTIO_PCI_CAP_DEVICE_CFG,
			    bar_id, 2 + VIO9P_TAG_MAX);
			virtio_pci_add_cap(id, VIRTIO_PCI_CAP_ISR_CFG, bar_id,
			    0);
			virtio_pci_add_cap(id, VIRTIO_PCI_CAP_NOTIFY_CFG,
			    bar_id, 0);

			/*
			 * MSI-X (SMP guests only).  The userland LAPIC fabric
			 * that delivers an edge interrupt to a specific vcpu
			 * only exists when the guest has more than one vcpu; on
			 * the single-cpu legacy path we keep INTx.  Add a
			 * dedicated MMIO BAR for the MSI-X table + PBA and
			 * register an emulation handler over its GPA range.
			 */
			if (vmc->vmc_ncpus > 1) {
				int msix_bar;

				msix_bar = pci_add_bar(id, PCI_MAPREG_TYPE_MEM,
				    NULL, dev);
				if (msix_bar == -1) {
					log_warnx("can't add msix bar for "
					    "virtio 9p device");
					return (1);
				}
				dev->msix_bar_gpa =
				    pci_get_bar_addr(id, msix_bar);
				if (mmio_register(dev->msix_bar_gpa,
				    VIOFS_MSIX_BAR_SIZE, virtio_msix_mmio_read,
				    virtio_msix_mmio_write, dev) == -1)
					log_warnx("can't register msix mmio "
					    "handler for virtio 9p device");
#if VIOFS_MSIX_ENABLE
				virtio_add_msix_cap(id, msix_bar,
				    VIRTIO_9P_QUEUES + 1);
#endif
			}

			/*
			 * Device specific initialization.  The share dir fd is
			 * opened by the device subprocess itself under unveil(2)
			 * (a directory fd cannot be passed here: pledge "sendfd"
			 * rejects it), so leave it unset.
			 */
			dev->dev_type = VMD_DEVTYPE_VIOFS;
			dev->vmm_id = vm->vm_vmmid;
			dev->viofs.share_fd = -1;
			dev->viofs.flags = vmc->vmc_share_flags[i];
			dev->viofs.credmode = vmc->vmc_share_credmode[i];
			dev->viofs.maproot = vmc->vmc_share_maproot[i];
			dev->viofs.idx = i;
			(void)strlcpy(dev->viofs.path, vmc->vmc_shares[i],
			    sizeof(dev->viofs.path));
			(void)strlcpy(dev->viofs.tag, vmc->vmc_share_tag[i],
			    sizeof(dev->viofs.tag));

			SLIST_INSERT_HEAD(&virtio_devs, dev, dev_next);
		}
	}

	/*
	 * Launch virtio devices that support subprocess execution.
	 */
	SLIST_FOREACH(dev, &virtio_devs, dev_next) {
		if (virtio_dev_launch(vm, dev) != 0) {
			log_warnx("failed to launch virtio device");
			return (1);
		}
	}

	/* Virtio 0.9 VMM Control Interface */
	dev = &vmmci;
	if (pci_add_device(&id, PCI_VENDOR_OPENBSD, PCI_PRODUCT_OPENBSD_CONTROL,
	    PCI_CLASS_COMMUNICATIONS, PCI_SUBCLASS_COMMUNICATIONS_MISC,
	    PCI_VENDOR_OPENBSD, PCI_PRODUCT_VIRTIO_VMMCI, 0, 1, NULL)) {
		log_warnx("can't add PCI vmm control device");
		return (1);
	}
	virtio_dev_init(vm, dev, id, 0, 0,
	    VMMCI_F_TIMESYNC | VMMCI_F_ACK | VMMCI_F_SYNCRTC);
	if (pci_add_bar(id, PCI_MAPREG_TYPE_IO, vmmci_io, dev) == -1) {
		log_warnx("can't add bar for vmm control device");
		return (1);
	}

	ret = pthread_mutex_init(&dev->vmmci.mutex, NULL);
	if (ret) {
		errno = ret;
		log_warn("could not initialize vmmci mutex");
		return (1);
	}
	evtimer_set(&dev->vmmci.timeout, vmmci_timeout, dev);
	vm_pipe_init2(&dev->vmmci.dev_pipe, vmmci_pipe_dispatch, dev);
	event_add(&dev->vmmci.dev_pipe.read_ev, NULL);

	return (0);
}

/*
 * vionet_set_hostmac
 *
 * Sets the hardware address for the host-side tap(4) on a vionet_dev.
 *
 * This should only be called from the event-loop thread
 *
 * vm: pointer to the current vmd_vm instance
 * idx: index into the array of vionet_dev's for the target vionet_dev
 * addr: ethernet address to set
 */
void
vionet_set_hostmac(struct vmd_vm *vm, unsigned int idx, uint8_t *addr)
{
	struct vmop_create_params	*vmc = &vm->vm_params;
	struct virtio_dev		*dev;
	struct vionet_dev		*vionet = NULL;
	int ret;

	if (idx > vmc->vmc_nnics)
		fatalx("%s: invalid vionet index: %u", __func__, idx);

	SLIST_FOREACH(dev, &virtio_devs, dev_next) {
		if (dev->dev_type == VMD_DEVTYPE_NET
		    && dev->vionet.idx == idx) {
			vionet = &dev->vionet;
			break;
		}
	}
	if (vionet == NULL)
		fatalx("%s: dev == NULL, idx = %u", __func__, idx);

	/* Set the local vm process copy. */
	memcpy(vionet->hostmac, addr, sizeof(vionet->hostmac));

	/* Send the information to the device process. */
	ret = imsg_compose_event(&dev->async_iev, IMSG_DEVOP_HOSTMAC, 0, 0, -1,
	    vionet->hostmac, sizeof(vionet->hostmac));
	if (ret == -1) {
		log_warnx("%s: failed to queue hostmac to vionet dev %u",
		    __func__, idx);
		return;
	}
}

void
virtio_shutdown(struct vmd_vm *vm)
{
	int ret, status;
	pid_t pid = 0;
	struct virtio_dev *dev, *tmp;
	struct viodev_msg msg;
	struct imsgbuf *ibuf;

	/* Ensure that our disks are synced. */
	if (vioscsi != NULL)
		vioscsi->vioscsi.file.close(vioscsi->vioscsi.file.p, 0);

	/*
	 * Broadcast shutdown to child devices. We need to do this
	 * synchronously as we have already stopped the async event thread.
	 */
	SLIST_FOREACH(dev, &virtio_devs, dev_next) {
		memset(&msg, 0, sizeof(msg));
		msg.type = VIODEV_MSG_SHUTDOWN;
		ibuf = &dev->sync_iev.ibuf;
		ret = imsg_compose(ibuf, VIODEV_MSG_SHUTDOWN, 0, 0, -1,
		    &msg, sizeof(msg));
		if (ret == -1)
			fatalx("%s: failed to send shutdown to device",
			    __func__);
		if (imsgbuf_flush(ibuf) == -1)
			fatalx("%s: imsgbuf_flush", __func__);
	}

	/*
	 * Wait for all children to shutdown using a simple approach of
	 * iterating over known child devices and waiting for them to die.
	 */
	SLIST_FOREACH_SAFE(dev, &virtio_devs, dev_next, tmp) {
		/*
		 * M3b Phase B: the transparent viofs was fork+exec'd by
		 * PROC_PARENT (so it could keep root), not by this VM process.
		 * It is therefore NOT our child -- waitpid() here would return
		 * ECHILD.  The orderly writeback flush already happened above
		 * over the VM-owned sync channel (VIODEV_MSG_SHUTDOWN); PARENT
		 * reaps the orphan when PROC_VMM notifies it on VM death.  Skip
		 * the local waitpid() for these, and tolerate ECHILD if a future
		 * change ever routes one here.
		 */
		if (dev->dev_parent_launched) {
			log_debug("%s: device pid %d is PARENT-launched; "
			    "PARENT will reap", __func__, dev->dev_pid);
			free(dev);
			continue;
		}
		log_debug("%s: waiting on device pid %d", __func__,
		    dev->dev_pid);
		do {
			pid = waitpid(dev->dev_pid, &status, WNOHANG);
		} while (pid == 0 || (pid == -1 && errno == EINTR));
		if (pid == dev->dev_pid)
			log_debug("%s: device for pid %d is stopped",
			    __func__, pid);
		else if (pid == -1 && errno == ECHILD)
			log_debug("%s: device pid %d already reaped", __func__,
			    dev->dev_pid);
		else
			log_warnx("%s: unexpected pid %d", __func__, pid);
		free(dev);
	}
}

void virtio_broadcast_imsg(struct vmd_vm *vm, uint16_t type, void *data,
    uint16_t datalen)
{
	struct virtio_dev *dev;
	int ret;

	SLIST_FOREACH(dev, &virtio_devs, dev_next) {
		ret = imsg_compose_event(&dev->async_iev, type, 0, 0, -1, data,
		    datalen);
		if (ret == -1) {
			log_warnx("%s: failed to broadcast imsg type %u",
			    __func__, type);
		}
	}

}

void
virtio_stop(struct vmd_vm *vm)
{
	return virtio_broadcast_imsg(vm, IMSG_VMDOP_PAUSE_VM, NULL, 0);
}

void
virtio_start(struct vmd_vm *vm)
{
	return virtio_broadcast_imsg(vm, IMSG_VMDOP_UNPAUSE_VM, NULL, 0);
}

/*
 * Initialize a new virtio device structure.
 */
static void
virtio_dev_init(struct vmd_vm *vm, struct virtio_dev *dev, uint8_t pci_id,
    uint16_t queue_size, uint16_t num_queues, uint64_t features)
{
	size_t i;
	uint16_t device_id;

	if (num_queues > 0 && num_queues > VIRTIO_MAX_QUEUES)
		fatalx("%s: num_queues too large", __func__);

	device_id = pci_get_subsys_id(pci_id);
	if (!device_id)
		fatalx("%s: invalid pci device id %u", __func__, pci_id);

	memset(dev, 0, sizeof(*dev));

	dev->pci_id = pci_id;
	dev->device_id = device_id;
	dev->irq = pci_get_dev_irq(pci_id);
	dev->isr = 0;
	dev->vm_id = vm->vm_vmid;
	dev->vmm_id = vm->vm_vmmid;

	dev->device_feature = features;

	dev->pci_cfg.config_generation = 0;
	dev->cfg.device_feature = features;

	dev->num_queues = num_queues;
	dev->queue_size = queue_size;
	dev->cfg.queue_size = queue_size;

	/* No MSI-X vectors assigned until the guest negotiates them. */
	dev->config_msix_vector = VIRTIO_MSI_NO_VECTOR;

	dev->async_fd = -1;
	dev->sync_fd = -1;

	if (num_queues > 0) {
		for (i = 0; i < num_queues; i++)
			virtio_vq_init(dev, i);
	}
}

void
virtio_vq_init(struct virtio_dev *dev, size_t idx)
{
	struct virtio_vq_info *vq_info = NULL;
	int v1 = (dev->device_feature & VIRTIO_F_VERSION_1) ? 1 : 0;

	if (idx >= dev->num_queues)
		fatalx("%s: invalid virtqueue index", __func__);
	vq_info = &dev->vq[idx];

	vq_info->q_gpa = 0;
	vq_info->qs = dev->queue_size;
	vq_info->mask = dev->queue_size - 1;

	if (v1) {
		vq_info->vq_enabled = 0;
		vq_info->vq_availoffset = 0;
		vq_info->vq_usedoffset = 0;
	} else {
		/* Always enable on pre-1.0 virtio devices. */
		vq_info->vq_enabled = 1;
		vq_info->vq_availoffset =
		    sizeof(struct vring_desc) * vq_info->qs;
		vq_info->vq_usedoffset = VIRTQUEUE_ALIGN(
		    sizeof(struct vring_desc) * vq_info->qs +
		    sizeof(uint16_t) * (2 + vq_info->qs));
	}

	vq_info->last_avail = 0;
	vq_info->notified_avail = 0;

	/* Reset to legacy INTx until the guest assigns an MSI-X vector. */
	vq_info->msix_vector = VIRTIO_MSI_NO_VECTOR;
}


static void
virtio_pci_add_cap(uint8_t pci_id, uint8_t cfg_type, uint8_t bar_id,
    uint32_t dev_cfg_len)
{
	struct virtio_pci_common_cap cap;

	memset(&cap, 0, sizeof(cap));

	cap.virtio.cap_vndr = PCI_CAP_VENDSPEC;
	cap.virtio.cap_len = sizeof(struct virtio_pci_cap);
	cap.virtio.bar = bar_id;
	cap.virtio.cfg_type = cfg_type;

	switch (cfg_type) {
	case VIRTIO_PCI_CAP_COMMON_CFG:
		cap.virtio.offset = VIO1_CFG_BAR_OFFSET;
		cap.virtio.length = sizeof(struct virtio_pci_common_cfg);
		break;
	case VIRTIO_PCI_CAP_DEVICE_CFG:
		/* XXX maybe inspect the virtio device and lookup the len. */
		cap.virtio.offset = VIO1_DEV_BAR_OFFSET;
		cap.virtio.length = dev_cfg_len;
		break;
	case VIRTIO_PCI_CAP_ISR_CFG:
		cap.virtio.offset = VIO1_ISR_BAR_OFFSET;
		cap.virtio.length = sizeof(uint8_t);
		break;
	case VIRTIO_PCI_CAP_NOTIFY_CFG:
		cap.virtio.offset = VIO1_NOTIFY_BAR_OFFSET;
		cap.virtio.length = sizeof(uint16_t);
		cap.notify.notify_off_multiplier = 0;
		break;
	default:
		fatalx("%s: invalid pci capability config type %u", __func__,
		    cfg_type);
	}

	if (pci_add_capability(pci_id, &cap.pci) == -1) {
		fatalx("%s: can't add capability for virtio pci device %u",
		    __func__, pci_id);
	}
}

/*
 * Add a standard PCI MSI-X capability to a device.  The MSI-X table and
 * the pending-bit array (PBA) both live in the device's MSI-X MMIO BAR
 * (bar_id) at the fixed offsets below.  nvec is the number of table
 * entries (one per virtqueue plus one for config-change interrupts).
 */
static void
virtio_add_msix_cap(uint8_t pci_id, uint8_t bar_id, uint16_t nvec)
{
	struct msix_cap {
		uint8_t  mc_cap_id;	/* PCI_CAP_MSIX */
		uint8_t  mc_next;
		uint16_t mc_msg_ctrl;	/* [10:0] table size-1, [15] enable */
		uint32_t mc_table;	/* [31:3] offset, [2:0] BIR */
		uint32_t mc_pba;	/* [31:3] offset, [2:0] BIR */
	} __packed mc;
	struct pci_cap cap;

	memset(&mc, 0, sizeof(mc));
	mc.mc_cap_id = PCI_CAP_MSIX;
	mc.mc_next = 0;
	mc.mc_msg_ctrl = nvec - 1;	/* Enable bit set later by the guest. */
	mc.mc_table = (VIOFS_MSIX_TABLE_OFFSET & ~0x7U) | (bar_id & 0x7);
	mc.mc_pba = (VIOFS_MSIX_PBA_OFFSET & ~0x7U) | (bar_id & 0x7);

	/* pci_add_capability() stores a fixed-size pci_cap; zero-pad. */
	memset(&cap, 0, sizeof(cap));
	memcpy(&cap, &mc, sizeof(mc));

	if (pci_add_capability(pci_id, &cap) == -1)
		fatalx("%s: can't add msix capability for pci device %u",
		    __func__, pci_id);
}

/*
 * Emulate guest reads of the MSI-X table BAR (VM process).  off is the
 * byte offset into the BAR.  The table is a flat array of 32-bit dwords;
 * the PBA region reports no pending bits in this prototype.
 */
static int
virtio_msix_mmio_read(uint64_t off, uint8_t bytes, uint64_t *val, void *cookie)
{
	struct virtio_dev *dev = cookie;
	uint32_t *t = (uint32_t *)dev->msix_table;
	size_t ndw = sizeof(dev->msix_table) / (sizeof(uint32_t));
	uint64_t idx = off / 4;

	*val = 0;
	if (off >= VIOFS_MSIX_PBA_OFFSET || (off & 0x3) != 0)
		return (0);
	if (idx < ndw)
		*val = t[idx];
	if (bytes == 8 && (idx + 1) < ndw)
		*val |= (uint64_t)t[idx + 1] << 32;
	return (0);
}

/*
 * Emulate guest writes to the MSI-X table BAR (VM process).  The guest
 * programs each entry's message address/data and per-vector mask bit.
 */
static int
virtio_msix_mmio_write(uint64_t off, uint8_t bytes, uint64_t val, void *cookie)
{
	struct virtio_dev *dev = cookie;
	uint32_t *t = (uint32_t *)dev->msix_table;
	size_t ndw = sizeof(dev->msix_table) / (sizeof(uint32_t));
	uint64_t idx = off / 4;

	/* PBA is read-only; table accesses are dword-aligned. */
	if (off >= VIOFS_MSIX_PBA_OFFSET || (off & 0x3) != 0)
		return (0);
	if (idx < ndw)
		t[idx] = (uint32_t)val;
	if (bytes == 8 && (idx + 1) < ndw)
		t[idx + 1] = (uint32_t)(val >> 32);
	return (0);
}

/*
 * Deliver an MSI-X interrupt (VM process).  Decode the x86 MSI message
 * stored in the device's table entry and inject an edge interrupt to the
 * destination vcpu's LAPIC.  Unlike legacy INTx there is no ISR register
 * to read back, so this avoids the second guest->host round-trip.
 */
static void
virtio_deliver_msix(struct virtio_dev *dev, uint16_t vector)
{
	struct virtio_msix_entry *e;
	uint32_t apic_id;
	uint8_t vec;

	if (vector >= VIRTIO_MSIX_MAX_VECTORS)
		return;
	e = &dev->msix_table[vector];

	/* Honor the per-vector mask bit (PBA tracking omitted). */
	if (e->vector_ctrl & 0x1)
		return;

	/*
	 * x86 MSI message, physical destination mode (what the guest
	 * programs): addr[19:12] = destination APIC id, data[7:0] = the
	 * delivered interrupt vector.
	 */
	apic_id = (e->addr_lo >> 12) & 0xff;
	vec = e->data & 0xff;
	if (vec == 0)
		return;		/* entry not yet programmed */

	lapic_smp_deliver_ipi(apic_id, vec);
}

/*
 * Fork+exec a child virtio device. Returns 0 on success.
 */
static int
virtio_dev_launch(struct vmd_vm *vm, struct virtio_dev *dev)
{
	char *nargv[12], num[32], vmm_fd[32], vm_name[VM_NAME_MAX], t[2];
	pid_t dev_pid;
	int sync_fds[2], async_fds[2], ret = 0, launch_via_parent;
	size_t i, sz = 0;
	struct viodev_msg msg;
	struct virtio_dev *dev_entry, dev_copy;
	struct imsg imsg;
	struct imsgev *iev = &dev->sync_iev;
	struct vmd_vm vm_copy;
	struct vmop_dev_launch vdl;

	switch (dev->dev_type) {
	case VMD_DEVTYPE_NET:
		log_debug("%s: launching vionet%d", vm->vm_params.vmc_name,
		    dev->vionet.idx);
		break;
	case VMD_DEVTYPE_DISK:
		log_debug("%s: launching vioblk%d", vm->vm_params.vmc_name,
		    dev->vioblk.idx);
		break;
	case VMD_DEVTYPE_SCSI:
		log_debug("%s: launching vioscsi", vm->vm_params.vmc_name);
		break;
	case VMD_DEVTYPE_VIOFS:
		log_debug("%s: launching vio9p%d", vm->vm_params.vmc_name,
		    dev->viofs.idx);
		break;
		/* NOTREACHED */
	default:
		log_warn("%s: invalid device type", __func__);
		return (EINVAL);
	}

	/* We need two channels: one synchronous (IO reads) and one async. */
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, PF_UNSPEC,
	    sync_fds) == -1) {
		log_warn("failed to create socketpair");
		return (errno);
	}
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, PF_UNSPEC,
	    async_fds) == -1) {
		log_warn("failed to create async socketpair");
		return (errno);
	}

	/*
	 * M3b Phase B: the transparent-credmode viofs must run as root so its
	 * per-op seteuid()/setegid() works.  This per-VM process is _vmd, so we
	 * cannot fork+exec a root child here.  Instead PROC_PARENT (the last
	 * root process) forks+execs it on our behalf.  Everything else -- squash
	 * viofs, vioblk, vionet, vioscsi -- is still fork+exec'd locally below,
	 * exactly as before.  Only WHO calls fork()+exec() changes; this process
	 * keeps the [0] runtime channels and drives the dev_copy/vm_copy
	 * handshake unchanged in both cases.
	 */
	launch_via_parent = (dev->dev_type == VMD_DEVTYPE_VIOFS &&
	    dev->viofs.credmode == VMSHARE_CRED_TRANSPARENT);

	if (launch_via_parent) {
		/*
		 * libevent's SIGPIPE handler is not armed yet (we run during
		 * init_emulated_hw(), before event_dispatch()); ignore SIGPIPE
		 * so a write to vm_iev after PROC_VMM dies surfaces as EPIPE
		 * from imsgbuf_flush() instead of killing this process.
		 */
		signal(SIGPIPE, SIG_IGN);
		/*
		 * Ask PROC_PARENT to fork+exec the root viofs.  We send the two
		 * CHILD-end socketpair fds (sync_fds[1], async_fds[1]) up; the
		 * PARENT-launched child inherits them, so the runtime data path
		 * never traverses PROC_PARENT.  imsg carries exactly one fd per
		 * message, so this is two consecutive single-fd imsgs correlated
		 * by peerid == vm->vm_vmid (mirrors the N-disk-fd pattern).  The
		 * VM child's only imsg channel up is vm->vm_iev (-> PROC_VMM).
		 */
		memset(&vdl, 0, sizeof(vdl));
		vdl.vdl_vmid = vm->vm_vmid;
		vdl.vdl_sync_fd_no = sync_fds[1];
		vdl.vdl_async_fd_no = async_fds[1];
		vdl.vdl_status = 0;
		vdl.vdl_devtype = dev->dev_type;
		/*
		 * M3b remediation: tell the root side WHICH share this is so it
		 * can re-derive the trusted policy from config.  We send only the
		 * index; PARENT validates it against this VM's own vmc_nshares
		 * and ignores any policy fields we might set.
		 */
		vdl.vdl_share_idx = dev->viofs.idx;
		strlcpy(vdl.vdl_vmname, vm->vm_params.vmc_name,
		    sizeof(vdl.vdl_vmname));

		/*
		 * Plain imsg_compose (no libevent arming) + a manual flush per
		 * message: the event loop is not running yet (we are in
		 * init_emulated_hw(), before event_dispatch()), and imsg carries
		 * exactly one fd per message, so the two child-end fds go up as
		 * two separate flushed messages.
		 */
		if (imsg_compose(&vm->vm_iev.ibuf,
		    IMSG_VMDOP_DEV_LAUNCH_REQUEST, vm->vm_vmid, getpid(),
		    sync_fds[1], &vdl, sizeof(vdl)) == -1) {
			log_warn("%s: failed to compose dev launch request",
			    __func__);
			ret = errno;
			goto err;
		}
		if (imsgbuf_flush(&vm->vm_iev.ibuf) == -1) {
			log_warn("%s: failed to flush dev launch request",
			    __func__);
			ret = errno;
			goto err;
		}
		if (imsg_compose(&vm->vm_iev.ibuf,
		    IMSG_VMDOP_DEV_LAUNCH_FD_ASYNC, vm->vm_vmid, getpid(),
		    async_fds[1], &vdl, sizeof(vdl)) == -1) {
			log_warn("%s: failed to compose dev launch async fd",
			    __func__);
			ret = errno;
			goto err;
		}
		if (imsgbuf_flush(&vm->vm_iev.ibuf) == -1) {
			log_warn("%s: failed to flush dev launch async fd",
			    __func__);
			ret = errno;
			goto err;
		}

		/*
		 * PARENT now owns the child-end fds via inheritance; drop our
		 * copies (mirror of the parent branch's close_fd below).  We do
		 * NOT clear the sync_fds[1]/async_fds[1] integers: the converge
		 * path below serializes those exact numbers into dev_copy so the
		 * PARENT-launched child (which inherited them) reads valid fds.
		 */
		close_fd(sync_fds[1]);
		close_fd(async_fds[1]);

		/*
		 * Block for PARENT's IMSG_VMDOP_DEV_LAUNCH_RESPONSE before
		 * driving the handshake.  On failure the device-launch fails
		 * exactly like a local fork() failure today.  On success
		 * dev->dev_parent_launched is set (and dev->dev_pid left as a
		 * sentinel 0) so virtio_shutdown() does not try to waitpid() a
		 * child that is not ours -- the device pid lives in PARENT.
		 */
		if (virtio_dev_launch_await_parent(vm, dev, sync_fds[0],
		    async_fds[0]) == -1) {
			/* await_parent closed [0] on failure; nothing to do. */
			return (-1);
		}

		/*
		 * Converge with the local-fork parent path.  The child reads the
		 * fd integers we wrote into dev_copy (sync_fds[1]/async_fds[1]);
		 * PARENT dup2()'d the inherited fds to those exact numbers, so
		 * they are valid in the child.
		 */
		goto parent_ready;
	}

	/* Fork... */
	dev_pid = fork();
	if (dev_pid == -1) {
		ret = errno;
		log_warn("%s: fork failed", __func__);
		goto err;
	}

	if (dev_pid > 0) {
		/* Parent */
		close_fd(sync_fds[1]);
		close_fd(async_fds[1]);

		/* Save the child's pid to help with cleanup. */
		dev->dev_pid = dev_pid;

 parent_ready:
		/* Set the channel fds to the child's before sending. */
		dev->sync_fd = sync_fds[1];
		pthread_mutex_init(&dev->sync_mtx, NULL);
		dev->async_fd = async_fds[1];

		/* 1. Send over our configured device. */
		log_debug("%s: sending '%c' type device struct", __func__,
			dev->dev_type);
		memcpy(&dev_copy, dev, sizeof(dev_copy));
		bzero(&dev_copy.async_iev, sizeof(dev_copy.async_iev));
		bzero(&dev_copy.sync_iev, sizeof(dev_copy.sync_iev));
		bzero(&dev_copy.dev_next, sizeof(dev_copy.dev_next));
		sz = atomicio(vwrite, sync_fds[0], &dev_copy, sizeof(dev_copy));
		if (sz != sizeof(dev_copy)) {
			log_warnx("%s: failed to send device", __func__);
			ret = EIO;
			goto err;
		}

		/* Close data fds. Only the child device needs them now. */
		if (virtio_dev_closefds(dev) == -1) {
			log_warnx("%s: failed to close device data fds",
			    __func__);
			goto err;
		}

		/* 2. Send over details on the VM (including memory fds). */
		log_debug("%s: sending vm message for '%s'", __func__,
			vm->vm_params.vmc_name);
		memcpy(&vm_copy, vm, sizeof(vm_copy));
		vm_copy.vm_kernel_path = NULL;
		bzero(&vm_copy.vm_entry, sizeof(vm_copy.vm_entry));
		bzero(&vm_copy.vm_iev, sizeof(vm_copy.vm_iev));
		for (i = 0; i < nitems(vm_copy.vm_ifs); i++) {
			vm_copy.vm_ifs[i].vif_name = NULL;
			vm_copy.vm_ifs[i].vif_switch = NULL;
			vm_copy.vm_ifs[i].vif_group = NULL;
			bzero(&vm_copy.vm_ifs[i].vif_entry,
			    sizeof(vm_copy.vm_ifs[i].vif_entry));
		}
		sz = atomicio(vwrite, sync_fds[0], &vm_copy, sizeof(vm_copy));
		if (sz != sizeof(vm_copy)) {
			log_warnx("%s: failed to send vm details", __func__);
			ret = EIO;
			goto err;
		}

		/*
		 * Initialize our imsg channel to the child device. The initial
		 * communication will be synchronous. We expect the child to
		 * report itself "ready" to confirm the launch was a success.
		 */
		if (imsgbuf_init(&iev->ibuf, sync_fds[0]) == -1) {
			log_warn("%s: failed to init imsgbuf", __func__);
			goto err;
		}
		imsgbuf_allow_fdpass(&iev->ibuf);
		ret = imsgbuf_read_one(&iev->ibuf, &imsg);
		if (ret == 0 || ret == -1) {
			log_warnx("%s: failed to receive ready message from "
			    "'%c' type device", __func__, dev->dev_type);
			ret = EIO;
			goto err;
		}
		ret = 0;

		viodev_msg_read(&imsg, &msg);
		imsg_free(&imsg);

		if (msg.type != VIODEV_MSG_READY) {
			log_warnx("%s: expected ready message, got type %d",
			    __func__, msg.type);
			ret = EINVAL;
			goto err;
		}
		log_debug("%s: device reports ready via sync channel",
		    __func__);

		/*
		 * Wire in the async event handling, but after reverting back
		 * to the parent's fd's.
		 */
		dev->sync_fd = sync_fds[0];
		dev->async_fd = async_fds[0];
		vm_device_pipe(dev, virtio_dispatch_dev, NULL);
	} else {
		/* Child */
		close_fd(async_fds[0]);
		close_fd(sync_fds[0]);

		/* Close pty. Virtio devices do not need it. */
		close_fd(vm->vm_tty);
		vm->vm_tty = -1;

		if (vm->vm_cdrom != -1 && dev->dev_type != VMD_DEVTYPE_SCSI) {
			close_fd(vm->vm_cdrom);
			vm->vm_cdrom = -1;
		}

		/* Keep data file descriptors open after exec. */
		SLIST_FOREACH(dev_entry, &virtio_devs, dev_next) {
			if (dev_entry == dev)
				continue;
			if (virtio_dev_closefds(dev_entry) == -1)
				fatalx("unable to close other virtio devs");
		}

		memset(num, 0, sizeof(num));
		snprintf(num, sizeof(num), "%d", sync_fds[1]);
		memset(vmm_fd, 0, sizeof(vmm_fd));
		snprintf(vmm_fd, sizeof(vmm_fd), "%d", env->vmd_fd);
		memset(vm_name, 0, sizeof(vm_name));
		snprintf(vm_name, sizeof(vm_name), "%s",
		    vm->vm_params.vmc_name);

		t[0] = dev->dev_type;
		t[1] = '\0';

		i = 0;
		nargv[i++] = env->argv0;
		nargv[i++] = "-X";
		nargv[i++] = num;
		nargv[i++] = "-t";
		nargv[i++] = t;
		nargv[i++] = "-i";
		nargv[i++] = vmm_fd;
		nargv[i++] = "-p";
		nargv[i++] = vm_name;
		if (env->vmd_debug)
			nargv[i++] = "-d";
		if (env->vmd_verbose == 1)
			nargv[i++] = "-v";
		else if (env->vmd_verbose > 1)
			nargv[i++] = "-vv";
		nargv[i++] = NULL;
		if (i > sizeof(nargv) / sizeof(nargv[0]))
			fatalx("%s: nargv overflow", __func__);

		/* Control resumes in vmd.c:main(). */
		execvp(nargv[0], nargv);

		ret = errno;
		log_warn("%s: failed to exec device", __func__);
		_exit(ret);
		/* NOTREACHED */
	}

	return (ret);

err:
	close_fd(sync_fds[0]);
	close_fd(sync_fds[1]);
	close_fd(async_fds[0]);
	close_fd(async_fds[1]);
	return (ret);
}

/*
 * Block until PROC_PARENT reports the result of forking+exec'ing the
 * transparent viofs device (M3b Phase B).  Returns 0 on success with
 * dev->dev_parent_launched set (the device pid lives in PARENT, so dev->dev_pid
 * is left as a sentinel 0 and must never be waitpid()'d here); returns -1 on
 * failure, having closed the caller's [0] channel ends.
 *
 * This is a bounded, synchronous read on the VM child's vm_iev channel.  It is
 * called from virtio_dev_launch() -> init_emulated_hw(), i.e. BEFORE run_vm()
 * starts the libevent loop, so there is no concurrent reader on vm->vm_iev and
 * no deadlock with vm_dispatch_vmm().  Each iteration poll()s with a timeout so
 * a dead PARENT cannot wedge the VM; any unrelated imsg (none are expected
 * pre-vcpu) is skipped defensively.
 */
#define VIO_DEV_LAUNCH_TMO_MS	(30 * 1000)	/* PARENT launch reply wait */
static int
virtio_dev_launch_await_parent(struct vmd_vm *vm, struct virtio_dev *dev,
    int sync0, int async0)
{
	struct imsgbuf		*ibuf = &vm->vm_iev.ibuf;
	struct imsg		 imsg;
	struct vmop_dev_launch	 vdl;
	struct pollfd		 pfd;
	uint32_t		 type, peerid;
	int			 ret;

	for (;;) {
		/*
		 * Bound the wait so a PROC_PARENT that dies after taking our
		 * REQUEST (and thus never sends a RESPONSE) cannot wedge this
		 * VM forever in init_emulated_hw().  PARENT replies promptly on
		 * both success and failure, so a timeout means PARENT is gone.
		 */
		pfd.fd = ibuf->fd;
		pfd.events = POLLIN;
		ret = poll(&pfd, 1, VIO_DEV_LAUNCH_TMO_MS);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			log_warn("%s: poll", __func__);
			goto fail;
		}
		if (ret == 0) {
			log_warnx("%s: timed out awaiting dev launch response",
			    __func__);
			goto fail;
		}

		ret = imsgbuf_read_one(ibuf, &imsg);
		if (ret == -1) {
			log_warn("%s: imsgbuf_read_one", __func__);
			goto fail;
		}
		if (ret == 0) {
			log_warnx("%s: vmm channel closed awaiting dev launch",
			    __func__);
			goto fail;
		}

		type = imsg_get_type(&imsg);
		peerid = imsg_get_id(&imsg);
		if (type != IMSG_VMDOP_DEV_LAUNCH_RESPONSE ||
		    peerid != vm->vm_vmid) {
			/* Not ours; ignore and keep waiting (defensive). */
			log_warnx("%s: ignoring imsg type %u peerid %u while "
			    "awaiting dev launch", __func__, type, peerid);
			imsg_free(&imsg);
			continue;
		}

		if (imsg_get_data(&imsg, &vdl, sizeof(vdl))) {
			log_warnx("%s: malformed dev launch response", __func__);
			imsg_free(&imsg);
			goto fail;
		}
		imsg_free(&imsg);

		if (vdl.vdl_status != 0) {
			log_warnx("%s: PARENT failed to launch '%c' device: %s",
			    __func__, dev->dev_type,
			    strerror(vdl.vdl_status));
			goto fail;
		}

		/*
		 * The device pid lives in PROC_PARENT now; this VM process is
		 * NOT its parent and must not waitpid() it (virtio_shutdown()
		 * honors dev_parent_launched).  We keep a sentinel so the pid is
		 * never used as a local waitpid() target here.
		 */
		dev->dev_pid = 0;
		dev->dev_parent_launched = 1;

		log_debug("%s: PARENT launched '%c' device for vm %u",
		    __func__, dev->dev_type, vm->vm_vmid);
		return (0);
	}

 fail:
	close_fd(sync0);
	close_fd(async0);
	return (-1);
}

/*
 * Initialize an async imsg channel for a virtio device.
 */
int
vm_device_pipe(struct virtio_dev *dev, void (*cb)(int, short, void *),
    struct event_base *ev_base)
{
	struct imsgev *iev = &dev->async_iev;
	int fd = dev->async_fd;

	log_debug("%s: initializing '%c' device pipe (fd=%d)", __func__,
	    dev->dev_type, fd);

	if (imsgbuf_init(&iev->ibuf, fd) == -1)
		fatal("imsgbuf_init");
	imsgbuf_allow_fdpass(&iev->ibuf);
	iev->handler = cb;
	iev->data = dev;
	iev->events = EV_READ;
	imsg_event_add2(iev, ev_base);

	return (0);
}

void
virtio_dispatch_dev(int fd, short event, void *arg)
{
	struct virtio_dev	*dev = (struct virtio_dev*)arg;
	struct imsgev		*iev = &dev->async_iev;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	struct viodev_msg	 msg;
	ssize_t			 n = 0;
	uint32_t		 type;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("%s: imsgbuf_read", __func__);
		if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			log_debug("%s: pipe dead (EV_READ)", __func__);
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1) {
			if (errno == EPIPE) {
				/* this pipe is dead, remove the handler */
				log_debug("%s: pipe dead (EV_WRITE)", __func__);
				event_del(&iev->ev);
				event_loopexit(NULL);
				return;
			}
			fatal("%s: imsgbuf_write", __func__);
		}
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)
			break;

		type = imsg_get_type(&imsg);
		switch (type) {
		case IMSG_DEVOP_MSG:
			viodev_msg_read(&imsg, &msg);
			handle_dev_msg(&msg, dev);
			break;
		default:
			log_warnx("%s: got non devop imsg %d", __func__, type);
			break;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}


static int
handle_dev_msg(struct viodev_msg *msg, struct virtio_dev *gdev)
{
	uint32_t vmm_id = gdev->vmm_id;

	switch (msg->type) {
	case VIODEV_MSG_KICK:
		if (msg->vector != VIRTIO_MSI_NO_VECTOR) {
			/*
			 * MSI-X: deliver an edge interrupt straight to the
			 * target vcpu's LAPIC.  DEASSERT is a no-op since
			 * MSI-X is edge-triggered (no level line to lower).
			 */
			if (msg->state == INTR_STATE_ASSERT)
				virtio_deliver_msix(gdev, msg->vector);
		} else if (msg->state == INTR_STATE_ASSERT)
			vcpu_assert_irq(vmm_id, msg->vcpu, msg->irq);
		else if (msg->state == INTR_STATE_DEASSERT)
			vcpu_deassert_irq(vmm_id, msg->vcpu, msg->irq);
		break;
	case VIODEV_MSG_READY:
		log_debug("%s: device reports ready", __func__);
		break;
	case VIODEV_MSG_ERROR:
		log_warnx("%s: device reported error", __func__);
		break;
	case VIODEV_MSG_INVALID:
	case VIODEV_MSG_IO_READ:
	case VIODEV_MSG_IO_WRITE:
		/* FALLTHROUGH */
	default:
		log_warnx("%s: unsupported device message type %d", __func__,
		    msg->type);
		return (1);
	}

	return (0);
};

/*
 * Called by the VM process while processing IO from the VCPU thread.
 *
 * N.b. Since the VCPU thread calls this function, we cannot mutate the event
 * system. All ipc messages must be sent manually and cannot be queued for
 * the event loop to push them. (We need to perform a synchronous read, so
 * this isn't really a big deal.)
 */
int
virtio_pci_io(int dir, uint16_t reg, uint32_t *data, uint8_t *intr,
    void *cookie, uint8_t sz)
{
	struct virtio_dev *dev = (struct virtio_dev *)cookie;
	struct imsgbuf *ibuf = &dev->sync_iev.ibuf;
	struct imsg imsg;
	struct viodev_msg msg;
	int ret = 0;

	/* Serialize: multiple vcpu threads may call this concurrently. */
	pthread_mutex_lock(&dev->sync_mtx);

	memset(&msg, 0, sizeof(msg));
	msg.reg = reg;
	msg.io_sz = sz;

	if (dir == 0) {
		msg.type = VIODEV_MSG_IO_WRITE;
		msg.data = *data;
		msg.data_valid = 1;
	} else
		msg.type = VIODEV_MSG_IO_READ;

	if (msg.type == VIODEV_MSG_IO_WRITE) {
		/*
		 * Write request. No reply expected.
		 */
		ret = imsg_compose(ibuf, IMSG_DEVOP_MSG, 0, 0, -1, &msg,
		    sizeof(msg));
		if (ret == -1) {
			log_warn("%s: failed to send async io event to virtio"
			    " device", __func__);
			pthread_mutex_unlock(&dev->sync_mtx);
			return (ret);
		}
		if (imsgbuf_flush(ibuf) == -1) {
			log_warnx("%s: imsgbuf_flush (write)", __func__);
			pthread_mutex_unlock(&dev->sync_mtx);
			return (-1);
		}
	} else {
		/*
		 * Read request. Requires waiting for a reply.
		 */
		ret = imsg_compose(ibuf, IMSG_DEVOP_MSG, 0, 0, -1, &msg,
		    sizeof(msg));
		if (ret == -1) {
			log_warnx("%s: failed to send sync io event to virtio"
			    " device", __func__);
			pthread_mutex_unlock(&dev->sync_mtx);
			return (ret);
		}
		if (imsgbuf_flush(ibuf) == -1) {
			log_warnx("%s: imsgbuf_flush (read)", __func__);
			pthread_mutex_unlock(&dev->sync_mtx);
			return (-1);
		}

		/* Read our reply. */
		ret = imsgbuf_read_one(ibuf, &imsg);
		if (ret == 0 || ret == -1) {
			log_warn("%s: imsgbuf_read (n=%d)", __func__, ret);
			pthread_mutex_unlock(&dev->sync_mtx);
			return (-1);
		}
		viodev_msg_read(&imsg, &msg);
		imsg_free(&imsg);

		if (msg.type == VIODEV_MSG_IO_READ && msg.data_valid) {
			DPRINTF("%s: got sync read response (reg=%s)", __func__,
			    virtio_reg_name(msg.reg));
			*data = msg.data;
			/*
			 * The synchronous reply carries DATA ONLY and never
			 * mutates the device's IOAPIC line.  Every line op
			 * (assert AND the ISR-read deassert) is emitted by the
			 * device on its async KICK channel and applied by the
			 * VM process event-loop thread (handle_dev_msg),
			 * making that thread the sole, in-order mutator of the
			 * line.  This removes an assert(async)/deassert(sync)
			 * cross-thread reorder on the level line: a coalesced
			 * completion can no longer be clobbered by a stale
			 * deassert running on the vcpu thread.
			 */
		} else {
			log_warnx("%s: expected IO_READ, got %d", __func__,
			    msg.type);
			pthread_mutex_unlock(&dev->sync_mtx);
			return (-1);
		}
	}

	pthread_mutex_unlock(&dev->sync_mtx);
	return (0);
}

void
virtio_assert_irq(struct virtio_dev *dev, int vcpu)
{
	struct viodev_msg msg;
	int ret;

	memset(&msg, 0, sizeof(msg));
	msg.irq = dev->irq;
	msg.vcpu = vcpu;
	msg.type = VIODEV_MSG_KICK;
	msg.state = INTR_STATE_ASSERT;
	/*
	 * MSI-X vector for the data path (viofs has a single request
	 * queue).  VIRTIO_MSI_NO_VECTOR selects the legacy INTx path in
	 * the VM process; any device that has not negotiated MSI-X leaves
	 * vq[0].msix_vector at NO_VECTOR.
	 */
	msg.vector = dev->vq[0].msix_vector;

	ret = imsg_compose_event(&dev->async_iev, IMSG_DEVOP_MSG, 0, 0, -1,
	    &msg, sizeof(msg));
	if (ret == -1)
		log_warnx("%s: failed to assert irq %d", __func__, dev->irq);
}

void
virtio_deassert_irq(struct virtio_dev *dev, int vcpu)
{
	struct viodev_msg msg;
	int ret;

	memset(&msg, 0, sizeof(msg));
	msg.irq = dev->irq;
	msg.vcpu = vcpu;
	msg.type = VIODEV_MSG_KICK;
	msg.state = INTR_STATE_DEASSERT;
	/* See virtio_assert_irq(); MSI-X deassert is a no-op in the VM proc. */
	msg.vector = dev->vq[0].msix_vector;

	ret = imsg_compose_event(&dev->async_iev, IMSG_DEVOP_MSG, 0, 0, -1,
	    &msg, sizeof(msg));
	if (ret == -1)
		log_warnx("%s: failed to deassert irq %d", __func__, dev->irq);
}

/*
 * Close all underlying file descriptors for a given virtio device.
 */
static int
virtio_dev_closefds(struct virtio_dev *dev)
{
	size_t i;

	switch (dev->dev_type) {
		case VMD_DEVTYPE_DISK:
			for (i = 0; i < dev->vioblk.ndisk_fd; i++) {
				close_fd(dev->vioblk.disk_fd[i]);
				dev->vioblk.disk_fd[i] = -1;
			}
			break;
		case VMD_DEVTYPE_NET:
			close_fd(dev->vionet.data_fd);
			dev->vionet.data_fd = -1;
			break;
		case VMD_DEVTYPE_SCSI:
			close_fd(dev->vioscsi.cdrom_fd);
			dev->vioscsi.cdrom_fd = -1;
			break;
		case VMD_DEVTYPE_VIOFS:
			close_fd(dev->viofs.share_fd);
			dev->viofs.share_fd = -1;
			break;
	default:
		log_warnx("%s: invalid device type", __func__);
		return (-1);
	}

	close_fd(dev->async_fd);
	dev->async_fd = -1;
	close_fd(dev->sync_fd);
	dev->sync_fd = -1;

	return (0);
}

void
viodev_msg_read(struct imsg *imsg, struct viodev_msg *msg)
{
	if (imsg_get_data(imsg, msg, sizeof(*msg)))
		fatal("%s", __func__);
}

void
vionet_hostmac_read(struct imsg *imsg, struct vionet_dev *dev)
{
	if (imsg_get_data(imsg, dev->hostmac, sizeof(dev->hostmac)))
		fatal("%s", __func__);
}
