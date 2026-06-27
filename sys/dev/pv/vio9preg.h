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

#ifndef _DEV_PV_VIO9PREG_H_
#define _DEV_PV_VIO9PREG_H_

/* virtio-9p device-specific feature bits. */
#define VIRTIO_9P_F_MOUNT_TAG	(1ULL << 0)	/* device exports a mount tag */

/*
 * Device configuration space layout: { le16 tag_len; u8 tag[tag_len] }.
 * Mirrors the host server's viofs_dev_read() (usr.sbin/vmd/viofs.c).
 */
#define VIRTIO_9P_CONFIG_TAG_LEN	0	/* le16 tag length, offset 0 */
#define VIRTIO_9P_CONFIG_TAG		2	/* tag bytes, offset 2 */

/* Mount tag cap; must match usr.sbin/vmd VIO9P_TAG_MAX (vmd.h). */
#define VIO9P_TAG_MAX		32

/* msize bounds mirror the host server (VIOFS_MSIZE_{MIN,MAX}, viofs.c). */
#define VIO9P_MSIZE_MIN		512
#define VIO9P_MSIZE_MAX		(64 * 1024)

#endif /* _DEV_PV_VIO9PREG_H_ */
