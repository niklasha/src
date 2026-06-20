/* $OpenBSD$ */
/*
 * Copyright (c) 2026 Niklas Hallqvist <niklas@hallqvist.se>
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

#ifndef _VMD_IOAPIC_H_
#define _VMD_IOAPIC_H_

#include <sys/types.h>
#include <stdint.h>

/*
 * Intel 82093AA-style IO-APIC.  One instance per VM (the legacy MP
 * spec allows multiple but vmd has no use for more than one).
 *
 * Memory-mapped registers are accessed indirectly through a tiny
 * pair of windows at the global MMIO base:
 *
 *   IOREGSEL  (offset 0x00, low byte writable)  - selects which
 *                                                  internal register
 *                                                  IOWIN reads/writes
 *   IOWIN     (offset 0x10, 32-bit window)      - data port
 *
 * Internal registers (selected via IOREGSEL):
 *
 *   0x00 ID      - bits 24:27 carry the APIC ID; rest reserved
 *   0x01 VER     - low byte = version (0x11 for 82093AA),
 *                  bits 16:23 = max redir entry (= NPINS - 1)
 *   0x02 ARB     - arbitration ID (RO; not used in physical mode)
 *   0x10..0x3F  - 24 redirection-table entries (RTEs).  Each RTE is
 *                  64 bits, accessed as two 32-bit halves:
 *                    0x10 + 2*N = entry N low half (bits  0:31)
 *                    0x11 + 2*N = entry N high half (bits 32:63)
 *
 * RTE bit layout (64 bits):
 *
 *   0:7   vector
 *   8:10  delivery mode (fixed / lowpri / SMI / NMI / INIT / ExtINT)
 *   11    destination mode (0=physical, 1=logical)
 *   12    delivery status (RO; we keep clear after each delivery)
 *   13    interrupt input pin polarity (0=high, 1=low)
 *   14    remote IRR (RO; level-triggered in-service indicator)
 *   15    trigger mode (0=edge, 1=level)
 *   16    mask
 *   17:55 reserved
 *   56:63 destination apic id (physical mode)
 */

#define IOAPIC_MMIO_BASE	0xfec00000UL
#define IOAPIC_MMIO_SIZE	0x1000

#define IOAPIC_REG_IOREGSEL	0x00
#define IOAPIC_REG_IOWIN	0x10

/* Selectable internal register indices. */
#define IOAPIC_IDX_ID		0x00
#define IOAPIC_IDX_VER		0x01
#define IOAPIC_IDX_ARB		0x02
#define IOAPIC_IDX_RTE_BASE	0x10
#define IOAPIC_IDX_RTE(n)	(IOAPIC_IDX_RTE_BASE + 2 * (n))

/* IOAPIC version (low byte) and per-instance NPINS-1 (bits 16:23). */
#define IOAPIC_VERSION		0x11

/* RTE field decoding. */
#define IOAPIC_RTE_VEC(v)		((v) & 0xff)
#define IOAPIC_RTE_DM_MASK		0x700ULL
#define IOAPIC_RTE_DM_SHIFT		8
#define IOAPIC_RTE_DM_FIXED		0
#define IOAPIC_RTE_DM_LOWPRI		1
#define IOAPIC_RTE_DM_SMI		2
#define IOAPIC_RTE_DM_NMI		4
#define IOAPIC_RTE_DM_INIT		5
#define IOAPIC_RTE_DM_EXTINT		7
#define IOAPIC_RTE_DEST_LOGICAL		(1ULL << 11)
#define IOAPIC_RTE_DELIVERY_STATUS	(1ULL << 12)
#define IOAPIC_RTE_POL_LOW		(1ULL << 13)
#define IOAPIC_RTE_REMOTE_IRR		(1ULL << 14)
#define IOAPIC_RTE_LEVEL		(1ULL << 15)
#define IOAPIC_RTE_MASKED		(1ULL << 16)
#define IOAPIC_RTE_DEST_SHIFT		56

/*
 * Bits the guest may write; everything else is RO (delivery status,
 * remote IRR) or reserved.  Low half: bits 0-10 (vector + delivery mode),
 * 11 (dest mode), 13 (polarity), 15 (trigger), 16 (mask).
 */
#define IOAPIC_RTE_WRITABLE_LO		0x0001afffUL
#define IOAPIC_RTE_WRITABLE_HI		0xff000000UL

#define IOAPIC_MAX_PINS			24

/*
 * Opaque IO-APIC state.  vmd holds one of these per VM and dispatches
 * MMIO at IOAPIC_MMIO_BASE plus device-side line assertions (the
 * ISA/PCI fabric calls ioapic_assert_irq when a virtual device wants
 * to inject an IRQ).
 *
 * THREAD-SAFETY: not thread-safe per instance -- the caller serialises
 * (single per-VM mutex).  Same contract as lapic.c.
 */
struct ioapic;

/*
 * Callback from the IO-APIC up into the surrounding fabric: deliver
 * vector vec to LAPIC target_lapic.  For level-triggered interrupts
 * the integration glue records (pin, vec) so a later ioapic_eoi() can
 * be matched.
 *
 * SECURITY NOTE: target_lapic is derived from the guest-controlled
 * RTE destination field and is NOT range-checked here.  The caller
 * MUST validate it against the VM's actual vcpu count before invoking
 * vmm(4) ioctls.  See SECURITY.md.
 */
struct ioapic_ops {
	void	(*deliver)(void *cookie, uint32_t target_lapic, uint8_t vec,
		    int level_triggered, uint8_t pin);
};

struct ioapic	*ioapic_new(uint8_t id, uint8_t pin_count);
void		 ioapic_free(struct ioapic *);
void		 ioapic_set_ops(struct ioapic *, const struct ioapic_ops *,
		    void *cookie);
uint8_t		 ioapic_id(struct ioapic *);

uint32_t	 ioapic_mmio_read(struct ioapic *, uint16_t off);
void		 ioapic_mmio_write(struct ioapic *, uint16_t off,
		    uint32_t val);

/*
 * Edges from the surrounding fabric:
 *
 *   ioapic_assert_irq(io, pin)
 *     A device drove input line "pin" high.  For edge-triggered RTEs
 *     this fires one delivery (unless masked).  For level-triggered
 *     RTEs it raises remote_IRR; further assertions while remote_IRR
 *     is set are coalesced.
 *
 *   ioapic_deassert_irq(io, pin)
 *     A device dropped input line "pin" low.  Clears the internal
 *     line-state record.  For level-triggered RTEs this does NOT
 *     clear remote_IRR -- that only happens via ioapic_eoi() from the
 *     handling LAPIC.
 *
 *   ioapic_eoi(io, vec)
 *     The LAPIC has completed handling a vector.  For level-triggered
 *     RTEs programmed to that vector, clear remote_IRR; if the line
 *     is still asserted, re-deliver (matches real-hardware behaviour
 *     and is necessary for shared level-triggered legacy IRQs).
 */
void		 ioapic_assert_irq(struct ioapic *, uint8_t pin);
void		 ioapic_deassert_irq(struct ioapic *, uint8_t pin);
void		 ioapic_eoi(struct ioapic *, uint8_t vec);

/*
 * Predicate: is the RTE for `pin` unmasked?  Used by vcpu_assert_irq
 * to decide whether the guest's IOAPIC owns this line (APIC mode) or
 * the legacy i8259 should fire instead.  Returns 0 for io == NULL or
 * pin out of range.
 */
int		 ioapic_pin_unmasked(struct ioapic *, uint8_t pin);
int		 ioapic_pin_configured(struct ioapic *, uint8_t pin);

#endif /* !_VMD_IOAPIC_H_ */
