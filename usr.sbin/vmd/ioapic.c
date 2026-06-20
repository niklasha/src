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

/*
 * Per-VM IO-APIC (Intel 82093AA) emulation.  Sibling to lapic.c:
 * library-shaped, no vmd headers, depends only on libc.  All
 * cross-cpu effects go through the ioapic_ops vector installed by
 * the caller.
 *
 * Scope of the first cut:
 *   - Indirect MMIO via IOREGSEL/IOWIN.
 *   - 24 redirection table entries (RTEs), physical destination mode.
 *   - Edge and level triggering, with remote-IRR tracking.
 *   - Fixed and NMI delivery modes routed through ops->deliver.
 *   - Lowest-priority degrades to fixed-to-destination (same
 *     simplification vmd's existing PIC code uses).
 *   - Mask honoured at delivery time.
 *
 * Things deliberately left as inert writable registers (or #if 0'd
 * below) until vmd actually needs them: logical destination mode
 * (DM=logical + LDR/DFR matching), ExtINT routing (vmd uses i8259
 * directly and bypasses the IO-APIC for legacy ISA), SMI delivery,
 * the arbitration ID register, level-triggered EOI from MSI/MSI-X
 * (those use the LAPIC EOI directly).
 */

#include <sys/types.h>

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ioapic.h"

struct ioapic {
	pthread_mutex_t		 lock;		/* serialises all mutation */
	uint8_t			 id;
	uint8_t			 pin_count;	/* normally 24 */
	uint8_t			 ioregsel;	/* low byte */

	uint64_t		 rte[IOAPIC_MAX_PINS];
	uint32_t		 line_state;	/* bit per pin: 1=asserted */
	/* bit per pin: a device assert is pending delivery */
	uint32_t		 armed;

	const struct ioapic_ops	*ops;
	void			*cookie;
};

static void	 ioapic_reset(struct ioapic *);
static uint32_t	 read_indirect(struct ioapic *, uint8_t idx);
static void	 write_indirect(struct ioapic *, uint8_t idx, uint32_t val);
static void	 try_deliver(struct ioapic *, uint8_t pin);
static int	 line_get(const struct ioapic *, uint8_t pin);
static void	 line_set(struct ioapic *, uint8_t pin, int v);

/*
 * Allocate and reset.  pin_count is clamped to IOAPIC_MAX_PINS; a
 * pin_count of 0 is replaced by the AT-classic value of 24.
 */
struct ioapic *
ioapic_new(uint8_t id, uint8_t pin_count)
{
	struct ioapic *io;

	io = calloc(1, sizeof(*io));
	if (io == NULL)
		return (NULL);
	if (pthread_mutex_init(&io->lock, NULL) != 0) {
		free(io);
		return (NULL);
	}
	io->id = id;
	io->pin_count = pin_count == 0 ? IOAPIC_MAX_PINS : pin_count;
	if (io->pin_count > IOAPIC_MAX_PINS)
		io->pin_count = IOAPIC_MAX_PINS;
	ioapic_reset(io);
	return (io);
}

void
ioapic_free(struct ioapic *io)
{
	if (io == NULL)
		return;
	pthread_mutex_destroy(&io->lock);
	free(io);
}

void
ioapic_set_ops(struct ioapic *io, const struct ioapic_ops *ops, void *cookie)
{
	io->ops = ops;
	io->cookie = cookie;
}

uint8_t
ioapic_id(struct ioapic *io)
{
	uint8_t id;

	pthread_mutex_lock(&io->lock);
	id = io->id;
	pthread_mutex_unlock(&io->lock);
	return (id);
}

/*
 * Predicate: is RTE[pin] unmasked?  Used by vcpu_assert_irq to decide
 * whether the guest's IOAPIC owns this line (APIC mode) or the legacy
 * i8259 path should fire.  Takes the lock so we observe a coherent
 * snapshot of the RTE rather than a torn read.
 */
int
ioapic_pin_unmasked(struct ioapic *io, uint8_t pin)
{
	int unmasked;

	if (io == NULL)
		return (0);
	pthread_mutex_lock(&io->lock);
	unmasked = (pin < io->pin_count) &&
	    ((io->rte[pin] & IOAPIC_RTE_MASKED) == 0);
	pthread_mutex_unlock(&io->lock);
	return (unmasked);
}

/*
 * ioapic_pin_configured
 *
 * True if the guest has programmed this pin's RTE (assigned a real vector),
 * i.e. it owns the line through the IOAPIC -- regardless of whether the pin
 * is *currently* masked.  Linux masks a level-triggered RTE for the duration
 * of each IRQ's service (mask -> handler -> EOI -> unmask), so "currently
 * unmasked" is the WRONG test for routing: a device completion that arrives
 * mid-service would spill to the i8259 (which the guest isn't listening on
 * for an APIC-mode line) and be lost.  Asserting on the IOAPIC even while
 * masked is safe -- ioapic_assert_irq latches line_state and write_indirect
 * re-delivers on unmask.  The reset RTE is masked with vector 0, so a
 * non-zero vector means "configured".
 */
int
ioapic_pin_configured(struct ioapic *io, uint8_t pin)
{
	int configured;

	if (io == NULL)
		return (0);
	pthread_mutex_lock(&io->lock);
	configured = (pin < io->pin_count) &&
	    (IOAPIC_RTE_VEC(io->rte[pin]) != 0);
	pthread_mutex_unlock(&io->lock);
	return (configured);
}

/*
 * MMIO read.  IOREGSEL appears at offsets 0x00..0x0f; IOWIN at
 * 0x10..0x1f.  Everything else returns zero.  The architecture
 * specifies 32-bit accesses; we don't enforce it, the integration
 * glue does.
 */
uint32_t
ioapic_mmio_read(struct ioapic *io, uint16_t off)
{
	uint32_t val = 0;

	pthread_mutex_lock(&io->lock);
	if (off < 0x10)
		val = (uint32_t)io->ioregsel;
	else if (off < 0x20)
		val = read_indirect(io, io->ioregsel);
	pthread_mutex_unlock(&io->lock);
	return (val);
}

void
ioapic_mmio_write(struct ioapic *io, uint16_t off, uint32_t val)
{
	pthread_mutex_lock(&io->lock);
	if (off < 0x10) {
		/*
		 * IOREGSEL: only the low byte is honoured per SDM
		 * 10.4.1; the upper 24 bits are reserved.
		 */
		io->ioregsel = (uint8_t)val;
	} else if (off < 0x20) {
		write_indirect(io, io->ioregsel, val);
	}
	/* writes past 0x1f are silently dropped */
	pthread_mutex_unlock(&io->lock);
}

/*
 * Device-side line assertion.  For edge triggers we deliver once on
 * the 0->1 transition; for level triggers we deliver each time the
 * line is asserted while remote_IRR is clear (set + delivery is
 * atomic in real hw; we do them in sequence).
 */
void
ioapic_assert_irq(struct ioapic *io, uint8_t pin)
{
	int was;

	pthread_mutex_lock(&io->lock);
	if (pin >= io->pin_count) {
		pthread_mutex_unlock(&io->lock);
		return;
	}
	was = line_get(io, pin);
	line_set(io, pin, 1);
	io->armed |= (1u << pin);

	if (io->rte[pin] & IOAPIC_RTE_LEVEL) {
		/*
		 * Level: deliver whenever asserted, unless remote_IRR
		 * says a previous delivery is still in service.
		 */
		if ((io->rte[pin] & IOAPIC_RTE_REMOTE_IRR) == 0)
			try_deliver(io, pin);
		/*
		 * else: a previous delivery is still in service; coalesce
		 * (the line stays asserted and re-delivers on EOI).
		 */
	} else {
		/*
		 * Edge: deliver on every assert.  Real hw requires
		 * a 0->1 transition, but vmd device emulators
		 * (i8253, etc.) only call assert -- they never
		 * explicitly deassert -- so a one-shot model would
		 * only fire once.  Treat each call as a fresh edge.
		 * This matches what kvm and qemu do for legacy
		 * edge-triggered ISA interrupts.
		 */
		(void)was;
		try_deliver(io, pin);
	}
	pthread_mutex_unlock(&io->lock);
}

void
ioapic_deassert_irq(struct ioapic *io, uint8_t pin)
{
	pthread_mutex_lock(&io->lock);
	if (pin < io->pin_count)
		line_set(io, pin, 0);
	pthread_mutex_unlock(&io->lock);
}

/*
 * EOI broadcast from a LAPIC.  Scan the RTE table for any
 * level-triggered entry programmed to deliver vector vec; clear
 * its remote_IRR and, if the device line is still asserted,
 * re-deliver.  Edge-triggered entries are unaffected by EOI.
 */
void
ioapic_eoi(struct ioapic *io, uint8_t vec)
{
	uint8_t pin;

	pthread_mutex_lock(&io->lock);
	for (pin = 0; pin < io->pin_count; pin++) {
		if ((io->rte[pin] & IOAPIC_RTE_LEVEL) == 0)
			continue;
		if (IOAPIC_RTE_VEC(io->rte[pin]) != vec)
			continue;
		if ((io->rte[pin] & IOAPIC_RTE_REMOTE_IRR) == 0)
			continue;
		io->rte[pin] &= ~IOAPIC_RTE_REMOTE_IRR;
		/*
		 * Level-triggered re-delivery (SDM 3A 11.5.5; I/O APIC
		 * datasheet "remote IRR" semantics): if the device line
		 * is still asserted, an interrupt arrived while remote_IRR
		 * held off delivery (it was coalesced in ioapic_assert_irq,
		 * "line stays hi").  We MUST re-deliver it now -- otherwise
		 * that completion is lost forever and the vioblk/vionet
		 * queue stalls (the device-mapper / vda read hang).
		 *
		 * This terminates rather than IRQ-storms: a virtio device
		 * deasserts its line when the guest reads the ISR status
		 * register (virtio_io_isr -> vcpu_deassert_irq).  Once the
		 * guest's handler drains the queue and reads ISR, line_get()
		 * returns 0 on the next EOI and the cycle stops.
		 */
		if (line_get(io, pin) && (io->armed & (1u << pin)))
			/* re-deliver only a fresh, undelivered assert */
			try_deliver(io, pin);
	}
	pthread_mutex_unlock(&io->lock);
}

/*
 * Internal helpers.
 */

static void
ioapic_reset(struct ioapic *io)
{
	int i;

	io->ioregsel = 0;
	io->line_state = 0;
	io->armed = 0;
	/*
	 * All RTEs come up masked, with vector 0.  This matches
	 * the SDM-defined post-reset state and what guests assume.
	 */
	for (i = 0; i < IOAPIC_MAX_PINS; i++)
		io->rte[i] = IOAPIC_RTE_MASKED;
}

static uint32_t
read_indirect(struct ioapic *io, uint8_t idx)
{
	uint32_t val;
	uint8_t pin;

	switch (idx) {
	case IOAPIC_IDX_ID:
		return (((uint32_t)io->id) << 24);
	case IOAPIC_IDX_VER:
		val  = (uint32_t)IOAPIC_VERSION;
		val |= ((uint32_t)(io->pin_count - 1)) << 16;
		return (val);
	case IOAPIC_IDX_ARB:
		return (((uint32_t)io->id) << 24);
	default:
		break;
	}

	if (idx >= IOAPIC_IDX_RTE_BASE &&
	    idx < IOAPIC_IDX_RTE_BASE + 2 * io->pin_count) {
		pin = (idx - IOAPIC_IDX_RTE_BASE) >> 1;
		if (idx & 1)
			return ((uint32_t)(io->rte[pin] >> 32));
		else
			return ((uint32_t)(io->rte[pin] & 0xffffffffu));
	}
	return (0);
}

static void
write_indirect(struct ioapic *io, uint8_t idx, uint32_t val)
{
	uint64_t lo, hi, mask;
	uint8_t pin;

	switch (idx) {
	case IOAPIC_IDX_ID:
		io->id = (val >> 24) & 0xf;
		return;
	case IOAPIC_IDX_VER:
	case IOAPIC_IDX_ARB:
		return;					/* read-only */
	default:
		break;
	}

	if (idx >= IOAPIC_IDX_RTE_BASE &&
	    idx < IOAPIC_IDX_RTE_BASE + 2 * io->pin_count) {
		pin = (idx - IOAPIC_IDX_RTE_BASE) >> 1;

		if (idx & 1) {
			mask = (uint64_t)IOAPIC_RTE_WRITABLE_HI << 32;
			hi = ((uint64_t)val << 32) & mask;
			io->rte[pin] = (io->rte[pin] & ~mask) | hi;
		} else {
			mask = (uint64_t)IOAPIC_RTE_WRITABLE_LO;
			lo = (uint64_t)val & mask;
			io->rte[pin] = (io->rte[pin] & ~mask) | lo;
		}

		/*
		 * Unmasking a level-triggered RTE that has a still-
		 * asserted line should re-deliver.  Edge-triggered RTEs
		 * don't latch (no remote_IRR), so unmasking them without
		 * a fresh edge is silent -- matching real hardware.
		 */
		if ((io->rte[pin] & IOAPIC_RTE_MASKED) == 0 &&
		    (io->rte[pin] & IOAPIC_RTE_LEVEL) &&
		    (io->rte[pin] & IOAPIC_RTE_REMOTE_IRR) == 0 &&
		    line_get(io, pin) && (io->armed & (1u << pin)))
			try_deliver(io, pin);
	}
}

/*
 * Resolve an RTE to a (target, vector) pair and invoke ops->deliver.
 * For level-triggered entries, set remote_IRR so that re-arrivals
 * while the previous delivery is in service are coalesced.
 */
static void
try_deliver(struct ioapic *io, uint8_t pin)
{
	uint64_t rte;
	uint8_t vec, dm;
	uint32_t target;
	int level;

	rte = io->rte[pin];
	if (rte & IOAPIC_RTE_MASKED)
		return;
	/* this pending assert is being delivered */
	io->armed &= ~(1u << pin);

	vec = (uint8_t)IOAPIC_RTE_VEC(rte);
	dm = (uint8_t)((rte & IOAPIC_RTE_DM_MASK) >> IOAPIC_RTE_DM_SHIFT);
	target = (uint32_t)(rte >> IOAPIC_RTE_DEST_SHIFT) & 0xff;
	level = (rte & IOAPIC_RTE_LEVEL) ? 1 : 0;

	if (rte & IOAPIC_RTE_DEST_LOGICAL) {
		/*
		 * Logical destination mode: in flat mode (the only mode
		 * we support), the destination field is a bitmap where
		 * bit N means "deliver to APIC ID N".  Linux uses logical
		 * mode for IRQ load-balancing even when MADT advertises
		 * physical-mode entries.
		 *
		 * For FIXED: deliver to all matching CPUs.
		 * For LOWPRI: pick the lowest-numbered matching CPU.
		 */
		uint8_t bm = (uint8_t)(target & 0xff);
		uint8_t cpu;

		for (cpu = 0; cpu < 8; cpu++) {
			if ((bm & (1u << cpu)) == 0)
				continue;
			if (io->ops != NULL && io->ops->deliver != NULL)
				io->ops->deliver(io->cookie, cpu, vec,
				    level, pin);
			if (dm == IOAPIC_RTE_DM_LOWPRI)
				break;
		}
		if (level)
			io->rte[pin] |= IOAPIC_RTE_REMOTE_IRR;
		return;
	}

	switch (dm) {
	case IOAPIC_RTE_DM_FIXED:
	case IOAPIC_RTE_DM_LOWPRI:
		/*
		 * Lowest-priority arbitration would walk all eligible
		 * LAPICs and pick the one with the lowest TPR.  We
		 * degrade to "deliver to the physical destination,"
		 * which is the simplification vmd's existing 8259 code
		 * makes as well.
		 */
		break;
	case IOAPIC_RTE_DM_NMI:
		break;
#if 0
	case IOAPIC_RTE_DM_SMI:
	case IOAPIC_RTE_DM_INIT:
		/*
		 * SMI and INIT from IO-APIC are exotic -- SMI for chipset
		 * SMM events, INIT for hardware-issued startup.  Neither
		 * is reachable from any device vmd emulates today.
		 */
#endif
#if 0
	case IOAPIC_RTE_DM_EXTINT:
		/*
		 * ExtINT routes the legacy 8259 INTR line through the
		 * IO-APIC.  vmd's i8259.c has its own delivery path
		 * straight to vcpu 0 (via vcpu_assert_irq), so the
		 * IO-APIC ExtINT path is unused.
		 */
#endif
	default:
		return;
	}

	if (io->ops != NULL && io->ops->deliver != NULL)
		io->ops->deliver(io->cookie, target, vec, level, pin);

	if (level)
		io->rte[pin] |= IOAPIC_RTE_REMOTE_IRR;
}

static int
line_get(const struct ioapic *io, uint8_t pin)
{
	return ((io->line_state & (1u << pin)) != 0);
}

static void
line_set(struct ioapic *io, uint8_t pin, int v)
{
	if (v)
		io->line_state |= (1u << pin);
	else
		io->line_state &= ~(1u << pin);
}
