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

#ifndef _VMD_LAPIC_H_
#define _VMD_LAPIC_H_

#include <sys/types.h>
#include <stdint.h>
#include <pthread.h>

/*
 * xAPIC MMIO layout.  Every register occupies 16 bytes; only the low 32
 * bits are meaningful.  Reads of reserved offsets return zero; writes to
 * reserved offsets are dropped.
 *
 * The full description is in Intel SDM vol. 3A chapter 10.4.  We give
 * names only to the registers vmd will actually touch in the first
 * SMP guest implementation.
 */

#define LAPIC_MMIO_BASE			0xfee00000UL
#define LAPIC_MMIO_SIZE			0x1000

/*
 * Emulated APIC bus clock.  Intel does not specify a fixed rate in
 * silicon; modern guests calibrate against an external clock (PIT
 * or HPET).  The constant therefore matters only as a stable value
 * that vmd surfaces consistently between MMIO reads and timer-tick
 * accounting.  Picked at 100 MHz (10 ns per bus tick before the
 * DCR-programmed divider) -- close to the historic Pentium-era
 * frequency Linux uses as a sanity fallback.
 */
#define LAPIC_BUS_NS_PER_TICK		100ULL	/* 10 MHz */

#define LAPIC_REG_ID			0x020
#define LAPIC_REG_VERSION		0x030
#define LAPIC_REG_TPR			0x080
#define LAPIC_REG_APR			0x090
#define LAPIC_REG_PPR			0x0a0
#define LAPIC_REG_EOI			0x0b0
#define LAPIC_REG_LDR			0x0d0
#define LAPIC_REG_DFR			0x0e0
#define LAPIC_REG_SVR			0x0f0
/* ISR is eight 32-bit registers at 0x100, 0x110, ..., 0x170 */
#define LAPIC_REG_ISR_BASE		0x100
#define LAPIC_REG_TMR_BASE		0x180
#define LAPIC_REG_IRR_BASE		0x200
#define LAPIC_REG_ESR			0x280
#define LAPIC_REG_LVT_CMCI		0x2f0
#define LAPIC_REG_ICR_LO		0x300
#define LAPIC_REG_ICR_HI		0x310
#define LAPIC_REG_LVT_TIMER		0x320
#define LAPIC_REG_LVT_THERMAL		0x330
#define LAPIC_REG_LVT_PERF		0x340
#define LAPIC_REG_LVT_LINT0		0x350
#define LAPIC_REG_LVT_LINT1		0x360
#define LAPIC_REG_LVT_ERROR		0x370
#define LAPIC_REG_TIMER_ICR		0x380
#define LAPIC_REG_TIMER_CCR		0x390
#define LAPIC_REG_TIMER_DCR		0x3e0

/* Spurious vector register flag bits */
#define LAPIC_SVR_APIC_ENABLE		(1u << 8)
#define LAPIC_SVR_FOCUS_DIS		(1u << 9)
#define LAPIC_SVR_EOI_SUPPRESS		(1u << 12)

/* ICR field decoding */
#define LAPIC_ICR_VEC(v)		((v) & 0xff)
#define LAPIC_ICR_DM_MASK		0x700
#define LAPIC_ICR_DM_SHIFT		8
#define LAPIC_ICR_DM_FIXED		0
#define LAPIC_ICR_DM_LOWPRI		1
#define LAPIC_ICR_DM_SMI		2
#define LAPIC_ICR_DM_NMI		4
#define LAPIC_ICR_DM_INIT		5
#define LAPIC_ICR_DM_STARTUP		6
#define LAPIC_ICR_DEST_MODE		(1u << 11)
#define LAPIC_ICR_DELIVERY_STATUS	(1u << 12)
#define LAPIC_ICR_LEVEL_ASSERT		(1u << 14)
#define LAPIC_ICR_TRIGGER_LEVEL		(1u << 15)
#define LAPIC_ICR_DEST_SHORT_MASK	0xc0000
#define LAPIC_ICR_DEST_SHORT_SHIFT	18
#define LAPIC_ICR_DEST_NONE		0
#define LAPIC_ICR_DEST_SELF		1
#define LAPIC_ICR_DEST_ALL		2
#define LAPIC_ICR_DEST_OTHERS		3
#define LAPIC_ICR_HI_DEST_SHIFT		24

/* LVT entry common bits */
#define LAPIC_LVT_VEC(v)		((v) & 0xff)
#define LAPIC_LVT_DM(v)			(((v) >> 8) & 0x7)
#define LAPIC_LVT_PENDING		(1u << 12)
#define LAPIC_LVT_POLARITY		(1u << 13)
#define LAPIC_LVT_REMOTE_IRR		(1u << 14)
#define LAPIC_LVT_TRIGGER_LEVEL		(1u << 15)
#define LAPIC_LVT_MASKED		(1u << 16)
#define LAPIC_LVT_TIMER_PERIODIC	(1u << 17)
#define LAPIC_LVT_TIMER_TSCDEADLINE	(1u << 18)

/*
 * Opaque per-vcpu LAPIC state.  Sized by lapic_new(), released by
 * lapic_free().  vmd holds one of these per vcpu and consults it for
 * MMIO accesses to that vcpu's 0xfee00000 page.
 *
 * THREAD-SAFETY: lapic.c is single-threaded per instance.  All
 * lapic_* calls on a given struct lapic must be serialised by the
 * caller (typically by holding the same per-vcpu mutex that already
 * guards the surrounding vmd device-emulation state).  No internal
 * locking is provided.
 */
struct lapic;

/*
 * Callbacks from the LAPIC up into the surrounding vmd device-emulation
 * layer.  These are the operations that, on real hardware, would cross
 * cpu boundaries via the inter-processor interrupt network.
 *
 * SECURITY NOTE: target_vcpu values passed to these callbacks come
 * straight from the guest's ICR destination field -- i.e. attacker
 * controlled.  The caller MUST validate target_vcpu against the
 * actual vcpu count of the VM before invoking vmm(4) ioctls
 * (vcpu_intr, vcpu_assert_irq, vcpu_reset, ...) with it.  lapic.c
 * does not range-check destinations.  See SECURITY.md S2.3.
 *
 * kick      - the LAPIC has set IRR[vec] on the target vcpu; if that
 *             vcpu is currently inside VMM_IOC_RUN, make it leave so
 *             that the pending interrupt can be evaluated and (when
 *             appropriate) injected on next entry.
 * broadcast - the guest wrote ICR with destination shorthand ALL or
 *             OTHERS.  The lapic layer cannot enumerate sibling vcpus,
 *             so the surrounding fabric must do it.  include_self is
 *             1 for "all incl self", 0 for "all but self".
 * startup   - the SIPI message: target vcpu must begin executing in
 *             16-bit real mode at CS:IP = sipi_vector<<8 : 0.
 * init      - INIT IPI: drop the target vcpu into the wait-for-SIPI
 *             state with its register file reset to the architectural
 *             INIT values.
 */
struct lapic_ops {
	void	(*kick)(void *cookie, uint32_t target_vcpu);
	void	(*broadcast)(void *cookie, uint32_t source_vcpu,
		    uint8_t vec, int include_self);
	void	(*startup)(void *cookie, uint32_t target_vcpu,
		    uint8_t sipi_vector);
	void	(*init)(void *cookie, uint32_t target_vcpu);
	/*
	 * deliver - atomic set-IRR + kick for unicast non-self FIXED /
	 *           LOWPRI IPIs.  The plain `kick` callback only wakes
	 *           the target; it does NOT set the target's IRR.  Using
	 *           kick alone for cross-vcpu fixed delivery loses the
	 *           interrupt: the target wakes, intr_pending() reads
	 *           IRR=0, and it halts again.  `deliver` runs
	 *           lapic_set_irr on the TARGET's LAPIC first, then
	 *           wakes it, so the pending vector is visible when the
	 *           target re-enters its run loop.
	 */
	void	(*deliver)(void *cookie, uint32_t target_vcpu, uint8_t vec);
	/*
	 * eoi_bcast - notify external IRQ controllers (e.g. IOAPIC) that
	 * the LAPIC has consumed vector `vec` so they can clear remote_IRR
	 * on the matching level-triggered redirection entry.  Called on
	 * each LAPIC EOI; may be NULL (legacy non-SMP path).
	 */
	void	(*eoi_bcast)(void *cookie, uint32_t source_vcpu, uint8_t vec);
};

/*
 * Lifecycle and configuration.
 */
struct lapic	*lapic_new(uint32_t vcpu_id);
void		 lapic_free(struct lapic *);
void		 lapic_set_ops(struct lapic *, const struct lapic_ops *,
		    void *cookie);
uint32_t	 lapic_id(struct lapic *);
int		 lapic_is_enabled(struct lapic *);

/*
 * Guest MMIO access.  off is the byte offset within the LAPIC page.
 * Sizes other than 4 bytes are not defined by xAPIC; vmd should reject
 * them at the EPT-fault decode layer before calling these.
 */
uint32_t	 lapic_mmio_read(struct lapic *, uint16_t off);
void		 lapic_mmio_write(struct lapic *, uint16_t off, uint32_t val);

/*
 * Timer driving.  The lapic has no clock of its own -- the caller
 * is responsible for advancing the internal sense of "now" via
 * lapic_tick().  Time units are nanoseconds on an arbitrary
 * monotonic clock; the lapic only uses differences.
 *
 * The emulated bus clock is fixed at 100 MHz (10 ns per tick before
 * the divider applies -- see LAPIC_BUS_NS_PER_TICK in the .c).
 * Guests calibrate against the i8253 PIT in vmd, so the absolute
 * value matters only as a constant.
 *
 *   lapic_tick(l, now_ns)
 *     Advance the internal clock to now_ns; if the timer LVT was
 *     armed and the deadline has been reached, set IRR for the
 *     timer vector and (in periodic mode) re-arm.  Returns 1 if a
 *     timer interrupt was raised, 0 otherwise.
 *
 *   lapic_next_deadline(l)
 *     Return the absolute time at which the lapic next wants to
 *     fire its timer, or UINT64_MAX if no timer is armed.  vmd
 *     uses this to compute kevent timeouts so that the vcpu thread
 *     does not sleep past the deadline.
 */
int		 lapic_tick(struct lapic *, uint64_t now_ns);
uint64_t	 lapic_next_deadline(struct lapic *);

/*
 * Edges from outside (device emulation, IPI-from-peer):
 *   set_irr   - mark a vector pending on this LAPIC.  Invokes ops->kick.
 *   pending   - return -1 if nothing is deliverable (taking TPR/PPR
 *               into account), otherwise the vector number, without
 *               consuming.
 *   ack       - consume the highest pending vector: move its bit from
 *               IRR to ISR, clear the IRR bit, return the vector.
 *               Returns 0xff if there was nothing to ack (matches the
 *               xAPIC spurious-vector convention -- see SDM 10.9).
 *               This is ambiguous with a legitimate vec-0xff
 *               interrupt; the recommended caller pattern is to
 *               consult lapic_pending() first (returns -1 for "no
 *               interrupt") and only call lapic_ack() when pending
 *               is non-negative.
 *   eoi       - guest wrote to LAPIC_REG_EOI: clear the top ISR bit.
 */
void		 lapic_set_irr(struct lapic *, uint8_t vec);
int		 lapic_pending(struct lapic *);
int		 lapic_pending_nofire(struct lapic *);
uint8_t		 lapic_ack(struct lapic *);
void		 lapic_unack(struct lapic *, uint8_t vec);
void		 lapic_eoi(struct lapic *);

#endif /* !_VMD_LAPIC_H_ */
