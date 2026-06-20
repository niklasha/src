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
 * Per-vcpu local APIC (xAPIC) emulation, intended to back vmd's
 * SMP-guest support.  Lives inside the vmd vm process, one instance
 * per emulated vcpu, owning the guest-physical page at
 * LAPIC_MMIO_BASE for that vcpu's view.
 *
 * Scope of the first cut:
 *   - xAPIC memory-mapped registers.  No x2APIC, no MSR access.
 *   - Interrupt routing via IRR / ISR; software-priority arbitration
 *     using TPR / PPR is implemented but no thresholding tricks.
 *   - ICR write decoded for fixed, NMI, INIT, STARTUP.  Lowest-pri,
 *     SMI and self-IPI shorthand are accepted but only the most
 *     common shapes are simulated (see ipi_send()).
 *   - Timer LVT register exists but firing is not implemented in this
 *     file; the surrounding vmd glue is expected to call
 *     lapic_set_irr() with the timer vector from a separate clock
 *     source.
 *
 * The file is deliberately library-shaped: it includes no vmd headers
 * and depends on no global state.  All cross-vcpu effects go through
 * the lapic_ops vector that the caller installs via lapic_set_ops().
 * That keeps the module trivially linkable into a stand-alone test
 * harness (see test/test_lapic.c).
 */

#include <sys/types.h>

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lapic.h"

extern void log_warnx(const char *, ...);

/*
 * Read the host monotonic clock in nanoseconds.  Used to drive the
 * LAPIC timer in real time without requiring an external lapic_tick()
 * pacemaker.  Falls back to 0 on the (impossible on OpenBSD) failure
 * path so timer_remaining_count() just reports the initial value.
 */
static uint64_t
mono_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (0);
	return ((uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec);
}

/*
 * The xAPIC register file occupies one 4 KiB page.  Each register is
 * 16 bytes apart (one cacheline) so the indexed array has 1024/16 =
 * 64 slots.  Only the low 32 bits of each slot are architecturally
 * defined.
 */
#define LAPIC_NREGS		(LAPIC_MMIO_SIZE / 16)
#define LAPIC_REG_INDEX(off)	((off) >> 4)

/*
 * 256 interrupt vectors -> 8 32-bit dwords each for IRR and ISR.
 */
#define LAPIC_NVEC		256
#define LAPIC_VEC_DWORDS	(LAPIC_NVEC / 32)

/*
 * Internal timer state.  Distinct from the MMIO ICR / CCR shadow
 * registers because we keep them recomputed lazily on read.
 */
struct lapic_timer {
	uint64_t	 clock_ns;	/* "now" as last set by lapic_tick */
	uint64_t	 deadline_ns;	/* UINT64_MAX => disarmed */
	uint32_t	 initial;	/* shadow of ICR (count units) */
	uint32_t	 divider;	/* result of dcr_divider() */
};

struct lapic {
	/*
	 * Per-LAPIC mutex.  Protects irr, isr, regs[], timer.*.  Three
	 * threads can concurrently mutate one LAPIC: the owning vcpu
	 * thread (intr_pending/intr_ack/eoi/mmio), the BSP vcpu thread
	 * (lapic_set_irr from lapic_deliver_cb for cross-vcpu IPIs),
	 * and the dedicated lapic-timer thread (lapic_tick).  Without
	 * this lock the 256-bit IRR/ISR bitmaps and the regs[] mirror
	 * become inconsistent, leading to lost interrupts (TLB
	 * shootdown deadlock) and stale PPR reads.
	 *
	 * Internal helpers assume the lock is held; public entry points
	 * acquire it.  See the _locked vs unlocked split below.
	 */
	pthread_mutex_t		 lock;
	uint32_t		 id;		/* vcpu / apic id */
	uint32_t		 regs[LAPIC_NREGS];
	uint32_t		 irr[LAPIC_VEC_DWORDS];
	uint32_t		 isr[LAPIC_VEC_DWORDS];
	struct lapic_timer	 timer;

	const struct lapic_ops	*ops;
	void			*cookie;
};

/*
 * Architectural reset state, populated by lapic_reset().  Fields not
 * listed here default to zero per the SDM.
 */
#define LAPIC_VERSION_VAL	0x00050014u	/* xAPIC, 6 LVT entries */
#define LAPIC_SVR_RESET		0x000000ffu	/* vec = 0xff, disabled */
#define LAPIC_LVT_RESET		LAPIC_LVT_MASKED
#define LAPIC_DFR_RESET		0xffffffffu

static void	 lapic_reset(struct lapic *);
static void	 lapic_recompute_ppr(struct lapic *);
static void	 vec_set(uint32_t *bitmap, uint8_t vec);
static void	 vec_clr(uint32_t *bitmap, uint8_t vec);
static int	 vec_highest(const uint32_t *bitmap);
static void	 mirror_irr_to_regs(struct lapic *);
static void	 mirror_isr_to_regs(struct lapic *);
static void	 ipi_send(struct lapic *, uint32_t icr_lo, uint32_t icr_hi);
static uint32_t	 dcr_divider(uint32_t dcr);
static void	 timer_arm(struct lapic *, uint32_t initial);
static void	 timer_disarm(struct lapic *);
static uint32_t	 timer_remaining_count(struct lapic *);
static int	 timer_fire_if_due(struct lapic *);

/*
 * _locked variants: assume the per-LAPIC mutex is already held by the
 * caller.  Public entry points wrap these with lock/unlock so that all
 * mutations of irr/isr/regs/timer happen under the lock.
 */
static void	 lapic_set_irr_locked(struct lapic *, uint8_t vec);
static int	 lapic_pending_locked(struct lapic *);
static uint8_t	 lapic_ack_locked(struct lapic *);
static int	 lapic_eoi_locked(struct lapic *);
static uint32_t	 lapic_mmio_read_locked(struct lapic *, uint16_t off);
static void	 lapic_mmio_write_locked(struct lapic *, uint16_t off,
		    uint32_t val);

/*
 * Allocate and reset a per-vcpu LAPIC.
 */
struct lapic *
lapic_new(uint32_t vcpu_id)
{
	struct lapic *l;

	l = calloc(1, sizeof(*l));
	if (l == NULL)
		return (NULL);
	if (pthread_mutex_init(&l->lock, NULL) != 0) {
		free(l);
		return (NULL);
	}
	l->id = vcpu_id;
	lapic_reset(l);
	return (l);
}

void
lapic_free(struct lapic *l)
{
	if (l == NULL)
		return;
	pthread_mutex_destroy(&l->lock);
	free(l);
}

void
lapic_set_ops(struct lapic *l, const struct lapic_ops *ops, void *cookie)
{
	l->ops = ops;
	l->cookie = cookie;
}

uint32_t
lapic_id(struct lapic *l)
{
	return (l->id);
}

int
lapic_is_enabled(struct lapic *l)
{
	int enabled;

	pthread_mutex_lock(&l->lock);
	enabled = ((l->regs[LAPIC_REG_INDEX(LAPIC_REG_SVR)]
	    & LAPIC_SVR_APIC_ENABLE) != 0);
	pthread_mutex_unlock(&l->lock);
	return (enabled);
}

/*
 * Read a 32-bit register.  Reads of write-only registers (EOI) return
 * zero per SDM 10.4.1.  Reads of reserved offsets also return zero,
 * silently.
 */
uint32_t
lapic_mmio_read(struct lapic *l, uint16_t off)
{
	uint32_t val;

	pthread_mutex_lock(&l->lock);
	val = lapic_mmio_read_locked(l, off);
	pthread_mutex_unlock(&l->lock);
	return (val);
}

static uint32_t
lapic_mmio_read_locked(struct lapic *l, uint16_t off)
{
	uint32_t idx;

	if (off >= LAPIC_MMIO_SIZE)
		return (0);
	idx = LAPIC_REG_INDEX(off);

	switch (off) {
	case LAPIC_REG_EOI:
		return (0);			/* write-only */
	case LAPIC_REG_PPR:
		lapic_recompute_ppr(l);
		return (l->regs[idx]);
	case LAPIC_REG_TIMER_CCR:
		return (timer_remaining_count(l));
	default:
		return (l->regs[idx]);
	}
}

/*
 * Write a 32-bit register.  Most writes simply update the shadow,
 * but a handful of registers have side effects: EOI consumes the top
 * of ISR; ICR-low triggers an IPI; SVR enables/disables; ID is
 * read-only (silently dropped).
 */
void
lapic_mmio_write(struct lapic *l, uint16_t off, uint32_t val)
{
	pthread_mutex_lock(&l->lock);
	lapic_mmio_write_locked(l, off, val);
	pthread_mutex_unlock(&l->lock);
}

static void
lapic_mmio_write_locked(struct lapic *l, uint16_t off, uint32_t val)
{
	uint32_t idx;

	if (off >= LAPIC_MMIO_SIZE)
		return;
	idx = LAPIC_REG_INDEX(off);

	switch (off) {
	case LAPIC_REG_ID:
		/* writable on xAPIC but discouraged; honour for completeness */
		l->regs[idx] = val & 0xff000000u;
		l->id = val >> 24;
		break;
	case LAPIC_REG_VERSION:
	case LAPIC_REG_APR:
	case LAPIC_REG_PPR:
		/* read-only */
		break;
	case LAPIC_REG_EOI: {
		int vec = lapic_eoi_locked(l);
		if (vec >= 0 && l->ops != NULL && l->ops->eoi_bcast != NULL) {
			const struct lapic_ops *ops = l->ops;
			void *cookie = l->cookie;
			uint32_t id = l->id;
			/*
			 * Drop our lock around eoi_bcast: it may call
			 * back into ioapic_eoi -> try_deliver ->
			 * lapic_set_irr on THIS same lapic, which would
			 * recursively reacquire l->lock and deadlock.
			 */
			pthread_mutex_unlock(&l->lock);
			ops->eoi_bcast(cookie, id, (uint8_t)vec);
			pthread_mutex_lock(&l->lock);
		}
		break;
	}
	case LAPIC_REG_ICR_LO:
		/*
		 * Real silicon raises delivery_status while an IPI is in
		 * flight and clears it on completion.  Our delivery path
		 * is synchronous (ops->kick / ops->broadcast return before
		 * the mmio_write does), so the bit must always read back
		 * as 0.  Store the guest's value but force DS clear.
		 */
		l->regs[idx] = val & ~LAPIC_ICR_DELIVERY_STATUS;
		ipi_send(l, val, l->regs[LAPIC_REG_INDEX(LAPIC_REG_ICR_HI)]);
		break;
	case LAPIC_REG_ICR_HI:
		l->regs[idx] = val & 0xff000000u;
		break;
	case LAPIC_REG_SVR:
		l->regs[idx] = val & 0x000003ffu;
		break;
	case LAPIC_REG_TPR:
		l->regs[idx] = val & 0xff;
		lapic_recompute_ppr(l);
		break;
	case LAPIC_REG_TIMER_ICR:
		l->regs[idx] = val;
		l->timer.initial = val;
		if (val == 0)
			timer_disarm(l);
		else
			timer_arm(l, val);
		break;
	case LAPIC_REG_TIMER_DCR:
		/* Bits 3,1,0 form the divisor index; bit 2 reserved. */
		l->regs[idx] = val & 0xb;
		l->timer.divider = dcr_divider(val);
		/*
		 * If the timer is currently armed, the SDM says changing
		 * the divider re-bases the deadline from now using the
		 * remaining count.  We approximate by re-arming with the
		 * raw remaining count converted under the new divider.
		 */
		if (l->timer.deadline_ns != UINT64_MAX) {
			uint32_t r = timer_remaining_count(l);

			if (r > 0)
				timer_arm(l, r);
		}
		break;
	case LAPIC_REG_LVT_TIMER:
		l->regs[idx] = val & 0x310ffu;
		/*
		 * If newly masked, suppress firing; if unmasked,
		 * keep the existing deadline (SDM leaves this
		 * implementation defined).
		 */
		break;
	default:
		l->regs[idx] = val;
		break;
	}
}

/*
 * Mark a vector as pending and kick the vcpu out of guest mode if
 * the lapic is enabled.  Called from device emulation (vionet,
 * vioblk, ...) and from ipi_send() for fixed-delivery IPIs.
 */
void
lapic_set_irr(struct lapic *l, uint8_t vec)
{
	pthread_mutex_lock(&l->lock);
	lapic_set_irr_locked(l, vec);
	pthread_mutex_unlock(&l->lock);
}

static void
lapic_set_irr_locked(struct lapic *l, uint8_t vec)
{
	int kick;
	const struct lapic_ops *ops;
	void *cookie;
	uint32_t id;

	if (vec < 16)
		return;				/* reserved vectors */
	vec_set(l->irr, vec);
	mirror_irr_to_regs(l);
	/*
	 * Snapshot ops/cookie under the lock, then drop the lock around
	 * the kick callback.  The callback talks to vmd's vcpu thread
	 * fabric (vcpu_unhalt / vcpu_signal_run, which take vm_mtx and
	 * vcpu_run_mtx[n]) -- holding lapic.lock across that would risk
	 * deadlock against any future code path that calls into the
	 * lapic from a context that already holds those mutexes.
	 */
	kick = (l->ops != NULL && l->ops->kick != NULL &&
	    ((l->regs[LAPIC_REG_INDEX(LAPIC_REG_SVR)]
	    & LAPIC_SVR_APIC_ENABLE) != 0));
	if (kick) {
		ops = l->ops;
		cookie = l->cookie;
		id = l->id;
		pthread_mutex_unlock(&l->lock);
		ops->kick(cookie, id);
		pthread_mutex_lock(&l->lock);
	}
}

/*
 * Return the vector that would be delivered next, or -1 if none.
 * Honours PPR (i.e. respect the guest's task/interrupt priority).
 *
 * As a side effect this drains any pending timer expirations: each
 * pending check naturally advances the lapic's sense of "now" and
 * fires any armed deadline that has elapsed.  This lets us avoid a
 * dedicated lapic_tick() pacemaker thread -- the vcpu run loop
 * polls lapic_pending() every iteration anyway.
 */
int
lapic_pending(struct lapic *l)
{
	int vec;

	pthread_mutex_lock(&l->lock);
	vec = lapic_pending_locked(l);
	pthread_mutex_unlock(&l->lock);
	return (vec);
}

static int
lapic_pending_locked(struct lapic *l)
{
	int vec;
	uint32_t ppr;

	if ((l->regs[LAPIC_REG_INDEX(LAPIC_REG_SVR)]
	    & LAPIC_SVR_APIC_ENABLE) == 0)
		return (-1);
	/* Advance clock and fire timer if its deadline elapsed. */
	l->timer.clock_ns = mono_ns();
	(void)timer_fire_if_due(l);
	vec = vec_highest(l->irr);
	if (vec < 0)
		return (-1);
	lapic_recompute_ppr(l);
	ppr = l->regs[LAPIC_REG_INDEX(LAPIC_REG_PPR)];
	if ((uint32_t)(vec >> 4) <= (ppr >> 4))
		return (-1);		/* masked by current PPR */
	return (vec);
}

/*
 * Side-effect-free variant of lapic_pending(): report whether a vector
 * is already pending in IRR (above PPR) WITHOUT advancing the clock or
 * firing/kicking a due timer.  The normal lapic_pending() fires the
 * timer, which on a due deadline calls ops->kick -> vcpu_unhalt(), which
 * takes vcpu_run_mtx -- so it MUST NOT be called from a context already
 * holding that mutex (the vcpu_run_loop halt decision) or it self-
 * deadlocks.  This read-only check is safe there; the 1ms timer thread
 * remains responsible for actually firing due timers.
 */
int
lapic_pending_nofire(struct lapic *l)
{
	int vec;
	uint32_t ppr;

	pthread_mutex_lock(&l->lock);
	if ((l->regs[LAPIC_REG_INDEX(LAPIC_REG_SVR)]
	    & LAPIC_SVR_APIC_ENABLE) == 0) {
		pthread_mutex_unlock(&l->lock);
		return (-1);
	}
	vec = vec_highest(l->irr);
	if (vec < 0) {
		pthread_mutex_unlock(&l->lock);
		return (-1);
	}
	lapic_recompute_ppr(l);
	ppr = l->regs[LAPIC_REG_INDEX(LAPIC_REG_PPR)];
	pthread_mutex_unlock(&l->lock);
	if ((uint32_t)(vec >> 4) <= (ppr >> 4))
		return (-1);		/* masked by current PPR */
	return (vec);
}

/*
 * Consume the highest pending vector: move it from IRR into ISR and
 * return its number.  Returns 0xff (spurious convention) if nothing
 * is ready.
 */
uint8_t
lapic_ack(struct lapic *l)
{
	uint8_t vec;

	pthread_mutex_lock(&l->lock);
	vec = lapic_ack_locked(l);
	pthread_mutex_unlock(&l->lock);
	return (vec);
}

static uint8_t
lapic_ack_locked(struct lapic *l)
{
	int vec;

	vec = lapic_pending_locked(l);
	if (vec < 0)
		return (0xff);
	vec_clr(l->irr, (uint8_t)vec);
	vec_set(l->isr, (uint8_t)vec);
	mirror_irr_to_regs(l);
	mirror_isr_to_regs(l);
	lapic_recompute_ppr(l);
	return ((uint8_t)vec);
}

/*
 * Undo a speculative lapic_ack() for a SPECIFIC vector: move it from
 * ISR back to IRR and recompute PPR.  Called when the kernel declined
 * to actually inject the vector we ack'd (guest not interruptible), so
 * it must be retried rather than left stranded in ISR (a stuck ISR bit
 * pins PPR and masks all lower-priority vectors).  No-op if the vector
 * is not currently in ISR (e.g. it was an i8259 vector, or the guest
 * already EOI'd it).
 */
void
lapic_unack(struct lapic *l, uint8_t vec)
{
	pthread_mutex_lock(&l->lock);
	if (l->isr[vec >> 5] & (1U << (vec & 31))) {
		vec_clr(l->isr, vec);
		vec_set(l->irr, vec);
		mirror_irr_to_regs(l);
		mirror_isr_to_regs(l);
		lapic_recompute_ppr(l);
	}
	pthread_mutex_unlock(&l->lock);
}

/*
 * EOI: clear the highest ISR bit.  Matches xAPIC semantics: any
 * write to EOI completes the topmost in-service interrupt, regardless
 * of value.
 */
void
lapic_eoi(struct lapic *l)
{
	int vec;
	pthread_mutex_lock(&l->lock);
	vec = lapic_eoi_locked(l);
	pthread_mutex_unlock(&l->lock);
	if (vec >= 0 && l->ops != NULL && l->ops->eoi_bcast != NULL)
		l->ops->eoi_bcast(l->cookie, l->id, (uint8_t)vec);
}

static int
lapic_eoi_locked(struct lapic *l)
{
	int vec;

	vec = vec_highest(l->isr);
	if (vec < 0)
		return (-1);
	vec_clr(l->isr, (uint8_t)vec);
	mirror_isr_to_regs(l);
	lapic_recompute_ppr(l);
	return (vec);
}

/*
 * Advance the lapic's sense of "now" and fire the timer if its
 * deadline has been reached.  Returns 1 if a timer interrupt was
 * raised, 0 otherwise.
 */
int
lapic_tick(struct lapic *l, uint64_t now_ns)
{
	int r;

	pthread_mutex_lock(&l->lock);
	l->timer.clock_ns = now_ns;
	r = timer_fire_if_due(l);
	pthread_mutex_unlock(&l->lock);
	return (r);
}

uint64_t
lapic_next_deadline(struct lapic *l)
{
	uint64_t d;

	pthread_mutex_lock(&l->lock);
	d = l->timer.deadline_ns;
	pthread_mutex_unlock(&l->lock);
	return (d);
}

/*
 * Internal helpers below.
 */

static void
lapic_reset(struct lapic *l)
{
	int i;

	memset(l->regs, 0, sizeof(l->regs));
	memset(l->irr,  0, sizeof(l->irr));
	memset(l->isr,  0, sizeof(l->isr));

	l->regs[LAPIC_REG_INDEX(LAPIC_REG_ID)]      = l->id << 24;
	l->regs[LAPIC_REG_INDEX(LAPIC_REG_VERSION)] = LAPIC_VERSION_VAL;
	l->regs[LAPIC_REG_INDEX(LAPIC_REG_SVR)]     = LAPIC_SVR_RESET;
	l->regs[LAPIC_REG_INDEX(LAPIC_REG_DFR)]     = LAPIC_DFR_RESET;

	for (i = 0; i < 6; i++) {
		uint16_t lvt = LAPIC_REG_LVT_TIMER + ((uint16_t)i << 4);

		l->regs[LAPIC_REG_INDEX(lvt)] = LAPIC_LVT_RESET;
	}
	l->regs[LAPIC_REG_INDEX(LAPIC_REG_LVT_CMCI)] = LAPIC_LVT_RESET;

	l->timer.clock_ns = 0;
	l->timer.deadline_ns = UINT64_MAX;
	l->timer.initial = 0;
	l->timer.divider = dcr_divider(0);	/* /2 per SDM 10.5.4 default */
}

/*
 * Processor Priority Register is the max of TPR and the priority
 * class of the highest in-service interrupt (vec >> 4).
 */
static void
lapic_recompute_ppr(struct lapic *l)
{
	uint32_t tpr;
	int isrv;
	uint32_t ppr;

	tpr = l->regs[LAPIC_REG_INDEX(LAPIC_REG_TPR)] & 0xff;
	isrv = vec_highest(l->isr);
	if (isrv < 0) {
		ppr = tpr;
	} else if ((tpr >> 4) >= (uint32_t)(isrv >> 4)) {
		ppr = tpr;
	} else {
		ppr = (uint32_t)isrv & 0xf0;
	}
	l->regs[LAPIC_REG_INDEX(LAPIC_REG_PPR)] = ppr;
}

/*
 * 256-bit vector-bitmap helpers.  The xAPIC IRR/ISR layout puts
 * vector V in bit (V mod 32) of dword (V / 32), with the lowest
 * vector in the lowest dword at register offsets 0x100 / 0x200.
 */
static void
vec_set(uint32_t *bitmap, uint8_t vec)
{
	bitmap[vec >> 5] |= (1u << (vec & 31));
}

static void
vec_clr(uint32_t *bitmap, uint8_t vec)
{
	bitmap[vec >> 5] &= ~(1u << (vec & 31));
}

static int
vec_highest(const uint32_t *bitmap)
{
	int i, b;

	for (i = LAPIC_VEC_DWORDS - 1; i >= 0; i--) {
		if (bitmap[i] == 0)
			continue;
		for (b = 31; b >= 0; b--) {
			if (bitmap[i] & (1u << b))
				return ((i << 5) | b);
		}
	}
	return (-1);
}

/*
 * Reflect the IRR/ISR shadow bitmaps into the MMIO register array so
 * that guest reads of 0x200..0x270 (IRR) and 0x100..0x170 (ISR)
 * return current values.
 */
static void
mirror_irr_to_regs(struct lapic *l)
{
	int i;

	for (i = 0; i < LAPIC_VEC_DWORDS; i++)
		l->regs[LAPIC_REG_INDEX(LAPIC_REG_IRR_BASE + (i << 4))] =
		    l->irr[i];
}

static void
mirror_isr_to_regs(struct lapic *l)
{
	int i;

	for (i = 0; i < LAPIC_VEC_DWORDS; i++)
		l->regs[LAPIC_REG_INDEX(LAPIC_REG_ISR_BASE + (i << 4))] =
		    l->isr[i];
}

/*
 * Decode an ICR write and pass the high-level intent up to the caller
 * via the ops vector.  The ICR's destination shorthand is honoured:
 * NONE -> use the destination field; SELF / ALL / OTHERS go via the
 * broadcast op so the caller can enumerate sibling vcpus.
 *
 * Lowest-priority delivery falls back to "fixed to destination" for
 * now; vmd's existing PIC code does the same simplification.
 */
static void
ipi_send(struct lapic *l, uint32_t icr_lo, uint32_t icr_hi)
{
	const struct lapic_ops *ops;
	void *cookie;
	uint32_t dm, shorthand, dest, source_id;
	uint8_t vec;
	int is_broadcast, include_self, dest_logical;

	vec = (uint8_t)LAPIC_ICR_VEC(icr_lo);
	dm = (icr_lo & LAPIC_ICR_DM_MASK) >> LAPIC_ICR_DM_SHIFT;
	shorthand = (icr_lo & LAPIC_ICR_DEST_SHORT_MASK)
	    >> LAPIC_ICR_DEST_SHORT_SHIFT;
	dest = icr_hi >> LAPIC_ICR_HI_DEST_SHIFT;
	dest_logical = (icr_lo & LAPIC_ICR_DEST_MODE) != 0;
	is_broadcast = 0;
	include_self = 0;


	switch (shorthand) {
	case LAPIC_ICR_DEST_NONE:
		break;
	case LAPIC_ICR_DEST_SELF:
		dest = l->id;
		break;
	case LAPIC_ICR_DEST_ALL:
		is_broadcast = 1;
		include_self = 1;
		break;
	case LAPIC_ICR_DEST_OTHERS:
		is_broadcast = 1;
		include_self = 0;
		break;
	}

	if (l->ops == NULL)
		return;

	/*
	 * Self-IPI fast path: mutate THIS lapic's IRR under the lock we
	 * already hold.  Physical mode only -- in logical mode `dest` is
	 * a bitmap, and comparing it against l->id would mis-fire (e.g.
	 * cpu1 sending logical->cpu0 has dest=0x01==l->id and would wrongly
	 * self-deliver).  Logical self-IPIs fall through to the bitmap
	 * loop below, which delivers correctly.
	 */
	if (!is_broadcast && !dest_logical && dest == l->id &&
	    (dm == LAPIC_ICR_DM_FIXED || dm == LAPIC_ICR_DM_LOWPRI)) {
		lapic_set_irr_locked(l, vec);
		return;
	}

	/*
	 * For any path that calls into the surrounding fabric (broadcast,
	 * cross-vcpu deliver, kick on other vcpu, init, startup) we drop
	 * the lock first.  The callbacks may walk into OTHER lapics
	 * (e.g. lapic_broadcast iterates lapic_set_irr on every sibling)
	 * and, in the include_self case, even back into THIS lapic -- a
	 * recursive lock would deadlock.  Snapshot ops/cookie/id under
	 * the lock, then release before the upcall.
	 */
	ops = l->ops;
	cookie = l->cookie;
	source_id = l->id;
	pthread_mutex_unlock(&l->lock);

	/* Broadcasts are delegated wholesale to the caller. */
	if (is_broadcast) {
		switch (dm) {
		case LAPIC_ICR_DM_FIXED:
		case LAPIC_ICR_DM_LOWPRI:
		case LAPIC_ICR_DM_NMI:
			if (ops->broadcast != NULL)
				ops->broadcast(cookie, source_id, vec,
				    include_self);
			break;
		case LAPIC_ICR_DM_INIT:
			/*
			 * Broadcast INIT: SeaBIOS sends INIT with
			 * destination shorthand ALL_BUT_SELF before
			 * the SIPI to place all APs in wait-for-SIPI.
			 * Iterate and call ops->init on each target.
			 */
			if (ops->init != NULL) {
				uint32_t t;
				for (t = 0; t < 64; t++) {
					if (!include_self && t == source_id)
						continue;
					ops->init(cookie, t);
				}
			}
			break;
		case LAPIC_ICR_DM_STARTUP:
			/*
			 * Broadcast SIPI: same as INIT -- SeaBIOS uses
			 * destination shorthand ALL_BUT_SELF for SIPI.
			 * Each target AP that is in wait-for-SIPI state
			 * will be started at CS:IP = vec<<8 : 0.
			 */
			if (ops->startup != NULL) {
				uint32_t t;
				for (t = 0; t < 64; t++) {
					if (!include_self && t == source_id)
						continue;
					ops->startup(cookie, t, vec);
				}
			}
			break;
		default:
			break;
		}
		goto out;
	}

	/*
	 * Directed (non-shorthand) delivery.  In PHYSICAL mode `dest` is
	 * a single APIC id.  In LOGICAL mode `dest` is an 8-bit flat-mode
	 * bitmap: bit N => logical APIC id (1<<N) => cpu N, because Linux's
	 * init_apic_ldr_flat() programs LDR = 1<<cpuid and we advertise
	 * APIC id == cpu id.  Deliver to EVERY set destination -- a
	 * multi-target logical IPI (e.g. {cpu1,cpu2}=0b0110) must reach
	 * both, not be dropped.  This mirrors the IOAPIC logical path.
	 * Flat mode addresses at most 8 cpus; >8-cpu logical (cluster /
	 * x2apic) is out of scope and would need real LDR/DFR tracking.
	 */
	switch (dm) {
	case LAPIC_ICR_DM_FIXED:
	case LAPIC_ICR_DM_LOWPRI:
		if (dest_logical) {
			uint32_t b;
			for (b = 0; b < 8; b++) {
				if ((dest & (1u << b)) == 0)
					continue;
				if (ops->deliver != NULL)
					ops->deliver(cookie, b, vec);
				else if (ops->kick != NULL)
					ops->kick(cookie, b);
			}
		} else if (ops->deliver != NULL) {
			/*
			 * Cross-vcpu directed delivery.  Use deliver so the
			 * target's IRR is set BEFORE the wake, otherwise
			 * the target wakes, sees IRR=0 in intr_pending,
			 * and halts again -- losing the IPI.  This is
			 * the scheduler-IPI fix.
			 */
			ops->deliver(cookie, dest, vec);
		} else if (ops->kick != NULL) {
			/*
			 * Legacy fallback: callers that have not yet
			 * implemented `deliver` still get the wake (but
			 * leak the interrupt).  Kept for source
			 * compatibility only.
			 */
			ops->kick(cookie, dest);
		}
		break;
	case LAPIC_ICR_DM_NMI:
		if (dest_logical) {
			uint32_t b;
			for (b = 0; b < 8; b++) {
				if ((dest & (1u << b)) && ops->kick != NULL)
					ops->kick(cookie, b);
			}
		} else if (ops->kick != NULL)
			ops->kick(cookie, dest);
		break;
	case LAPIC_ICR_DM_INIT:
		if (ops->init != NULL)
			ops->init(cookie, dest);
		break;
	case LAPIC_ICR_DM_STARTUP:
		if (ops->startup != NULL)
			ops->startup(cookie, dest, vec);
		break;
#if 0
	case LAPIC_ICR_DM_SMI:
		/*
		 * SMI is for legacy x86 system management; OpenBSD
		 * guests do not send SMIs.  Until vmd has SMI support
		 * in any direction, swallow.
		 */
#endif
	default:
		break;
	}
out:
	/* Re-acquire so the caller's invariant (lock held) is restored. */
	pthread_mutex_lock(&l->lock);
}

/*
 * APIC timer divider decode.  SDM 10.5.4: bits 3,1,0 of DCR form a
 * 3-bit index; bit 2 reserved.  Index -> divisor mapping below.
 */
static uint32_t
dcr_divider(uint32_t dcr)
{
	static const uint32_t div[8] = {
		2, 4, 8, 16, 32, 64, 128, 1
	};
	uint32_t idx;

	idx = ((dcr & 0x8) >> 1) | (dcr & 0x3);
	return (div[idx & 7]);
}

static void
timer_arm(struct lapic *l, uint32_t initial)
{
	uint64_t now, span_ns;

	now = mono_ns();
	l->timer.clock_ns = now;	/* "armed at" timestamp */
	span_ns = (uint64_t)initial * (uint64_t)l->timer.divider
	    * LAPIC_BUS_NS_PER_TICK;
	l->timer.deadline_ns = now + span_ns;
}

static void
timer_disarm(struct lapic *l)
{
	l->timer.deadline_ns = UINT64_MAX;
	l->regs[LAPIC_REG_INDEX(LAPIC_REG_TIMER_CCR)] = 0;
}

/*
 * Compute the timer's current count value (ticks remaining until the
 * next fire).  Zero if the deadline has passed or the timer is
 * disarmed.
 *
 * Reads CLOCK_MONOTONIC directly so the count decrements in real time
 * without requiring an external pacemaker (lapic_tick).  Guests that
 * calibrate the LAPIC timer against the i8253 PIT (OpenBSD's
 * lapic_calibrate_timer is the motivating case) need CCR to
 * MONOTONICALLY DECREASE while they spin on PIT IRQ0 -- that ratio is
 * how they derive a frequency.
 *
 * Also honours periodic mode: when the deadline passes we re-base
 * clock_ns and shift deadline_ns by one initial span, so the next
 * read shows a freshly-reloaded count.  This keeps periodic timers
 * advancing even when nothing else is calling lapic_tick().
 *
 * One-shot mode latches at 0 once the deadline passes, matching SDM
 * 10.5.4.
 */
static uint32_t
timer_remaining_count(struct lapic *l)
{
	uint64_t now, ns_left, count, span_ns;
	uint32_t per_tick, lvt;

	if (l->timer.deadline_ns == UINT64_MAX)
		return (0);
	if (l->timer.initial == 0)
		return (0);

	per_tick = l->timer.divider * LAPIC_BUS_NS_PER_TICK;
	if (per_tick == 0)
		return (0);

	now = mono_ns();
	l->timer.clock_ns = now;

	if (now >= l->timer.deadline_ns) {
		lvt = l->regs[LAPIC_REG_INDEX(LAPIC_REG_LVT_TIMER)];
		if (lvt & LAPIC_LVT_TIMER_PERIODIC) {
			/*
			 * Advance the deadline by however many full
			 * periods have elapsed, so we don't burn cpu
			 * playing catch-up on a stale armament.
			 */
			span_ns = (uint64_t)l->timer.initial
			    * (uint64_t)l->timer.divider
			    * LAPIC_BUS_NS_PER_TICK;
			if (span_ns == 0)
				return (0);
			do {
				l->timer.deadline_ns += span_ns;
			} while (l->timer.deadline_ns <= now);
		} else {
			return (0);
		}
	}

	ns_left = l->timer.deadline_ns - now;
	count = ns_left / per_tick;
	if (count > 0xffffffffULL)
		count = 0xffffffffULL;
	return ((uint32_t)count);
}

/*
 * Called from lapic_tick().  Raises the timer LVT vector via IRR if
 * the timer is armed, unmasked, and the deadline has passed.  In
 * periodic mode re-arms; in one-shot disarms.
 *
 * TSC-deadline mode is currently #if 0'd -- vmd has no need to expose
 * IA32_TSC_DEADLINE MSR to the guest in the first SMP cut.
 */
static int
timer_fire_if_due(struct lapic *l)
{
	uint32_t lvt;
	uint8_t vec;

	if (l->timer.deadline_ns == UINT64_MAX)
		return (0);
	if (l->timer.deadline_ns > l->timer.clock_ns)
		return (0);

	/*
	 * Defensive: an armed timer with initial=0 would re-arm to
	 * fire immediately, producing an infinite loop in
	 * lapic_tick().  The public API makes this combination
	 * unreachable (a TIMER_ICR write of 0 disarms) but we belt-
	 * and-brace it here against future refactors.  See
	 * SECURITY.md S2.5.
	 */
	if (l->timer.initial == 0) {
		timer_disarm(l);
		return (0);
	}

	lvt = l->regs[LAPIC_REG_INDEX(LAPIC_REG_LVT_TIMER)];

	/*
	 * Re-arm (periodic) or disarm (one-shot) the timer state BEFORE
	 * raising the vector, not after.  lapic_set_irr_locked() drops
	 * l->lock around ops->kick (to avoid a lock-order inversion with the
	 * vcpu-run mutexes), which opens a window in which the woken vcpu can
	 * run far enough to service the timer interrupt and reprogram the
	 * one-shot via a TIMER_ICR (initial-count) write -- i.e. call
	 * timer_arm() and set a fresh deadline -- all before this function
	 * regains the lock.  The OLD ordering then fell through to the
	 * trailing "else timer_disarm(l)" and clobbered that fresh deadline
	 * back to UINT64_MAX.  OpenBSD drives the LAPIC timer in ONE-SHOT
	 * mode and reprograms the initial-count on every tick from
	 * clockintr's lapic_timer_rearm(); a single clobbered re-arm leaves
	 * the timer disarmed forever (one-shot has no self-reload), so the
	 * 0xc0 hardclock vector never fires again and the guest's periodic
	 * clock stalls.  Linux is spared because it programs the timer
	 * PERIODIC, whose deadline auto-reloads here and in
	 * timer_remaining_count() with no per-tick guest re-arm to lose.
	 * Updating the arm state first makes the disarm/re-arm atomic with
	 * respect to the kick's lock drop: a racing guest re-arm now lands
	 * AFTER our state update and is preserved.
	 */
	if (lvt & LAPIC_LVT_TIMER_PERIODIC) {
		timer_arm(l, l->timer.initial);
		l->regs[LAPIC_REG_INDEX(LAPIC_REG_TIMER_CCR)] =
		    l->timer.initial;
	} else {
		timer_disarm(l);
	}

	if (lvt & LAPIC_LVT_MASKED)
		return (1);

#if 0
	if (lvt & LAPIC_LVT_TIMER_TSCDEADLINE) {
		/*
		 * TSC-deadline mode is signalled via the LVT timer entry's
		 * mode bits.  Implementing it requires advertising
		 * CPUID.1:ECX.TSC_DEADLINE[24] to the guest and handling
		 * MSR_IA32_TSC_DEADLINE writes -- neither of which vmd
		 * currently does.  Left for follow-up.
		 */
	}
#endif

	vec = (uint8_t)(lvt & 0xff);
	if (vec >= 16)
		lapic_set_irr_locked(l, vec);
	return (1);
}
