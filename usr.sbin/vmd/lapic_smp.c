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
 * Glue between vmd's per-VM device fabric and the standalone
 * lapic/ioapic emulation libraries.
 *
 * - One LAPIC per vcpu (per Intel SDM: each cpu has its own LAPIC at
 *   the same architectural MMIO base 0xfee00000).
 * - One IOAPIC per VM (at 0xfec00000).
 * - MMIO dispatch is selected by the *calling* vcpu's id, which we
 *   carry in a __thread variable set at the top of vcpu_run_loop.
 *
 * AP start-up via INIT/SIPI/SIPI lands in the lapic ops->startup callback,
 * which is implemented via deferred SIPI (vcpu_sipi_pending) -- for now we log
 * it so we can see the guest trying.
 */

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "vmd.h"
#include "mmio.h"
#include "lapic.h"
#include "ioapic.h"

/*
 * Per-IPI / per-MMIO trace logs.  Off by default; flip the #define
 * to debug SMP boot-up or cross-vcpu IPI delivery.
 */

/* Public entry points -- also declared in vmd.h once integration commits. */
int	 lapic_smp_init(uint32_t vmm_id, uint32_t ncpus);
void	 lapic_smp_free(void);
struct lapic	*lapic_smp_get(uint32_t vcpu_id);
uint32_t	 lapic_smp_ncpus(void);
struct ioapic	*lapic_smp_ioapic(void);
int	 lapic_smp_timer_start(void);
void	 lapic_smp_timer_stop(void);

/*
 * Set by vcpu_run_loop at the top of each iteration so device-emulation
 * code (called synchronously from VMM_IOC_RUN exits) can identify the
 * vcpu making the request without threading vrp through every call.
 */
__thread uint32_t current_vcpu_id;

/* Per-VM SMP fabric.  Allocated by lapic_smp_init, freed by lapic_smp_free. */
struct lapic_smp {
	struct lapic	**lapics;	/* [ncpus] */
	struct ioapic	 *ioapic;
	uint32_t	  ncpus;
	uint32_t	  vmm_id;
};

static struct lapic_smp	*g_smp;		/* one per vm process */

/*
 * Background LAPIC-timer driver.
 *
 * Each LAPIC computes its timer expiry lazily - see lapic.c.  That
 * works as long as somebody periodically advances the lapic's internal
 * "now" (via lapic_tick / lapic_pending).  When the guest HLTs every
 * vcpu, vmd parks the per-vcpu pthreads on vcpu_run_cond and nothing
 * else calls into the lapic, so the next timer interrupt is never
 * raised and the guest stays idle forever.
 *
 * The simplest fix is one pthread per VM that ticks every LAPIC on a
 * fixed wall-clock cadence (1 ms here, ~1000 Hz - finer than any
 * reasonable kernel tick rate but cheap on a modern CPU).  When a
 * timer is due, timer_fire_if_due (called via lapic_tick) sets IRR
 * and the existing ops->kick callback unhalts the target vcpu, which
 * picks up the interrupt on its next VMM_IOC_RUN.
 *
 * Race profile: the only contended field with the per-vcpu thread is
 * the LAPIC's IRR/timer state.  A prior audit accepted that IRR
 * writes are racy (atomic enough on word-sized stores under x86); the
 * timer thread is no worse than the cross-vcpu IPI path that already
 * writes the same bits.
 */
static pthread_t	 g_timer_tid;
static int		 g_timer_running;	/* 1 while thread alive */
static volatile sig_atomic_t g_timer_stop;	/* writer asks thread to exit */

static uint64_t
mono_ns_smp(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (0);
	return ((uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec);
}

static void *
lapic_timer_thread(void *arg)
{
	struct timespec ts;
	uint32_t i;
	uint64_t now;

	(void)arg;

	/*
	 * 1 ms wall-clock cadence (1000 Hz).  This bounds how often a
	 * halted vcpu can be woken for its LAPIC timer.  The AP has no
	 * i8259/PIT fallback (intr_pending gates that to vcpu 0), so its
	 * entire timekeeping heartbeat comes from this thread: too coarse
	 * a cadence starves the AP of ticks (RCU stalls, multi-minute
	 * boots) since a guest running at 250-1000 Hz loses most of its
	 * ticks.  1 ms keeps up with a 1000 Hz guest; the extra wakeups
	 * are negligible on a modern CPU.  (Was 10 ms == 100 Hz, which
	 * throttled every guest timer 10x.)
	 */
	ts.tv_sec = 0;
	ts.tv_nsec = 1000000L;	/* 1 ms */

	while (!g_timer_stop) {
		(void)nanosleep(&ts, NULL);
		if (g_smp == NULL)
			continue;
		now = mono_ns_smp();
		for (i = 0; i < g_smp->ncpus; i++) {
			struct lapic *l = g_smp->lapics[i];
			if (l == NULL)
				continue;
			/*
			 * lapic_tick advances the lapic's notion of now;
			 * timer_fire_if_due (called inside) sets IRR and
			 * invokes ops->kick to nudge the target vcpu out
			 * of its halt/sleep so it can take the interrupt.
			 */
			(void)lapic_tick(l, now);
		}
	}
	return (NULL);
}

int
lapic_smp_timer_start(void)
{
	int r;

	if (g_timer_running)
		return (0);
	g_timer_stop = 0;
	r = pthread_create(&g_timer_tid, NULL, lapic_timer_thread, NULL);
	if (r != 0)
		return (r);
	(void)pthread_set_name_np(g_timer_tid, "lapic-timer");
	g_timer_running = 1;
	return (0);
}

void
lapic_smp_timer_stop(void)
{
	if (!g_timer_running)
		return;
	g_timer_stop = 1;
	(void)pthread_join(g_timer_tid, NULL);
	g_timer_running = 0;
}

/* -------- MMIO dispatch thunks: pick the right LAPIC by current vcpu -- */

static int
lapic_mmio_read_cb(uint64_t off, uint8_t bytes, uint64_t *val, void *cookie)
{
	(void)bytes;
	(void)cookie;
	if (g_smp == NULL || current_vcpu_id >= g_smp->ncpus) {
		log_warnx("lapic_read: bad ctx (g_smp=%p vcpu_id=%u)",
		    g_smp, current_vcpu_id);
		return (-1);
	}
	*val = lapic_mmio_read(g_smp->lapics[current_vcpu_id], (uint16_t)off);
	return (0);
}

static int
lapic_mmio_write_cb(uint64_t off, uint8_t bytes, uint64_t val, void *cookie)
{
	(void)bytes;
	(void)cookie;
	if (g_smp == NULL || current_vcpu_id >= g_smp->ncpus) {
		log_warnx("lapic_write: bad ctx (g_smp=%p vcpu_id=%u)",
		    g_smp, current_vcpu_id);
		return (-1);
	}
	lapic_mmio_write(g_smp->lapics[current_vcpu_id], (uint16_t)off,
	    (uint32_t)val);
	return (0);
}

static int
ioapic_mmio_read_cb(uint64_t off, uint8_t bytes, uint64_t *val, void *cookie)
{
	(void)bytes;
	(void)cookie;
	if (g_smp == NULL || g_smp->ioapic == NULL)
		return (-1);
	*val = ioapic_mmio_read(g_smp->ioapic, (uint16_t)off);
	return (0);
}

static int
ioapic_mmio_write_cb(uint64_t off, uint8_t bytes, uint64_t val, void *cookie)
{
	(void)bytes;
	(void)cookie;
	if (g_smp == NULL || g_smp->ioapic == NULL)
		return (-1);
	ioapic_mmio_write(g_smp->ioapic, (uint16_t)off, (uint32_t)val);
	return (0);
}

/* -------- LAPIC -> vmd ops callbacks ----------------------------------- */

/*
 * Real-mode init state template from x86_vm.c.  vcpu_init_flat16 is the
 * BIOS-equivalent reset state with CS:IP = F000:FFF0.  Stage 7 derives
 * the AP's SIPI start state from this by overriding CS.sel/CS.base and
 * RIP per Intel SDM 10.4.4.
 */
extern const struct vcpu_reg_state vcpu_init_flat16;

/*
 * Per-vcpu "waiting for SIPI" flag.  Set by lapic_init_cb when the
 * guest BSP sends INIT to a target AP; consumed by lapic_startup on
 * the subsequent SIPI.  Indexed by target vcpu id.  The BSP (vcpu 0)
 * is never INIT'd in normal boot; the flag is just unused for it.
 *
 * No explicit lock: only ever read/written from BSP (vcpu 0) context
 * while the BSP processes its LAPIC ICR write, and from the
 * IOC_RESETCPU path which is serialised by the kernel's vc_lock.
 * Concurrent SIPI from multiple sources to the same target is not a
 * scenario the OpenBSD kernel produces, so we tolerate the very small
 * race window in exchange for keeping the AP-wakeup path lock-free.
 */
static uint8_t vcpu_waiting_for_sipi[VMM_MAX_VCPUS_PER_VM];

/*
 * Resolve a single APIC-space target to a vcpu index.
 *
 * Common case is a direct APIC-id match.  Callers pass a single APIC
 * id: LAPIC ICR physical-dest field, a PV-IPI bitmap entry (min+bit),
 * or a per-cpu index already expanded from a logical-flat bitmap by
 * ipi_send() or the IOAPIC try_deliver logical branch.
 *
 * STOPGAP (still required; re-added after empirical regression test):
 * A Linux SMP guest still emits IOAPIC RTE physical-mode dest values
 * that look like logical-flat bits (e.g. dest=2 for cpu1 in a 2-vcpu
 * VM, i.e. 1<<1).  We initially removed this fallback on the theory
 * that the upstream MADT length over-count (F02) was the sole root
 * cause; restarting dev-1 without the fallback hung the guest before
 * the first virtio-blk read because the bridging IRQ was correctly
 * dropped.  Until we identify and fix the *true* root cause of the
 * mis-encoded dest, single-bit values that miss the direct match are
 * decoded as logical-flat bit indices so device IRQs land somewhere.
 *
 * Both code paths log on use: lone-bit fallback (likely benign mis-
 * encoding by guest) and outright miss (would-be dropped IRQ).  Higher
 * caps than before so post-boot misses don't get hidden by Linux's
 * one-time APIC enumeration probe (which scans 2..21 sequentially).
 *
 * Returns UINT32_MAX if unresolved.
 */
static uint32_t
resolve_apic_to_vcpu(uint32_t target_apic)
{
	uint32_t vi;

	if (g_smp == NULL)
		return UINT32_MAX;
	for (vi = 0; vi < g_smp->ncpus; vi++) {
		if (g_smp->lapics[vi] != NULL &&
		    lapic_id(g_smp->lapics[vi]) == target_apic)
			return vi;
	}
	/* STOPGAP: lone-bit physical dest -> logical-flat bit. */
	if (target_apic != 0 && (target_apic & (target_apic - 1)) == 0) {
		uint32_t bp = 0, t = target_apic;
		while ((t & 1) == 0) { t >>= 1; bp++; }
		if (bp < g_smp->ncpus)
			/* Linux logical-dest bit mis-encoded as physical */
			return bp;
	}
	return UINT32_MAX;		/* no matching APIC; IRQ dropped */
}

static void
lapic_kick(void *cookie, uint32_t target_apic)
{
	uint32_t target_vcpu;
	(void)cookie;
	target_vcpu = resolve_apic_to_vcpu(target_apic);
	if (target_vcpu == UINT32_MAX)
		return;
	/* Unhalt + signal so the target leaves VMM_IOC_RUN to take the irq. */
	vcpu_unhalt(target_vcpu);
	vcpu_signal_run(target_vcpu);
	/* Tell the kernel a pending intr is queued for this vcpu. */
	if (g_smp->vmm_id != 0)
		(void)vcpu_intr(g_smp->vmm_id, target_vcpu, 1);
}

static void
lapic_broadcast(void *cookie, uint32_t source_vcpu, uint8_t vec,
    int include_self)
{
	uint32_t i;
	if (g_smp == NULL)
		return;
	for (i = 0; i < g_smp->ncpus; i++) {
		if (i == source_vcpu && !include_self)
			continue;
		lapic_set_irr(g_smp->lapics[i], vec);
		lapic_kick(cookie, i);
	}
}

/*
 * SIPI: actually wake the AP.  Per Intel SDM 10.4.4: if the target is
 * in wait-for-SIPI state, set CS:CSbase per the SIPI vector byte and
 * RIP = 0; if it's already running, the SIPI is dropped (most kernels
 * send two SIPIs by convention).
 *
 * Implementation: we drive the AP into real-mode at CS:IP =
 * sipi_vec<<8 : 0 by re-issuing VMM_IOC_RESETCPU with a derived
 * vcpu_reg_state.  The vcpu's kernel state is STOPPED here (the
 * thread is parked on vcpu_run_cond before ever calling VMM_IOC_RUN),
 * which is the precondition vm_resetcpu requires.
 */
/*
 * Per-vcpu pending SIPI vector.  Written by the BSP's LAPIC ICR handler,
 * consumed by the AP's own vcpu_run_loop thread via vcpu_sipi_pending().
 * Value 0 = no SIPI pending; non-zero = SIPI vector + 1 (so vector 0x00
 * can be distinguished from "no SIPI").
 *
 * The AP's thread calls vcpu_reset from its own context, which is required
 * by vmm(4)'s VMM_IOC_RESETCPU: the VMCS must be manipulated on the same
 * thread that will subsequently VMLAUNCH/VMRESUME it.  Calling vcpu_reset
 * from the BSP's thread causes the VMCS update to be lost or applied to
 * the wrong physical CPU's VMCS cache, resulting in the AP executing with
 * stale register state (rip=0xdfdfdfdf...) and immediately exiting as
 * VM_EXIT_TERMINATED.
 */
static volatile uint16_t vcpu_sipi_vec[VMM_MAX_VCPUS_PER_VM];

/*
 * Called from vcpu_run_loop (vm.c) on the AP's own thread after
 * waking from halt.  Returns 1 if a SIPI was pending and the vcpu
 * was successfully reset to the SIPI vector, 0 otherwise.
 */
int
vcpu_sipi_pending(uint32_t vmm_id, uint32_t vcpu_id)
{
	struct vcpu_reg_state vrs;
	uint16_t vec_plus_1;
	uint8_t sipi_vector;
	uint32_t cs_base, cs_sel;
	int r;

	vec_plus_1 = vcpu_sipi_vec[vcpu_id];
	if (vec_plus_1 == 0)
		return (0);

	sipi_vector = (uint8_t)(vec_plus_1 - 1);
	vcpu_sipi_vec[vcpu_id] = 0;

	cs_sel = (uint32_t)sipi_vector << 8;
	cs_base = (uint32_t)sipi_vector << 12;

	memcpy(&vrs, &vcpu_init_flat16, sizeof(vrs));
	vrs.vrs_sregs[VCPU_REGS_CS].vsi_sel = cs_sel;
	vrs.vrs_sregs[VCPU_REGS_CS].vsi_base = cs_base;
	vrs.vrs_gprs[VCPU_REGS_RIP] = 0x0;

	r = vcpu_reset(vmm_id, vcpu_id, &vrs);
	if (r != 0) {
		log_warnx("%s: vcpu_reset(vm=%u vcpu=%u) failed: %d",
		    __func__, vmm_id, vcpu_id, r);
		return (0);
	}
	return (1);
}

static void
lapic_startup(void *cookie, uint32_t target_apic, uint8_t sipi_vector)
{
	uint32_t target_vcpu;
	(void)cookie;

	target_vcpu = resolve_apic_to_vcpu(target_apic);
	if (target_vcpu == UINT32_MAX)
		return;
	if (!vcpu_waiting_for_sipi[target_vcpu]) {
		return;
	}

	/*
	 * Store the vector for the AP's thread to consume.  The +1
	 * encoding lets us distinguish "SIPI with vector 0x00" from
	 * "no SIPI pending".
	 */
	vcpu_sipi_vec[target_vcpu] = (uint16_t)sipi_vector + 1;
	vcpu_waiting_for_sipi[target_vcpu] = 0;

	/* Wake the AP thread so it can apply the reset itself. */
	vcpu_unhalt(target_vcpu);
	vcpu_signal_run(target_vcpu);
}

/*
 * INIT IPI: the target vcpu enters wait-for-SIPI state.  We don't
 * touch register state here -- the kernel will overwrite everything
 * on the subsequent SIPI via vcpu_reset.  Just ensure the AP stays
 * halted (it already is during boot) and arm the wait flag.
 *
 * On a real CPU INIT would also reset most architectural state, but
 * since the AP has never run yet its state is still the post-create
 * default; resetting it again would be redundant work.  If we ever
 * support runtime CPU hotplug or guest INIT-from-running this will
 * need to also call vcpu_reset.
 */
static void
lapic_init_cb(void *cookie, uint32_t target_apic)
{
	uint32_t target_vcpu;
	(void)cookie;

	target_vcpu = resolve_apic_to_vcpu(target_apic);
	if (target_vcpu == UINT32_MAX)
		return;

	vcpu_waiting_for_sipi[target_vcpu] = 1;
	vcpu_halt(target_vcpu);
}

/*
 * Atomic set-IRR + kick for cross-vcpu unicast FIXED/LOWPRI IPIs.
 * Called from lapic.c::ipi_send when the ICR destination is not the
 * sender.  Without this, the plain `kick` callback would wake the
 * target but its IRR would still be 0, so intr_pending() would
 * return -1 and it would immediately halt again -- losing scheduler
 * IPIs and stalling SMP boot at root mount.
 *
 * The ordering matters: set IRR FIRST so that the moment the target
 * vcpu thread wakes and looks at its LAPIC, the pending vector is
 * visible.
 */
static void
lapic_deliver_cb(void *cookie, uint32_t target_apic, uint8_t vec)
{
	uint32_t target_vcpu;
	(void)cookie;
	target_vcpu = resolve_apic_to_vcpu(target_apic);
	if (target_vcpu == UINT32_MAX || g_smp->lapics[target_vcpu] == NULL)
		return;
	/*
	 * Set IRR on the TARGET's LAPIC first so when it wakes,
	 * intr_pending() finds the vector ready to inject.
	 */
	lapic_set_irr(g_smp->lapics[target_vcpu], vec);
	/* Then kick it out of halt to take the interrupt. */
	vcpu_unhalt(target_vcpu);
	vcpu_signal_run(target_vcpu);
	if (g_smp->vmm_id != 0)
		(void)vcpu_intr(g_smp->vmm_id, target_vcpu, 1);
}

static void lapic_eoi_bcast_cb(void *, uint32_t, uint8_t);

/*
 * Public wrapper for PV-IPI: deliver vector to target vcpu.
 * Sets IRR on target's LAPIC and kicks it.
 */
void
lapic_smp_deliver_ipi(uint32_t target_vcpu, uint8_t vec)
{
	lapic_deliver_cb(NULL, target_vcpu, vec);
}

static const struct lapic_ops lapic_ops_vmd = {
	.kick      = lapic_kick,
	.broadcast = lapic_broadcast,
	.startup   = lapic_startup,
	.init      = lapic_init_cb,
	.deliver   = lapic_deliver_cb,
	.eoi_bcast = lapic_eoi_bcast_cb,
};

/* -------- IOAPIC -> LAPIC routing -------------------------------------- */

/*
 * IOAPIC redirects an interrupt pin to a specific destination vcpu's
 * LAPIC.  For now we route everything to vcpu 0 (legacy behaviour).
 * Stage 6 will honour the IOAPIC's redirection table per-pin.
 */
/* Forward decl: defined below alongside ioapic_assert_to_lapic. */
static void	 lapic_eoi_bcast_cb(void *, uint32_t, uint8_t);

static void
lapic_eoi_bcast_cb(void *cookie, uint32_t source_vcpu, uint8_t vec)
{
	(void)cookie;
	(void)source_vcpu;
	if (g_smp == NULL || g_smp->ioapic == NULL)
		return;
	ioapic_eoi(g_smp->ioapic, vec);
}

static void
ioapic_assert_to_lapic(void *cookie, uint32_t target_apic, uint8_t vec,
    int level_triggered, uint8_t pin)
{
	uint32_t target_vcpu;
	(void)cookie;
	(void)level_triggered;
	(void)pin;
	target_vcpu = resolve_apic_to_vcpu(target_apic);
	if (target_vcpu == UINT32_MAX)
		return;
	lapic_set_irr(g_smp->lapics[target_vcpu], vec);
	/* lapic_kick expects an APIC ID; we already have the vcpu, so
	 * inline what it does to avoid a redundant resolve. */
	vcpu_unhalt(target_vcpu);
	vcpu_signal_run(target_vcpu);
	if (g_smp->vmm_id != 0)
		(void)vcpu_intr(g_smp->vmm_id, target_vcpu, 1);
}

static const struct ioapic_ops ioapic_ops_vmd = {
	.deliver = ioapic_assert_to_lapic,
};

/* -------- Public API ---------------------------------------------------- */

int
lapic_smp_init(uint32_t vmm_id, uint32_t ncpus)
{
	uint32_t i;

	if (g_smp != NULL)		/* already initialised */
		return (0);

	g_smp = calloc(1, sizeof(*g_smp));
	if (g_smp == NULL)
		return (ENOMEM);
	g_smp->ncpus = ncpus;
	g_smp->vmm_id = vmm_id;

	g_smp->lapics = calloc(ncpus, sizeof(*g_smp->lapics));
	if (g_smp->lapics == NULL)
		goto fail;
	for (i = 0; i < ncpus; i++) {
		g_smp->lapics[i] = lapic_new(i);
		if (g_smp->lapics[i] == NULL)
			goto fail;
		lapic_set_ops(g_smp->lapics[i], &lapic_ops_vmd, NULL);
	}
	/*
	 * IOAPIC APIC id = ncpus, matching the MADT/MP-table entries
	 * (see acpi.c / mptable.c).  Creating it as 0 made the IOAPICID
	 * register read back 0 -- colliding with vcpu0's LAPIC id and
	 * defeating the collision-avoidance the tables rely on.
	 */
	g_smp->ioapic = ioapic_new((uint8_t)ncpus, 24); /* 24 redir entries */
	if (g_smp->ioapic == NULL)
		goto fail;
	ioapic_set_ops(g_smp->ioapic, &ioapic_ops_vmd, NULL);

	if (mmio_register(0xfee00000ULL, 0x1000ULL,
	    lapic_mmio_read_cb, lapic_mmio_write_cb, NULL) != 0)
		goto fail;
	if (mmio_register(0xfec00000ULL, 0x1000ULL,
	    ioapic_mmio_read_cb, ioapic_mmio_write_cb, NULL) != 0)
		goto fail;
	log_info("%s: registered LAPIC+IOAPIC for %u vcpus", __func__, ncpus);
	return (0);
fail:
	lapic_smp_free();
	return (ENOMEM);
}

/*
 * Public accessor used by the cross-arch intr_pending/intr_ack
 * implementation in x86_vm.c so it can consult the per-vcpu LAPIC IRR
 * before injecting an interrupt on VMM_IOC_RUN.  Returns NULL if the
 * SMP fabric hasn't been initialised (single-cpu legacy path) or if
 * the vcpu id is out of range.
 */
struct lapic *
lapic_smp_get(uint32_t vcpu_id)
{
	if (g_smp == NULL || vcpu_id >= g_smp->ncpus)
		return (NULL);
	return (g_smp->lapics[vcpu_id]);
}

uint32_t
lapic_smp_ncpus(void)
{
	if (g_smp == NULL)
		return (0);
	return (g_smp->ncpus);
}

/*
 * Accessor for the per-VM IOAPIC.  Returned NULL when the SMP fabric
 * hasn't been initialised; callers (vcpu_assert_irq / vcpu_deassert_irq
 * in x86_vm.c) use this to decide whether to pulse the IOAPIC pin
 * alongside the legacy i8259 line.
 */
struct ioapic *
lapic_smp_ioapic(void)
{
	return (g_smp != NULL ? g_smp->ioapic : NULL);
}

void
lapic_smp_free(void)
{
	uint32_t i;
	if (g_smp == NULL)
		return;
	if (g_smp->lapics != NULL) {
		for (i = 0; i < g_smp->ncpus; i++)
			if (g_smp->lapics[i] != NULL)
				lapic_free(g_smp->lapics[i]);
		free(g_smp->lapics);
	}
	if (g_smp->ioapic != NULL)
		ioapic_free(g_smp->ioapic);
	free(g_smp);
	g_smp = NULL;
}
