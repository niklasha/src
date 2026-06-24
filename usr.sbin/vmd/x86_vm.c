/*	$OpenBSD: x86_vm.c,v 1.15 2026/02/11 14:09:00 dv Exp $	*/
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

#include <sys/stat.h>
#include <sys/types.h>

#include <dev/ic/i8253reg.h>
#include <dev/isa/isareg.h>

#include <machine/pte.h>
#include <machine/specialreg.h>
#include <machine/vmmvar.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <zlib.h>

#include "atomicio.h"
#include "fw_cfg.h"
#include "mmio.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#define PAGE_MASK (PAGE_SIZE - 1)
#endif

#include "i8253.h"
#include "i8259.h"
#include "ioapic.h"
#include "lapic.h"
#include "loadfile.h"
#include "mptable.h"
#include "mc146818.h"
#include "ns8250.h"
#include "pci.h"
#include "virtio.h"

/*
 * Hooks from lapic_smp.c: lapic_smp_get returns the per-vcpu LAPIC
 * (NULL on legacy single-cpu path); lapic_smp_ncpus returns 0 when the
 * SMP fabric is uninitialised.  intr_pending/intr_ack use these to
 * consult IRR before falling back to the legacy 8259 PIC.
 * lapic_smp_ioapic returns the per-VM IOAPIC (NULL on legacy path);
 * vcpu_assert_irq / vcpu_deassert_irq use it to pulse IOAPIC pins so
 * APs receive ISA IRQs via mpbios's IOAPIC->LAPIC routing.
 */
extern struct lapic	*lapic_smp_get(uint32_t);
extern uint32_t		 lapic_smp_ncpus(void);
extern struct ioapic	*lapic_smp_ioapic(void);

/*
 * ACPI PM timer: 24-bit free-running counter at 3.579545 MHz.
 * Readable at port 0x608 (32 bits, high 8 bits read as zero).
 * Provides a stable reference clock for guest timekeeping;
 * Linux uses it to validate TSC and as a clocksource fallback.
 */
#define ACPI_PM_TIMER_PORT	0x608
#define ACPI_PM_TIMER_FREQ	3579545ULL

static struct timespec acpi_pmtimer_ts;

static void
acpi_pmtimer_init(void)
{
	clock_gettime(CLOCK_MONOTONIC, &acpi_pmtimer_ts);
}

static uint8_t
vcpu_exit_acpi_pmtimer(struct vm_run_params *vrp)
{
	struct vm_exit *vei = vrp->vrp_exit;
	struct timespec now, delta;
	uint64_t ns;
	uint32_t count;

	if (vei->vei.vei_dir == VEI_DIR_OUT)
		return 0xFF;	/* writes ignored */

	/* Only the PM timer port returns a meaningful value. */
	if (vei->vei.vei_port != ACPI_PM_TIMER_PORT) {
		set_return_data(vei, 0);
		return 0xFF;
	}

	clock_gettime(CLOCK_MONOTONIC, &now);
	timespecsub(&now, &acpi_pmtimer_ts, &delta);
	ns = delta.tv_sec * 1000000000ULL + delta.tv_nsec;
	count = (uint32_t)((ns * ACPI_PM_TIMER_FREQ) / 1000000000ULL);
	count &= 0x00FFFFFF;	/* 24-bit counter */

	set_return_data(vei, count);
	return 0xFF;
}

typedef uint8_t (*io_fn_t)(struct vm_run_params *);

#define LOWMEM_KB	576
#define MAX_PORTS	65536

io_fn_t	ioports_map[MAX_PORTS];

int	 translate_gva(struct vm_exit*, uint64_t, uint64_t *, int);

static int	loadfile_bios(gzFile, off_t, struct vcpu_reg_state *);
static int	vcpu_exit_eptviolation(struct vm_run_params *);
static void	vcpu_exit_inout(struct vm_run_params *);

extern struct vmd_vm	*current_vm;
extern int		 con_fd;

/*
 * Represents a standard register set for an OS to be booted
 * as a flat 64 bit address space.
 *
 * NOT set here are:
 *  RIP
 *  RSP
 *  GDTR BASE
 *
 * Specific bootloaders should clone this structure and override
 * those fields as needed.
 *
 * Note - CR3 and various bits in CR0 may be overridden by vmm(4) based on
 *        features of the CPU in use.
 */
static const struct vcpu_reg_state vcpu_init_flat64 = {
	.vrs_gprs[VCPU_REGS_RFLAGS] = 0x2,
	.vrs_gprs[VCPU_REGS_RIP] = 0x0,
	.vrs_gprs[VCPU_REGS_RSP] = 0x0,
	.vrs_crs[VCPU_REGS_CR0] = CR0_ET | CR0_PE | CR0_PG,
	.vrs_crs[VCPU_REGS_CR3] = PML4_PAGE,
	.vrs_crs[VCPU_REGS_CR4] = CR4_PAE | CR4_PSE,
	.vrs_crs[VCPU_REGS_PDPTE0] = 0ULL,
	.vrs_crs[VCPU_REGS_PDPTE1] = 0ULL,
	.vrs_crs[VCPU_REGS_PDPTE2] = 0ULL,
	.vrs_crs[VCPU_REGS_PDPTE3] = 0ULL,
	.vrs_sregs[VCPU_REGS_CS] = { 0x8, 0xFFFFFFFF, 0xC09F, 0x0},
	.vrs_sregs[VCPU_REGS_DS] = { 0x10, 0xFFFFFFFF, 0xC093, 0x0},
	.vrs_sregs[VCPU_REGS_ES] = { 0x10, 0xFFFFFFFF, 0xC093, 0x0},
	.vrs_sregs[VCPU_REGS_FS] = { 0x10, 0xFFFFFFFF, 0xC093, 0x0},
	.vrs_sregs[VCPU_REGS_GS] = { 0x10, 0xFFFFFFFF, 0xC093, 0x0},
	.vrs_sregs[VCPU_REGS_SS] = { 0x10, 0xFFFFFFFF, 0xC093, 0x0},
	.vrs_gdtr = { 0x0, 0xFFFF, 0x0, 0x0},
	.vrs_idtr = { 0x0, 0xFFFF, 0x0, 0x0},
	.vrs_sregs[VCPU_REGS_LDTR] = { 0x0, 0xFFFF, 0x0082, 0x0},
	.vrs_sregs[VCPU_REGS_TR] = { 0x0, 0xFFFF, 0x008B, 0x0},
	.vrs_msrs[VCPU_REGS_EFER] = EFER_LME | EFER_LMA,
	.vrs_drs[VCPU_REGS_DR0] = 0x0,
	.vrs_drs[VCPU_REGS_DR1] = 0x0,
	.vrs_drs[VCPU_REGS_DR2] = 0x0,
	.vrs_drs[VCPU_REGS_DR3] = 0x0,
	.vrs_drs[VCPU_REGS_DR6] = 0xFFFF0FF0,
	.vrs_drs[VCPU_REGS_DR7] = 0x400,
	.vrs_msrs[VCPU_REGS_STAR] = 0ULL,
	.vrs_msrs[VCPU_REGS_LSTAR] = 0ULL,
	.vrs_msrs[VCPU_REGS_CSTAR] = 0ULL,
	.vrs_msrs[VCPU_REGS_SFMASK] = 0ULL,
	.vrs_msrs[VCPU_REGS_KGSBASE] = 0ULL,
	.vrs_msrs[VCPU_REGS_MISC_ENABLE] = 0ULL,
	.vrs_crs[VCPU_REGS_XCR0] = XFEATURE_X87
};

/*
 * Represents a standard register set for an BIOS to be booted
 * as a flat 16 bit address space.
 */
const struct vcpu_reg_state vcpu_init_flat16 = {
	.vrs_gprs[VCPU_REGS_RFLAGS] = 0x2,
	.vrs_gprs[VCPU_REGS_RIP] = 0xFFF0,
	.vrs_gprs[VCPU_REGS_RSP] = 0x0,
	.vrs_crs[VCPU_REGS_CR0] = 0x60000010,
	.vrs_crs[VCPU_REGS_CR3] = 0,
	.vrs_sregs[VCPU_REGS_CS] = { 0xF000, 0xFFFF, 0x809F, 0xF0000},
	.vrs_sregs[VCPU_REGS_DS] = { 0x0, 0xFFFF, 0x8093, 0x0},
	.vrs_sregs[VCPU_REGS_ES] = { 0x0, 0xFFFF, 0x8093, 0x0},
	.vrs_sregs[VCPU_REGS_FS] = { 0x0, 0xFFFF, 0x8093, 0x0},
	.vrs_sregs[VCPU_REGS_GS] = { 0x0, 0xFFFF, 0x8093, 0x0},
	.vrs_sregs[VCPU_REGS_SS] = { 0x0, 0xFFFF, 0x8093, 0x0},
	.vrs_gdtr = { 0x0, 0xFFFF, 0x0, 0x0},
	.vrs_idtr = { 0x0, 0xFFFF, 0x0, 0x0},
	.vrs_sregs[VCPU_REGS_LDTR] = { 0x0, 0xFFFF, 0x0082, 0x0},
	.vrs_sregs[VCPU_REGS_TR] = { 0x0, 0xFFFF, 0x008B, 0x0},
	.vrs_msrs[VCPU_REGS_EFER] = 0ULL,
	.vrs_drs[VCPU_REGS_DR0] = 0x0,
	.vrs_drs[VCPU_REGS_DR1] = 0x0,
	.vrs_drs[VCPU_REGS_DR2] = 0x0,
	.vrs_drs[VCPU_REGS_DR3] = 0x0,
	.vrs_drs[VCPU_REGS_DR6] = 0xFFFF0FF0,
	.vrs_drs[VCPU_REGS_DR7] = 0x400,
	.vrs_msrs[VCPU_REGS_STAR] = 0ULL,
	.vrs_msrs[VCPU_REGS_LSTAR] = 0ULL,
	.vrs_msrs[VCPU_REGS_CSTAR] = 0ULL,
	.vrs_msrs[VCPU_REGS_SFMASK] = 0ULL,
	.vrs_msrs[VCPU_REGS_KGSBASE] = 0ULL,
	.vrs_crs[VCPU_REGS_XCR0] = XFEATURE_X87
};

/*
 * create_memory_map
 *
 * Sets up the guest physical memory ranges that the VM can access.
 */
void
create_memory_map(struct vmd_vm *vm)
{
	struct vmop_create_params *vmc = &vm->vm_params;
	size_t len, mem_bytes;
	size_t above_1m = 0, above_4g = 0;

	mem_bytes = vmc->vmc_memranges[0].vmr_size;
	vmc->vmc_nmemranges = 0;
	if (mem_bytes == 0 || mem_bytes > VMM_MAX_VM_MEM_SIZE)
		return;

	/* First memory region: 0 - LOWMEM_KB (DOS low mem) */
	len = LOWMEM_KB * 1024;
	vmc->vmc_memranges[0].vmr_gpa = 0x0;
	vmc->vmc_memranges[0].vmr_size = len;
	vmc->vmc_memranges[0].vmr_type = VM_MEM_RAM;
	mem_bytes -= len;

	/*
	 * Second memory region: LOWMEM_KB - 1MB.
	 *
	 * N.B. - Normally ROMs or parts of video RAM are mapped here.
	 * We have to add this region, because some systems
	 * unconditionally write to 0xb8000 (VGA RAM), and
	 * we need to make sure that vmm(4) permits accesses
	 * to it. So allocate guest memory for it.
	 */
	len = MB(1) - (LOWMEM_KB * 1024);
	vmc->vmc_memranges[1].vmr_gpa = LOWMEM_KB * 1024;
	vmc->vmc_memranges[1].vmr_size = len;
	vmc->vmc_memranges[1].vmr_type = VM_MEM_RESERVED;
	mem_bytes -= len;

	/*
	 * If we have less than 4MB remaining to assign, still create a 2nd
	 * BIOS area.
	 */
	if (mem_bytes <= MB(4)) {
		vmc->vmc_memranges[2].vmr_gpa = PCI_MMIO_BAR_END;
		vmc->vmc_memranges[2].vmr_size = MB(4);
		vmc->vmc_memranges[2].vmr_type = VM_MEM_RESERVED;
		vmc->vmc_nmemranges = 3;
		return;
	}

	/*
	 * Calculate the how to split any remaining memory across the 4GB
	 * boundary while making sure we do not place physical memory into
	 * MMIO ranges.
	 */
	if (mem_bytes > PCI_MMIO_BAR_BASE - MB(1)) {
		above_1m = PCI_MMIO_BAR_BASE - MB(1);
		above_4g = mem_bytes - above_1m;
	} else {
		above_1m = mem_bytes;
		above_4g = 0;
	}

	/* Third memory region: area above 1MB to MMIO region */
	vmc->vmc_memranges[2].vmr_gpa = MB(1);
	vmc->vmc_memranges[2].vmr_size = above_1m;
	vmc->vmc_memranges[2].vmr_type = VM_MEM_RAM;

	/* Fourth region: PCI MMIO range */
	vmc->vmc_memranges[3].vmr_gpa = PCI_MMIO_BAR_BASE;
	vmc->vmc_memranges[3].vmr_size = PCI_MMIO_BAR_END -
	    PCI_MMIO_BAR_BASE + 1;
	vmc->vmc_memranges[3].vmr_type = VM_MEM_MMIO;

	/* Fifth region: 2nd copy of BIOS above MMIO ending at 4GB */
	vmc->vmc_memranges[4].vmr_gpa = PCI_MMIO_BAR_END + 1;
	vmc->vmc_memranges[4].vmr_size = MB(4);
	vmc->vmc_memranges[4].vmr_type = VM_MEM_RESERVED;

	/* Sixth region: any remainder above 4GB */
	if (above_4g > 0) {
		vmc->vmc_memranges[5].vmr_gpa = GB(4);
		vmc->vmc_memranges[5].vmr_size = above_4g;
		vmc->vmc_memranges[5].vmr_type = VM_MEM_RAM;
		vmc->vmc_nmemranges = 6;
	} else
		vmc->vmc_nmemranges = 5;
}

static int vm_boot_is_bios;

int
load_firmware(struct vmd_vm *vm, struct vcpu_reg_state *vrs)
{
	int		ret;
	gzFile		fp;
	struct stat	sb;

	/*
	 * Set up default "flat 64 bit" register state - RIP, RSP, and
	 * GDT info will be set in bootloader
	 */
	memcpy(vrs, &vcpu_init_flat64, sizeof(*vrs));

	/*
	 * Set when the firmware is a (SeaBIOS) BIOS image rather than an
	 * ELF kernel; gates how the MP table is published below.
	 */
	vm_boot_is_bios = 0;

	/* Find and open kernel image */
	if ((fp = gzdopen(vm->vm_kernel, "r")) == NULL)
		fatalx("failed to open kernel - exiting");

	/* Load kernel image */
	ret = loadfile_elf(fp, vm, vrs, vm->vm_params.vmc_bootdevice);

	/*
	 * Try BIOS as a fallback (only if it was provided as an image
	 * with vm->vm_kernel and the file is not compressed)
	 */
	if (ret && errno == ENOEXEC && vm->vm_kernel != -1 &&
	    gzdirect(fp) && (ret = fstat(vm->vm_kernel, &sb)) == 0) {
		ret = loadfile_bios(fp, sb.st_size, vrs);
		vm_boot_is_bios = 1;
	}

	gzclose(fp);

	return (ret);
}


/*
 * loadfile_bios
 *
 * Alternatively to loadfile_elf, this function loads a non-ELF BIOS image
 * directly into memory.
 *
 * Parameters:
 *  fp: file of a kernel file to load
 *  size: uncompressed size of the image
 *  (out) vrs: register state to set on init for this kernel
 *
 * Return values:
 *  0 if successful
 *  various error codes returned from read(2) or loadelf functions
 */
int
loadfile_bios(gzFile fp, off_t size, struct vcpu_reg_state *vrs)
{
	off_t	 off = 0;
	size_t	 lower_sz = size;

	/*
	 * While a 15 byte firmware is most likely useless, given the
	 * reset vector on a PC is 15 bytes below 0xFFFFF, make sure
	 * we will at least align to that boundary.
	 */
	if (size < 15) {
		log_warnx("bios image too small");
		return (-1);
	}

	/* Assumptions elsewhere in memory layout limit to 4 MiB. */
	if (size > (off_t)MB(4)) {
		log_warnx("bios image too large (> 4 MiB)");
		return (-1);
	}

	/* Set up a "flat 16 bit" register state for BIOS. */
	memcpy(vrs, &vcpu_init_flat16, sizeof(*vrs));

	/* Read a full copy into BIOS area ending at 4 GiB. */
	if (gzrewind(fp) == -1)
		return (-1);

	off = GB(4) - size;
	if (mread(fp, off, size) != (size_t)size) {
		errno = EIO;
		return (-1);
	}

	/*
	 * Copy whatever fits of the upper part of the image
	 * into the lower BIOS area ending at 1 MiB.
	 */
	if (gzrewind(fp) == -1)
		return (-1);

	lower_sz = MB(1) - (LOWMEM_KB * 1024);
	lower_sz = MIN((off_t)lower_sz, size);
	if (gzseek(fp, size - lower_sz, SEEK_SET) == -1)
		return (-1);

	off = MB(1) - lower_sz;
	if (mread(fp, off, lower_sz) != lower_sz)
		return (-1);

	log_debug("%s: loaded BIOS image", __func__);

	return (0);
}

/*
 * init_emulated_hw
 *
 * Initializes the userspace hardware emulation.
 *
 * Returns 0 on success, 1 on failure.
 */
int
init_emulated_hw(struct vmd_vm *vm, int child_cdrom,
    int child_disks[][VM_MAX_BASE_PER_DISK], int *child_taps)
{
	struct vmop_create_params *vmc = &vm->vm_params;
	size_t i;
	uint64_t memlo, memhi;

	/* Calculate memory size for NVRAM registers */
	memlo = memhi = 0;
	for (i = 0; i < vmc->vmc_nmemranges; i++) {
		if (vmc->vmc_memranges[i].vmr_gpa == MB(1) &&
		    vmc->vmc_memranges[i].vmr_size > (15 * MB(1)))
			memlo = vmc->vmc_memranges[i].vmr_size - (15 * MB(1));
		else if (vmc->vmc_memranges[i].vmr_gpa == GB(4))
			memhi = vmc->vmc_memranges[i].vmr_size;
	}

	/* Reset the IO port map */
	memset(&ioports_map, 0, sizeof(io_fn_t) * MAX_PORTS);

	/* Init i8253 PIT */
	i8253_init(vm->vm_vmmid);
	ioports_map[TIMER_CTRL] = vcpu_exit_i8253;
	ioports_map[TIMER_BASE + TIMER_CNTR0] = vcpu_exit_i8253;
	ioports_map[TIMER_BASE + TIMER_CNTR1] = vcpu_exit_i8253;
	ioports_map[TIMER_BASE + TIMER_CNTR2] = vcpu_exit_i8253;
	ioports_map[PCKBC_AUX] = vcpu_exit_i8253_misc;
	ioports_map[0x64] = vcpu_exit_i8253_misc;	/* KBC status: ready */
	ioports_map[0x60] = vcpu_exit_i8253_misc;	/* KBC data */

	/* Init ACPI PM timer */
	acpi_pmtimer_init();
	/* ACPI PM I/O block: 0x600-0x60B (PM base).
	 * Only the PM timer at +8 returns meaningful data; other offsets return
	 * 0 on read and ignore writes.  NOTE: MUST stay below
	 * VM_PCI_IO_BAR_BASE (0x1000): the PCI I/O BAR window (0x1000-0xFFFF)
	 * is mapped to vcpu_exit_pci just below and would otherwise overwrite
	 * these entries, misrouting PM1/PM-timer accesses to the PCI dispatcher
	 * (guest ACPI reads garbage -> the "PM1 stuck" SCI spin).  The matching
	 * FADT base is acpi.c ACPI_PM_BASE.
	 */
	{
		int p;
		for (p = 0x600; p <= 0x60B; p++)
			ioports_map[p] = vcpu_exit_acpi_pmtimer;
	}


	/* Init mc146818 RTC */
	mc146818_init(vm->vm_vmmid, memlo, memhi);
	ioports_map[IO_RTC] = vcpu_exit_mc146818;
	ioports_map[IO_RTC + 1] = vcpu_exit_mc146818;

	/* Init master and slave PICs */
	i8259_init();
	ioports_map[IO_ICU1] = vcpu_exit_i8259;
	ioports_map[IO_ICU1 + 1] = vcpu_exit_i8259;
	ioports_map[IO_ICU2] = vcpu_exit_i8259;
	ioports_map[IO_ICU2 + 1] = vcpu_exit_i8259;
	ioports_map[ELCR0] = vcpu_exit_elcr;
	ioports_map[ELCR1] = vcpu_exit_elcr;

	/* Init ns8250 UART */
	ns8250_init(con_fd, vm->vm_vmmid);
	for (i = COM1_DATA; i <= COM1_SCR; i++)
		ioports_map[i] = vcpu_exit_com;

	/* Initialize PCI */
	for (i = VM_PCI_IO_BAR_BASE; i <= VM_PCI_IO_BAR_END; i++)
		ioports_map[i] = vcpu_exit_pci;

	ioports_map[PCI_MODE1_ADDRESS_REG] = vcpu_exit_pci;
	ioports_map[PCI_MODE1_DATA_REG] = vcpu_exit_pci;
	ioports_map[PCI_MODE1_DATA_REG + 1] = vcpu_exit_pci;
	ioports_map[PCI_MODE1_DATA_REG + 2] = vcpu_exit_pci;
	ioports_map[PCI_MODE1_DATA_REG + 3] = vcpu_exit_pci;
	pci_init();

	/* Initialize virtio devices */
	if (virtio_init(current_vm, child_cdrom, child_disks, child_taps))
		return (1);

	/*
	 * Init QEMU fw_cfg interface. Must be done last for pci hardware
	 * detection.
	 */
	fw_cfg_init(vmc);

	/* ELF boot: write MP table for guest SMP discovery.
	 * IOAPIC's APIC ID must not collide with any LAPIC's APIC ID
	 * (LAPIC IDs are 0..ncpus-1).  If it does, Linux renumbers
	 * the colliding LAPIC, and subsequent IOAPIC RTE writes carry
	 * the renumbered (out-of-range) APIC ID, causing silent IRQ
	 * drops in ioapic_assert_to_lapic.  ncpus is safely above the
	 * LAPIC range.
	 */
	if (vmc->vmc_ncpus > 1) {
		/*
		 * SeaBIOS owns the low-memory MP scan regions and its own
		 * MP table mis-resolves at high vcpu counts, so hand it the
		 * table via fw_cfg.  Direct ELF boot has no firmware loader,
		 * so write it to guest RAM directly.
		 */
		if (vm_boot_is_bios) {
			if (mptable_fwcfg(vmc->vmc_ncpus, 0,
			    vmc->vmc_ncpus) != 0)
				log_warnx("mptable_fwcfg failed");
		} else if (mptable_init(vmc->vmc_ncpus, 0,
		    vmc->vmc_ncpus) != 0)
			log_warnx("mptable_init failed");
	}

	ioports_map[FW_CFG_IO_SELECT] = vcpu_exit_fw_cfg;
	ioports_map[FW_CFG_IO_DATA] = vcpu_exit_fw_cfg;
	ioports_map[FW_CFG_IO_DMA_ADDR_HIGH] = vcpu_exit_fw_cfg_dma;
	ioports_map[FW_CFG_IO_DMA_ADDR_LOW] = vcpu_exit_fw_cfg_dma;

	return (0);
}

void
pause_vm_md(struct vmd_vm *vm)
{
	i8253_stop();
	mc146818_stop();
	ns8250_stop();
	virtio_stop(vm);
}

void
unpause_vm_md(struct vmd_vm *vm)
{
	i8253_start();
	mc146818_start();
	ns8250_start();
	virtio_start(vm);
}

/*
 * vcpu_exit_inout
 *
 * Handle all I/O exits that need to be emulated in vmd. This includes the
 * i8253 PIT, the com1 ns8250 UART, and the MC146818 RTC/NVRAM device.
 *
 * Parameters:
 *  vrp: vcpu run parameters containing guest state for this exit
 */
void
vcpu_exit_inout(struct vm_run_params *vrp)
{
	struct vm_exit *vei = vrp->vrp_exit;
	uint8_t intr = 0xFF;

	if (vei->vei.vei_rep || vei->vei.vei_string) {
#ifdef MMIO_DEBUG
		log_info("%s: %s%s%s %d-byte, enc=%d, data=0x%08x, port=0x%04x",
		    __func__,
		    vei->vei.vei_rep == 0 ? "" : "REP ",
		    vei->vei.vei_dir == VEI_DIR_IN ? "IN" : "OUT",
		    vei->vei.vei_string == 0 ? "" : "S",
		    vei->vei.vei_size, vei->vei.vei_encoding,
		    vei->vei.vei_data, vei->vei.vei_port);
		log_info("%s: ECX = 0x%llx, RDX = 0x%llx, RSI = 0x%llx",
		    __func__,
		    vei->vrs.vrs_gprs[VCPU_REGS_RCX],
		    vei->vrs.vrs_gprs[VCPU_REGS_RDX],
		    vei->vrs.vrs_gprs[VCPU_REGS_RSI]);
#endif /* MMIO_DEBUG */
		fatalx("%s: can't emulate REP prefixed IN(S)/OUT(S)",
		    __func__);
	}

	if (ioports_map[vei->vei.vei_port] != NULL)
		intr = ioports_map[vei->vei.vei_port](vrp);
	else if (vei->vei.vei_dir == VEI_DIR_IN)
		set_return_data(vei, 0xFFFFFFFF);

	vei->vrs.vrs_gprs[VCPU_REGS_RIP] += vei->vei.vei_insn_len;

	if (intr != 0xFF)
		vcpu_assert_irq(vrp->vrp_vm_id, vrp->vrp_vcpu_id, intr);
}

/*
 * vcpu_exit
 *
 * Handle a vcpu exit. This function is called when it is determined that
 * vmm(4) requires the assistance of vmd to support a particular guest
 * exit type (eg, accessing an I/O port or device). Guest state is contained
 * in 'vrp', and will be resent to vmm(4) on exit completion.
 *
 * Upon conclusion of handling the exit, the function determines if any
 * interrupts should be injected into the guest, and asserts the proper
 * IRQ line whose interrupt should be vectored.
 *
 * Parameters:
 *  vrp: vcpu run parameters containing guest state for this exit
 *
 * Return values:
 *  0: the exit was handled successfully
 *  1: an error occurred (eg, unknown exit reason passed in 'vrp')
 */
/* KVM hypercall number for SEND_IPI (from dev/pv/pvreg.h). */
#define KVM_HC_SEND_IPI		10

/*
 * vcpu_exit_vmcall
 *
 * Handle KVM paravirtual hypercalls.  Currently supports:
 *  - KVM_HC_SEND_IPI: deliver an IPI to a bitmap of target vcpus.
 *    rax = KVM_HC_SEND_IPI
 *    rbx = bitmap_lo (bits 0-63)
 *    rcx = bitmap_hi (bits 64-127)
 *    rdx = min_apic_id (bitmap is relative to this base)
 *    rsi = icr (vector in low 8 bits)
 *
 * Sets rax to number of IPIs delivered.
 */
static void
vcpu_exit_vmcall(struct vm_run_params *vrp)
{
	struct vcpu_reg_state *vrs = &vrp->vrp_exit->vrs;
	uint64_t hcall = vrs->vrs_gprs[VCPU_REGS_RAX];
	uint64_t bitmap_lo, bitmap_hi, min, icr;
	uint8_t vec;
	uint32_t target;
	int i, delivered = 0;

	if (hcall != KVM_HC_SEND_IPI) {
		/* Unknown hypercall - return -1000 (KVM_EPERM). */
		vrs->vrs_gprs[VCPU_REGS_RAX] = (uint64_t)-1000;
		return;
	}

	bitmap_lo = vrs->vrs_gprs[VCPU_REGS_RBX];
	bitmap_hi = vrs->vrs_gprs[VCPU_REGS_RCX];
	min = vrs->vrs_gprs[VCPU_REGS_RDX];	/* APIC id offset for bitmap */
	icr = vrs->vrs_gprs[VCPU_REGS_RSI];	/* ICR value */
	vec = (uint8_t)(icr & 0xff);

	for (i = 0; i < 64; i++) {
		if (bitmap_lo & (1ULL << i)) {
			target = (uint32_t)(min + i);
			/* lapic_smp_deliver_ipi resolves APIC ID -> vcpu
			 * and silently ignores invalid targets, so no
			 * bounds check needed here. */
			lapic_smp_deliver_ipi(target, vec);
			delivered++;
		}
	}
	for (i = 0; i < 64; i++) {
		if (bitmap_hi & (1ULL << i)) {
			target = (uint32_t)(min + 64 + i);
			lapic_smp_deliver_ipi(target, vec);
			delivered++;
		}
	}

	vrs->vrs_gprs[VCPU_REGS_RAX] = delivered;
}

int
vcpu_exit(struct vm_run_params *vrp)
{
	int ret;

	switch (vrp->vrp_exit_reason) {
	case VMX_EXIT_INT_WINDOW:
	case SVM_VMEXIT_VINTR:
	case VMX_EXIT_CPUID:
	case VMX_EXIT_EXTINT:
	case SVM_VMEXIT_INTR:
	case SVM_VMEXIT_MSR:
	case SVM_VMEXIT_CPUID:
		/*
		 * We may be exiting to vmd to handle a pending interrupt but
		 * at the same time the last exit type may have been one of
		 * these. In this case, there's nothing extra to be done
		 * here (and falling through to the default case below results
		 * in more vmd log spam).
		 */
		break;
	case SVM_VMEXIT_NPF:
	case VMX_EXIT_EPT_VIOLATION:
	case VMX_EXIT_APIC_ACCESS:
		ret = vcpu_exit_eptviolation(vrp);
		/*
		 * Propagate failure (EAGAIN on a decode/emulate miss,
		 * EFAULT on a protection fault) to vcpu_run_loop so it
		 * tears the VM down instead of re-running the same RIP
		 * forever (a guest-triggerable host-core livelock).
		 */
		if (ret)
			return (ret);
		break;
	case VMX_EXIT_IO:
	case SVM_VMEXIT_IOIO:
		vcpu_exit_inout(vrp);
		break;
	case VMX_EXIT_HLT:
	case SVM_VMEXIT_HLT:
		vcpu_halt(vrp->vrp_vcpu_id);
		break;
	case VMX_EXIT_VMCALL:
		vcpu_exit_vmcall(vrp);
		break;
	case VMX_EXIT_TRIPLE_FAULT:
	case SVM_VMEXIT_SHUTDOWN:
		/* reset VM */
		return (EAGAIN);
	default:
		log_debug("unknown exit reason 0x%x", vrp->vrp_exit_reason);
	}

	return (0);
}

/*
 * vcpu_exit_eptviolation
 *
 * handle an EPT Violation
 *
 * Parameters:
 *  vrp: vcpu run parameters containing guest state for this exit
 *
 * Return values:
 *  0: no action required
 *  EFAULT: a protection fault occured, kill the vm.
 */
static int
vcpu_exit_eptviolation(struct vm_run_params *vrp)
{
	struct vm_exit *ve = vrp->vrp_exit;
	int ret = 0;
	struct x86_insn insn;
	uint64_t va, pa;
	size_t len = 15;		/* Max instruction length in x86. */
	switch (ve->vee.vee_fault_type) {
	case VEE_FAULT_HANDLED:
		break;

	case VEE_FAULT_MMIO_ASSIST:
		/* Intel VMX might give us the length of the instruction. */
		if (ve->vee.vee_insn_info & VEE_LEN_VALID)
			len = ve->vee.vee_insn_len;

		if (len > 15)
			fatalx("%s: invalid instruction length %lu", __func__,
			    len);

		/* If we weren't given instruction bytes, we need to fetch. */
		if (!(ve->vee.vee_insn_info & VEE_BYTES_VALID)) {
			memset(ve->vee.vee_insn_bytes, 0,
			    sizeof(ve->vee.vee_insn_bytes));
			va = ve->vrs.vrs_gprs[VCPU_REGS_RIP];

			/*
			 * In real/unpaged mode, RIP is an offset from
			 * CS.base.  Form the linear address so
			 * translate_gva (which returns pa=va when
			 * CR0.PG is clear) produces the correct GPA.
			 */
			if (!(ve->vrs.vrs_crs[VCPU_REGS_CR0] & CR0_PG))
				va += ve->vrs.vrs_sregs[VCPU_REGS_CS].vsi_base;

			/* Clamp fetch length to current page. */
			if ((va & PAGE_MASK) + len > PAGE_SIZE)
				len = PAGE_SIZE - (va & PAGE_MASK);

			ret = translate_gva(ve, va, &pa, PROT_EXEC);
			if (ret != 0) {
				log_warnx("%s: failed gva translation",
				    __func__);
				goto mmio_done;
			}

			ret = read_mem(pa, ve->vee.vee_insn_bytes, len);
			if (ret != 0) {
				log_warnx("%s: failed to fetch instruction "
				    "bytes from 0x%llx", __func__, pa);
				goto mmio_done;
			}
		}

		ret = insn_decode(ve, &insn);
		if (ret == 0)
			ret = insn_emulate(ve, &insn);
	mmio_done:
		if (ret != 0) {
			char hb[64];
			int hi, hl = 0;
			for (hi = 0; hi < 15 && hl < 60; hi++)
				hl += snprintf(hb + hl, sizeof(hb) - hl,
				    "%02x ", ve->vee.vee_insn_bytes[hi]);
			log_warnx("%s: MMIO decode/emulate failed at "
			    "rip=0x%llx bytes=[%s] -- triple fault",
			    __func__,
			    (unsigned long long)ve->vrs.vrs_gprs[VCPU_REGS_RIP],
			    hb);
			return (EAGAIN);
		}
		break;

	case VEE_FAULT_PROTECT:
		log_debug("EPT Violation: rip=0x%llx",
		    ve->vrs.vrs_gprs[VCPU_REGS_RIP]);
		ret = EFAULT;
		break;

	default:
		fatalx("invalid fault_type %d", ve->vee.vee_fault_type);
		/* UNREACHED */
	}

	return (ret);
}

/*
 * vcpu_exit_pci
 *
 * Handle all I/O to the emulated PCI subsystem.
 *
 * Parameters:
 *  vrp: vcpu run parameters containing guest state for this exit
 *
 * Return value:
 *  Interrupt to inject to the guest VM, or 0xFF if no interrupt should
 *      be injected.
 */
uint8_t
vcpu_exit_pci(struct vm_run_params *vrp)
{
	struct vm_exit *vei = vrp->vrp_exit;
	uint8_t intr;

	intr = 0xFF;

	switch (vei->vei.vei_port) {
	case PCI_MODE1_ADDRESS_REG:
		pci_handle_address_reg(vrp);
		break;
	case PCI_MODE1_DATA_REG:
	case PCI_MODE1_DATA_REG + 1:
	case PCI_MODE1_DATA_REG + 2:
	case PCI_MODE1_DATA_REG + 3:
		pci_handle_data_reg(vrp);
		break;
	case VM_PCI_IO_BAR_BASE ... VM_PCI_IO_BAR_END:
		intr = pci_handle_io(vrp);
		break;
	default:
		log_warnx("unknown PCI register 0x%04x", vei->vei.vei_port);
		break;
	}

	return (intr);
}

/*
 * find_gpa_range
 *
 * Search for a contiguous guest physical mem range.
 *
 * Parameters:
 *  vcp: VM create parameters that contain the memory map to search in
 *  gpa: the starting guest physical address
 *  len: the length of the memory range
 *
 * Return values:
 *  NULL: on failure if there is no memory range as described by the parameters
 *  Pointer to vm_mem_range that contains the start of the range otherwise.
 */
struct vm_mem_range *
find_gpa_range(struct vmop_create_params *vmc, paddr_t gpa, size_t len)
{
	size_t i, n;
	struct vm_mem_range *vmr;

	/* Find the first vm_mem_range that contains gpa */
	for (i = 0; i < vmc->vmc_nmemranges; i++) {
		vmr = &vmc->vmc_memranges[i];
		if (gpa < vmr->vmr_gpa + vmr->vmr_size)
			break;
	}

	/* No range found. */
	if (i == vmc->vmc_nmemranges)
		return (NULL);

	/*
	 * vmr may cover the range [gpa, gpa + len) only partly. Make
	 * sure that the following vm_mem_ranges are contiguous and
	 * cover the rest.
	 */
	n = vmr->vmr_size - (gpa - vmr->vmr_gpa);
	if (len < n)
		len = 0;
	else
		len -= n;
	gpa = vmr->vmr_gpa + vmr->vmr_size;
	for (i = i + 1; len != 0 && i < vmc->vmc_nmemranges; i++) {
		vmr = &vmc->vmc_memranges[i];
		if (gpa != vmr->vmr_gpa)
			return (NULL);
		if (len <= vmr->vmr_size)
			len = 0;
		else
			len -= vmr->vmr_size;

		gpa = vmr->vmr_gpa + vmr->vmr_size;
	}

	if (len != 0)
		return (NULL);

	return (vmr);
}
/*
 * write_mem
 *
 * Copies data from 'buf' into the guest VM's memory at paddr 'dst'.
 *
 * Parameters:
 *  dst: the destination paddr_t in the guest VM
 *  buf: data to copy (or NULL to zero the data)
 *  len: number of bytes to copy
 *
 * Return values:
 *  0: success
 *  EINVAL: if the guest physical memory range [dst, dst + len) does not
 *      exist in the guest.
 */
int
write_mem(paddr_t dst, const void *buf, size_t len)
{
	const char *from = buf;
	char *to;
	size_t n, off;
	struct vm_mem_range *vmr;

	vmr = find_gpa_range(&current_vm->vm_params, dst, len);
	if (vmr == NULL) {
		errno = EINVAL;
		log_warn("%s: failed - invalid memory range dst = 0x%lx, "
		    "len = 0x%zx", __func__, dst, len);
		return (EINVAL);
	}

	off = dst - vmr->vmr_gpa;
	while (len != 0) {
		n = vmr->vmr_size - off;
		if (len < n)
			n = len;

		to = (char *)vmr->vmr_va + off;
		if (buf == NULL)
			memset(to, 0, n);
		else {
			memcpy(to, from, n);
			from += n;
		}
		len -= n;
		off = 0;
		vmr++;
	}

	return (0);
}

/*
 * read_mem
 *
 * Reads memory at guest paddr 'src' into 'buf'.
 *
 * Parameters:
 *  src: the source paddr_t in the guest VM to read from.
 *  buf: destination (local) buffer
 *  len: number of bytes to read
 *
 * Return values:
 *  0: success
 *  EINVAL: if the guest physical memory range [dst, dst + len) does not
 *      exist in the guest.
 */
int
read_mem(paddr_t src, void *buf, size_t len)
{
	char *from, *to = buf;
	size_t n, off;
	struct vm_mem_range *vmr;

	vmr = find_gpa_range(&current_vm->vm_params, src, len);
	if (vmr == NULL) {
		errno = EINVAL;
		log_warn("%s: failed - invalid memory range src = 0x%lx, "
		    "len = 0x%zx", __func__, src, len);
		return (EINVAL);
	}

	off = src - vmr->vmr_gpa;
	while (len != 0) {
		n = vmr->vmr_size - off;
		if (len < n)
			n = len;

		from = (char *)vmr->vmr_va + off;
		memcpy(to, from, n);

		to += n;
		len -= n;
		off = 0;
		vmr++;
	}

	return (0);
}

/*
 * hvaddr_mem
 *
 * Translate a guest physical address to a host virtual address, checking the
 * provided memory range length to confirm it's contiguous within the same
 * guest memory range (vm_mem_range).
 *
 * Parameters:
 *  gpa: guest physical address to translate
 *  len: number of bytes in the intended range
 *
 * Return values:
 *  void* to host virtual memory on success
 *  NULL on error, setting errno to:
 *    EFAULT: gpa falls outside guest memory ranges
 *    EINVAL: requested len extends beyond memory range
 */
void *
hvaddr_mem(paddr_t gpa, size_t len)
{
	struct vm_mem_range *vmr;
	size_t off;

	vmr = find_gpa_range(&current_vm->vm_params, gpa, len);
	if (vmr == NULL) {
		log_warnx("%s: failed - invalid gpa: 0x%lx\n", __func__, gpa);
		errno = EFAULT;
		return (NULL);
	}

	off = gpa - vmr->vmr_gpa;
	if (len > (vmr->vmr_size - off)) {
		log_warnx("%s: failed - invalid memory range: gpa=0x%lx, "
		    "len=%zu", __func__, gpa, len);
		errno = EINVAL;
		return (NULL);
	}

	return ((char *)vmr->vmr_va + off);
}

/*
 * vcpu_assert_irq
 *
 * Injects the specified IRQ on the supplied vcpu/vm
 *
 * Parameters:
 *  vm_id: VMM vm ID to inject to
 *  vcpu_id: VCPU ID to inject to
 *  irq: IRQ to inject
 */
void
vcpu_assert_irq(uint32_t vmm_id, uint32_t vcpu_id, int irq)
{
	static int intr_fail_ct;
	struct ioapic *io;

	/*
	 * Route to EXACTLY ONE controller per assert.  Previously we
	 * always poked both the i8259 and the IOAPIC, which leaked
	 * (master_vec_base + irq) onto cpu0 in APIC-mode SMP guests --
	 * e.g. Linux with PIC base 0x30 + COM1 IRQ 4 = vec 52, the
	 * spurious "0.52 No irq handler for vector" the user observed.
	 * In APIC mode (IOAPIC present and the pin's RTE unmasked) the
	 * guest owns this line through the IOAPIC; otherwise fall back
	 * to the legacy PIC.
	 */
	io = lapic_smp_ioapic();
	if (io != NULL && irq >= 0 && irq < 24 &&
	    ioapic_pin_configured(io, (uint8_t)irq)) {
		/*
		 * Guest owns this line through the IOAPIC.  Assert there even
		 * if the pin is momentarily masked (Linux masks a level RTE
		 * while servicing it) -- ioapic_assert_irq latches line_state
		 * and the unmask path re-delivers.  Spilling to the i8259 here
		 * loses the interrupt (the guest isn't listening on the PIC for
		 * an APIC-mode line) and the device IRQ storms (e.g. a vioblk
		 * completion never reaches the guest -> disk I/O hangs).
		 */
		ioapic_assert_irq(io, (uint8_t)irq);
	} else {
		i8259_assert_irq(irq);
	}

	if (vcpu_intr(vmm_id, vcpu_id, 1)) {
		if (++intr_fail_ct < 20)
			log_warnx("%s: can't assert INTR for vm %u vcpu %u",
			    __func__, vmm_id, vcpu_id);
		if (intr_fail_ct == 20)
			log_warnx("%s: suppressing further warnings",
			    __func__);
	} else
		intr_fail_ct = 0;
	vcpu_unhalt(vcpu_id);
	vcpu_signal_run(vcpu_id);
}

/*
 * vcpu_deassert_irq
 *
 * Clears the specified IRQ on the supplied vcpu/vm
 *
 * Parameters:
 *  vm_id: VMM vm ID to clear in
 *  vcpu_id: VCPU ID to clear in
 *  irq: IRQ to clear
 */
void
vcpu_deassert_irq(uint32_t vmm_id, uint32_t vcpu_id, int irq)
{
	struct ioapic *io;

	/*
	 * Mirror vcpu_assert_irq: deassert on the same controller that
	 * the assert went to.  Keeping both deassert calls is safe (they
	 * just clear line-state on a controller that wasn't asserted),
	 * but routing precisely keeps the i8259 IRR coherent with what
	 * the guest sees and avoids spurious i8259_is_pending below.
	 */
	io = lapic_smp_ioapic();
	if (io != NULL && irq >= 0 && irq < 24 &&
	    ioapic_pin_configured(io, (uint8_t)irq)) {
		ioapic_deassert_irq(io, (uint8_t)irq);
	} else {
		i8259_deassert_irq(irq);
	}

	if (!i8259_is_pending()) {
		if (vcpu_intr(vmm_id, vcpu_id, 0))
			log_warnx("%s: can't deassert INTR for vmm_id %d, "
			    "vcpu_id %d", __func__, vmm_id, vcpu_id);
	}
}

/*
 * set_return_data
 *
 * Utility function for manipulating register data in vm exit info structs. This
 * function ensures that the data is copied to the vei->vei.vei_data field with
 * the proper size for the operation being performed.
 *
 * Parameters:
 *  vei: exit information
 *  data: return data
 */
void
set_return_data(struct vm_exit *vei, uint32_t data)
{
	switch (vei->vei.vei_size) {
	case 1:
		vei->vei.vei_data &= ~0xFF;
		vei->vei.vei_data |= (uint8_t)data;
		break;
	case 2:
		vei->vei.vei_data &= ~0xFFFF;
		vei->vei.vei_data |= (uint16_t)data;
		break;
	case 4:
		vei->vei.vei_data = data;
		break;
	}
}

/*
 * get_input_data
 *
 * Utility function for manipulating register data in vm exit info
 * structs. This function ensures that the data is copied from the
 * vei->vei.vei_data field with the proper size for the operation being
 * performed.
 *
 * Parameters:
 *  vei: exit information
 *  data: location to store the result
 */
void
get_input_data(struct vm_exit *vei, uint32_t *data)
{
	switch (vei->vei.vei_size) {
	case 1:
		*data &= 0xFFFFFF00;
		*data |= (uint8_t)vei->vei.vei_data;
		break;
	case 2:
		*data &= 0xFFFF0000;
		*data |= (uint16_t)vei->vei.vei_data;
		break;
	case 4:
		*data = vei->vei.vei_data;
		break;
	default:
		log_warnx("%s: invalid i/o size %d", __func__,
		    vei->vei.vei_size);
	}

}

/*
 * translate_gva
 *
 * Translates a guest virtual address to a guest physical address by walking
 * the currently active page table (if needed).
 *
 * XXX ensure translate_gva updates the A bit in the PTE
 * XXX ensure translate_gva respects segment base and limits in i386 mode
 * XXX ensure translate_gva respects segment wraparound in i8086 mode
 * XXX ensure translate_gva updates the A bit in the segment selector
 * XXX ensure translate_gva respects CR4.LMSLE if available
 *
 * Parameters:
 *  exit: The VCPU this translation should be performed for (guest MMU settings
 *   are gathered from this VCPU)
 *  va: virtual address to translate
 *  pa: pointer to paddr_t variable that will receive the translated physical
 *   address. 'pa' is unchanged on error.
 *  mode: one of PROT_READ, PROT_WRITE, PROT_EXEC indicating the mode in which
 *   the address should be translated
 *
 * Return values:
 *  0: the address was successfully translated - 'pa' contains the physical
 *     address currently mapped by 'va'.
 *  EFAULT: the PTE for 'VA' is unmapped. A #PF will be injected in this case
 *     and %cr2 set in the vcpu structure.
 *  EINVAL: an error occurred reading paging table structures
 */
int
translate_gva(struct vm_exit* exit, uint64_t va, uint64_t* pa, int mode)
{
	int level, shift, pdidx;
	uint64_t pte, pt_paddr, pte_paddr, mask, low_mask, high_mask;
	uint64_t shift_width, pte_size;
	struct vcpu_reg_state *vrs;

	vrs = &exit->vrs;

	if (!pa)
		return (EINVAL);

	if (!(vrs->vrs_crs[VCPU_REGS_CR0] & CR0_PG)) {
		log_debug("%s: unpaged, va=pa=0x%llx", __func__, va);
		*pa = va;
		return (0);
	}

	pt_paddr = vrs->vrs_crs[VCPU_REGS_CR3];

	log_debug("%s: guest %%cr0=0x%llx, %%cr3=0x%llx", __func__,
	    vrs->vrs_crs[VCPU_REGS_CR0], vrs->vrs_crs[VCPU_REGS_CR3]);

	if (vrs->vrs_crs[VCPU_REGS_CR0] & CR0_PE) {
		if (vrs->vrs_crs[VCPU_REGS_CR4] & CR4_PAE) {
			pte_size = sizeof(uint64_t);
			shift_width = 9;

			if (vrs->vrs_msrs[VCPU_REGS_EFER] & EFER_LMA) {
				/* 4 level paging */
				level = 4;
				mask = L4_MASK;
				shift = L4_SHIFT;
			} else {
				/* 32 bit with PAE paging */
				level = 3;
				mask = L3_MASK;
				shift = L3_SHIFT;
			}
		} else {
			/* 32 bit paging */
			level = 2;
			shift_width = 10;
			mask = 0xFFC00000;
			shift = 22;
			pte_size = sizeof(uint32_t);
		}
	} else
		return (EINVAL);

	/* XXX: Check for R bit in segment selector and set A bit */

	for (;level > 0; level--) {
		pdidx = (va & mask) >> shift;
		pte_paddr = (pt_paddr) + (pdidx * pte_size);

		log_debug("%s: read pte level %d @ GPA 0x%llx", __func__,
		    level, pte_paddr);
		if (read_mem(pte_paddr, &pte, pte_size)) {
			log_warn("%s: failed to read pte", __func__);
			return (EFAULT);
		}

		log_debug("%s: PTE @ 0x%llx = 0x%llx", __func__, pte_paddr,
		    pte);

		/* XXX: Set CR2  */
		if (!(pte & PG_V))
			return (EFAULT);

		/* XXX: Check for SMAP */
		if ((mode == PROT_WRITE) && !(pte & PG_RW))
			return (EPERM);

		if ((exit->cpl > 0) && !(pte & PG_u))
			return (EPERM);

		pte = pte | PG_U;
		if (mode == PROT_WRITE)
			pte = pte | PG_M;
		if (write_mem(pte_paddr, &pte, pte_size)) {
			log_warn("%s: failed to write back flags to pte",
			    __func__);
			return (EIO);
		}

		/* XXX: EINVAL if in 32bit and PG_PS is 1 but CR4.PSE is 0 */
		if (pte & PG_PS)
			break;

		if (level > 1) {
			pt_paddr = pte & PG_FRAME;
			shift -= shift_width;
			mask = mask >> shift_width;
		}
	}

	low_mask = (1 << shift) - 1;
	high_mask = (((uint64_t)1ULL << ((pte_size * 8) - 1)) - 1) ^ low_mask;
	*pa = (pte & high_mask) | (va & low_mask);

	log_debug("%s: final GPA for GVA 0x%llx = 0x%llx\n", __func__, va, *pa);

	return (0);
}

int
intr_pending(struct vmd_vm *vm, uint32_t vcpu_id)
{
	struct lapic *l;

	/* i8259 first: LAPIC timer always-pending can starve disk IRQs. */
	if (vcpu_id == 0 && i8259_is_pending())
		return (1);
	if (lapic_smp_ncpus() > 1 && vcpu_id < lapic_smp_ncpus()) {
		l = lapic_smp_get(vcpu_id);
		if (l != NULL && lapic_pending(l) >= 0)
			return (1);
	}
	return (0);
}

/*
 * Side-effect-free counterpart to intr_pending(): does NOT fire/kick a
 * due LAPIC timer (i8259_is_pending and lapic_pending_nofire are pure
 * reads).  Safe to call while holding vcpu_run_mtx -- intr_pending()
 * itself is not, because lapic_pending() can fire a timer whose kick
 * re-enters vcpu_unhalt()/vcpu_run_mtx.  Used by the halt decision in
 * vcpu_run_loop to catch a vector a racing timer-thread kick already set.
 */
/*
 * Undo a speculative intr_ack() when the kernel declined to inject the
 * vector (see vcpu_run_loop gated-ack).  Restores the LAPIC vector from
 * ISR back to IRR so it is retried, preventing a stranded ISR bit from
 * pinning PPR and masking lower-priority vectors.  i8259 vectors are not
 * restored here (lapic_unack is a no-op for them); the legacy PIC has
 * its own in-service/EOI handling and is not the SMP-orphan path.
 */
void
intr_unack(struct vmd_vm *vm, uint32_t vcpu_id, uint8_t vec)
{
	struct lapic *l;

	if (lapic_smp_ncpus() > 1 && vcpu_id < lapic_smp_ncpus()) {
		l = lapic_smp_get(vcpu_id);
		if (l != NULL)
			lapic_unack(l, vec);
	}
}

int
intr_pending_nofire(struct vmd_vm *vm, uint32_t vcpu_id)
{
	struct lapic *l;

	if (vcpu_id == 0 && i8259_is_pending())
		return (1);
	if (lapic_smp_ncpus() > 1 && vcpu_id < lapic_smp_ncpus()) {
		l = lapic_smp_get(vcpu_id);
		if (l != NULL && lapic_pending_nofire(l) >= 0)
			return (1);
	}
	return (0);
}

int
intr_ack(struct vmd_vm *vm, uint32_t vcpu_id)
{
	struct lapic *l;
	int lvec;

	l = (lapic_smp_ncpus() > 1 && vcpu_id < lapic_smp_ncpus()) ?
	    lapic_smp_get(vcpu_id) : NULL;
	lvec = (l != NULL) ? lapic_pending(l) : -1;

	/* Same priority as intr_pending: i8259 first. */
	if (vcpu_id == 0 && i8259_is_pending())
		/* i8259 first: timer can starve disk IRQs */
		return i8259_ack();
	if (l != NULL && lvec >= 0)
		return ((int)lapic_ack(l));
	return (0xff);		/* spurious */
}

void
intr_toggle_el(struct vmd_vm *vm, int irq, int val)
{
	/* XXX select active interrupt controller */
	pic_set_elcr(irq, val);
}
