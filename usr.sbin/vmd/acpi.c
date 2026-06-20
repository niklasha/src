/* $OpenBSD$ */
/*
 * ACPI table generator for vmd, handed to SeaBIOS (vmm-bios) via the
 * QEMU fw_cfg "BIOS linker/loader" protocol (etc/table-loader).
 *
 * Instead of write_mem()-ing the tables to fixed low GPAs (which the
 * SeaBIOS firmware clobbers / does not surface, leaving the guest with
 * "acpi at bios0 not configured" and SMP only from the MP table), vmd
 * now exposes three fw_cfg files:
 *
 *   etc/acpi/rsdp    - the 20-byte RSDP
 *   etc/acpi/tables  - RSDT || FADT || MADT || DSDT, concatenated
 *   etc/table-loader - an array of 128-byte loader command entries
 *
 * SeaBIOS ALLOCATEs the blobs in safe high (tables) / FSEG (rsdp)
 * memory, ADD_POINTERs to patch the inter-table pointers to the real
 * allocation addresses, and ADD_CHECKSUMs to fill the header checksum
 * bytes.  The guest then finds the RSDP in the FSEG, configures ACPI
 * and reads the MADT -> SMP works up to VMM_MAX_VCPUS_PER_VM.
 *
 * Generates RSDP + RSDT + FADT + MADT + minimal DSDT so guests
 * can discover the ACPI PM timer at port 0x608 and enumerate
 * SMP CPUs and the IOAPIC.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "vmd.h"
#include "fw_cfg.h"
#include "acpi.h"

/*
 * PM base MUST be below VM_PCI_IO_BAR_BASE (0x1000): vmd maps the PCI I/O BAR
 * window 0x1000-0xFFFF to vcpu_exit_pci, which would clobber the PM block's
 * ioports_map entries and misroute PM1/PM-timer to the PCI dispatcher (guest
 * ACPI reads garbage -> "PM1 stuck" SCI spin).  Keep in sync with the
 * registration in x86_vm.c init_emulated_hw and ACPI_PM_TIMER_PORT.
 */
#define ACPI_PM_BASE	0x600

/* fw_cfg file names */
#define ACPI_FILE_RSDP		"etc/acpi/rsdp"
#define ACPI_FILE_TABLES	"etc/acpi/tables"
#define ACPI_FILE_LOADER	"etc/table-loader"

/*
 * QEMU BIOS linker/loader command set, as consumed by SeaBIOS
 * (romfile_loader.h).  Each command entry is EXACTLY 128 bytes.
 */
#define ACPI_LOADER_ALLOCATE	0x1
#define ACPI_LOADER_ADD_POINTER	0x2
#define ACPI_LOADER_ADD_CHECKSUM 0x3

#define ACPI_LOADER_ZONE_HIGH	0x1
#define ACPI_LOADER_ZONE_FSEG	0x2

struct acpi_loader_allocate {
	char		file[56];
	uint32_t	align;
	uint8_t		zone;
} __packed;

struct acpi_loader_add_pointer {
	char		dest_file[56];
	char		src_file[56];
	uint32_t	offset;
	uint8_t		size;
} __packed;

struct acpi_loader_add_checksum {
	char		file[56];
	uint32_t	offset;
	uint32_t	start;
	uint32_t	length;
} __packed;

struct acpi_loader_entry {
	uint32_t	command;
	union {
		struct acpi_loader_allocate	allocate;
		struct acpi_loader_add_pointer	add_pointer;
		struct acpi_loader_add_checksum	add_checksum;
		char				pad[124];
	} u;
} __packed;
CTASSERT(sizeof(struct acpi_loader_entry) == 128);

int
acpi_init(uint32_t ncpus)
{
	/* RSDP — Root System Description Pointer (20 bytes) */
	struct {
		char		signature[8];	/* "RSD PTR " */
		uint8_t		checksum;
		char		oemid[6];
		uint8_t		revision;
		uint32_t	rsdt_addr;
	} __packed rsdp;

	/* RSDT — Root System Description Table */
	struct {
		char		signature[4];	/* "RSDT" */
		uint32_t	length;
		uint8_t		revision;
		uint8_t		checksum;
		char		oemid[6];
		char		oem_table_id[8];
		uint32_t	oem_revision;
		uint32_t	creator_id;
		uint32_t	creator_revision;
		uint32_t	entry[2];	/* -> FADT, MADT */
	} __packed rsdt;

	/* FADT — Fixed ACPI Description Table */
	struct {
		char		signature[4];	/* "FACP" */
		uint32_t	length;
		uint8_t		revision;
		uint8_t		checksum;
		char		oemid[6];
		char		oem_table_id[8];
		uint32_t	oem_revision;
		uint32_t	creator_id;
		uint32_t	creator_revision;
		uint32_t	firmware_ctrl;
		uint32_t	dsdt;
		uint8_t		reserved;
		uint8_t		preferred_pm_profile;
		uint16_t	sci_int;
		uint32_t	smi_cmd;
		uint8_t		acpi_enable;
		uint8_t		acpi_disable;
		uint8_t		s4bios_req;
		uint8_t		pstate_cnt;
		uint32_t	pm1a_evt_blk;
		uint32_t	pm1b_evt_blk;
		uint32_t	pm1a_cnt_blk;
		uint32_t	pm1b_cnt_blk;
		uint32_t	pm2_cnt_blk;
		uint32_t	pm_tmr_blk;
		uint32_t	gpe0_blk;
		uint32_t	gpe1_blk;
		uint8_t		pm1_evt_len;
		uint8_t		pm1_cnt_len;
		uint8_t		pm2_cnt_len;
		uint8_t		pm_tmr_len;
		uint8_t		gpe0_blk_len;
		uint8_t		gpe1_blk_len;
		uint8_t		gpe1_base;
		uint8_t		cst_cnt;
		uint16_t	p_lvl2_lat;
		uint16_t	p_lvl3_lat;
		uint16_t	flush_size;
		uint16_t	flush_stride;
		uint8_t		duty_offset;
		uint8_t		duty_width;
		uint8_t		day_alrm;
		uint8_t		mon_alrm;
		uint8_t		century;
		uint16_t	iapc_boot_arch;
		uint8_t		reserved2;
		uint32_t	flags;
	} __packed fadt;

	/* Minimal DSDT — just a header, no AML */
	struct {
		char		signature[4];	/* "DSDT" */
		uint32_t	length;
		uint8_t		revision;
		uint8_t		checksum;
		char		oemid[6];
		char		oem_table_id[8];
		uint32_t	oem_revision;
		uint32_t	creator_id;
		uint32_t	creator_revision;
	} __packed dsdt;

	/* MADT - Multiple APIC Description Table */
	struct madt_lapic {
		uint8_t		type;
		uint8_t		length;
		uint8_t		processor_id;
		uint8_t		apic_id;
		uint32_t	flags;
	} __packed;
	struct madt_ioapic {
		uint8_t		type;
		uint8_t		length;
		uint8_t		ioapic_id;
		uint8_t		reserved;
		uint32_t	address;
		uint32_t	gsi_base;
	} __packed;
	struct {
		char		signature[4];
		uint32_t	length;
		uint8_t		revision;
		uint8_t		checksum;
		char		oemid[6];
		char		oem_table_id[8];
		uint32_t	oem_revision;
		uint32_t	creator_id;
		uint32_t	creator_revision;
		uint32_t	local_apic_addr;
		uint32_t	flags;
		struct madt_lapic	lapics[VMM_MAX_VCPUS_PER_VM];
		struct madt_ioapic	ioapic;
	} __packed madt;
	uint32_t i;

	/*
	 * The contiguous "etc/acpi/tables" blob and the offsets of each
	 * table within it.  Sized for the worst case (full LAPIC array)
	 * plus alignment slack.
	 */
	static uint8_t tables[sizeof(rsdt) + sizeof(fadt) + sizeof(madt) +
	    sizeof(dsdt) + 64];
	uint32_t rsdt_off, fadt_off, madt_off, dsdt_off, tables_len;
	uint32_t rsdt_len, fadt_len, dsdt_len, madt_len;

	/* The "etc/table-loader" command array. */
	struct acpi_loader_entry loader[11];
	struct acpi_loader_entry *e;
	uint32_t nloader = 0;

	/* DSDT */
	memset(&dsdt, 0, sizeof(dsdt));
	memcpy(dsdt.signature, "DSDT", 4);
	dsdt.length = sizeof(dsdt);
	dsdt.revision = 1;
	memcpy(dsdt.oemid, "OBSDVM", 6);
	memcpy(dsdt.oem_table_id, "VMDDSDT ", 8);
	/* checksum filled by the loader (ADD_CHECKSUM) */
	dsdt_len = sizeof(dsdt);

	/* FADT */
	memset(&fadt, 0, sizeof(fadt));
	memcpy(fadt.signature, "FACP", 4);
	fadt.length = sizeof(fadt);
	fadt.revision = 1;
	memcpy(fadt.oemid, "OBSDVM", 6);
	memcpy(fadt.oem_table_id, "VMDFADT ", 8);
	/*
	 * fadt.dsdt is patched by ADD_POINTER to the real allocation
	 * address; pre-fill with the DSDT's offset within the tables blob.
	 */
	fadt.firmware_ctrl = 0;	/* no FACS */
	/*
	 * SCI interrupt GSI.  MUST be non-zero and must NOT collide with the
	 * i8254 timer (IRQ0/GSI0) or any emulated device IRQ (com=4, RTC=8,
	 * virtio=3/5/6/7/9).  Leaving this 0 put the ACPI SCI on GSI0, which
	 * the guest programs as a LEVEL pin; the PIT (i8253_fire asserts IRQ0
	 * = pin0, never deasserts) then drove that level pin and, once IRQ0
	 * routes through the IOAPIC (APIC mode, reached at cpus>1), ioapic_eoi
	 * re-delivered it without bound -> a clock-interrupt storm that wedged
	 * the guest at cpus>=2 (the "PM1 stuck" guest's second bug).
	 *
	 * GSI 13 is the one clean ISA-range slot: it is NOT a fixed device
	 * (timer=0, com=4, RTC=8), NOT the cascade (2), and NOT in the PCI
	 * device pool pci_pic_irqs[] = {3,5,6,7,9,10,11,12,14,15} (so it can
	 * never be handed to a virtio device).  Kept <=15 so it is also valid
	 * in legacy PIC mode (i8259 covers 0-15).  vmd never asserts pin 13;
	 * the SCI never actually fires under vmd -- it just must not share a
	 * pin with the timer or a device.
	 */
	fadt.sci_int = 13;
	fadt.pm1a_evt_blk = ACPI_PM_BASE;
	fadt.pm1_evt_len = 4;
	fadt.pm1a_cnt_blk = ACPI_PM_BASE + 4;
	fadt.pm1_cnt_len = 2;
	fadt.pm_tmr_blk = ACPI_PM_BASE + 8;
	fadt.pm_tmr_len = 4;
	fadt.p_lvl2_lat = 0xFFFF;	/* C2 not supported */
	fadt.p_lvl3_lat = 0xFFFF;	/* C3 not supported */
	fadt.flags = (1 << 0)		/* WBINVD */
	    | (1 << 4)			/* RESET_REG_SUP */
	    | (1 << 8);		/* TMR_VAL_EXT (24-bit PM timer) */
	/* checksum filled by the loader (ADD_CHECKSUM) */
	fadt_len = sizeof(fadt);

	/* MADT */
	memset(&madt, 0, sizeof(madt));
	memcpy(madt.signature, "APIC", 4);
	memcpy(madt.oemid, "OBSDVM", 6);
	memcpy(madt.oem_table_id, "VMDMADT ", 8);
	madt.revision = 1;
	madt.local_apic_addr = 0xFEE00000;
	madt.flags = 1;		/* PCAT_COMPAT: legacy 8259 present */
	if (ncpus == 0)
		ncpus = 1;
	if (ncpus > VMM_MAX_VCPUS_PER_VM)
		ncpus = VMM_MAX_VCPUS_PER_VM;
	for (i = 0; i < ncpus; i++) {
		madt.lapics[i].type = 0;	/* Processor Local APIC */
		madt.lapics[i].length = 8;
		madt.lapics[i].processor_id = (uint8_t)i;
		madt.lapics[i].apic_id = (uint8_t)i;
		madt.lapics[i].flags = 1;	/* enabled */
	}
	madt.ioapic.type = 1;		/* I/O APIC */
	madt.ioapic.length = 12;
	/*
	 * IOAPIC's APIC ID must not collide with any LAPIC's APIC ID
	 * (0..ncpus-1).  On collision Linux silently renumbers the
	 * conflicting LAPIC, breaking ioapic_assert_to_lapic's
	 * vcpu-index lookup.  ncpus is safely above the LAPIC range.
	 */
	madt.ioapic.ioapic_id = (uint8_t)ncpus;
	madt.ioapic.address = 0xFEC00000;
	madt.ioapic.gsi_base = 0;
	/*
	 * Pack: move the IOAPIC entry to sit immediately after the
	 * trimmed LAPIC array, so it lands inside the written length.
	 * Without this, the IOAPIC bytes are past the trimmed length
	 * and never reach the guest, forcing Linux into MP-table
	 * fallback (which collides on the IOAPIC ID).
	 */
	if (ncpus < VMM_MAX_VCPUS_PER_VM)
		memmove(&madt.lapics[ncpus], &madt.ioapic,
		    sizeof(struct madt_ioapic));
	/*
	 * Length = fixed header + ncpus LAPIC entries + one IOAPIC entry.
	 * `sizeof(madt) - sizeof(madt.lapics)` already counts the header
	 * AND the embedded madt.ioapic member, so do NOT add
	 * sizeof(struct madt_ioapic) again -- doing so over-counted by 12
	 * bytes and left a trailing type=0/length=0 subtable that makes
	 * Linux's MADT parser abort on the zero-length entry, corrupting
	 * APIC enumeration.
	 */
	madt.length = sizeof(madt) - sizeof(madt.lapics) +
	    ncpus * sizeof(struct madt_lapic);
	madt_len = madt.length;
	/* checksum filled by the loader (ADD_CHECKSUM) */

	/* RSDT */
	memset(&rsdt, 0, sizeof(rsdt));
	memcpy(rsdt.signature, "RSDT", 4);
	rsdt.length = sizeof(rsdt);
	rsdt.revision = 1;
	memcpy(rsdt.oemid, "OBSDVM", 6);
	memcpy(rsdt.oem_table_id, "VMDRSDT ", 8);
	/* entries patched by ADD_POINTER; checksum by ADD_CHECKSUM */
	rsdt_len = sizeof(rsdt);

	/* RSDP */
	memset(&rsdp, 0, sizeof(rsdp));
	memcpy(rsdp.signature, "RSD PTR ", 8);
	memcpy(rsdp.oemid, "OBSDVM", 6);
	rsdp.revision = 0;		/* ACPI 1.0 */
	/* rsdp.rsdt_addr patched by ADD_POINTER; checksum by ADD_CHECKSUM */

	/*
	 * Lay out the tables blob: RSDT || FADT || MADT || DSDT.
	 * Each table is 4-byte aligned (its length is already a multiple
	 * of 4 here, but be explicit).  Record each offset; pre-fill the
	 * inter-table pointer fields with the *offset within this blob*
	 * (the loader's ADD_POINTER then adds the real alloc base).
	 */
#define ALIGN4(x)	(((x) + 3u) & ~3u)
	memset(tables, 0, sizeof(tables));
	rsdt_off = 0;
	fadt_off = ALIGN4(rsdt_off + rsdt_len);
	madt_off = ALIGN4(fadt_off + fadt_len);
	dsdt_off = ALIGN4(madt_off + madt_len);
	tables_len = dsdt_off + dsdt_len;
	if (tables_len > sizeof(tables)) {
		log_warnx("%s: tables blob overflow (%u > %zu)", __func__,
		    tables_len, sizeof(tables));
		return (-1);
	}

	rsdt.entry[0] = fadt_off;	/* -> FADT */
	rsdt.entry[1] = madt_off;	/* -> MADT */
	fadt.dsdt = dsdt_off;		/* -> DSDT */

	memcpy(tables + rsdt_off, &rsdt, rsdt_len);
	memcpy(tables + fadt_off, &fadt, fadt_len);
	memcpy(tables + madt_off, &madt, madt_len);
	memcpy(tables + dsdt_off, &dsdt, dsdt_len);

	rsdp.rsdt_addr = rsdt_off;	/* -> RSDT */

	/*
	 * Build the "etc/table-loader" command array.
	 *   - ALLOCATE both files.
	 *   - ADD_POINTERs to patch inter-table pointers (before checksums).
	 *   - ADD_CHECKSUMs to compute every header checksum (run last).
	 */
	memset(loader, 0, sizeof(loader));

	/* ALLOCATE etc/acpi/rsdp, FSEG, align 16 */
	e = &loader[nloader++];
	e->command = ACPI_LOADER_ALLOCATE;
	strlcpy(e->u.allocate.file, ACPI_FILE_RSDP,
	    sizeof(e->u.allocate.file));
	e->u.allocate.align = 16;
	e->u.allocate.zone = ACPI_LOADER_ZONE_FSEG;

	/* ALLOCATE etc/acpi/tables, HIGH, align 64 */
	e = &loader[nloader++];
	e->command = ACPI_LOADER_ALLOCATE;
	strlcpy(e->u.allocate.file, ACPI_FILE_TABLES,
	    sizeof(e->u.allocate.file));
	e->u.allocate.align = 64;
	e->u.allocate.zone = ACPI_LOADER_ZONE_HIGH;

	/* ADD_POINTER rsdp.rsdt_addr -> tables (RSDT) */
	e = &loader[nloader++];
	e->command = ACPI_LOADER_ADD_POINTER;
	strlcpy(e->u.add_pointer.dest_file, ACPI_FILE_RSDP,
	    sizeof(e->u.add_pointer.dest_file));
	strlcpy(e->u.add_pointer.src_file, ACPI_FILE_TABLES,
	    sizeof(e->u.add_pointer.src_file));
	e->u.add_pointer.offset = 16;	/* rsdp.rsdt_addr */
	e->u.add_pointer.size = 4;

	/* ADD_POINTER rsdt.entry[0] -> tables (FADT) */
	e = &loader[nloader++];
	e->command = ACPI_LOADER_ADD_POINTER;
	strlcpy(e->u.add_pointer.dest_file, ACPI_FILE_TABLES,
	    sizeof(e->u.add_pointer.dest_file));
	strlcpy(e->u.add_pointer.src_file, ACPI_FILE_TABLES,
	    sizeof(e->u.add_pointer.src_file));
	e->u.add_pointer.offset = rsdt_off + 36;	/* entry[0] */
	e->u.add_pointer.size = 4;

	/* ADD_POINTER rsdt.entry[1] -> tables (MADT) */
	e = &loader[nloader++];
	e->command = ACPI_LOADER_ADD_POINTER;
	strlcpy(e->u.add_pointer.dest_file, ACPI_FILE_TABLES,
	    sizeof(e->u.add_pointer.dest_file));
	strlcpy(e->u.add_pointer.src_file, ACPI_FILE_TABLES,
	    sizeof(e->u.add_pointer.src_file));
	e->u.add_pointer.offset = rsdt_off + 40;	/* entry[1] */
	e->u.add_pointer.size = 4;

	/* ADD_POINTER fadt.dsdt -> tables (DSDT) */
	e = &loader[nloader++];
	e->command = ACPI_LOADER_ADD_POINTER;
	strlcpy(e->u.add_pointer.dest_file, ACPI_FILE_TABLES,
	    sizeof(e->u.add_pointer.dest_file));
	strlcpy(e->u.add_pointer.src_file, ACPI_FILE_TABLES,
	    sizeof(e->u.add_pointer.src_file));
	e->u.add_pointer.offset = fadt_off + 40;	/* fadt.dsdt */
	e->u.add_pointer.size = 4;

	/* ADD_CHECKSUM rsdp (offset 8, over the 20-byte RSDP) */
	e = &loader[nloader++];
	e->command = ACPI_LOADER_ADD_CHECKSUM;
	strlcpy(e->u.add_checksum.file, ACPI_FILE_RSDP,
	    sizeof(e->u.add_checksum.file));
	e->u.add_checksum.offset = 8;
	e->u.add_checksum.start = 0;
	e->u.add_checksum.length = sizeof(rsdp);

	/* ADD_CHECKSUM RSDT */
	e = &loader[nloader++];
	e->command = ACPI_LOADER_ADD_CHECKSUM;
	strlcpy(e->u.add_checksum.file, ACPI_FILE_TABLES,
	    sizeof(e->u.add_checksum.file));
	e->u.add_checksum.offset = rsdt_off + 9;
	e->u.add_checksum.start = rsdt_off;
	e->u.add_checksum.length = rsdt_len;

	/* ADD_CHECKSUM FADT */
	e = &loader[nloader++];
	e->command = ACPI_LOADER_ADD_CHECKSUM;
	strlcpy(e->u.add_checksum.file, ACPI_FILE_TABLES,
	    sizeof(e->u.add_checksum.file));
	e->u.add_checksum.offset = fadt_off + 9;
	e->u.add_checksum.start = fadt_off;
	e->u.add_checksum.length = fadt_len;

	/* ADD_CHECKSUM MADT */
	e = &loader[nloader++];
	e->command = ACPI_LOADER_ADD_CHECKSUM;
	strlcpy(e->u.add_checksum.file, ACPI_FILE_TABLES,
	    sizeof(e->u.add_checksum.file));
	e->u.add_checksum.offset = madt_off + 9;
	e->u.add_checksum.start = madt_off;
	e->u.add_checksum.length = madt_len;

	/* ADD_CHECKSUM DSDT */
	e = &loader[nloader++];
	e->command = ACPI_LOADER_ADD_CHECKSUM;
	strlcpy(e->u.add_checksum.file, ACPI_FILE_TABLES,
	    sizeof(e->u.add_checksum.file));
	e->u.add_checksum.offset = dsdt_off + 9;
	e->u.add_checksum.start = dsdt_off;
	e->u.add_checksum.length = dsdt_len;

	if (nloader > nitems(loader)) {
		log_warnx("%s: loader command overflow", __func__);
		return (-1);
	}

	/* Register the three fw_cfg files (fw_cfg_add_file copies data). */
	fw_cfg_add_file(ACPI_FILE_RSDP, &rsdp, sizeof(rsdp));
	fw_cfg_add_file(ACPI_FILE_TABLES, tables, tables_len);
	fw_cfg_add_file(ACPI_FILE_LOADER, loader,
	    nloader * sizeof(struct acpi_loader_entry));

	return (0);
}
