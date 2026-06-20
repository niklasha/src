/* $OpenBSD$ */
/*
 * Intel MultiProcessor Specification v1.4 table generator for vmd.
 * Used by the ELF direct-boot path only; SeaBIOS generates its own
 * MP table via CONFIG_MPTABLE.
 *
 * Lays out:
 *   0xF0000  MP Floating Pointer Structure        (16 bytes, sig "_MP_")
 *   0xF0010  MP Configuration Table header       (44 bytes, sig "PCMP")
 *   0xF003C  N processor entries                 (20 bytes each, type 0)
 *   ...      1 bus entry "ISA"                   (8 bytes, type 1)
 *   ...      1 IOAPIC entry                      (8 bytes, type 2)
 *
 * Both the floating pointer and the configuration table header carry a
 * checksum byte such that the unsigned sum of all bytes of the structure
 * is 0 mod 256.  Intel MPS v1.4 SS 4.1 and 4.2.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "vmd.h"
#include "mptable.h"

#define MPTABLE_FP_GPA		0xF0BF0UL	/* BIOS ROM range */
#define MPTABLE_CFG_GPA		0x9FC10UL

#define MPTABLE_LAPIC_ADDR	0xFEE00000UL
#define MPTABLE_IOAPIC_ADDR	0xFEC00000UL

#define MP_FP_SIG		"_MP_"
#define MP_CFG_SIG		"PCMP"

#define MP_ENTRY_CPU		0x00
#define MP_ENTRY_BUS		0x01
#define MP_ENTRY_IOAPIC		0x02
#define MP_ENTRY_INT		0x03

#define MP_CPU_EN		0x01	/* CPU enabled */
#define MP_CPU_BP		0x02	/* CPU is bootstrap processor */
#define MP_IOAPIC_EN		0x01

#define MP_APIC_VERSION		0x14	/* integrated APIC */

struct mp_floating_pointer {
	uint8_t		sig[4];		/* "_MP_" */
	uint32_t	phys_addr;	/* points to MP config table */
	uint8_t		length;		/* in 16-byte units; always 1 */
	uint8_t		spec_rev;	/* 0x04 == v1.4 */
	uint8_t		checksum;
	uint8_t		feature[5];	/* feature bytes 1..5 */
} __packed;

struct mp_config_table {
	uint8_t		sig[4];		/* "PCMP" */
	uint16_t	base_length;	/* incl. this header */
	uint8_t		spec_rev;	/* 0x04 */
	uint8_t		checksum;
	uint8_t		oem_id[8];
	uint8_t		product_id[12];
	uint32_t	oem_table_ptr;
	uint16_t	oem_table_size;
	uint16_t	entry_count;
	uint32_t	lapic_addr;
	uint16_t	ext_length;
	uint8_t		ext_checksum;
	uint8_t		reserved;
} __packed;

struct mp_proc_entry {
	uint8_t		type;		/* 0 */
	uint8_t		apic_id;
	uint8_t		apic_ver;
	uint8_t		cpu_flags;	/* EN | BP */
	uint32_t	cpu_signature;	/* family/model/stepping */
	uint32_t	feature_flags;	/* CPUID(1) EDX */
	uint32_t	reserved[2];
} __packed;

struct mp_bus_entry {
	uint8_t		type;		/* 1 */
	uint8_t		bus_id;
	uint8_t		bus_type[6];	/* e.g. "ISA   " */
} __packed;

struct mp_ioapic_entry {
	uint8_t		type;		/* 2 */
	uint8_t		apic_id;
	uint8_t		apic_ver;
	uint8_t		flags;		/* EN */
	uint32_t	addr;		/* 0xFEC00000 */
} __packed;

/*
 * MP IO interrupt assignment entry (type 3).  Per MPS v1.4 S 4.3.4.
 * Used to tell the kernel which IOAPIC pin a given ISA IRQ is wired
 * to.  Without these entries, the kernel does NOT program the IOAPIC
 * redirection table for ISA devices, so virtio IRQs are dropped.
 */
struct mp_int_entry {
	uint8_t		type;		/* 3 */
	uint8_t		int_type;	/* 0=INT 1=NMI 2=SMI 3=ExtINT */
	uint16_t	flags;		/* polarity / trigger */
	uint8_t		src_bus_id;
	uint8_t		src_bus_irq;
	uint8_t		dst_apic_id;
	uint8_t		dst_apic_pin;
} __packed;

static uint8_t	mp_acc(const void *, size_t);
static uint8_t	mp_checksum(const void *, size_t);

static uint8_t
mp_acc(const void *buf, size_t len)
{
	const uint8_t *p = buf;
	uint8_t s = 0;
	size_t i;

	for (i = 0; i < len; i++)
		s = (uint8_t)(s + p[i]);
	return (s);
}

static uint8_t
mp_checksum(const void *buf, size_t len)
{
	return ((uint8_t)(0u - mp_acc(buf, len)));
}

int
mptable_init(uint32_t ncpus, uint8_t lapic_base, uint8_t ioapic_id)
{
	struct mp_floating_pointer fp;
	struct mp_config_table cfg;
	struct mp_proc_entry cpu;
	struct mp_int_entry ie;
	struct mp_bus_entry bus;
	struct mp_ioapic_entry ioapic;
	uint32_t off, i, k;
	uint16_t base_len;
	uint8_t s;
	int rc;

	if (ncpus == 0)
		ncpus = 1;

	base_len = (uint16_t)(sizeof(cfg)
	    + ncpus * sizeof(cpu)
	    + sizeof(bus)
	    + sizeof(ioapic)
	    + 16 * sizeof(struct mp_int_entry));

	/* Floating pointer at 0xF0000 */
	memset(&fp, 0, sizeof(fp));
	memcpy(fp.sig, MP_FP_SIG, 4);
	fp.phys_addr = (uint32_t)MPTABLE_CFG_GPA;
	fp.length    = 1;
	fp.spec_rev  = 0x04;
	fp.checksum  = 0;
	fp.checksum  = mp_checksum(&fp, sizeof(fp));

	/* Configuration table header */
	memset(&cfg, 0, sizeof(cfg));
	memcpy(cfg.sig, MP_CFG_SIG, 4);
	cfg.base_length    = base_len;
	cfg.spec_rev       = 0x04;
	memcpy(cfg.oem_id,     "OpenBSD ", 8);
	memcpy(cfg.product_id, "vmd MP v1.4 ", 12);
	cfg.entry_count    = (uint16_t)(ncpus + 2 + 16);
	cfg.lapic_addr     = (uint32_t)MPTABLE_LAPIC_ADDR;

	/* Compute checksum by summing the byte image piece by piece. */
	s = mp_acc(&cfg, sizeof(cfg));
	for (i = 0; i < ncpus; i++) {
		memset(&cpu, 0, sizeof(cpu));
		cpu.type      = MP_ENTRY_CPU;
		cpu.apic_id   = (uint8_t)(lapic_base + i);
		cpu.apic_ver  = MP_APIC_VERSION;
		cpu.cpu_flags = (uint8_t)(MP_CPU_EN |
		    (i == 0 ? MP_CPU_BP : 0));
		cpu.cpu_signature = 0x00000600;
		cpu.feature_flags = 0x00000201;
		s = (uint8_t)(s + mp_acc(&cpu, sizeof(cpu)));
	}
	memset(&bus, 0, sizeof(bus));
	bus.type   = MP_ENTRY_BUS;
	bus.bus_id = 0;
	memcpy(bus.bus_type, "ISA   ", 6);
	s = (uint8_t)(s + mp_acc(&bus, sizeof(bus)));

	memset(&ioapic, 0, sizeof(ioapic));
	ioapic.type     = MP_ENTRY_IOAPIC;
	ioapic.apic_id  = ioapic_id;
	ioapic.apic_ver = MP_APIC_VERSION;
	ioapic.flags    = MP_IOAPIC_EN;
	ioapic.addr     = (uint32_t)MPTABLE_IOAPIC_ADDR;
	s = (uint8_t)(s + mp_acc(&ioapic, sizeof(ioapic)));

	/*
	 * INT entries: full identity -- ISA IRQ N -> IOAPIC pin N for all
	 * 16 ISA IRQs, including IRQ0 -> pin 0.  This MUST match where vmd
	 * actually asserts each line: vcpu_assert_irq() casts the irq number
	 * straight to the IOAPIC pin (ioapic_assert_irq(io, irq), x86_vm.c),
	 * so IRQ0 is driven on pin 0.  The MADT (acpi.c) emits no Interrupt
	 * Source Override, so an ACPI guest also identity-maps IRQ0 -> GSI0
	 * -> pin 0.  Keeping this loop identity makes MP-table and MADT
	 * discovery agree with the assert path on pin 0.  Flags = 0
	 * (conforming polarity + edge-triggered, the ISA default).
	 */
	for (k = 0; k < 16; k++) {
			memset(&ie, 0, sizeof(ie));
			ie.type         = MP_ENTRY_INT;
			ie.int_type     = 0;	/* vectored INT */
			ie.flags        = 0;	/* conforming/edge */
			ie.src_bus_id   = 0;	/* ISA */
			ie.src_bus_irq  = (uint8_t)k;
			ie.dst_apic_id  = ioapic_id;
			ie.dst_apic_pin = (uint8_t)k;
			s = (uint8_t)(s + mp_acc(&ie, sizeof(ie)));
		}

	cfg.checksum = (uint8_t)(0u - s);

	/* Emit */
	if ((rc = write_mem(MPTABLE_FP_GPA, &fp, sizeof(fp))) != 0)
		return (rc);

	off = MPTABLE_CFG_GPA;
	if ((rc = write_mem(off, &cfg, sizeof(cfg))) != 0)
		return (rc);
	off += sizeof(cfg);

	for (i = 0; i < ncpus; i++) {
		memset(&cpu, 0, sizeof(cpu));
		cpu.type      = MP_ENTRY_CPU;
		cpu.apic_id   = (uint8_t)(lapic_base + i);
		cpu.apic_ver  = MP_APIC_VERSION;
		cpu.cpu_flags = (uint8_t)(MP_CPU_EN |
		    (i == 0 ? MP_CPU_BP : 0));
		cpu.cpu_signature = 0x00000600;
		cpu.feature_flags = 0x00000201;
		if ((rc = write_mem(off, &cpu, sizeof(cpu))) != 0)
			return (rc);
		off += sizeof(cpu);
	}

	memset(&bus, 0, sizeof(bus));
	bus.type   = MP_ENTRY_BUS;
	bus.bus_id = 0;
	memcpy(bus.bus_type, "ISA   ", 6);
	if ((rc = write_mem(off, &bus, sizeof(bus))) != 0)
		return (rc);
	off += sizeof(bus);

	memset(&ioapic, 0, sizeof(ioapic));
	ioapic.type     = MP_ENTRY_IOAPIC;
	ioapic.apic_id  = ioapic_id;
	ioapic.apic_ver = MP_APIC_VERSION;
	ioapic.flags    = MP_IOAPIC_EN;
	ioapic.addr     = (uint32_t)MPTABLE_IOAPIC_ADDR;
	if ((rc = write_mem(off, &ioapic, sizeof(ioapic))) != 0)
		return (rc);
	off += sizeof(ioapic);

	/*
	 * 16 INT entries: ISA IRQ N -> IOAPIC pin N.
	 */
	for (k = 0; k < 16; k++) {
			memset(&ie, 0, sizeof(ie));
			ie.type         = MP_ENTRY_INT;
			ie.int_type     = 0;
			ie.flags        = 0;
			ie.src_bus_id   = 0;
			ie.src_bus_irq  = (uint8_t)k;
			ie.dst_apic_id  = ioapic_id;
			ie.dst_apic_pin = (uint8_t)k;
			if ((rc = write_mem(off, &ie, sizeof(ie))) != 0)
				return (rc);
			off += sizeof(ie);
		}

	return (0);
}
