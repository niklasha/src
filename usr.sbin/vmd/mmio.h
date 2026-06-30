/*	$OpenBSD: mmio.h,v 1.2 2024/07/09 09:31:37 dv Exp $	*/

/*
 * Copyright (c) 2022 Dave Voutila <dv@openbsd.org>
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

#ifndef _MMIO_H_
#define _MMIO_H_

#include <sys/types.h>

/* Code segment bits  */
#define CS_L		(1 << 13)
#define CS_D		(1 << 14)

#define EFLAGS_VM	(1 << 17)	/* Virtual 8086 Mode enabled */

/* Instruction Prefixes (SDM Vol 2, 2.1.1) */
#define LEG_1_LOCK	0xF0
#define LEG_1_REPNE	0xF2
#define LEG_1_REP	0xF3
#define LEG_2_CS	0x2E
#define LEG_2_SS	0x36
#define LEG_2_DS	0x3E
#define LEG_2_ES	0x26
#define LEG_2_FS	0x64
#define LEG_2_GS	0x65
#define LEG_3_OPSZ	0x66		/* Operand size override */
#define LEG_4_ADDRSZ	0x67		/* Address size override */

/* REX prefix bit fields */
#define REX_B		0x01
#define REX_X		0x02
#define REX_R		0x04
#define REX_W		0x08
#define REX_BASE	0x40

#define REX_NONE	0x00

/* VEX prefixes (unsupported) */
#define VEX_2_BYTE	0xC5
#define VEX_3_BYTE	0xC4

#define ESCAPE		0x0F

struct x86_prefix {
	uint8_t		pfx_group1;	/* LOCK, REP, or REPNE */
	uint8_t		pfx_group2;	/* Segment overrides */
	uint8_t		pfx_group3;	/* Operand size override */
	uint8_t		pfx_group4;	/* Address size override */
	uint8_t		pfx_rex;	/* REX prefix for long mode */
};

enum x86_opcode_type {
	OP_UNKNOWN = 0,		/* Default value when undecoded. */
	OP_IN,
	OP_INS,
	OP_MOV,
	OP_MOVZX,
	OP_MOVSX,
	OP_OUT,
	OP_OUTS,
	OP_TEST,
	OP_ADD,
	OP_OR,
	OP_AND,
	OP_SUB,
	OP_XOR,
	OP_CMP,
	OP_XCHG,
	OP_BTS,
	OP_BTR,
	OP_BTC,
	OP_BT,
	OP_GROUP1,		/* 0x81/0x83: resolved to ALU op after ModRM */
	OP_BT_GROUP,		/* 0x0F BA: resolved to BT* after ModRM */
	OP_TWO_BYTE,		/* Opcode is two bytes, not one. */
	OP_UNSUPPORTED,		/* Valid decode, but no current support. */
};

/* Instruction Operand Encoding as described in the SDM Vol 2, Ch 3-5. */
enum x86_operand_enc {
	OP_ENC_UNKNOWN = 0,
	OP_ENC_I,		/* Only immediate operand */
	OP_ENC_MI,		/* Immediate to ModRM */
	OP_ENC_MR,		/* Register to ModRM */
	OP_ENC_RM,		/* ModRm to Register */
	OP_ENC_FD,		/* Value @ segment offset to RAX */
	OP_ENC_TD,		/* RAX to segment offset */
	OP_ENC_OI,		/* Immediate to Register (no emul. needed!) */
	OP_ENC_ZO,		/* No ModRM byte. */
};

/* Displacement bytes */
enum x86_disp_type {
	DISP_NONE = 0,
	DISP_0,
	DISP_1,
	DISP_2,			/* Requires Legacy prefix LEG_4_ADDRSZ */
	DISP_4,
};

struct x86_opcode {
	uint8_t			op_bytes[2];		/* VEX unsupported */
	uint8_t			op_bytes_len;		/* Length of opcode */
	enum x86_opcode_type	op_type;		/* Type of opcode */
	enum x86_operand_enc	op_encoding;		/* Operand encoding */
};

struct x86_insn {
	uint8_t			insn_bytes[15];		/* Original payload */
	uint8_t			insn_bytes_len;		/* Size of payload */
	int			insn_cpu_mode;		/* CPU mode */

	struct x86_prefix 	insn_prefix;		/* Combined prefixes */
	struct x86_opcode	insn_opcode;

	uint8_t			insn_modrm;		/* ModR/M */
#define MODRM_MOD(x)		((x >> 6) & 0x3)
#define MODRM_REGOP(x)		((x >> 3) & 0x7)
#define MODRM_RM(x)		((x >> 0) & 0x7)
	uint8_t			insn_modrm_valid;	/* Is ModR/M set? */

	vaddr_t			insn_gva;		/* Guest Virtual Addr */
	int			insn_reg;		/* Register */

	uint8_t			insn_sib;		/* Scale-Index-Base */
#define SIB_SCALE(x)		(((x) >> 6) & 0x3)
#define SIB_INDEX(x)		(((x) >> 3) & 0x7)
#define SIB_BASE(x)		(((x) >> 0) & 0x7)
	uint8_t			insn_sib_valid;		/* SIB byte set? */

	uint64_t		insn_disp;		/* Displacement */
	enum x86_disp_type	insn_disp_type;

	uint64_t		insn_immediate;		/* Immediate data */
	uint8_t			insn_immediate_len;
};

int	insn_decode(struct vm_exit *, struct x86_insn *);
int	insn_emulate(struct vm_exit *, struct x86_insn *);

/* From x86_vm.c -- walks guest page tables to translate GVA to GPA. */
int	translate_gva(struct vm_exit *, uint64_t, uint64_t *, int);

/*
 * Register a MMIO handler for a GPA range.  Used by LAPIC/IOAPIC and
 * any other device that needs to trap MMIO accesses from the guest.
 * Returns 0 on success, -1 if the per-VM handler table is full.
 */
int	mmio_register(uint64_t, uint64_t,
	    int (*)(uint64_t, uint8_t, uint64_t *, void *),
	    int (*)(uint64_t, uint8_t, uint64_t, void *),
	    void *);

/*
 * Relocate a registered handler (matched by cookie) when the guest
 * reprograms the device's MMIO BAR.  Returns 0 if moved, -1 if no match.
 */
int	mmio_move(void *cookie, uint64_t new_base);

#endif /* _MMIO_H_ */
