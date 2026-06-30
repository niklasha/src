/*	$OpenBSD: x86_mmio.c,v 1.1 2024/07/10 10:41:19 dv Exp $	*/
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

#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <machine/specialreg.h>

#include "vmd.h"
#include "mmio.h"

#define MMIO_DEBUG 0

extern char* __progname;

/*
 * SMP/MMIO: dispatch table for userland MMIO emulation.
 * Devices (LAPIC, IOAPIC, ...) register a GPA range and read/write callbacks
 * via mmio_register().  emulate_mov uses the table to route accesses.
 * Per-VM scope: each vm process has its own table.
 */
#define MMIO_MAX_HANDLERS	8

struct mmio_handler {
	uint64_t	 base;
	uint64_t	 size;
	int		(*read)(uint64_t off, uint8_t bytes, uint64_t *val,
			    void *cookie);
	int		(*write)(uint64_t off, uint8_t bytes, uint64_t val,
			    void *cookie);
	void		*cookie;
};

static struct mmio_handler	 mmio_handlers[MMIO_MAX_HANDLERS];
static int			 mmio_n_handlers;

/*
 * Must be called before vcpu threads start; table is read
 * lock-free from multiple vcpu threads after that.
 */
int
mmio_register(uint64_t base, uint64_t size,
    int (*read)(uint64_t, uint8_t, uint64_t *, void *),
    int (*write)(uint64_t, uint8_t, uint64_t, void *),
    void *cookie)
{
	if (mmio_n_handlers >= MMIO_MAX_HANDLERS)
		return (-1);
	mmio_handlers[mmio_n_handlers++] = (struct mmio_handler){
		.base = base, .size = size,
		.read = read, .write = write, .cookie = cookie,
	};
	return (0);
}

/*
 * Relocate a previously-registered handler (matched by cookie) to a new
 * base address.  The guest reprograms a device's MMIO BAR during PCI
 * resource assignment, which moves the GPA window the handler covers;
 * unlike I/O BARs (re-read live from config space on each access), an
 * MMIO handler snapshots its base and must be told about the move.
 *
 * BAR assignment happens during early single-threaded boot, so updating
 * the base (a single aligned store, read lock-free by mmio_find on other
 * vcpu threads) does not race with live MMIO to this window.  Returns 0
 * if a handler matched, -1 otherwise.
 */
int
mmio_move(void *cookie, uint64_t new_base)
{
	int i;
	for (i = 0; i < mmio_n_handlers; i++) {
		if (mmio_handlers[i].cookie == cookie) {
			mmio_handlers[i].base = new_base;
			return (0);
		}
	}
	return (-1);
}

static struct mmio_handler *
mmio_find(uint64_t gpa)
{
	int i;
	struct mmio_handler *h;

	for (i = 0; i < mmio_n_handlers; i++) {
		h = &mmio_handlers[i];
		if (gpa >= h->base && gpa < h->base + h->size)
			return (h);
	}
	return (NULL);
}

/*
 * Operand byte-size table for MOV variants we care about (MMIO targets).
 * For unknown opcodes we fall back to 4 -- the common case for LAPIC
 * register access from a 64-bit kernel.  Refined as needed.
 */
static uint8_t
mov_operand_bytes(struct x86_insn *insn)
{
	uint8_t op;

	if (insn->insn_opcode.op_bytes_len < 1)
		return (4);
	op = insn->insn_opcode.op_bytes[0];

	/* MOV r/m8, r8 / MOV r8, r/m8 */
	if (op == 0x88 || op == 0x8A || op == 0xA0 || op == 0xA2 ||
	    op == 0xC6)
		return (1);

	/* For the 16/32/64-bit MOV variants, check REX.W and 0x66 prefix. */
	if (insn->insn_prefix.pfx_rex & REX_W)
		return (8);
	if (insn->insn_prefix.pfx_group3 == LEG_3_OPSZ)
		return (2);
	return (4);
}

/*
 * alu_operand_bytes
 *
 * Determine operand size for ALU instructions (ADD/OR/AND/SUB/XOR/CMP).
 * 8-bit forms use odd-1 opcodes (0x00/0x02 vs 0x01/0x03), but all the
 * MMIO-relevant ALU opcodes in our table are the 16/32/64-bit forms.
 * Group 1 (0x81/0x83) is always 16/32/64-bit (the imm size differs but
 * the r/m operand size follows the standard REX.W / 0x66 rules).
 */
static uint8_t
alu_operand_bytes(struct x86_insn *insn)
{
	if (insn->insn_prefix.pfx_rex & REX_W)
		return (8);
	if (insn->insn_prefix.pfx_group3 == LEG_3_OPSZ)
		return (2);
	return (4);
}

static inline uint64_t
mask_operand(uint64_t val, uint8_t bytes)
{
	switch (bytes) {
	case 1: return (val & 0xffULL);
	case 2: return (val & 0xffffULL);
	case 4: return (val & 0xffffffffULL);
	default: return (val);
	}
}

static inline void
write_gpr(uint64_t *gprs, int reg, uint64_t val, uint8_t bytes)
{
	switch (bytes) {
	case 8:
		gprs[reg] = val;
		break;
	case 4:
		gprs[reg] = val & 0xffffffffULL;
		break;
	case 2:
		gprs[reg] = (gprs[reg] & ~0xffffULL) | (val & 0xffffULL);
		break;
	case 1:
		gprs[reg] = (gprs[reg] & ~0xffULL) | (val & 0xffULL);
		break;
	}
}

static inline uint64_t
sign_extend8(uint64_t val)
{
	return ((uint64_t)(int64_t)(int8_t)(uint8_t)val);
}

static inline uint64_t
sign_extend16(uint64_t val)
{
	return ((uint64_t)(int64_t)(int16_t)(uint16_t)val);
}

static inline uint64_t
sign_extend32(uint64_t val)
{
	return ((uint64_t)(int64_t)(int32_t)(uint32_t)val);
}

static inline int
parity_even(uint8_t val)
{
	val ^= val >> 4;
	val ^= val >> 2;
	val ^= val >> 1;
	return (!(val & 1));
}

/* Operation descriptor for table-driven MMIO emulation. */
#define MMIO_F_RFLAGS		0x01	/* update RFLAGS after compute */
#define MMIO_F_WRITEBACK	0x02	/* write result to dst (reg or mem) */
/* SUB/CMP-style borrow semantics for flags */
#define MMIO_F_SUB		0x04
#define MMIO_F_LOGIC		0x08	/* AND/OR/XOR: CF=OF=0, AF undef */
/* swap: write old mem to reg, old reg to mem */
#define MMIO_F_XCHG		0x10

static uint64_t
op_add(uint64_t a, uint64_t b)
{
	return (a + b);
}

static uint64_t
op_sub(uint64_t a, uint64_t b)
{
	return (a - b);
}

static uint64_t
op_or(uint64_t a, uint64_t b)
{
	return (a | b);
}

static uint64_t
op_and(uint64_t a, uint64_t b)
{
	return (a & b);
}

static uint64_t
op_xor(uint64_t a, uint64_t b)
{
	return (a ^ b);
}

static uint64_t
op_mov(uint64_t a, uint64_t b)
{
	return (b);
}

struct mmio_op {
	uint64_t	(*compute)(uint64_t, uint64_t);
	int		 flags;
};

static const struct mmio_op *
mmio_op_for(enum x86_opcode_type op)
{
	static const struct mmio_op ops[] = {
		[OP_MOV]  = { op_mov, MMIO_F_WRITEBACK },
		[OP_ADD]  = { op_add, MMIO_F_RFLAGS | MMIO_F_WRITEBACK },
		[OP_OR]   = { op_or,
		    MMIO_F_RFLAGS | MMIO_F_WRITEBACK | MMIO_F_LOGIC },
		[OP_AND]  = { op_and,
		    MMIO_F_RFLAGS | MMIO_F_WRITEBACK | MMIO_F_LOGIC },
		[OP_SUB]  = { op_sub,
		    MMIO_F_RFLAGS | MMIO_F_WRITEBACK | MMIO_F_SUB },
		[OP_XOR]  = { op_xor,
		    MMIO_F_RFLAGS | MMIO_F_WRITEBACK | MMIO_F_LOGIC },
		[OP_CMP]  = { op_sub, MMIO_F_RFLAGS | MMIO_F_SUB },
		[OP_TEST] = { op_and, MMIO_F_RFLAGS | MMIO_F_LOGIC },
		[OP_XCHG] = { op_mov, MMIO_F_WRITEBACK | MMIO_F_XCHG },
	};
	if (op >= nitems(ops) || ops[op].compute == NULL)
		return (NULL);
	return (&ops[op]);
}

struct x86_decode_state {
	uint8_t	s_bytes[15];
	size_t	s_len;
	size_t	s_idx;
};

enum decode_result {
	DECODE_ERROR = 0,	/* Something went wrong. */
	DECODE_DONE,		/* Decode success and no more work needed. */
	DECODE_MORE,		/* Decode success and more work required. */
};

static const char *str_cpu_mode(int);
static const char *str_decode_res(enum decode_result);
static const char *str_opcode(struct x86_opcode *);
static const char *str_operand_enc(struct x86_opcode *);
static const char *str_reg(int);
static const char *str_sreg(int);
static int detect_cpu_mode(struct vcpu_reg_state *);

static enum decode_result decode_prefix(struct x86_decode_state *,
    struct x86_insn *);
static enum decode_result decode_opcode(struct x86_decode_state *,
    struct x86_insn *);
static enum decode_result decode_modrm(struct x86_decode_state *,
    struct x86_insn *);
static int get_modrm_reg(struct x86_insn *);
static int get_modrm_addr(struct x86_insn *, struct vcpu_reg_state *vrs);
static enum decode_result decode_disp(struct x86_decode_state *,
    struct x86_insn *);
static enum decode_result decode_sib(struct x86_decode_state *,
    struct x86_insn *);
static enum decode_result decode_imm(struct x86_decode_state *,
    struct x86_insn *);

static enum decode_result peek_byte(struct x86_decode_state *, uint8_t *);
static enum decode_result next_byte(struct x86_decode_state *, uint8_t *);
static enum decode_result next_value(struct x86_decode_state *, size_t,
    uint64_t *);
static int is_valid_state(struct x86_decode_state *, const char *);

static void update_rflags_alu(uint64_t *, uint64_t, uint64_t, uint64_t,
    uint8_t, int, int);
static int emulate_generic(struct x86_insn *, struct vm_exit *);
static int emulate_movzx(struct x86_insn *, struct vm_exit *);
static int emulate_movsx(struct x86_insn *, struct vm_exit *);
static int emulate_bt_group(struct x86_insn *, struct vm_exit *);

/* Lookup table for 1-byte opcodes, in opcode alphabetical order. */
const enum x86_opcode_type x86_1byte_opcode_tbl[256] = {
	/* ALU: r/m, r  (MR encoding -- write to memory) */
	[0x01] = OP_ADD,
	[0x09] = OP_OR,
	[0x21] = OP_AND,
	[0x29] = OP_SUB,
	[0x31] = OP_XOR,
	[0x39] = OP_CMP,

	/* ALU: r, r/m  (RM encoding -- read from memory) */
	[0x03] = OP_ADD,
	[0x0B] = OP_OR,
	[0x23] = OP_AND,
	[0x2B] = OP_SUB,
	[0x33] = OP_XOR,
	[0x3B] = OP_CMP,

	/* Group 1: ALU r/m, imm  (MI encoding, /reg selects operation) */
	[0x81] = OP_GROUP1,
	[0x83] = OP_GROUP1,

	/* XCHG r/m, r */
	[0x87] = OP_XCHG,

	/* MOV */
	[0x88] = OP_MOV,
	[0x89] = OP_MOV,
	[0x8A] = OP_MOV,
	[0x8B] = OP_MOV,
	[0x8C] = OP_MOV,
	[0xA0] = OP_MOV,
	[0xA1] = OP_MOV,
	[0xA2] = OP_MOV,
	[0xA3] = OP_MOV,
	[0xC6] = OP_MOV,
	[0xC7] = OP_MOV,

	/* MOVS */
	[0xA4] = OP_UNSUPPORTED,
	[0xA5] = OP_UNSUPPORTED,

	/* TEST r/m, imm -- group 3, sub-opcodes /0 and /1 only. */
	[0xF6] = OP_TEST,
	[0xF7] = OP_TEST,

	[ESCAPE] = OP_TWO_BYTE,
};

/* Lookup table for 1-byte operand encodings, in opcode alphabetical order. */
const enum x86_operand_enc x86_1byte_operand_enc_tbl[256] = {
	/* ALU: r/m, r  (MR) */
	[0x01] = OP_ENC_MR,
	[0x09] = OP_ENC_MR,
	[0x21] = OP_ENC_MR,
	[0x29] = OP_ENC_MR,
	[0x31] = OP_ENC_MR,
	[0x39] = OP_ENC_MR,

	/* ALU: r, r/m  (RM) */
	[0x03] = OP_ENC_RM,
	[0x0B] = OP_ENC_RM,
	[0x23] = OP_ENC_RM,
	[0x2B] = OP_ENC_RM,
	[0x33] = OP_ENC_RM,
	[0x3B] = OP_ENC_RM,

	/* Group 1: r/m, imm (MI) */
	[0x81] = OP_ENC_MI,
	[0x83] = OP_ENC_MI,

	/* XCHG r/m, r  (MR) */
	[0x87] = OP_ENC_MR,

	/* MOV */
	[0x88] = OP_ENC_MR,
	[0x89] = OP_ENC_MR,
	[0x8A] = OP_ENC_RM,
	[0x8B] = OP_ENC_RM,
	[0x8C] = OP_ENC_MR,
	[0xA0] = OP_ENC_FD,
	[0xA1] = OP_ENC_FD,
	[0xA2] = OP_ENC_TD,
	[0xA3] = OP_ENC_TD,
	[0xC6] = OP_ENC_MI,
	[0xC7] = OP_ENC_MI,

	/* MOVS */
	[0xA4] = OP_ENC_ZO,
	[0xA5] = OP_ENC_ZO,

	/* TEST r/m, imm */
	[0xF6] = OP_ENC_MI,
	[0xF7] = OP_ENC_MI,
};

const enum x86_opcode_type x86_2byte_opcode_tbl[256] = {
	/* MOVZX */
	[0xB6] = OP_MOVZX,
	[0xB7] = OP_MOVZX,

	/* MOVSX */
	[0xBE] = OP_MOVSX,
	[0xBF] = OP_MOVSX,

	/* BT/BTS/BTR/BTC group (0x0F BA /reg selects variant) */
	[0xBA] = OP_BT_GROUP,
};

const enum x86_operand_enc x86_2byte_operand_enc_table[256] = {
	/* MOVZX */
	[0xB6] = OP_ENC_RM,
	[0xB7] = OP_ENC_RM,

	/* MOVSX */
	[0xBE] = OP_ENC_RM,
	[0xBF] = OP_ENC_RM,

	/* BT group: r/m, imm8 (MI) */
	[0xBA] = OP_ENC_MI,
};

/*
 * peek_byte
 *
 * Fetch the next byte fron the instruction bytes without advancing the
 * position in the stream.
 *
 * Return values:
 *  DECODE_DONE: byte was found and is the last in the stream
 *  DECODE_MORE: byte was found and there are more remaining to be read
 *  DECODE_ERROR: state is invalid and not byte was found, *byte left unchanged
 */
static enum decode_result
peek_byte(struct x86_decode_state *state, uint8_t *byte)
{
	enum decode_result res;

	if (state == NULL)
		return (DECODE_ERROR);

	if (state->s_idx == state->s_len)
		return (DECODE_ERROR);

	if (state->s_idx + 1 == state->s_len)
		res = DECODE_DONE;
	else
		res = DECODE_MORE;

	if (byte != NULL)
		*byte = state->s_bytes[state->s_idx];
	return (res);
}

/*
 * next_byte
 *
 * Fetch the next byte fron the instruction bytes, advancing the position in the
 * stream and mutating decode state.
 *
 * Return values:
 *  DECODE_DONE: byte was found and is the last in the stream
 *  DECODE_MORE: byte was found and there are more remaining to be read
 *  DECODE_ERROR: state is invalid and not byte was found, *byte left unchanged
 */
static enum decode_result
next_byte(struct x86_decode_state *state, uint8_t *byte)
{
	uint8_t next;

	/* Cheat and see if we're going to fail. */
	if (peek_byte(state, &next) == DECODE_ERROR)
		return (DECODE_ERROR);

	if (byte != NULL)
		*byte = next;
	state->s_idx++;

	return (state->s_idx < state->s_len ? DECODE_MORE : DECODE_DONE);
}

/*
 * Fetch the next `n' bytes as a single uint64_t value.
 */
static enum decode_result
next_value(struct x86_decode_state *state, size_t n, uint64_t *value)
{
	uint8_t bytes[8];
	size_t i;
	enum decode_result res;

	if (value == NULL)
		return (DECODE_ERROR);

	if (n == 0 || n > sizeof(bytes))
		return (DECODE_ERROR);

	memset(bytes, 0, sizeof(bytes));
	for (i = 0; i < n; i++)
		if ((res = next_byte(state, &bytes[i])) == DECODE_ERROR)
			return (DECODE_ERROR);

	*value = *((uint64_t*)bytes);

	return (res);
}

/*
 * is_valid_state
 *
 * Validate the decode state looks viable.
 *
 * Returns:
 *  1: if state is valid
 *  0: if an invariant is detected
 */
static int
is_valid_state(struct x86_decode_state *state, const char *fn_name)
{
	const char *s = (fn_name != NULL) ? fn_name : __func__;

	if (state == NULL) {
		log_warnx("%s: null state", s);
		return (0);
	}
	if (state->s_len > sizeof(state->s_bytes)) {
		log_warnx("%s: invalid length", s);
		return (0);
	}
	if (state->s_idx + 1 > state->s_len) {
		log_warnx("%s: invalid index", s);
		return (0);
	}

	return (1);
}

#if MMIO_DEBUG
static void
dump_regs(struct vcpu_reg_state *vrs)
{
	size_t i;
	struct vcpu_segment_info *vsi;

	for (i = 0; i < VCPU_REGS_NGPRS; i++)
		log_debug("%s: %s 0x%llx", __progname, str_reg(i),
		    vrs->vrs_gprs[i]);

	for (i = 0; i < VCPU_REGS_NSREGS; i++) {
		vsi = &vrs->vrs_sregs[i];
		log_debug("%s: %s { sel: 0x%04x, lim: 0x%08x, ar: 0x%08x, "
		    "base: 0x%llx }", __progname, str_sreg(i),
		    vsi->vsi_sel, vsi->vsi_limit, vsi->vsi_ar, vsi->vsi_base);
	}
}

static void
dump_insn(struct x86_insn *insn)
{
	log_debug("instruction { %s, enc=%s, len=%d, mod=0x%02x, ("
	    "reg=%s, addr=0x%lx) sib=0x%02x }",
	    str_opcode(&insn->insn_opcode),
	    str_operand_enc(&insn->insn_opcode), insn->insn_bytes_len,
	    insn->insn_modrm, str_reg(insn->insn_reg),
	    insn->insn_gva, insn->insn_sib);
}
#endif /* MMIO_DEBUG */

__unused static const char *
str_cpu_mode(int mode)
{
	switch (mode) {
	case VMM_CPU_MODE_REAL: return "REAL";
	case VMM_CPU_MODE_PROT: return "PROT";
	case VMM_CPU_MODE_PROT32: return "PROT32";
	case VMM_CPU_MODE_COMPAT: return "COMPAT";
	case VMM_CPU_MODE_LONG: return "LONG";
	default: return "UNKNOWN";
	}
}

__unused static const char *
str_decode_res(enum decode_result res) {
	switch (res) {
	case DECODE_DONE: return "DONE";
	case DECODE_MORE: return "MORE";
	case DECODE_ERROR: return "ERROR";
	default: return "UNKNOWN";
	}
}

static const char *
str_opcode(struct x86_opcode *opcode)
{
	switch (opcode->op_type) {
	case OP_IN: return "IN";
	case OP_INS: return "INS";
	case OP_MOV: return "MOV";
	case OP_MOVZX: return "MOVZX";
	case OP_MOVSX: return "MOVSX";
	case OP_OUT: return "OUT";
	case OP_OUTS: return "OUTS";
	case OP_TEST: return "TEST";
	case OP_ADD: return "ADD";
	case OP_OR: return "OR";
	case OP_AND: return "AND";
	case OP_SUB: return "SUB";
	case OP_XOR: return "XOR";
	case OP_CMP: return "CMP";
	case OP_XCHG: return "XCHG";
	case OP_BT: return "BT";
	case OP_BTS: return "BTS";
	case OP_BTR: return "BTR";
	case OP_BTC: return "BTC";
	case OP_UNSUPPORTED: return "UNSUPPORTED";
	default: return "UNKNOWN";
	}
}

__unused static const char *
str_operand_enc(struct x86_opcode *opcode)
{
	switch (opcode->op_encoding) {
	case OP_ENC_I: return "I";
	case OP_ENC_MI: return "MI";
	case OP_ENC_MR: return "MR";
	case OP_ENC_RM: return "RM";
	case OP_ENC_FD: return "FD";
	case OP_ENC_TD: return "TD";
	case OP_ENC_OI: return "OI";
	case OP_ENC_ZO: return "ZO";
	default: return "UNKNOWN";
	}
}

__unused static const char *
str_reg(int reg) {
	switch (reg) {
	case VCPU_REGS_RAX: return "RAX";
	case VCPU_REGS_RCX: return "RCX";
	case VCPU_REGS_RDX: return "RDX";
	case VCPU_REGS_RBX: return "RBX";
	case VCPU_REGS_RSI: return "RSI";
	case VCPU_REGS_RDI: return "RDI";
	case VCPU_REGS_R8:  return " R8";
	case VCPU_REGS_R9:  return " R9";
	case VCPU_REGS_R10: return "R10";
	case VCPU_REGS_R11: return "R11";
	case VCPU_REGS_R12: return "R12";
	case VCPU_REGS_R13: return "R13";
	case VCPU_REGS_R14: return "R14";
	case VCPU_REGS_R15: return "R15";
	case VCPU_REGS_RSP: return "RSP";
	case VCPU_REGS_RBP: return "RBP";
	case VCPU_REGS_RIP: return "RIP";
	case VCPU_REGS_RFLAGS: return "RFLAGS";
	default: return "UNKNOWN";
	}
}

__unused static const char *
str_sreg(int sreg) {
	switch (sreg) {
	case VCPU_REGS_CS: return "CS";
	case VCPU_REGS_DS: return "DS";
	case VCPU_REGS_ES: return "ES";
	case VCPU_REGS_FS: return "FS";
	case VCPU_REGS_GS: return "GS";
	case VCPU_REGS_SS: return "SS";
	case VCPU_REGS_LDTR: return "LDTR";
	case VCPU_REGS_TR: return "TR";
	default: return "UNKNOWN";
	}
}

static int
detect_cpu_mode(struct vcpu_reg_state *vrs)
{
	uint64_t cr0, cr4, cs, efer, rflags;

	/* Is protected mode enabled? */
	cr0 = vrs->vrs_crs[VCPU_REGS_CR0];
	if (!(cr0 & CR0_PE))
		return (VMM_CPU_MODE_REAL);

	cr4 = vrs->vrs_crs[VCPU_REGS_CR4];
	cs = vrs->vrs_sregs[VCPU_REGS_CS].vsi_ar;
	efer = vrs->vrs_msrs[VCPU_REGS_EFER];
	rflags = vrs->vrs_gprs[VCPU_REGS_RFLAGS];

	/* Check for Long modes. */
	if ((efer & EFER_LME) && (cr4 & CR4_PAE) && (cr0 & CR0_PG)) {
		if (cs & CS_L) {
			/* Long Modes */
			if (!(cs & CS_D))
				return (VMM_CPU_MODE_LONG);
			log_warnx("%s: invalid cpu mode", __progname);
			return (VMM_CPU_MODE_UNKNOWN);
		} else {
			/* Compatibility Modes */
			if (cs & CS_D) /* XXX Add Compat32 mode */
				return (VMM_CPU_MODE_UNKNOWN);
			return (VMM_CPU_MODE_COMPAT);
		}
	}

	/* Check for 32-bit Protected Mode. */
	if (cs & CS_D)
		return (VMM_CPU_MODE_PROT32);

	/* Check for virtual 8086 mode. */
	if (rflags & EFLAGS_VM) {
		/* XXX add Virtual8086 mode */
		log_warnx("%s: Virtual 8086 mode", __progname);
		return (VMM_CPU_MODE_UNKNOWN);
	}

	/* Can't determine mode. */
	log_warnx("%s: invalid cpu mode", __progname);
	return (VMM_CPU_MODE_UNKNOWN);
}

static enum decode_result
decode_prefix(struct x86_decode_state *state, struct x86_insn *insn)
{
	enum decode_result res = DECODE_ERROR;
	struct x86_prefix *prefix;
	uint8_t byte;

	if (!is_valid_state(state, __func__) || insn == NULL)
		return (-1);

	prefix = &insn->insn_prefix;
	memset(prefix, 0, sizeof(*prefix));

	/*
	 * Decode prefixes. The last of its kind wins. The behavior is undefined
	 * in the Intel SDM (see Vol 2, 2.1.1 Instruction Prefixes.)
	 */
	while ((res = peek_byte(state, &byte)) != DECODE_ERROR) {
		switch (byte) {
		case LEG_1_LOCK:
		case LEG_1_REPNE:
		case LEG_1_REP:
			prefix->pfx_group1 = byte;
			break;
		case LEG_2_CS:
		case LEG_2_SS:
		case LEG_2_DS:
		case LEG_2_ES:
		case LEG_2_FS:
		case LEG_2_GS:
			prefix->pfx_group2 = byte;
			break;
		case LEG_3_OPSZ:
			prefix->pfx_group3 = byte;
			break;
		case LEG_4_ADDRSZ:
			prefix->pfx_group4 = byte;
			break;
		case REX_BASE...REX_BASE + 0x0F:
			if (insn->insn_cpu_mode == VMM_CPU_MODE_LONG)
				prefix->pfx_rex = byte;
			else /* INC encountered */
				return (DECODE_ERROR);
			break;
		case VEX_2_BYTE:
		case VEX_3_BYTE:
			log_warnx("%s: VEX not supported", __func__);
			return (DECODE_ERROR);
		default:
			/* Something other than a valid prefix. */
			return (DECODE_MORE);
		}
		/* Advance our position. */
		next_byte(state, NULL);
	}

	return (res);
}

static enum decode_result
decode_modrm(struct x86_decode_state *state, struct x86_insn *insn)
{
	enum decode_result res;
	uint8_t byte = 0;
	uint64_t moffs;
	size_t asz;

	if (!is_valid_state(state, __func__) || insn == NULL)
		return (DECODE_ERROR);

	insn->insn_modrm_valid = 0;

	/* Check the operand encoding to see if we fetch a byte or abort. */
	switch (insn->insn_opcode.op_encoding) {
	case OP_ENC_MR:
	case OP_ENC_RM:
	case OP_ENC_MI:
		res = next_byte(state, &byte);
		if (res == DECODE_ERROR) {
			log_warnx("%s: failed to get modrm byte", __func__);
			break;
		}
		insn->insn_modrm = byte;
		insn->insn_modrm_valid = 1;
		break;

	case OP_ENC_FD:
	case OP_ENC_TD:
		/*
		 * FD/TD: direct moffs address, no ModRM.  Size is 2
		 * bytes in 16-bit mode, 4 bytes in 32-bit mode.
		 */
		{
			moffs = 0;
			if (insn->insn_cpu_mode == VMM_CPU_MODE_REAL)
				asz = (insn->insn_prefix.pfx_group4 ==
				    LEG_4_ADDRSZ) ? 4 : 2;
			else if (insn->insn_cpu_mode == VMM_CPU_MODE_PROT ||
			    insn->insn_cpu_mode == VMM_CPU_MODE_PROT32)
				asz = (insn->insn_prefix.pfx_group4 ==
				    LEG_4_ADDRSZ) ? 2 : 4;
			else
				asz = (insn->insn_prefix.pfx_group4 ==
				    LEG_4_ADDRSZ) ? 4 : 8;
			res = next_value(state, asz, &moffs);
			if (res == DECODE_ERROR)
				break;
			insn->insn_gva = moffs;
			insn->insn_reg = VCPU_REGS_RAX;
		}
		break;

	case OP_ENC_I:
	case OP_ENC_OI:
		log_warnx("%s: instruction does not need memory assist",
		    __func__);
		res = DECODE_ERROR;
		break;

	default:
		/* Peek to see if we're done decode. */
		res = peek_byte(state, NULL);
	}

	return (res);
}

static int
get_modrm_reg(struct x86_insn *insn)
{
	if (insn == NULL)
		return (-1);

	if (insn->insn_modrm_valid) {
		switch (MODRM_REGOP(insn->insn_modrm)) {
		case 0:
			insn->insn_reg = VCPU_REGS_RAX;
			break;
		case 1:
			insn->insn_reg = VCPU_REGS_RCX;
			break;
		case 2:
			insn->insn_reg = VCPU_REGS_RDX;
			break;
		case 3:
			insn->insn_reg = VCPU_REGS_RBX;
			break;
		case 4:
			insn->insn_reg = VCPU_REGS_RSP;
			break;
		case 5:
			insn->insn_reg = VCPU_REGS_RBP;
			break;
		case 6:
			insn->insn_reg = VCPU_REGS_RSI;
			break;
		case 7:
			insn->insn_reg = VCPU_REGS_RDI;
			break;
		}
	}

	/* REX R bit selects extended registers in LONG mode. */
	if (insn->insn_prefix.pfx_rex & REX_R)
		insn->insn_reg += 8;

	return (0);
}

static int
get_modrm_addr(struct x86_insn *insn, struct vcpu_reg_state *vrs)
{
	uint8_t mod, rm;
	vaddr_t addr = 0x0UL;

	if (insn == NULL || vrs == NULL)
		return (-1);

	if (insn->insn_modrm_valid) {
		int reg = -1;

		rm = MODRM_RM(insn->insn_modrm);
		mod = MODRM_MOD(insn->insn_modrm);

		switch (rm) {
		case 0b000:
			reg = VCPU_REGS_RAX;
			break;
		case 0b001:
			reg = VCPU_REGS_RCX;
			break;
		case 0b010:
			reg = VCPU_REGS_RDX;
			break;
		case 0b011:
			reg = VCPU_REGS_RBX;
			break;
		case 0b100:
			/*
			 * rm==4 with mod!=11 selects a SIB byte, whose base
			 * (including REX.B) is resolved separately; only
			 * mod==11 names a register directly here.
			 */
			if (mod == 0b11)
				reg = VCPU_REGS_RSP;
			break;
		case 0b101:
			/*
			 * mod==0 with rm==5 is [RIP+disp32] (resolved
			 * post-decode); REX.B does not apply there.
			 */
			if (mod != 0b00)
				reg = VCPU_REGS_RBP;
			break;
		case 0b110:
			reg = VCPU_REGS_RSI;
			break;
		case 0b111:
			reg = VCPU_REGS_RDI;
			break;
		}

		/*
		 * REX.B extends the ModRM base register in LONG mode, the
		 * same way REX.R extends ModRM.reg in get_modrm_reg().  It
		 * is deliberately not applied to the SIB (rm==4, mod!=11) or
		 * RIP-relative (rm==5, mod==0) forms, which leave reg == -1.
		 */
		if (reg != -1) {
			if (insn->insn_prefix.pfx_rex & REX_B)
				reg += 8;
			addr = vrs->vrs_gprs[reg];
		}

		insn->insn_gva = addr;
	}

	return (0);
}

static enum decode_result
decode_disp(struct x86_decode_state *state, struct x86_insn *insn)
{
	enum decode_result res = DECODE_ERROR;
	uint64_t disp = 0;

	if (!is_valid_state(state, __func__) || insn == NULL)
		return (DECODE_ERROR);

	if (!insn->insn_modrm_valid)
		return (DECODE_ERROR);

	switch (MODRM_MOD(insn->insn_modrm)) {
	case 0x00:
		/*
		 * mod==0/rm==5 always encodes a disp32; the
		 * semantics differ by mode (see below).
		 */
		if (MODRM_RM(insn->insn_modrm) == 5) {
			/*
			 * mod=0/rm=5: [disp32] in all modes.
			 * In LONG/COMPAT this is RIP-relative (resolved
			 * post-decode); in PROT32/PROT/REAL it is an
			 * absolute 32-bit address.
			 */
			insn->insn_disp_type = DISP_4;
			res = next_value(state, 4, &disp);
			if (res == DECODE_ERROR)
				return (res);
			insn->insn_disp = disp;
		} else if (MODRM_RM(insn->insn_modrm) == 4 &&
		    insn->insn_sib_valid &&
		    SIB_BASE(insn->insn_sib) == 5) {
			/*
			 * SIB-encoded absolute addressing: mod==0 with rm==4
			 * (SIB follows) and SIB.base==5 encodes a disp32 with
			 * no base register.  (REX.B does NOT extend the base
			 * here -- this is the special "no base" encoding.)
			 */
			insn->insn_disp_type = DISP_4;
			res = next_value(state, 4, &disp);
			if (res == DECODE_ERROR)
				return (res);
			insn->insn_disp = disp;
		} else {
			insn->insn_disp_type = DISP_0;
			res = DECODE_MORE;
		}
		break;
	case 0x01:
		insn->insn_disp_type = DISP_1;
		res = next_value(state, 1, &disp);
		if (res == DECODE_ERROR)
			return (res);
		insn->insn_disp = disp;
		break;
	case 0x02:
		if (insn->insn_prefix.pfx_group4 == LEG_4_ADDRSZ) {
			insn->insn_disp_type = DISP_2;
			res = next_value(state, 2, &disp);
		} else {
			insn->insn_disp_type = DISP_4;
			res = next_value(state, 4, &disp);
		}
		if (res == DECODE_ERROR)
			return (res);
		insn->insn_disp = disp;
		break;
	default:
		insn->insn_disp_type = DISP_NONE;
		res = DECODE_MORE;
	}

	return (res);
}

static enum decode_result
decode_opcode(struct x86_decode_state *state, struct x86_insn *insn)
{
	enum decode_result res;
	enum x86_opcode_type type;
	enum x86_operand_enc enc;
	struct x86_opcode *opcode = &insn->insn_opcode;
	uint8_t byte, byte2;

	if (!is_valid_state(state, __func__) || insn == NULL)
		return (-1);

	memset(opcode, 0, sizeof(*opcode));

	res = next_byte(state, &byte);
	if (res == DECODE_ERROR)
		return (res);

	type = x86_1byte_opcode_tbl[byte];
	switch(type) {
	case OP_UNKNOWN:
	case OP_UNSUPPORTED:
		log_warnx("%s: unsupported opcode 0x%02x", __func__, byte);
		return (DECODE_ERROR);

	case OP_TWO_BYTE:
		res = next_byte(state, &byte2);
		if (res == DECODE_ERROR)
			return (res);

		type = x86_2byte_opcode_tbl[byte2];
		if (type == OP_UNKNOWN || type == OP_UNSUPPORTED) {
			log_warnx("%s: unsupported 2-byte opcode 0x0F 0x%02x",
			    __func__, byte2);
			return (DECODE_ERROR);
		}

		opcode->op_bytes[0] = byte;
		opcode->op_bytes[1] = byte2;
		opcode->op_bytes_len = 2;
		enc = x86_2byte_operand_enc_table[byte2];
		break;

	default:
		/* We've potentially got a known 1-byte opcode. */
		opcode->op_bytes[0] = byte;
		opcode->op_bytes_len = 1;
		enc = x86_1byte_operand_enc_tbl[byte];
	}

	if (enc == OP_ENC_UNKNOWN)
		return (DECODE_ERROR);

	opcode->op_type = type;
	opcode->op_encoding = enc;

	return (res);
}

static enum decode_result
decode_sib(struct x86_decode_state *state, struct x86_insn *insn)
{
	enum decode_result res;
	uint8_t byte;

	if (!is_valid_state(state, __func__) || insn == NULL)
		return (-1);

	/* SIB is optional, so assume we will be continuing. */
	res = DECODE_MORE;

	insn->insn_sib_valid = 0;
	if (!insn->insn_modrm_valid)
		return (res);

	/* XXX is SIB valid in all cpu modes? */
	if (MODRM_RM(insn->insn_modrm) == 0b100) {
		res = next_byte(state, &byte);
		if (res != DECODE_ERROR) {
			insn->insn_sib_valid = 1;
			insn->insn_sib = byte;
		}
	}

	return (res);
}

static enum decode_result
decode_imm(struct x86_decode_state *state, struct x86_insn *insn)
{
	enum decode_result res;
	size_t num_bytes;
	uint64_t value;

	if (!is_valid_state(state, __func__) || insn == NULL)
		return (DECODE_ERROR);

	/* Only handle MI encoded instructions. Others shouldn't need assist. */
	if (insn->insn_opcode.op_encoding != OP_ENC_MI)
		return (DECODE_DONE);

	/* Exceptions related to MOV instructions. */
	if (insn->insn_opcode.op_type == OP_MOV) {
		switch (insn->insn_opcode.op_bytes[0]) {
		case 0xC6:
			num_bytes = 1;
			break;
		case 0xC7:
			if (insn->insn_cpu_mode == VMM_CPU_MODE_REAL)
				num_bytes = 2;
			else
				num_bytes = 4;
			break;
		default:
			log_warnx("%s: cannot decode immediate bytes for MOV",
			    __func__);
			return (DECODE_ERROR);
		}
	} else if (insn->insn_opcode.op_type == OP_TEST) {
		/*
		 * Group-3 TEST r/m, imm:
		 *   0xF6 -> 8-bit imm
		 *   0xF7 -> 16-bit imm if 0x66 prefix, else 32-bit
		 *           (even with REX.W: TEST r/m64 takes 32-bit imm
		 *           that is sign-extended).
		 */
		if (insn->insn_opcode.op_bytes[0] == 0xF6) {
			num_bytes = 1;
		} else if (insn->insn_prefix.pfx_group3 == LEG_3_OPSZ) {
			num_bytes = 2;
		} else {
			num_bytes = 4;
		}
	} else if (insn->insn_opcode.op_type == OP_GROUP1) {
		/*
		 * Group 1 immediate sizes:
		 *   0x81 -> 32-bit imm (sign-extended for REX.W 64-bit ops)
		 *          16-bit imm if 0x66 prefix
		 *   0x83 -> 8-bit sign-extended imm
		 */
		if (insn->insn_opcode.op_bytes[0] == 0x83) {
			num_bytes = 1;
		} else if (insn->insn_prefix.pfx_group3 == LEG_3_OPSZ) {
			num_bytes = 2;
		} else {
			num_bytes = 4;
		}
	} else if (insn->insn_opcode.op_type == OP_BT_GROUP) {
		/* BT/BTS/BTR/BTC r/m, imm8: always 1 byte immediate. */
		num_bytes = 1;
	} else {
		/* Fallback to interpreting based on cpu mode and REX. */
		if (insn->insn_cpu_mode == VMM_CPU_MODE_REAL)
			num_bytes = 2;
		else if (insn->insn_prefix.pfx_rex == REX_NONE)
			num_bytes = 4;
		else
			num_bytes = 8;
	}

	res = next_value(state, num_bytes, &value);
	if (res != DECODE_ERROR) {
		insn->insn_immediate = value;
		insn->insn_immediate_len = num_bytes;
	}

	return (res);
}


/*
 * insn_decode
 *
 * Decode an x86 instruction from the provided instruction bytes.
 *
 * Return values:
 *  0: successful decode
 *  Non-zero: an exception occurred during decode
 */
int
insn_decode(struct vm_exit *exit, struct x86_insn *insn)
{
	enum decode_result res;
	struct vcpu_reg_state *vrs = &exit->vrs;
	struct x86_decode_state state;
	char hexbuf[64];
	uint8_t *bytes, len;
	uint8_t mod, sscale, sindex, sbase, rm;
	int64_t disp, disp32;
	uint64_t ea;
	int has_base, index_reg, base_reg;
	int mode, i, hlen;

	if (exit == NULL || insn == NULL) {
		log_warnx("%s: invalid input", __func__);
		return (DECODE_ERROR);
	}

	bytes = exit->vee.vee_insn_bytes;
	len = exit->vee.vee_insn_len;

	/* 0. Initialize state and instruction objects. */
	memset(insn, 0, sizeof(*insn));
	memset(&state, 0, sizeof(state));
	state.s_len = len;
	memcpy(&state.s_bytes, bytes, len);

	/* 1. Detect CPU mode. */
	mode = detect_cpu_mode(vrs);
	if (mode == VMM_CPU_MODE_UNKNOWN) {
		log_warnx("%s: failed to identify cpu mode", __func__);
#if MMIO_DEBUG
		dump_regs(vrs);
#endif
		return (-1);
	}
	insn->insn_cpu_mode = mode;

#if MMIO_DEBUG
	log_debug("%s: cpu mode %s detected", __progname, str_cpu_mode(mode));
	printf("%s: got bytes: [ ", __progname);
	for (i = 0; i < len; i++) {
		printf("%02x ", bytes[i]);
	}
	printf("]\n");
#endif
	/* 2. Decode prefixes. */
	res = decode_prefix(&state, insn);
	if (res == DECODE_ERROR) {
		log_warnx("%s: error decoding prefixes", __func__);
		goto err;
	} else if (res == DECODE_DONE)
		goto done;

#if MMIO_DEBUG
	log_debug("%s: prefixes {g1: 0x%02x, g2: 0x%02x, g3: 0x%02x,"
	    " g4: 0x%02x,"
	    " rex: 0x%02x }", __progname, insn->insn_prefix.pfx_group1,
	    insn->insn_prefix.pfx_group2, insn->insn_prefix.pfx_group3,
	    insn->insn_prefix.pfx_group4, insn->insn_prefix.pfx_rex);
#endif

	/* 3. Pick apart opcode. Here we can start short-circuiting. */
	res = decode_opcode(&state, insn);
	if (res == DECODE_ERROR) {
		log_warnx("%s: error decoding opcode", __func__);
		goto err;
	} else if (res == DECODE_DONE)
		goto done;

#if MMIO_DEBUG
	log_debug("%s: found opcode %s (operand encoding %s) (%s)", __progname,
	    str_opcode(&insn->insn_opcode), str_operand_enc(&insn->insn_opcode),
	    str_decode_res(res));
#endif

	/* Process optional ModR/M byte. */
	res = decode_modrm(&state, insn);
	if (res == DECODE_ERROR) {
		log_warnx("%s: error decoding modrm", __func__);
		goto err;
	}
	if (get_modrm_addr(insn, vrs) != 0)
		goto err;
	if (get_modrm_reg(insn) != 0)
		goto err;
	if (res == DECODE_DONE)
		goto done;

#if MMIO_DEBUG
	if (insn->insn_modrm_valid)
		log_debug("%s: found ModRM 0x%02x (%s)", __progname,
		    insn->insn_modrm, str_decode_res(res));
#endif

	/* Process optional SIB byte. */
	res = decode_sib(&state, insn);
	if (res == DECODE_ERROR) {
		log_warnx("%s: error decoding sib", __func__);
		goto err;
	} else if (res == DECODE_DONE)
		goto done;

#if MMIO_DEBUG
	if (insn->insn_sib_valid)
		log_debug("%s: found SIB 0x%02x (%s)", __progname,
		    insn->insn_sib, str_decode_res(res));
#endif

	/* Process any Displacement bytes. */
	res = decode_disp(&state, insn);
	if (res == DECODE_ERROR) {
		log_warnx("%s: error decoding displacement", __func__);
		goto err;
	} else if (res == DECODE_DONE)
		goto done;

	/* Process any Immediate data bytes. */
	res = decode_imm(&state, insn);
	if (res == DECODE_ERROR) {
		log_warnx("%s: error decoding immediate bytes", __func__);
		goto err;
	}

done:
	insn->insn_bytes_len = state.s_idx;

	/*
	 * 64-bit RIP-relative addressing: effective address is
	 * (next-instruction RIP) + sign_extend(disp32).  Finalize
	 * insn_gva here because total instruction length is now known.
	 */
	if (insn->insn_modrm_valid &&
	    MODRM_MOD(insn->insn_modrm) == 0 &&
	    MODRM_RM(insn->insn_modrm) == 5) {
		if (insn->insn_cpu_mode == VMM_CPU_MODE_LONG ||
		    insn->insn_cpu_mode == VMM_CPU_MODE_COMPAT) {
			/* RIP-relative: next_RIP + sign_extend(disp32). */
			disp32 = (int64_t)(int32_t)insn->insn_disp;
			insn->insn_gva = vrs->vrs_gprs[VCPU_REGS_RIP]
			    + insn->insn_bytes_len + disp32;
		} else {
			/* PROT32/PROT/REAL: absolute 32-bit address. */
			insn->insn_gva = (uint32_t)insn->insn_disp;
		}
	}

	/*
	 * SIB-encoded addressing: effective address is
	 *   disp + (index_reg << scale) + base_reg
	 * with the special case that mod==0 + SIB.base==5 omits the base
	 * (just disp32) -- and SIB.index==4 omits the index register.
	 *
	 * REX.X extends SIB.index; REX.B extends SIB.base -- but NOT in the
	 * mod==0/base==5 "no base" encoding (Intel SDM Vol 2, 2.2.1.2).
	 */
	if (insn->insn_modrm_valid && insn->insn_sib_valid &&
	    MODRM_RM(insn->insn_modrm) == 4) {
		mod = MODRM_MOD(insn->insn_modrm);
		sscale = SIB_SCALE(insn->insn_sib);
		sindex = SIB_INDEX(insn->insn_sib);
		sbase  = SIB_BASE(insn->insn_sib);
		disp = 0;
		ea = 0;

		/* Sign-extend whatever disp we read (if any). */
		switch (insn->insn_disp_type) {
		case DISP_1:
			disp = (int64_t)(int8_t)insn->insn_disp;
			break;
		case DISP_2:
			disp = (int64_t)(int16_t)insn->insn_disp;
			break;
		case DISP_4:
			disp = (int64_t)(int32_t)insn->insn_disp;
			break;
		default:
			disp = 0;
			break;
		}

		/* Index register: SIB.index==4 means "none". */
		if (sindex != 4) {
			index_reg = sindex;
			if (insn->insn_prefix.pfx_rex & REX_X)
				index_reg += 8;
			ea += vrs->vrs_gprs[index_reg] << sscale;
		}

		/* Base register: special case mod==0/base==5 -> no base. */
		has_base = !(mod == 0 && sbase == 5);
		if (has_base) {
			base_reg = sbase;
			if (insn->insn_prefix.pfx_rex & REX_B)
				base_reg += 8;
			/*
			 * VCPU_REGS_* encoding matches x86's GPR encoding
			 * (0=RAX..7=RDI, 8=R8..15=R15), so index directly.
			 */
			ea += vrs->vrs_gprs[base_reg];
		}

		ea += (uint64_t)disp;
		insn->insn_gva = ea;
	}

	/*
	 * Non-SIB mod==1 / mod==2 addressing: get_modrm_addr() set insn_gva
	 * from the base register but did NOT add the disp.  Fold in the
	 * (sign-extended) displacement now that decode_disp has run.
	 *
	 * Skipped for rm==4 (SIB, handled above) and for mod==0/rm==5
	 * (RIP-relative, handled above).
	 */
	if (insn->insn_modrm_valid && !insn->insn_sib_valid) {
		mod = MODRM_MOD(insn->insn_modrm);
		rm  = MODRM_RM(insn->insn_modrm);
		disp = 0;

		if ((mod == 1 || mod == 2) && rm != 4) {
			switch (insn->insn_disp_type) {
			case DISP_1:
				disp = (int64_t)(int8_t)insn->insn_disp;
				break;
			case DISP_2:
				disp = (int64_t)(int16_t)insn->insn_disp;
				break;
			case DISP_4:
				disp = (int64_t)(int32_t)insn->insn_disp;
				break;
			default:
				disp = 0;
				break;
			}
			insn->insn_gva += (uint64_t)disp;
		}
	}

	/*
	 * Resolve Group 1 (0x81/0x83) to the actual ALU operation using
	 * the ModRM /reg field.  This must happen after decode_modrm so
	 * insn_modrm is valid.
	 */
	if (insn->insn_opcode.op_type == OP_GROUP1 &&
	    insn->insn_modrm_valid) {
		switch (MODRM_REGOP(insn->insn_modrm)) {
		case 0:
			insn->insn_opcode.op_type = OP_ADD;
			break;
		case 1:
			insn->insn_opcode.op_type = OP_OR;
			break;
		case 4:
			insn->insn_opcode.op_type = OP_AND;
			break;
		case 5:
			insn->insn_opcode.op_type = OP_SUB;
			break;
		case 6:
			insn->insn_opcode.op_type = OP_XOR;
			break;
		case 7:
			insn->insn_opcode.op_type = OP_CMP;
			break;
		default:
			log_warnx("%s: unsupported group-1 /reg=%u",
			    __func__, MODRM_REGOP(insn->insn_modrm));
			goto err;
		}
	}

	/*
	 * Resolve BT group (0x0F BA) to BT/BTS/BTR/BTC using the
	 * ModRM /reg field.
	 */
	if (insn->insn_opcode.op_type == OP_BT_GROUP &&
	    insn->insn_modrm_valid) {
		switch (MODRM_REGOP(insn->insn_modrm)) {
		case 4:
			insn->insn_opcode.op_type = OP_BT;
			break;
		case 5:
			insn->insn_opcode.op_type = OP_BTS;
			break;
		case 6:
			insn->insn_opcode.op_type = OP_BTR;
			break;
		case 7:
			insn->insn_opcode.op_type = OP_BTC;
			break;
		default:
			log_warnx("%s: unsupported BT group /reg=%u",
			    __func__, MODRM_REGOP(insn->insn_modrm));
			goto err;
		}
	}

	/*
	 * Real / unpaged mode: the decoder computes insn_gva as a bare
	 * offset (register value + displacement).  In real mode the
	 * effective physical address is segment_base + offset.  Use
	 * DS.base for data accesses (the common case for MMIO) so
	 * translate_gva (which returns pa=va when CR0.PG is clear)
	 * produces the correct GPA.
	 */
	if (insn->insn_cpu_mode == VMM_CPU_MODE_REAL &&
	    insn->insn_modrm_valid) {
		insn->insn_gva +=
		    vrs->vrs_sregs[VCPU_REGS_DS].vsi_base;
	}

#if MMIO_DEBUG
	log_debug("%s: final instruction length is %u", __func__,
		insn->insn_bytes_len);
	dump_insn(insn);
	log_debug("%s: modrm: {mod: %d, regop: %d, rm: %d}", __func__,
	    MODRM_MOD(insn->insn_modrm), MODRM_REGOP(insn->insn_modrm),
	    MODRM_RM(insn->insn_modrm));
	dump_regs(vrs);
#endif /* MMIO_DEBUG */
	return (0);

err:
	hlen = 0;
	for (i = 0; i < (int)state.s_len && i < 15 && hlen < 60; i++)
		hlen += snprintf(hexbuf + hlen, sizeof(hexbuf) - hlen,
		    "%02x ", state.s_bytes[i]);
	log_warnx("%s: decode FAILED rip=0x%llx mode=%d bytes=[%s]",
	    __func__, (unsigned long long)vrs->vrs_gprs[VCPU_REGS_RIP],
	    mode, hexbuf);
#if MMIO_DEBUG
	dump_insn(insn);
	log_debug("%s: modrm: {mod: %d, regop: %d, rm: %d}", __func__,
	    MODRM_MOD(insn->insn_modrm), MODRM_REGOP(insn->insn_modrm),
	    MODRM_RM(insn->insn_modrm));
	dump_regs(vrs);
#endif /* MMIO_DEBUG */
	return (-1);
}

/*
 * Generic MMIO emulation for MOV, ALU (ADD/OR/AND/SUB/XOR/CMP),
 * TEST, and XCHG.  Table-driven: the mmio_op descriptor selects
 * the compute function and which side-effects (flags, writeback,
 * swap) to apply.
 */
static int
emulate_generic(struct x86_insn *insn, struct vm_exit *exit)
{
	const struct mmio_op	*mop;
	struct mmio_handler	*h;
	uint64_t		 gpa, mem_val = 0, src_val, dst_val, result;
	uint8_t			 bytes, sub;
	int			 reg;
	enum x86_opcode_type	 op;

	op = insn->insn_opcode.op_type;
	mop = mmio_op_for(op);
	if (mop == NULL) {
		log_warnx("%s: no mmio_op for opcode %d", __func__, op);
		return (ENOTSUP);
	}

	/*
	 * Operand size.  MOV has its own table; everything else uses ALU rules.
	 */
	bytes = (op == OP_MOV) ? mov_operand_bytes(insn) :
	    alu_operand_bytes(insn);

	/* TEST operand size: 0xF6 is 8-bit. */
	if (op == OP_TEST) {
		if (insn->insn_opcode.op_bytes[0] == 0xF6)
			bytes = 1;
		else if (insn->insn_prefix.pfx_group3 == LEG_3_OPSZ)
			bytes = 2;
		else if (insn->insn_prefix.pfx_rex & REX_W)
			bytes = 8;
		else
			bytes = 4;
	}

	/* TEST group-3 sub-opcode validation. */
	if (op == OP_TEST) {
		sub = MODRM_REGOP(insn->insn_modrm);
		if (sub != 0 && sub != 1) {
			log_warnx("%s: unsupported group-3 /reg=%u",
			    __func__, sub);
			return (ENOTSUP);
		}
	}

	reg = insn->insn_reg;

	if (translate_gva(exit, insn->insn_gva, &gpa,
	    PROT_READ | PROT_WRITE) != 0) {
		log_warnx("%s: translate_gva failed gva=0x%llx",
		    __func__, (unsigned long long)insn->insn_gva);
		return (EFAULT);
	}

	h = mmio_find(gpa);

	/* --- Read memory operand --- */
	mem_val = 0;
	switch (insn->insn_opcode.op_encoding) {
	case OP_ENC_RM:
	case OP_ENC_MR:
	case OP_ENC_MI:
	case OP_ENC_FD:
		if (h != NULL && h->read != NULL)
			h->read(gpa - h->base, bytes, &mem_val, h->cookie);
		else if (read_mem(gpa, &mem_val, bytes) != 0)
			mem_val = 0;
		mem_val = mask_operand(mem_val, bytes);
		break;
	case OP_ENC_TD:
		/* Pure write to memory, no read needed. */
		break;
	default:
		log_warnx("%s: unsupported encoding %d", __func__,
		    insn->insn_opcode.op_encoding);
		return (ENOTSUP);
	}

	/* --- Determine dst and src for the compute function --- */
	switch (insn->insn_opcode.op_encoding) {
	case OP_ENC_RM:
		/* reg OP [mem]: dst=reg, src=mem */
		dst_val = exit->vrs.vrs_gprs[reg];
		src_val = mem_val;
		break;
	case OP_ENC_MR:
		/* [mem] OP reg: dst=mem, src=reg */
		dst_val = mem_val;
		src_val = mask_operand(exit->vrs.vrs_gprs[reg], bytes);
		break;
	case OP_ENC_MI:
		/* [mem] OP imm: dst=mem, src=imm */
		dst_val = mem_val;
		src_val = insn->insn_immediate;
		/*
		 * Sign-extend immediate for Group 1 (0x83) and 64-bit MOV
		 * (0xC7+REX.W).
		 */
		if (insn->insn_opcode.op_bytes[0] == 0x83)
			src_val = sign_extend8(src_val);
		else if (bytes == 8)
			src_val = sign_extend32(src_val);
		src_val = mask_operand(src_val, bytes);
		break;
	case OP_ENC_FD:
		/* RAX <- [moffs]: dst=RAX, src=mem */
		dst_val = exit->vrs.vrs_gprs[VCPU_REGS_RAX];
		src_val = mem_val;
		break;
	case OP_ENC_TD:
		/* [moffs] <- RAX: dst=mem(0), src=RAX */
		dst_val = 0;
		src_val = mask_operand(exit->vrs.vrs_gprs[VCPU_REGS_RAX],
		    bytes);
		break;
	default:
		return (ENOTSUP);
	}

	/* --- Compute --- */
	result = mop->compute(dst_val, src_val);

	/* --- RFLAGS --- */
	if (mop->flags & MMIO_F_RFLAGS) {
		update_rflags_alu(&exit->vrs.vrs_gprs[VCPU_REGS_RFLAGS],
		    dst_val, src_val, result, bytes,
		    (mop->flags & MMIO_F_SUB) ? 1 : 0,
		    (mop->flags & MMIO_F_LOGIC) ? 1 : 0);
	}

	/* --- Writeback --- */
	if (mop->flags & MMIO_F_XCHG) {
		/* XCHG: write old reg to mem, old mem to reg. */
		if (h != NULL && h->write != NULL)
			h->write(gpa - h->base, bytes,
			    mask_operand(exit->vrs.vrs_gprs[reg], bytes),
			    h->cookie);
		write_gpr(exit->vrs.vrs_gprs, reg, mem_val, bytes);
	} else if (mop->flags & MMIO_F_WRITEBACK) {
		switch (insn->insn_opcode.op_encoding) {
		case OP_ENC_RM:
			write_gpr(exit->vrs.vrs_gprs, reg, result, bytes);
			break;
		case OP_ENC_FD:
			write_gpr(exit->vrs.vrs_gprs, VCPU_REGS_RAX,
			    result, bytes);
			break;
		case OP_ENC_MR:
		case OP_ENC_MI:
		case OP_ENC_TD:
			result = mask_operand(result, bytes);
			if (h != NULL && h->write != NULL)
				h->write(gpa - h->base, bytes, result,
				    h->cookie);
			break;
		default:
			break;
		}
	}

	return (0);
}

static int
emulate_movzx(struct x86_insn *insn, struct vm_exit *exit)
{
	struct mmio_handler	*h;
	uint64_t		 gpa, val = 0;
	uint8_t			 byte, len, src_bytes, dst_bytes;
	int			 reg;

	/* Only RM is valid for MOVZX. */
	if (insn->insn_opcode.op_encoding != OP_ENC_RM) {
		log_warnx("invalid op encoding for MOVZX: %d",
		    insn->insn_opcode.op_encoding);
		return (-1);
	}

	len = insn->insn_opcode.op_bytes_len;
	if (len < 1 || len > sizeof(insn->insn_opcode.op_bytes)) {
		log_warnx("invalid opcode byte length: %d", len);
		return (-1);
	}

	byte = insn->insn_opcode.op_bytes[len - 1];
	switch (byte) {
	case 0xB6:	/* movzx r, r/m8 */
		src_bytes = 1;
		if (insn->insn_prefix.pfx_rex & REX_W)
			dst_bytes = 8;
		else if (insn->insn_prefix.pfx_group3 == LEG_3_OPSZ ||
		    insn->insn_cpu_mode == VMM_CPU_MODE_PROT ||
		    insn->insn_cpu_mode == VMM_CPU_MODE_REAL)
			dst_bytes = 2;
		else
			dst_bytes = 4;
		break;
	case 0xB7:	/* movzx r, r/m16 */
		src_bytes = 2;
		if (insn->insn_prefix.pfx_rex & REX_W)
			dst_bytes = 8;
		else
			dst_bytes = 4;
		break;
	default:
		log_warnx("invalid byte in MOVZX opcode: %x", byte);
		return (-1);
	}

	reg = insn->insn_reg;

	if (translate_gva(exit, insn->insn_gva, &gpa, PROT_READ) != 0) {
		log_warnx("emulate_movzx: translate_gva failed gva=0x%llx",
		    (unsigned long long)insn->insn_gva);
		return (EFAULT);
	}

	h = mmio_find(gpa);
	if (h != NULL && h->read != NULL)
		h->read(gpa - h->base, src_bytes, &val, h->cookie);
	else if (read_mem(gpa, &val, src_bytes) != 0)
		val = 0;

	/* Zero-extend from the source size, then write the destination. */
	if (src_bytes == 1)
		val &= 0xFF;
	else
		val &= 0xFFFF;

	write_gpr(exit->vrs.vrs_gprs, reg, val, dst_bytes);

	return (0);
}

/*
 * emulate_movsx
 *
 * MOVSX r, r/m -- sign-extending load from MMIO.
 * 0x0F BE: sign-extend byte to word/dword/qword
 * 0x0F BF: sign-extend word to dword/qword
 */
static int
emulate_movsx(struct x86_insn *insn, struct vm_exit *exit)
{
	struct mmio_handler	*h;
	uint64_t		 gpa, val = 0;
	uint8_t			 byte, len, src_bytes, dst_bytes;
	int			 reg;

	if (insn->insn_opcode.op_encoding != OP_ENC_RM) {
		log_warnx("invalid op encoding for MOVSX: %d",
		    insn->insn_opcode.op_encoding);
		return (-1);
	}

	len = insn->insn_opcode.op_bytes_len;
	if (len < 1 || len > sizeof(insn->insn_opcode.op_bytes)) {
		log_warnx("invalid opcode byte length for MOVSX: %d", len);
		return (-1);
	}

	byte = insn->insn_opcode.op_bytes[len - 1];
	switch (byte) {
	case 0xBE:
		src_bytes = 1;
		break;
	case 0xBF:
		src_bytes = 2;
		break;
	default:
		log_warnx("invalid byte in MOVSX opcode: 0x%02x", byte);
		return (-1);
	}

	/* Destination size follows REX.W / 0x66 rules. */
	if (insn->insn_prefix.pfx_rex & REX_W)
		dst_bytes = 8;
	else
		dst_bytes = 4;

	reg = insn->insn_reg;

	if (translate_gva(exit, insn->insn_gva, &gpa, PROT_READ) != 0) {
		log_warnx("emulate_movsx: translate_gva failed gva=0x%llx",
		    (unsigned long long)insn->insn_gva);
		return (EFAULT);
	}

	h = mmio_find(gpa);
	if (h != NULL && h->read != NULL)
		h->read(gpa - h->base, src_bytes, &val, h->cookie);
	else if (read_mem(gpa, &val, src_bytes) != 0)
		val = 0;

	/* Sign-extend from source size. */
	if (src_bytes == 1)
		val = sign_extend8(val);
	else
		val = sign_extend16(val);

	/* Write to destination register. */
	write_gpr(exit->vrs.vrs_gprs, reg, val, dst_bytes);

	return (0);
}

/*
 * update_rflags_alu
 *
 * Update RFLAGS for an ALU operation.  Handles ADD, SUB, AND, OR, XOR, CMP.
 *
 *   a, b:     source operands (for sub/cmp: a - b)
 *   result:   computed result
 *   bytes:    operand size (1, 2, 4, or 8)
 *   is_sub:   1 for SUB/CMP, 0 for ADD
 *   is_logic: 1 for AND/OR/XOR (CF=OF=0, AF undef), 0 for arith
 */
static void
update_rflags_alu(uint64_t *rflags, uint64_t a, uint64_t b, uint64_t result,
    uint8_t bytes, int is_sub, int is_logic)
{
	uint64_t mask, sign_bit, fl;

	switch (bytes) {
	case 1: mask = 0xFFULL; sign_bit = 1ULL << 7; break;
	case 2: mask = 0xFFFFULL; sign_bit = 1ULL << 15; break;
	case 4: mask = 0xFFFFFFFFULL; sign_bit = 1ULL << 31; break;
	case 8: mask = 0xFFFFFFFFFFFFFFFFULL; sign_bit = 1ULL << 63; break;
	default: return;
	}

	a &= mask;
	b &= mask;
	result &= mask;

	fl = *rflags;
	fl &= ~((1ULL << 0)    /* CF */
	      | (1ULL << 2)    /* PF */
	      | (1ULL << 4)    /* AF */
	      | (1ULL << 6)    /* ZF */
	      | (1ULL << 7)    /* SF */
	      | (1ULL << 11)); /* OF */

	/* ZF */
	if (result == 0)
		fl |= (1ULL << 6);

	/* SF */
	if (result & sign_bit)
		fl |= (1ULL << 7);

	/* PF -- parity of low byte */
	if (parity_even((uint8_t)result))
		fl |= (1ULL << 2);

	if (is_logic) {
		/* AND/OR/XOR: CF=0, OF=0, AF undefined (leave cleared). */
	} else if (is_sub) {
		/* CF: borrow -- set if a < b (unsigned). */
		if (a < b)
			fl |= (1ULL << 0);

		/*
		 * OF: signed overflow -- (a^b) has different signs AND
		 * (a^result) has different signs.
		 */
		if ((a ^ b) & (a ^ result) & sign_bit)
			fl |= (1ULL << 11);

		/* AF: borrow from bit 4. */
		if ((a & 0xF) < (b & 0xF))
			fl |= (1ULL << 4);
	} else {
		/* ADD: CF = carry out. */
		if (result < a)
			fl |= (1ULL << 0);

		/* OF: both operands same sign, result different sign. */
		if (~(a ^ b) & (a ^ result) & sign_bit)
			fl |= (1ULL << 11);

		/* AF: carry from bit 3 to bit 4. */
		if (((a & 0xF) + (b & 0xF)) > 0xF)
			fl |= (1ULL << 4);
	}

	*rflags = fl;
}

/*
 * emulate_bt_group
 *
 * BT/BTS/BTR/BTC r/m, imm8 -- bit test (and set/reset/complement).
 *
 * Reads a bit from the MMIO value, sets CF accordingly, then optionally
 * modifies the bit in the MMIO value.
 *
 * Other RFLAGS (OF, SF, AF, PF) are undefined per Intel SDM.
 */
static int
emulate_bt_group(struct x86_insn *insn, struct vm_exit *exit)
{
	struct mmio_handler	*h;
	uint64_t		 gpa, val = 0, bit_mask;
	uint64_t		*rflags;
	uint8_t			 bytes, bit_offset;
	enum x86_opcode_type	 op;

	bytes = alu_operand_bytes(insn);
	op = insn->insn_opcode.op_type;
	rflags = &exit->vrs.vrs_gprs[VCPU_REGS_RFLAGS];

	if (translate_gva(exit, insn->insn_gva, &gpa,
	    PROT_READ | PROT_WRITE) != 0) {
		log_warnx("emulate_bt_group: translate_gva failed gva=0x%llx",
		    (unsigned long long)insn->insn_gva);
		return (EFAULT);
	}

	h = mmio_find(gpa);

	/* Read current value. */
	if (h != NULL && h->read != NULL)
		h->read(gpa - h->base, bytes, &val, h->cookie);
	else if (read_mem(gpa, &val, bytes) != 0)
		val = 0;

	/* Bit offset is modulo operand size in bits. */
	bit_offset = (uint8_t)insn->insn_immediate % (bytes * 8);
	bit_mask = 1ULL << bit_offset;

	/* Set CF from the tested bit. */
	if (val & bit_mask)
		*rflags |= (1ULL << 0);   /* CF */
	else
		*rflags &= ~(1ULL << 0);  /* CF */

	/* Modify the bit if needed. */
	switch (op) {
	case OP_BT:
		/* Test only, no modification. */
		break;
	case OP_BTS:
		val |= bit_mask;
		if (h != NULL && h->write != NULL)
			h->write(gpa - h->base, bytes, val, h->cookie);
		break;
	case OP_BTR:
		val &= ~bit_mask;
		if (h != NULL && h->write != NULL)
			h->write(gpa - h->base, bytes, val, h->cookie);
		break;
	case OP_BTC:
		val ^= bit_mask;
		if (h != NULL && h->write != NULL)
			h->write(gpa - h->base, bytes, val, h->cookie);
		break;
	default:
		log_warnx("emulate_bt_group: unexpected op %d", op);
		return (ENOTSUP);
	}

	return (0);
}

/*
 * insn_emulate
 *
 * Returns:
 *  0: success
 *  EINVAL: exception occurred
 *  EFAULT: page fault occurred, requires retry
 *  ENOTSUP: an unsupported instruction was provided
 */
int
insn_emulate(struct vm_exit *exit, struct x86_insn *insn)
{
	int res;

	if (insn->insn_reg < 0 || insn->insn_reg >= VCPU_REGS_NGPRS) {
		log_warnx("%s: insn_reg %d out of bounds", __func__,
		    insn->insn_reg);
		return (-1);
	}

	switch (insn->insn_opcode.op_type) {
	case OP_MOV:
	case OP_ADD:
	case OP_OR:
	case OP_AND:
	case OP_SUB:
	case OP_XOR:
	case OP_CMP:
	case OP_TEST:
	case OP_XCHG:
		res = emulate_generic(insn, exit);
		break;

	case OP_MOVZX:
		res = emulate_movzx(insn, exit);
		break;

	case OP_MOVSX:
		res = emulate_movsx(insn, exit);
		break;

	case OP_BT:
	case OP_BTS:
	case OP_BTR:
	case OP_BTC:
		res = emulate_bt_group(insn, exit);
		break;

	default:
		log_warnx("%s: emulation not defined for %s", __func__,
		    str_opcode(&insn->insn_opcode));
		res = ENOTSUP;
	}

	if (res == 0)
		exit->vrs.vrs_gprs[VCPU_REGS_RIP] += insn->insn_bytes_len;

	return (res);
}
