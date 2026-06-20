/* $OpenBSD$ */
#ifndef _MPTABLE_H_
#define _MPTABLE_H_

#include <sys/types.h>
#include <stdint.h>

int mptable_init(uint32_t ncpus, uint8_t lapic_base, uint8_t ioapic_id);

#endif /* _MPTABLE_H_ */
