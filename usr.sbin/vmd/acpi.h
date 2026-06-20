/* $OpenBSD$ */
#ifndef _ACPI_H_
#define _ACPI_H_

#include <sys/types.h>
#include <stdint.h>

int acpi_init(uint32_t ncpus);

#endif /* _ACPI_H_ */
