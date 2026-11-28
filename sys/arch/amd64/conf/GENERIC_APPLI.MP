#	$OpenBSD: GENERIC.MP,v 1.14 2018/07/13 05:25:24 tb Exp $

include "arch/amd64/conf/GENERIC"

option	MULTIPROCESSOR
#option	MP_LOCKDEBUG
#option	WITNESS
option	SR_DEBUG
option	UMASS_DEBUG
option	USB_DEBUG
option	EHCI_DEBUG
option	WDCDEBUG
option	XNF_DEBUG
option	CONFIG_DRM_AMDGPU_CIK
option	AMDGPU_CIK

cpu*		at mainbus?
com2		at isa? port 0x3e8 irq 4

# ipmi(4) is disabled in GENERIC; the Appli kernels enable it so the BMC
# (HP iLO, Dell iDRAC, Supermicro) is usable from the OS (ipmitool, sensors).
# Only the mainbus (SMBIOS) instance: config(8) cannot re-enable the acpi
# one, which attaches "with ipmi_acpi"; use bsd.re-config "enable ipmi" there.
ipmi0	at mainbus? enable
