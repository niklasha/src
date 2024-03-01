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
