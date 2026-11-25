#	$OpenBSD$
#
# Regress tests for fsck_ffs.  Set FSCK_FFS to test a binary other
# than /sbin/fsck_ffs.

PROG=		ffsedit
NOMAN=		yes
WARNINGS=	yes

FSCK_FFS?=	/sbin/fsck_ffs

REGRESS_TARGETS=	run-regress-checkfsck
REGRESS_ROOT_TARGETS=	${REGRESS_TARGETS}

run-regress-checkfsck: ${PROG}
	${SUDO} ksh ${.CURDIR}/checkfsck ${.OBJDIR}/${PROG} ${FSCK_FFS}

.include <bsd.regress.mk>
