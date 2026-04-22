#	$OpenBSD$

RESIZE_FFS ?=	${.OBJDIR}/../../../usr.sbin/resize_ffs/resize_ffs

REGRESS_TARGETS =	grow-journal \
			shrink-relocate \
			shrink-move-dry-run \
			push-forward-shrink-fails \
			parse-overflow-fails \
			truncated-journal-fails
REGRESS_ROOT_TARGETS =	${REGRESS_TARGETS}

.for t in ${REGRESS_TARGETS}
$t:
	${SUDO} env OBJDIR=${.OBJDIR} SRCDIR=${.CURDIR} \
		RESIZE_FFS=${RESIZE_FFS} \
		ksh ${.CURDIR}/resize_ffs.sh $t
.endfor

.include <bsd.regress.mk>
