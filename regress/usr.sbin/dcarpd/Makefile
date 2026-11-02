#	$OpenBSD$

# Regress tests for dcarpd(8).  A master and a backup dcarpd run in
# routing domains 77 and 78, joined by veb(4); this needs root.  The
# installed dcarpd is tested unless DCARPD names another binary:
#	make DCARPD=/usr/src/usr.sbin/dcarpd/obj/dcarpd

DCARPD ?=	/usr/sbin/dcarpd

# Must match the interfaces created by dcarpd-test.
INTERFACES =	carp77 carp78 carp79 veb77 vport77 vport78 vether79

.if ! (make(clean) || make(cleandir) || make(obj))

.if ! exists(${DCARPD})
regress:
	@echo ${DCARPD} not found
	@echo SKIPPED
.endif

SYSCTL_CARP !=	/sbin/sysctl -n net.inet.carp.allow
.if ${SYSCTL_CARP} != 1
regress:
	@echo net.inet.carp.allow=${SYSCTL_CARP}
	@echo Set sysctl to 1 to run this regress.
	@echo SKIPPED
.endif

IFS_IN_USE !=	for i in ${INTERFACES}; do \
		    /sbin/ifconfig $$i >/dev/null 2>&1 && echo $$i; \
		done; true
.if ! empty(IFS_IN_USE)
regress:
	@echo interfaces already exist: ${IFS_IN_USE}
	@echo SKIPPED
.endif

.endif

.for t in route-change route-add other-carp
REGRESS_TARGETS +=	$t
REGRESS_ROOT_TARGETS +=	$t
$t:
	${SUDO} env OBJDIR=${.OBJDIR} DCARPD=${DCARPD} \
	    sh ${.CURDIR}/dcarpd-test $t
.endfor

CLEANFILES +=	dcarp.key dcarpd-*.log

.include <bsd.regress.mk>
