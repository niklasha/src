#	$OpenBSD$

# Regress tests for dcarpd(8).  A master and a backup dcarpd run in
# routing domains 77 and 78, joined by veb(4); this needs root.  The
# installed dcarpd is tested unless DCARPD names another binary:
#	make DCARPD=/usr/src/usr.sbin/dcarpd/obj/dcarpd

DCARPD ?=	/usr/sbin/dcarpd

# Must match the interfaces created by dcarpd-test.
INTERFACES =	carp77 carp78 carp79 veb77 veb79 \
		vport76 vport77 vport78 vport79 vport89

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

TESTS =		state-file gateway-from-route other-carp log-live \
		replay tampered wrong-key encrypted sync-interface \
		periodic address-change split-brain address-follow \
		older-generation lower-priority stale

# Waits for a recorded message to age out.
REGRESS_SLOW_TARGETS +=	stale

.for t in ${TESTS}
REGRESS_TARGETS +=	$t
REGRESS_ROOT_TARGETS +=	$t
$t: dcarp-replay
	${SUDO} env OBJDIR=${.OBJDIR} DCARPD=${DCARPD} \
	    REPLAY=${.OBJDIR}/dcarp-replay sh ${.CURDIR}/dcarpd-test $t
.endfor

dcarp-replay: dcarp-replay.c
	${CC} ${CFLAGS} -Wall -Werror -o $@ ${.CURDIR}/dcarp-replay.c

CLEANFILES +=	dcarp-replay dcarp.key dcarp.key.other dcarpd-*.log dcarpd-*.msg \
		dcarpd-*.state

.include <bsd.regress.mk>
