#	$OpenBSD$

# Regress tests for dcarpd(8).  A master and a backup dcarpd, and for one
# test a second backup, run in routing domains 75, 77 and 78, joined by
# veb(4); this needs root.  fake-dhcpleased plays dhcpleased(8)'s control
# socket.  The installed dcarpd is tested unless DCARPD names another
# binary:
#	make DCARPD=/usr/src/usr.sbin/dcarpd/obj/dcarpd

DCARPD ?=	/usr/sbin/dcarpd

# Must match the interfaces created by dcarpd-test.
INTERFACES =	carp75 carp77 carp78 carp79 carp88 veb77 veb79 vether77 \
		vport75 vport76 vport77 vport78 vport79 vport85 vport89

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

# A member of better priority comes back, or stays, backup only without
# preemption.
SYSCTL_PREEMPT !=	/sbin/sysctl -n net.inet.carp.preempt
.if ${SYSCTL_PREEMPT} != 0
REGRESS_SKIP_TARGETS +=	backup-follows-master no-address
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
		older-generation lower-priority equal-priority init-takes \
		no-address \
		backup-follows-master three-members backup-gateway-kept stale \
		restore-address restore-on-start state-generation \
		address-generation renew lease-time lease-size lease-silent \
		lease-future renew-ahead restore-address-v4 restore-master \
		lease-other restore-on-up replace-on-backup sigint start-fails \
		desync reject-repeat start-errors state-retry carp-copies \
		key-mode second-daemon short-messages interface-gone \
		two-addresses other-rdomain

# Waits for a recorded message to age out.
REGRESS_SLOW_TARGETS +=	stale

.for t in ${TESTS}
REGRESS_TARGETS +=	$t
REGRESS_ROOT_TARGETS +=	$t
$t: dcarp-replay fake-dhcpleased
	${SUDO} env OBJDIR=${.OBJDIR} DCARPD=${DCARPD} \
	    REPLAY=${.OBJDIR}/dcarp-replay LEASED=${.OBJDIR}/fake-dhcpleased \
	    sh ${.CURDIR}/dcarpd-test $t
.endfor

dcarp-replay: dcarp-replay.c
	${CC} ${CFLAGS} -Wall -Werror -o $@ ${.CURDIR}/dcarp-replay.c

fake-dhcpleased: fake-dhcpleased.c
	${CC} ${CFLAGS} -Wall -Werror -I${.CURDIR}/../../../sbin/dhcpleased \
	    -o $@ ${.CURDIR}/fake-dhcpleased.c -lutil

CLEANFILES +=	dcarp-replay fake-dhcpleased dcarp.key dcarp.key.other \
		dcarpd-hook dcarpd-*.hook dcarpd-*.lease dcarpd-*.lease.new \
		dcarpd-*.log dcarpd-*.msg dcarpd-*.sock dcarpd-*.sock.new \
		dcarpd-*.state

.include <bsd.regress.mk>
