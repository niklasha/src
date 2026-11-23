# $OpenBSD$

PROG=		dcarpd
SRCS=		dcarpd.c
MAN=		dcarpd.8

DPADD=		${LIBEVENT} ${LIBCRYPTO} ${LIBUTIL}
LDADD=		-levent -lcrypto -lutil
CFLAGS+=	-Wall -Werror
# struct ctl_engine_info, dhcpleased(8)'s answer on its control socket
CFLAGS+=	-I${.CURDIR}/../../sbin/dhcpleased

.include <bsd.prog.mk>
