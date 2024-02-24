# $OpenBSD$

PROG=		dcarpd
SRCS=		dcarpd.c
MAN=		dcarpd.8

DPADD=		${LIBEVENT} ${LIBCRYPTO}
LDADD=		-levent -lcrypto
CFLAGS+=	-Wall -Werror

.include <bsd.prog.mk>
