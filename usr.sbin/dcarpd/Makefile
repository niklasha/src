PROG=	dcarpd
SRCS=	dcarpd.c
MAN=	dcarpd.8

CFLAGS+= -Wall -Werror
LDADD+=	-levent -lcrypto
DPADD+=	${LIBEVENT} ${LIBCRYPTO}

.include <bsd.prog.mk>
