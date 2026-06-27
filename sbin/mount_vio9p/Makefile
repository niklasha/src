#	$OpenBSD$

.include <bsd.own.mk>

PROG=		mount_vio9p
SRCS=		mount_vio9p.c getmntopts.c
MAN=		mount_vio9p.8

# getmntopts.c / mntopts.h are shared with the other mount helpers.
MOUNT=		${.CURDIR}/../mount
.PATH:		${MOUNT}

CPPFLAGS+=	-I${MOUNT}
DPADD+=		${LIBUTIL}
LDADD+=		-lutil

.include <bsd.prog.mk>
