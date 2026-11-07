#	$OpenBSD$

SCRIPT=	dbupdate.sh
MAN=	dbupdate.8

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
	    ${.CURDIR}/${SCRIPT} ${DESTDIR}${BINDIR}/dbupdate

cert.pem: ${.CURDIR}/../../lib/libcrypto/cert.pem 
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m 444 \
	   ${.CURDIR}/../../lib/libcrypto/cert.pem ${DESTDIR}/etc/ssl/cert.pem

.include <bsd.prog.mk>
