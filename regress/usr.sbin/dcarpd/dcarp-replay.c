/*	$OpenBSD$	*/

/*
 * Copyright (c) 2026 Niklas Hallqvist
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Capture one DCARP message from the multicast group on an interface, or
 * send a captured one again, optionally with one byte inverted.  This plays
 * the attacker on the segment for dcarpd-test.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DCARP_GROUP	"224.0.0.18"
#define DCARP_PORT	3522

static void
usage(void)
{
	fprintf(stderr, "usage: dcarp-replay -i interface capture file\n"
	    "       dcarp-replay -i interface [-x offset] send file\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_in sin;
	struct ip_mreqn mreqn;
	unsigned char buf[512];
	const char *errstr, *ifname = NULL;
	ssize_t n;
	int ch, fd, s, offset = -1, one = 1;

	while ((ch = getopt(argc, argv, "i:x:")) != -1) {
		switch (ch) {
		case 'i':
			ifname = optarg;
			break;
		case 'x':
			offset = strtonum(optarg, 0, sizeof(buf) - 1, &errstr);
			if (errstr != NULL)
				errx(1, "offset %s: %s", optarg, errstr);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (ifname == NULL || argc != 2)
		usage();

	memset(&mreqn, 0, sizeof(mreqn));
	if (inet_pton(AF_INET, DCARP_GROUP, &mreqn.imr_multiaddr) != 1)
		errx(1, "bad group %s", DCARP_GROUP);
	if ((mreqn.imr_ifindex = if_nametoindex(ifname)) == 0)
		errx(1, "%s: no such interface", ifname);

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(DCARP_PORT);

	if (strcmp(argv[0], "capture") == 0) {
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one,
		    sizeof(one)) == -1)
			err(1, "SO_REUSEADDR");
		if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) == -1)
			err(1, "bind");
		if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreqn,
		    sizeof(mreqn)) == -1)
			err(1, "IP_ADD_MEMBERSHIP");
		alarm(30);
		if ((n = recv(s, buf, sizeof(buf), 0)) == -1)
			err(1, "recv");
		if ((fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC,
		    0600)) == -1)
			err(1, "%s", argv[1]);
		if (write(fd, buf, n) != n)
			err(1, "write %s", argv[1]);
		close(fd);
	} else if (strcmp(argv[0], "send") == 0) {
		if ((fd = open(argv[1], O_RDONLY)) == -1)
			err(1, "%s", argv[1]);
		if ((n = read(fd, buf, sizeof(buf))) == -1)
			err(1, "read %s", argv[1]);
		close(fd);
		if (offset >= n)
			errx(1, "offset %d beyond message of %zd bytes",
			    offset, n);
		if (offset >= 0)
			buf[offset] ^= 0xff;
		if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, &mreqn,
		    sizeof(mreqn)) == -1)
			err(1, "IP_MULTICAST_IF");
		sin.sin_addr = mreqn.imr_multiaddr;
		if (sendto(s, buf, n, 0, (struct sockaddr *)&sin,
		    sizeof(sin)) != n)
			err(1, "sendto");
	} else
		usage();

	return 0;
}
