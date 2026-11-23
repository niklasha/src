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
 * Play dhcpleased(8)'s control socket for dcarpd-test: answer
 * IMSG_CTL_SHOW_INTERFACE_INFO with the lease a file describes, read anew
 * for every request, and log every message received, so that the test can
 * tell that dcarpd asks for nothing else.  The file has lines
 *
 *	state Bound		dhcpleased's name of the state
 *	address 10.77.0.77	the address leased
 *	netmask 255.255.255.0
 *	lease 86400		the lease time, seconds
 *	acked 1794702621	when it was acknowledged, seconds since the
 *				epoch; dhcpleased reports that by its
 *				monotonic clock
 *	short 4			answer that many bytes too few
 *	long 4			answer that many bytes too many
 *	index 99		answer for that interface index
 *	end			answer IMSG_CTL_END, as for an interface
 *				dhcpleased does not handle
 *	silent			answer nothing, as a dhcpleased that takes
 *				the request for another, or hangs
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <err.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dhcpleased.h"

static void
usage(void)
{
	fprintf(stderr, "usage: fake-dhcpleased -f lease_file -l log "
	    "-s socket\n");
	exit(1);
}

static const char *
imsg_name(uint32_t type)
{
	switch (type) {
	case IMSG_CTL_LOG_VERBOSE:
		return "IMSG_CTL_LOG_VERBOSE";
	case IMSG_CTL_SHOW_INTERFACE_INFO:
		return "IMSG_CTL_SHOW_INTERFACE_INFO";
	case IMSG_CTL_SEND_REQUEST:
		return "IMSG_CTL_SEND_REQUEST";
	case IMSG_CTL_RELOAD:
		return "IMSG_CTL_RELOAD";
	default:
		return "unknown";
	}
}

/*
 * The answer for the interface, from the lease file.  The monotonic time
 * of the acknowledgement is computed once per value of "acked", so that it
 * stays the same, as dhcpleased's does, until the next one.
 */
enum { ANSWER, END, SILENT };

/* Room for "long" */
#define EXTRA	64

static int
answer(const char *path, uint32_t if_index, struct ctl_engine_info *cei,
    size_t *len)
{
	static long long last_acked = -1;
	static struct timespec request_time;
	struct timespec real, mono, age;
	char line[128], key[32], value[64];
	const char *errstr;
	long long acked = 0;
	int how = ANSWER;
	FILE *f;

	memset(cei, 0, sizeof(*cei));
	cei->if_index = if_index;
	cei->running = 1;
	cei->link_state = LINK_STATE_UP;
	*len = sizeof(*cei);
	if ((f = fopen(path, "r")) == NULL)
		err(1, "%s", path);
	while (fgets(line, sizeof(line), f) != NULL) {
		value[0] = '\0';
		if (sscanf(line, "%31s %63s", key, value) < 1)
			continue;
		if (strcmp(key, "state") == 0)
			strlcpy(cei->state, value, sizeof(cei->state));
		else if (strcmp(key, "address") == 0) {
			if (inet_pton(AF_INET, value, &cei->requested_ip) != 1)
				errx(1, "address %s", value);
		} else if (strcmp(key, "netmask") == 0) {
			if (inet_pton(AF_INET, value, &cei->mask) != 1)
				errx(1, "netmask %s", value);
		} else if (strcmp(key, "lease") == 0) {
			cei->lease_time = strtonum(value, 0, UINT32_MAX,
			    &errstr);
			if (errstr != NULL)
				errx(1, "lease %s: %s", value, errstr);
			cei->renewal_time = cei->lease_time / 2;
			cei->rebinding_time = cei->lease_time -
			    cei->lease_time / 8;
		} else if (strcmp(key, "acked") == 0) {
			acked = strtonum(value, 1, LLONG_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "acked %s: %s", value, errstr);
		} else if (strcmp(key, "short") == 0) {
			*len -= strtonum(value, 1, sizeof(*cei), &errstr);
			if (errstr != NULL)
				errx(1, "short %s: %s", value, errstr);
		} else if (strcmp(key, "long") == 0) {
			*len += strtonum(value, 1, EXTRA, &errstr);
			if (errstr != NULL)
				errx(1, "long %s: %s", value, errstr);
		} else if (strcmp(key, "index") == 0) {
			cei->if_index = strtonum(value, 0, UINT32_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "index %s: %s", value, errstr);
		} else if (strcmp(key, "end") == 0)
			how = END;
		else if (strcmp(key, "silent") == 0)
			how = SILENT;
		else
			errx(1, "%s: unknown keyword %s", path, key);
	}
	fclose(f);

	if (acked != last_acked) {
		clock_gettime(CLOCK_REALTIME, &real);
		clock_gettime(CLOCK_MONOTONIC, &mono);
		age.tv_sec = real.tv_sec - acked;
		age.tv_nsec = real.tv_nsec;
		timespecsub(&mono, &age, &request_time);
		last_acked = acked;
	}
	if (acked != 0)
		cei->request_time = request_time;
	cei->server_identifier = cei->dhcp_server = cei->requested_ip;
	return (how);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_un sun;
	struct {
		struct ctl_engine_info	cei;
		char			extra[EXTRA];
	} buf;
	struct ctl_engine_info *cei = &buf.cei;
	char tmp[sizeof(sun.sun_path)];
	struct imsgbuf ibuf;
	struct imsg imsg;
	const char *lease = NULL, *log = NULL, *sock = NULL;
	uint32_t if_index;
	size_t len;
	FILE *logf;
	ssize_t n;
	int ch, s, fd;

	while ((ch = getopt(argc, argv, "f:l:s:")) != -1) {
		switch (ch) {
		case 'f':
			lease = optarg;
			break;
		case 'l':
			log = optarg;
			break;
		case 's':
			sock = optarg;
			break;
		default:
			usage();
		}
	}
	if (lease == NULL || log == NULL || sock == NULL || optind != argc)
		usage();

	if ((logf = fopen(log, "a")) == NULL)
		err(1, "%s", log);
	setvbuf(logf, NULL, _IOLBF, 0);

	/* Listening before it shows up under its name */
	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(1, "socket");
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (snprintf(tmp, sizeof(tmp), "%s.new", sock) >= (int)sizeof(tmp))
		errx(1, "%s: name too long", sock);
	strlcpy(sun.sun_path, tmp, sizeof(sun.sun_path));
	unlink(tmp);
	if (bind(s, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "bind %s", tmp);
	if (listen(s, 5) == -1)
		err(1, "listen");
	if (rename(tmp, sock) == -1)
		err(1, "rename %s", sock);

	for (;;) {
		if ((fd = accept(s, NULL, NULL)) == -1)
			err(1, "accept");
		if (imsgbuf_init(&ibuf, fd) == -1)
			err(1, "imsgbuf_init");
		for (;;) {
			if ((n = imsgbuf_get(&ibuf, &imsg)) == -1)
				err(1, "imsgbuf_get");
			if (n == 0) {
				if (imsgbuf_read(&ibuf) != 1)
					break;	/* closed, or an error */
				continue;
			}
			fprintf(logf, "%s len %zu\n",
			    imsg_name(imsg_get_type(&imsg)),
			    imsg_get_len(&imsg));
			if (imsg_get_type(&imsg) ==
			    IMSG_CTL_SHOW_INTERFACE_INFO &&
			    imsg_get_data(&imsg, &if_index,
			    sizeof(if_index)) == 0) {
				memset(&buf, 0, sizeof(buf));
				switch (answer(lease, if_index, cei, &len)) {
				case END:
					imsg_compose(&ibuf, IMSG_CTL_END, 0,
					    imsg_get_pid(&imsg), -1, NULL, 0);
					break;
				case ANSWER:
					imsg_compose(&ibuf,
					    IMSG_CTL_SHOW_INTERFACE_INFO, 0,
					    imsg_get_pid(&imsg), -1, &buf, len);
					break;
				}
				if (imsgbuf_flush(&ibuf) == -1)
					warn("imsgbuf_flush");
			}
			imsg_free(&imsg);
		}
		imsgbuf_clear(&ibuf);
		close(fd);
	}
}
