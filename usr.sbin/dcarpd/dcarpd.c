/*
 * Copyright (c) 2023 Niklas Hallqvist
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <endian.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip_carp.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <ifaddrs.h>
#include <errno.h>
#include <event.h>

#include "dcarpd.h"

void usage(void);

#define CARP_MASTER 2

struct options global_options = {
	DEFAULT_KEY_FILE
};

int global_multicast_socket = -1;

// Global routing socket
int routing_socket = -1;

// Global variable to track the current CARP state
int current_carp_state = CARP_STATE_INIT;

/* Interface index of the carp interface given with -i */
unsigned int carp_ifindex;

/* Interface index of the interface carrying the messages, -s or -i */
unsigned int sync_ifindex;

/* Our identity and message counter as a sender */
uint64_t my_sender;
uint64_t my_sequence;

/* XChaCha20-Poly1305 keyed from the key file */
EVP_AEAD_CTX *aead_ctx;

/* Additional data bound to every message, separating it from other uses */
static const unsigned char dcarp_ad[] = "DCARP 1";

/* Last sequence number accepted per sender, against replays */
struct {
	uint64_t sender;
	uint64_t sequence;
	time_t seen;
} senders[DCARP_SENDERS];

void log_init() {
	if (global_options.foreground) {
		// In debug mode, log to stderr
		setlogmask(LOG_UPTO(LOG_INFO));
		openlog("dcarpd", LOG_CONS | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
	} else {
		// In normal mode, log to syslog
		openlog("dcarpd", LOG_CONS | LOG_NDELAY, LOG_DAEMON);
	}
}

void log_message(int level, const char *format, ...) {
	va_list args;
	va_start(args, format);

	if (level <= LOG_INFO + global_options.verbose) {
		if (global_options.foreground) {
			/* stderr is unbuffered: lines show up as they happen */
			vfprintf(stderr, format, args);
			fprintf(stderr, "\n");
		} else {
			vsyslog(level, format, args);
		}
	}

	va_end(args);
}

void log_close() {
	closelog();
}

/*
 * Log why a message was rejected, with its source address.  Anyone on
 * the segment can send to us, so log at most one rejection every
 * DCARP_REJECT_LOG_INTERVAL seconds and count the ones left out.
 */
void log_rejected(const struct sockaddr_in *from, const char *format, ...) {
	static time_t last;
	static unsigned int suppressed;
	char from_str[INET_ADDRSTRLEN];
	char reason[128];
	time_t now = time(NULL);
	va_list args;

	if (last != 0 && now - last < DCARP_REJECT_LOG_INTERVAL) {
		suppressed++;
		return;
	}

	va_start(args, format);
	vsnprintf(reason, sizeof(reason), format, args);
	va_end(args);
	inet_ntop(AF_INET, &from->sin_addr, from_str, sizeof(from_str));

	if (suppressed > 0)
		log_message(LOG_WARNING, "rejected message from %s: %s "
		    "(%u more rejected since the last report)", from_str,
		    reason, suppressed);
	else
		log_message(LOG_WARNING, "rejected message from %s: %s",
		    from_str, reason);
	last = now;
	suppressed = 0;
}

void log_perror(const char *message) {
	char buffer[256];

	if (message == NULL || message[0] == '\0') {
		snprintf(buffer, sizeof(buffer), "%s", strerror(errno));
	} else {
		snprintf(buffer, sizeof(buffer), "%s: %s", message, strerror(errno));
	}

	if (global_options.foreground) {
		// In debug mode, log to stderr
		fprintf(stderr, "%s\n", buffer);
	} else {
		// In normal mode, log to syslog
		syslog(LOG_ERR, "%s", buffer);
	}
}

void update_carp_state(int new_state) {
	if (new_state != current_carp_state) {
		current_carp_state = new_state;
		log_message(LOG_INFO, "CARP state changed to: %d", current_carp_state);

		if (new_state == CARP_STATE_MASTER) {
			distribute_ip_addresses();
		}
		// Add logic for other states as needed
	}
}

// Function to monitor CARP state changes
void monitor_carp_state() {
	// Implementation will depend on how you're detecting CARP state changes
	// This could involve interfacing with ifstated or other system mechanisms
}

int receive_message() {
	struct sockaddr_in from_addr;
	struct dcarp_message message;
	/* One byte extra, to notice messages that are too long */
	unsigned char buf[DCARP_WIRE_LEN + 1];
	union {
		struct cmsghdr hdr;
		unsigned char buf[CMSG_SPACE(sizeof(struct sockaddr_dl))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	unsigned int ifindex = 0;
	char ifname[IF_NAMESIZE];
	ssize_t received_bytes;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_name = &from_addr;
	msg.msg_namelen = sizeof(from_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	received_bytes = recvmsg(global_multicast_socket, &msg, 0);
	if (received_bytes < 0) {
		log_perror("recvmsg failed");
		return (-1);
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_RECVIF)
			ifindex = ((struct sockaddr_dl *)CMSG_DATA(cmsg))->sdl_index;
	}
	if (ifindex != sync_ifindex) {
		if (if_indextoname(ifindex, ifname) == NULL)
			snprintf(ifname, sizeof(ifname), "index %u", ifindex);
		log_rejected(&from_addr, "received on %s, not on %s", ifname,
		    global_options.sync_interface);
		return (-1);
	}

	if (received_bytes != DCARP_WIRE_LEN) {
		log_rejected(&from_addr, "%zd bytes, expected %zu",
		    received_bytes, DCARP_WIRE_LEN);
		return (-1);
	}

	if (open_message(buf, &message) != 0) {
		log_rejected(&from_addr,
		    "authentication failed (wrong key, or tampered with)");
		return (-1);
	}

	if (validate_message(&message, &from_addr) != 1)
		return (-1);

	return (process_received_message(&message, &from_addr));
}

/* Encrypt and authenticate a message into DCARP_WIRE_LEN bytes */
int seal_message(const struct dcarp_message *message, unsigned char *wire) {
	size_t len;

	arc4random_buf(wire, DCARP_NONCE_LEN);
	if (!EVP_AEAD_CTX_seal(aead_ctx, wire + DCARP_NONCE_LEN, &len,
	    DCARP_WIRE_LEN - DCARP_NONCE_LEN, wire, DCARP_NONCE_LEN,
	    (const unsigned char *)message, sizeof(*message), dcarp_ad,
	    sizeof(dcarp_ad)) || len != DCARP_WIRE_LEN - DCARP_NONCE_LEN) {
		log_message(LOG_ERR, "cannot encrypt message");
		return (-1);
	}
	return (0);
}

/* Authenticate and decrypt DCARP_WIRE_LEN bytes into a message */
int open_message(const unsigned char *wire, struct dcarp_message *message) {
	size_t len;

	if (!EVP_AEAD_CTX_open(aead_ctx, (unsigned char *)message, &len,
	    sizeof(*message), wire, DCARP_NONCE_LEN, wire + DCARP_NONCE_LEN,
	    DCARP_WIRE_LEN - DCARP_NONCE_LEN, dcarp_ad, sizeof(dcarp_ad)) ||
	    len != sizeof(*message))
		return (-1);
	return (0);
}

int send_message(const struct dcarp_message *message) {
	struct sockaddr_in multicast_addr;
	unsigned char wire[DCARP_WIRE_LEN];

	if (seal_message(message, wire) != 0)
		return (-1);

	memset(&multicast_addr, 0, sizeof(multicast_addr));
	multicast_addr.sin_family = AF_INET;
	multicast_addr.sin_addr.s_addr = inet_addr(DCARP_MULTICAST_ADDR);
	multicast_addr.sin_port = htons(DCARP_MULTICAST_PORT);
	
	if (multicast_addr.sin_addr.s_addr == htonl(INADDR_NONE)) {
		log_message(LOG_ERR, "Invalid multicast address");
		return (-1);
	}
	
	ssize_t sent_bytes = sendto(global_multicast_socket, wire, sizeof(wire),
	    0, (struct sockaddr *)&multicast_addr, sizeof(multicast_addr));

	if (sent_bytes < 0) {
		log_perror("sendto failed");
		return (-1);
	} else if (sent_bytes != sizeof(wire)) {
		log_message(LOG_ERR, "Mismatch in number of sent bytes");
		return (-1);
	}
	return (0);
}

int distribute_ip_addresses() {
	struct dcarp_message message;
	char carp_ip_str[INET_ADDRSTRLEN];
	char netmask_str[INET_ADDRSTRLEN];
	int rv;

	memset(&message, 0, sizeof(message));
	message.message_type = htonl(MSG_TYPE_IP_DISTRIBUTION);

	if (get_interface_ip_and_netmask(global_options.interface_name, &message.carp_ip, &message.netmask) != 0) {
		log_message(LOG_ERR, "Failed to retrieve IP and netmask for interface %s", global_options.interface_name);
		return (0);
	}

	// Convert the gateway IP from string to binary format
	inet_pton(AF_INET, global_options.gateway_ip, &message.gateway_ip);

	message.sender = htobe64(my_sender);
	message.sequence = htobe64(++my_sequence);
	message.timestamp = htobe64(time(NULL));

	rv = send_message(&message);
	if (rv == 0) {
		inet_ntop(AF_INET, &message.carp_ip, carp_ip_str,
		    sizeof(carp_ip_str));
		inet_ntop(AF_INET, &message.netmask, netmask_str,
		    sizeof(netmask_str));
		log_message(LOG_INFO, "sent %s netmask %s gateway %s on %s "
		    "(sender %016llx sequence %llu)", carp_ip_str, netmask_str,
		    global_options.gateway_ip, global_options.sync_interface,
		    (unsigned long long)my_sender,
		    (unsigned long long)my_sequence);
	}
	return (rv);
}

int process_received_message(const struct dcarp_message *message,
    const struct sockaddr_in *from) {
	char carp_ip_str[INET_ADDRSTRLEN];
	char netmask_str[INET_ADDRSTRLEN];
	char gateway_ip_str[INET_ADDRSTRLEN];
	char from_str[INET_ADDRSTRLEN];

	switch (ntohl(message->message_type)) {
        case MSG_TYPE_IP_DISTRIBUTION:
		inet_ntop(AF_INET, &message->carp_ip, carp_ip_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &message->netmask, netmask_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &message->gateway_ip, gateway_ip_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &from->sin_addr, from_str, INET_ADDRSTRLEN);

		log_message(LOG_INFO, "Received IP distribution message from %s "
		    "(sender %016llx sequence %llu): CARP IP: %s, Netmask: %s, "
		    "Gateway IP: %s", from_str,
		    (unsigned long long)be64toh(message->sender),
		    (unsigned long long)be64toh(message->sequence),
		    carp_ip_str, netmask_str, gateway_ip_str);
		if (current_carp_state == CARP_STATE_BACKUP) {
			if (global_options.dry_run) {
				log_message(LOG_WARNING, "Dry-run mode: Skipping network reconfiguration.");
				return (0);
			}
			if (configure_interface(global_options.interface_name, message->carp_ip, message->netmask) != 0)
				return (-1);
			return (configure_default_gateway(message->gateway_ip));
		}
		break;

        default:
		log_rejected(from, "unknown message type %u",
		    ntohl(message->message_type));
		return (-1);
	}
	return (0);
}

/*
 * Accept an authenticated message only if it is at most DCARP_MAX_AGE
 * seconds old (or early, for clocks that differ), and its sequence number
 * is higher than the last one accepted from the same sender.  The age
 * limit covers senders we do not remember, e.g. after a restart.
 */
int validate_message(const struct dcarp_message *message,
    const struct sockaddr_in *from) {
	uint64_t sender, sequence;
	long long age;
	time_t now;
	int i, slot;

	sender = be64toh(message->sender);
	sequence = be64toh(message->sequence);
	now = time(NULL);
	age = (long long)now - (long long)be64toh(message->timestamp);
	if (age > DCARP_MAX_AGE || age < -DCARP_MAX_AGE) {
		log_rejected(from, "timestamp %lld seconds %s (sender %016llx "
		    "sequence %llu); clocks out of sync, or a replay",
		    age < 0 ? -age : age, age < 0 ? "ahead" : "old",
		    (unsigned long long)sender, (unsigned long long)sequence);
		return (0);
	}

	/* Find the sender, or else the slot seen least recently */
	slot = 0;
	for (i = 0; i < DCARP_SENDERS; i++) {
		if (senders[i].seen != 0 && senders[i].sender == sender) {
			slot = i;
			break;
		}
		if (senders[i].seen < senders[slot].seen)
			slot = i;
	}
	if (i < DCARP_SENDERS && sequence <= senders[slot].sequence) {
		log_rejected(from, "replay: sender %016llx sequence %llu, "
		    "already at %llu", (unsigned long long)sender,
		    (unsigned long long)sequence,
		    (unsigned long long)senders[slot].sequence);
		return (0);
	}
	senders[slot].sender = sender;
	senders[slot].sequence = sequence;
	senders[slot].seen = now;

	return (1);
}

// Call this function in handle_master_transition
void handle_master_transition() {
	if (current_carp_state == CARP_STATE_MASTER) {
		log_message(LOG_INFO, "Transitioning to MASTER state. Distributing IP addresses...");
		distribute_ip_addresses();
	}
}

int configure_interface(const char *interface, const in_addr_t ip, const in_addr_t netmask) {
	int sockfd;
	struct in_aliasreq ifra;
	struct sockaddr_in *sin;
	char carp_ip_str[INET_ADDRSTRLEN];
	char netmask_str[INET_ADDRSTRLEN];

	sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		log_perror("socket");
		return (-1);
	}

	memset(&ifra, 0, sizeof(ifra));
	strncpy(ifra.ifra_name, interface, sizeof(ifra.ifra_name));
	sin = (struct sockaddr_in *)&ifra.ifra_addr;
	sin->sin_len = sizeof(*sin);	/* the kernel rejects sin_len 0 */
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ip;
	sin = (struct sockaddr_in *)&ifra.ifra_mask;
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = netmask;
	if (ioctl(sockfd, SIOCAIFADDR, &ifra) < 0) {
		log_perror("ioctl SIOCAIFADDR");
		inet_ntop(AF_INET, &ip, carp_ip_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &netmask, netmask_str, INET_ADDRSTRLEN);
		log_message(LOG_ERR, "IP: %s, Netmask: %s", carp_ip_str, netmask_str);
		close(sockfd);
		return (-1);
	}

	close(sockfd);
	return (0);
}

int configure_default_gateway(const in_addr_t gateway_ip) {
	struct {
		struct rt_msghdr	hdr;
		struct sockaddr_in	dst;
		struct sockaddr_in	gateway;
		struct sockaddr_in	netmask;
	} rtmsg;
	char gateway_ip_str[INET_ADDRSTRLEN];
	int sockfd;

	inet_ntop(AF_INET, &gateway_ip, gateway_ip_str, sizeof(gateway_ip_str));

	sockfd = socket(AF_ROUTE, SOCK_RAW, AF_INET);
	if (sockfd < 0) {
		log_perror("socket");
		return (-1);
	}

	/*
	 * The kernel takes exactly one routing message per write(2), so the
	 * header and the sockaddrs, in RTA_* bit order, go out in one buffer.
	 */
	memset(&rtmsg, 0, sizeof(rtmsg));
	rtmsg.hdr.rtm_msglen = sizeof(rtmsg);
	rtmsg.hdr.rtm_hdrlen = sizeof(rtmsg.hdr);
	rtmsg.hdr.rtm_version = RTM_VERSION;
	rtmsg.hdr.rtm_type = RTM_CHANGE;
	rtmsg.hdr.rtm_tableid = getrtable();
	rtmsg.hdr.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
	rtmsg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;

	/* Destination and netmask 0.0.0.0/0: the default route */
	rtmsg.dst.sin_len = sizeof(rtmsg.dst);
	rtmsg.dst.sin_family = AF_INET;
	rtmsg.netmask.sin_len = sizeof(rtmsg.netmask);
	rtmsg.netmask.sin_family = AF_INET;

	rtmsg.gateway.sin_len = sizeof(rtmsg.gateway);
	rtmsg.gateway.sin_family = AF_INET;
	rtmsg.gateway.sin_addr.s_addr = gateway_ip;

	/* Change the existing default route, or add one if there is none */
	if (write(sockfd, &rtmsg, sizeof(rtmsg)) == -1) {
		if (errno != ESRCH) {
			log_perror("RTM_CHANGE default route");
			goto fail;
		}
		rtmsg.hdr.rtm_type = RTM_ADD;
		if (write(sockfd, &rtmsg, sizeof(rtmsg)) == -1) {
			log_perror("RTM_ADD default route");
			goto fail;
		}
	}

	close(sockfd);
	log_message(LOG_NOTICE, "default route %s via %s",
	    rtmsg.hdr.rtm_type == RTM_ADD ? "added" : "changed", gateway_ip_str);
	return (0);

fail:
	close(sockfd);
	log_message(LOG_ERR, "could not set default route via %s",
	    gateway_ip_str);
	return (-1);
}

int get_carp_interface_state(const char *if_name) {
	int sockfd;
	struct ifreq ifr;
	struct carpreq carpr;

	sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		log_perror("socket");
		return (-1);
	}

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&carpr;

	if (ioctl(sockfd, SIOCGVH, &ifr) < 0) {
		log_perror("ioctl");
		close(sockfd);
		return (-1);
	}

	close(sockfd);

	if (carpr.carpr_vhids[0] == 0 || carpr.carpr_vhids[1] != 0) {
		log_message(LOG_ERR, "carp interface not active, or in balancing mode");
		return (-1);
	}

	return (carpr.carpr_states[0]);
}

int get_interface_ip_and_netmask(const char *if_name, in_addr_t *ip, in_addr_t *netmask) {
	struct ifaddrs *ifaddr, *ifa;
	struct sockaddr_in *sa;
	int found = 0;

	if (getifaddrs(&ifaddr) == -1) {
		log_perror("getifaddrs");
		return -1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, if_name) != 0)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			sa = (struct sockaddr_in *)(ifa->ifa_addr);
			*ip = sa->sin_addr.s_addr;

			sa = (struct sockaddr_in *)(ifa->ifa_netmask);
			*netmask = sa->sin_addr.s_addr;

			found = 1;
			break;
		}
	}

	freeifaddrs(ifaddr);

	return found ? 0 : -1;
}

// Callback function for routing messages
void routing_callback(int fd, short event, void *arg) {
	char msg[2048];
	struct rt_msghdr *rtm = (struct rt_msghdr *)msg;

	ssize_t n = read(fd, msg, sizeof(msg));
	if (n < sizeof(*rtm)) {
		log_message(LOG_ERR, "Error: routing message is too small (%zd bytes)", n);
		return;
	}

	switch (rtm->rtm_type) {
	case RTM_NEWADDR:
		log_message(LOG_DEBUG, "Received RTM_NEWADDR");
		// Handle RTM_NEWADDR
		break;
	case RTM_DELADDR:
		log_message(LOG_DEBUG, "Received RTM_DELADDR");
		// Handle RTM_DELADDR
		break;
	case RTM_IFINFO: {
		struct if_msghdr *ifm = (struct if_msghdr *)msg;

		if (n < sizeof(*ifm)) {
			log_perror("read");
			return;
		}

		/* Only our own carp interface, not every carp(4) on the host */
		if (ifm->ifm_data.ifi_type != IFT_CARP ||
		    ifm->ifm_index != carp_ifindex) {
			return;
		}
                int new_state = determine_carp_state(ifm);
		update_carp_state(new_state);
		
		
		break;
	}
	default:
		log_message(LOG_ERR, "Received unexpected routing message type %d", rtm->rtm_type);
		break;
	}
}

int determine_carp_state(struct if_msghdr *ifm) {
	switch(ifm->ifm_data.ifi_link_state) {
	case LINK_STATE_UP:
		log_message(LOG_DEBUG, "Carp interface is in MASTER state");
		return (CARP_STATE_MASTER);
	case LINK_STATE_DOWN:
		log_message(LOG_DEBUG, "Carp interface is in BACKUP state");
		return (CARP_STATE_BACKUP);
	default:
		log_message(LOG_ERR, "Carp interface is in UNKNOWN state");
		return (CARP_STATE_INIT);
	}
}

void setup_routing_socket(void)
{
	int rtfilter;
	int sockfd;
    
	// Open the socket
	sockfd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
	if (sockfd == -1) {
		log_perror("socket");
		log_close();
		exit(EXIT_FAILURE);
	}

	// Set the message type filter
	rtfilter = ROUTE_FILTER(RTM_IFINFO) | ROUTE_FILTER(RTM_NEWADDR) | ROUTE_FILTER(RTM_DELADDR);
	if (setsockopt(sockfd, PF_ROUTE, ROUTE_MSGFILTER, &rtfilter, sizeof(rtfilter)) == -1) {
		log_perror("setsockopt(ROUTE_MSGFILTER)");
		log_close();
		exit(EXIT_FAILURE);
	}
	routing_socket = sockfd;
}

void multicast_callback(int fd, short event, void *arg) {

	log_message(LOG_DEBUG, "Multicast message received...");
	receive_message();
}

int main(int argc, char *argv[]) {
	int ch;

	while ((ch = getopt(argc, argv, "dnvi:g:k:s:")) != -1) {
		switch (ch) {
		case 'd':
			global_options.foreground = 1;
			break;
		case 'i':
			global_options.interface_name = optarg;
			break;
		case 'g':
			global_options.gateway_ip = optarg;
			break;
		case 'n':
			global_options.dry_run = 1;
			break;
		case 'v':
			global_options.verbose++;
			break;
		case 'k':
			global_options.keyfile_path = optarg;
			break;
		case 's':
			global_options.sync_interface = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0 || global_options.interface_name == NULL || global_options.gateway_ip == NULL) {
		usage();
	}

	log_init();
	
	if (!global_options.dry_run && getuid() != 0) {
		log_message(LOG_ERR, "must be run as root.");
		goto err;
	}

	carp_ifindex = if_nametoindex(global_options.interface_name);
	if (carp_ifindex == 0) {
		log_message(LOG_ERR, "%s: no such interface",
		    global_options.interface_name);
		goto err;
	}
	if (global_options.sync_interface == NULL)
		global_options.sync_interface = global_options.interface_name;
	sync_ifindex = if_nametoindex(global_options.sync_interface);
	if (sync_ifindex == 0) {
		log_message(LOG_ERR, "%s: no such interface",
		    global_options.sync_interface);
		goto err;
	}
	arc4random_buf(&my_sender, sizeof(my_sender));

	if (!global_options.foreground) {
		daemonize();
	}

	aead_ctx = read_keyfile(global_options.keyfile_path);
	if (aead_ctx == NULL)
		goto err;
    
	signal(SIGINT, handle_signal);
	signal(SIGHUP, handle_signal);
	signal(SIGTERM, handle_signal);

	setup_multicast_socket();
	setup_routing_socket();

	current_carp_state = get_carp_interface_state(global_options.interface_name);

	if (current_carp_state == CARP_STATE_MASTER) {
		log_message(LOG_NOTICE, "%s is in MASTER state.", global_options.interface_name);
		distribute_ip_addresses();
	} else if (current_carp_state == CARP_STATE_BACKUP) {
		log_message(LOG_NOTICE, "%s is in BACKUP state.", global_options.interface_name);
		//solicit_master();
	} else if (current_carp_state == CARP_STATE_INIT) {
		log_message(LOG_NOTICE, "%s is in INIT state.", global_options.interface_name);
	} else {
		log_message(LOG_ERR, "%s is in unexpected state %d.", global_options.interface_name, current_carp_state);
		goto err;
	}
	
	event_init();
    
	// Create an event for the multicast socket
	struct event multicast_event;
	event_set(&multicast_event, global_multicast_socket, EV_READ | EV_PERSIST, multicast_callback, NULL);

	// Create an event for the routing socket
	struct event routing_event;
	event_set(&routing_event, routing_socket, EV_READ | EV_PERSIST, routing_callback, NULL);

	// Add the events
	event_add(&multicast_event, NULL);
	event_add(&routing_event, NULL);

	// Start monitoring CARP state changes
	monitor_carp_state();

	// Start the event loop
	event_dispatch();

	log_close();
	return (EXIT_SUCCESS);

err:
	log_close();
	return (EXIT_FAILURE);
}

/*
 * The XChaCha20-Poly1305 key is the SHA-256 hash of the whole key file (up
 * to DCARP_KEYFILE_MAX bytes).  Log a fingerprint, a hash of the key, so
 * the nodes' keys can be compared without showing them.
 */
EVP_AEAD_CTX *read_keyfile(const char *filename) {
	unsigned char buf[DCARP_KEYFILE_MAX];
	unsigned char key[SHA256_DIGEST_LENGTH];
	unsigned char fp[SHA256_DIGEST_LENGTH];
	EVP_AEAD_CTX *ctx;
	struct stat st;
	size_t n;
	FILE *f;

	// Perform checks on the key file
	if (stat(filename, &st) < 0) {
		log_perror("stat");
		return (NULL);
	}

	if (st.st_mode & (S_IRGRP | S_IROTH)) {
		log_message(LOG_ERR, "Keyfile should not be readable by others");
		return (NULL);
	}

	if (st.st_uid != 0 && !global_options.dry_run) {
		log_message(LOG_ERR, "Keyfile should be owned by root");
		return (NULL);
	}

	// Open and read key file
	f = fopen(filename, "r");
	if (!f) {
		log_perror("fopen");
		return (NULL);
	}
	n = fread(buf, 1, sizeof(buf), f);
	if (ferror(f) || n == 0) {
		log_message(LOG_ERR, "Keyfile %s: read error, or empty",
		    filename);
		fclose(f);
		explicit_bzero(buf, sizeof(buf));
		return (NULL);
	}
	fclose(f);

	SHA256(buf, n, key);
	explicit_bzero(buf, sizeof(buf));
	SHA256(key, sizeof(key), fp);

	if ((ctx = EVP_AEAD_CTX_new()) == NULL ||
	    !EVP_AEAD_CTX_init(ctx, EVP_aead_xchacha20_poly1305(), key,
	    DCARP_KEY_LEN, EVP_AEAD_DEFAULT_TAG_LENGTH, NULL)) {
		log_message(LOG_ERR, "cannot set up XChaCha20-Poly1305");
		EVP_AEAD_CTX_free(ctx);
		explicit_bzero(key, sizeof(key));
		return (NULL);
	}
	explicit_bzero(key, sizeof(key));

	log_message(LOG_INFO, "key from %s, fingerprint "
	    "%02x%02x%02x%02x%02x%02x%02x%02x", filename, fp[0], fp[1], fp[2],
	    fp[3], fp[4], fp[5], fp[6], fp[7]);
	return (ctx);
}

void daemonize() {
	if (daemon(1, 0) == -1) {
		log_perror("daemon");
		log_close();
		exit(EXIT_FAILURE);
	}
}

void handle_signal(int signal)
{
	switch (signal) {
        case SIGTERM:
		close_multicast_socket(); // You need to implement this
		log_message(LOG_NOTICE, "terminated by SIGTERM");
		log_close();
		exit(EXIT_SUCCESS);
		break;
        case SIGHUP: {
		// Reread keyfile
		EVP_AEAD_CTX *new_ctx = read_keyfile(global_options.keyfile_path);
		if (new_ctx) {
			EVP_AEAD_CTX_free(aead_ctx);
			aead_ctx = new_ctx;
			log_message(LOG_NOTICE, "Keyfile reloaded successfully");
		} else {
			log_message(LOG_WARNING, "Failed to reload keyfile. Using old key.");
		}
		break;
	}
        default:
		log_message(LOG_INFO, "Unhandled signal (%d) %s", signal, strsignal(signal));
		break;
	}
}

void setup_multicast_socket() {
	struct ip_mreqn mreqn;
	struct sockaddr_in addr;
	int yes = 1;

	/* Create a UDP socket */
	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		log_perror("socket");
		log_close();
		exit(EXIT_FAILURE);
	}

	/* Allow multiple sockets to use the same port number */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		log_perror("setsockopt(SO_REUSEADDR)");
		close(sock);
		log_close();
		exit(EXIT_FAILURE);
	}

	/* Set up destination address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY); /* receive multicast */
	addr.sin_port = htons(DCARP_MULTICAST_PORT);

	/* Bind to receive address */
	if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
		log_perror("bind");
		close(sock);
		log_close();
		exit(EXIT_FAILURE);
	}

	/* Use setsockopt() to request that the kernel join a multicast group */
	struct in_addr multicast_address;
	if (inet_aton(DCARP_MULTICAST_ADDR, &multicast_address) == 0) {
		log_perror("inet_aton");
		log_close();
		exit(EXIT_FAILURE);
	}

	/*
	 * Join and send on the sync interface (the carp interface unless -s
	 * is given), selected by index.  With INADDR_ANY the kernel would pick
	 * the interface of the route to the group, i.e. usually the default
	 * route, and the carp address cannot be used either: it changes with
	 * the DHCP lease on the master and may be missing when the daemon
	 * starts.
	 */
	memset(&mreqn, 0, sizeof(mreqn));
	mreqn.imr_multiaddr = multicast_address;
	mreqn.imr_ifindex = sync_ifindex;
	if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreqn, sizeof(mreqn)) < 0) {
		log_perror("setsockopt(IP_ADD_MEMBERSHIP)");
		close(sock);
		log_close();
		exit(EXIT_FAILURE);
	}
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &mreqn,
	    sizeof(mreqn)) < 0) {
		log_perror("setsockopt(IP_MULTICAST_IF)");
		close(sock);
		log_close();
		exit(EXIT_FAILURE);
	}
	/* Report the receiving interface, to drop messages from elsewhere */
	if (setsockopt(sock, IPPROTO_IP, IP_RECVIF, &yes, sizeof(yes)) < 0) {
		log_perror("setsockopt(IP_RECVIF)");
		close(sock);
		log_close();
		exit(EXIT_FAILURE);
	}
	global_multicast_socket = sock;
}

void close_multicast_socket() {
	// Close the multicast socket
	if (global_multicast_socket >= 0) {
		close(global_multicast_socket);
	}
}

void usage(void) {
	extern char *__progname;

	fprintf(stderr, "usage: %s [-d] [-v] [-n] -i interface -g gateway_ip "
	    "[-k key_file] [-s sync_interface]\n", __progname);
	exit(EXIT_FAILURE);
}
