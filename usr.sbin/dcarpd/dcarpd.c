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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip_carp.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
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

void log_init() {
	if (global_options.foreground) {
		// In debug mode, log to stderr
		setlogmask(LOG_UPTO(LOG_INFO));
		openlog("dcarpd", LOG_CONS | LOG_NDELAY | LOG_PERROR, LOG_LOCAL1);
	} else {
		// In normal mode, log to syslog
		openlog("dcarpd", LOG_CONS | LOG_NDELAY, LOG_LOCAL1);
	}
}

void log_message(int level, const char *format, ...) {
	va_list args;
	va_start(args, format);

	if (level <= LOG_INFO + global_options.verbose) {
		if (global_options.foreground) {
			vfprintf(level > LOG_ERR ? stdout : stderr, format, args);
			fprintf(level > LOG_ERR ? stdout : stderr, "\n");
		} else {
			vsyslog(level, format, args);
		}
	}

	va_end(args);
}

void log_close() {
	closelog();
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
	socklen_t from_addr_len = sizeof(from_addr);
	struct dcarp_message message;

	int received_bytes = recvfrom(global_multicast_socket, &message, sizeof(message), 0,
	    (struct sockaddr *)&from_addr, &from_addr_len);

	if (received_bytes < 0) {
		log_perror("recvfrom failed");
		return (-1);
	}

	if (validate_message(&message) != 1)
		return (-1);

	return (process_received_message(&message));
}

int send_message(const struct dcarp_message *message) {
	struct sockaddr_in multicast_addr;

	memset(&multicast_addr, 0, sizeof(multicast_addr));
	multicast_addr.sin_family = AF_INET;
	multicast_addr.sin_addr.s_addr = inet_addr(DCARP_MULTICAST_ADDR);
	multicast_addr.sin_port = htons(DCARP_MULTICAST_PORT);
	
	if (multicast_addr.sin_addr.s_addr == htonl(INADDR_NONE)) {
		log_message(LOG_ERR, "Invalid multicast address");
		return (-1);
	}
	
	int sent_bytes = sendto(global_multicast_socket, message, sizeof(*message), 0,
	    (struct sockaddr *)&multicast_addr, sizeof(multicast_addr));

	if (sent_bytes < 0) {
		log_perror("sendto failed");
		return (-1);
	} else if (sent_bytes != sizeof(*message)) {
		log_message(LOG_ERR, "Mismatch in number of sent bytes");
		return (-1);
	}
	return (0);
}

int add_hmac_signature(struct dcarp_message *message) {
	if (global_options.key == NULL) {
		log_message(LOG_ERR, "No key available for signing the message");
		return (-1);
	}

	unsigned int len;
	HMAC(EVP_sha256(), global_options.key, strlen(global_options.key),
	     (unsigned char*)message, sizeof(*message) - HMAC_LENGTH, message->hmac, &len);
	return (0);
}

int distribute_ip_addresses() {
	struct dcarp_message message;

	message.message_type = MSG_TYPE_IP_DISTRIBUTION;

	if (get_interface_ip_and_netmask(global_options.interface_name, &message.carp_ip, &message.netmask) != 0) {
		log_message(LOG_ERR, "Failed to retrieve IP and netmask for interface %s", global_options.interface_name);
		return (0);
	}

	// Convert the gateway IP from string to binary format
	inet_pton(AF_INET, global_options.gateway_ip, &message.gateway_ip);

	if (add_hmac_signature(&message) == -1)
		return (-1);
	
	return (send_message(&message));
}

int process_received_message(const struct dcarp_message *message) {
	char carp_ip_str[INET_ADDRSTRLEN];
	char netmask_str[INET_ADDRSTRLEN];
	char gateway_ip_str[INET_ADDRSTRLEN];

	switch (message->message_type) {
        case MSG_TYPE_IP_DISTRIBUTION:
		inet_ntop(AF_INET, &message->carp_ip, carp_ip_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &message->netmask, netmask_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &message->gateway_ip, gateway_ip_str, INET_ADDRSTRLEN);

		log_message(LOG_INFO, "Received IP distribution message: CARP IP: %s, Netmask: %s, Gateway IP: %s",
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
		log_message(LOG_ERR, "Unknown message type received: %d", message->message_type);
		return (-1);
	}
	return (0);
}

int validate_message(const struct dcarp_message *message) {
	unsigned char calculated_hmac[HMAC_LENGTH];
	unsigned int len;

	// Assuming global_options.key contains the HMAC key
	if (global_options.key == NULL) {
		log_message(LOG_ERR, "No key available for message validation");
		return (-1);
	}

	HMAC(EVP_sha256(), global_options.key, strlen(global_options.key),
	     (unsigned char*)message, sizeof(*message) - HMAC_LENGTH, calculated_hmac, &len);

	// Compare the received HMAC with the calculated one
	if (len == HMAC_LENGTH && memcmp(message->hmac, calculated_hmac, HMAC_LENGTH) == 0) {
		return (1);  // Valid message
	} else {
		return (0);  // Invalid or tampered message
	}
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
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ip;
	sin = (struct sockaddr_in *)&ifra.ifra_mask;
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
	int sockfd = socket(PF_ROUTE, SOCK_RAW, 0);
	struct rt_msghdr rt;
	struct sockaddr_in dst, gateway;

	if (sockfd < 0) {
		log_perror("socket");
		return (-1);
	}

	memset(&rt, 0, sizeof(rt));
	memset(&dst, 0, sizeof(dst));
	memset(&gateway, 0, sizeof(gateway));

	// Set up the route message
	rt.rtm_msglen = sizeof(rt) + sizeof(struct sockaddr_in) * 2;
	rt.rtm_version = RTM_VERSION;
	rt.rtm_type = RTM_CHANGE;
	rt.rtm_flags = RTF_UP | RTF_GATEWAY;
	rt.rtm_addrs = RTA_DST | RTA_GATEWAY;

	// Destination address (default route: 0.0.0.0)
	dst.sin_family = AF_INET;
	dst.sin_len = sizeof(struct sockaddr_in);
	dst.sin_addr.s_addr = htonl(INADDR_ANY);

	// Gateway address
	gateway.sin_family = AF_INET;
	gateway.sin_len = sizeof(struct sockaddr_in);
	gateway.sin_addr.s_addr = gateway_ip;

	// Write the route message
	write(sockfd, &rt, sizeof(rt));
	write(sockfd, &dst, sizeof(dst));
	write(sockfd, &gateway, sizeof(gateway));

	close(sockfd);
	return (0);
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

		if (ifm->ifm_data.ifi_type != IFT_CARP) {
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

	while ((ch = getopt(argc, argv, "dnvi:g:k:")) != -1) {
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

	if (!global_options.foreground) {
		daemonize();
	}

	global_options.key = read_keyfile(global_options.keyfile_path);
	if (!global_options.key)
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

char *read_keyfile(const char *filename) {
	// Perform checks on the key file
	struct stat st;
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
	FILE *f = fopen(filename, "r");
	if (!f) {
		log_perror("fopen");
		return (NULL);
	}

	char key[KEY_LENGTH + 1];
	int n;
	if ((n = fread(key, 1, KEY_LENGTH, f)) < 1) {
		log_message(LOG_ERR, "Keyfile read error or key length is not correct");
		fclose(f);
		return (NULL);
	}
	key[n] = '\0';

	fclose(f);

	// Hash the key
	// Using SHA256 here, but you can replace it with your preferred hash function
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256((unsigned char*)key, strlen(key), hash);

	// Convert hash to hex string
	char *hash_str = malloc(SHA256_DIGEST_LENGTH*2 + 1);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		snprintf(hash_str + i*2, 3, "%02x", hash[i]);
	}

	return (hash_str);
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
		char *new_key = read_keyfile(global_options.keyfile_path);
		if (new_key) {
			free(global_options.key);
			global_options.key = new_key;
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
	struct ip_mreq mreq;
	struct sockaddr_in addr;
	struct in_addr interface_addr;
	in_addr_t interface_netmask;
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

	mreq.imr_multiaddr.s_addr = multicast_address.s_addr;
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		log_perror("setsockopt(IP_ADD_MEMBERSHIP)");
		close(sock);
		log_close();
		exit(EXIT_FAILURE);
	}
	if (get_interface_ip_and_netmask(global_options.interface_name, &interface_addr.s_addr, &interface_netmask) != 0) {
		log_message(LOG_INFO, "could not get carp interface address");
	} else if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, 
	    (char *)&interface_addr, sizeof(interface_addr)) < 0) {
		log_perror("setsockopt(IP_MULTICAST_IF)");
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

	fprintf(stderr, "usage: %s [-d] [-v] [-n] -i interface -g gateway_ip [-k key_file]\n",
		__progname);
	exit(EXIT_FAILURE);
}
