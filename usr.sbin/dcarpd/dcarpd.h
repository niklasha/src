/*
 * Copyright (c) 2023 Your Name
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

#ifndef _DCARPD_H
#define _DCARPD_H

#include <net/if.h>
#include <netinet/in.h>

#define DEFAULT_KEY_FILE "/etc/dcarp.key"
#define DCARP_MULTICAST_ADDR "224.0.0.18"
#define DCARP_MULTICAST_PORT 3522
#define KEY_LENGTH 32

struct options {
	char *keyfile_path;
	char *key;
	char *interface_name;
	char *gateway_ip;
	int foreground;
	int verbose;
	int dry_run;
};

/* Ought to have been defined in ip_carp.h but isn't */
#define CARP_STATE_INIT    0
#define CARP_STATE_BACKUP  1
#define CARP_STATE_MASTER  2

#define HMAC_LENGTH 32  // Length of HMAC SHA-256 output

struct dcarp_message {
	int message_type;
	in_addr_t carp_ip;
	in_addr_t netmask;
	in_addr_t gateway_ip;
	// Future fields (e.g., DNS servers) can be noted here for later implementation
	unsigned char hmac[HMAC_LENGTH];  // HMAC signature
};

#define MSG_TYPE_IP_DISTRIBUTION 1    // Message type for IP distribution

int add_hmac_signature(struct dcarp_message *);
void close_multicast_socket(void);
int configure_default_gateway(const in_addr_t);
int configure_interface(const char *, in_addr_t, in_addr_t);
void daemonize(void);
int determine_carp_state(struct if_msghdr *);
int distribute_ip_addresses(void);
int get_interface_ip_and_netmask(const char *, in_addr_t *, in_addr_t *);
void handle_signal(int sig);
void log_close(void);
void log_init(void);
void log_message(int, const char *, ...);
void log_perror(const char *);
int process_received_message(const struct dcarp_message *);
char *read_keyfile(const char *);
int receive_message(void);
int send_message(const struct dcarp_message *);
void setup_multicast_socket(void);
void update_carp_state(int);
int validate_message(const struct dcarp_message *);

#endif // _DCARPD_H
