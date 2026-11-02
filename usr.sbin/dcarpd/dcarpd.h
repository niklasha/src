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
#define DCARP_KEYFILE_MAX 4096	/* bytes of the key file that are used */

struct options {
	char *keyfile_path;
	char *interface_name;
	char *sync_interface;	/* -s, carries the messages; default -i */
	char *gateway_ip;	/* -g, the carp network's gateway as master;
				   default the default route through -i */
	char *state_file;	/* -f, the configuration for ifstated(8) */
	int foreground;
	int verbose;
	int dry_run;
};

/* Ought to have been defined in ip_carp.h but isn't */
#define CARP_STATE_INIT    0
#define CARP_STATE_BACKUP  1
#define CARP_STATE_MASTER  2

/*
 * A message, all integers in network byte order.  On the wire it is sealed
 * with XChaCha20-Poly1305: a random nonce, the encrypted message and the
 * authentication tag.
 */
struct dcarp_message {
	uint32_t message_type;
	in_addr_t carp_ip;
	in_addr_t netmask;
	in_addr_t gateway_ip;
	uint64_t sender;	/* random, chosen when the sender starts */
	uint64_t sequence;	/* per sender, starts at 1 */
	int64_t timestamp;	/* seconds since the epoch */
	int64_t generation;	/* when the carp address was obtained; newer
				   configurations win */
	uint32_t demote;	/* the sender's carp(4) demote count, advbase */
	uint8_t advbase;	/* and advskew: the priority that decides */
	uint8_t advskew;	/* between configurations of one generation */
	uint16_t reserved;
	// Future fields (e.g., DNS servers) can be noted here for later implementation
};

/* The DHCP lease of the carp interface, whose time is the generation */
#define DCARP_LEASE_DIR		"/var/db/dhcpleased"

/* Where the configuration held is written, per carp interface */
#define DCARP_STATE_DIR		"/var/db/dcarpd"

/* A configuration last sent or applied, to notice changes */
struct dcarp_config {
	int valid;
	in_addr_t carp_ip;
	in_addr_t netmask;
	in_addr_t gateway_ip;
	int64_t generation;
};

#define DCARP_KEY_LEN		32	/* XChaCha20-Poly1305 key */
#define DCARP_NONCE_LEN		24
#define DCARP_TAG_LEN		16
#define DCARP_WIRE_LEN		(DCARP_NONCE_LEN + \
				    sizeof(struct dcarp_message) + DCARP_TAG_LEN)

#define MSG_TYPE_IP_DISTRIBUTION 1    // Message type for IP distribution

#define DCARP_INTERVAL		10	/* seconds between resends of a master;
					   must stay below DCARP_MAX_AGE */
#define DCARP_MAX_AGE		30	/* seconds a message is accepted */
#define DCARP_SENDERS		8	/* senders remembered against replay */
#define DCARP_REJECT_LOG_INTERVAL 10	/* seconds between logged rejects */

void close_multicast_socket(void);
int get_default_gateway(in_addr_t *);
int write_state_file(const struct dcarp_message *);
int configure_interface(const char *, in_addr_t, in_addr_t);
void daemonize(void);
int determine_carp_state(struct if_msghdr *);
int get_carp_priority(const char *, uint32_t *, uint8_t *, uint8_t *);
int interface_has_address(const char *, in_addr_t);
int64_t lease_generation(void);
uint32_t priority_key(uint32_t, uint8_t, uint8_t);
int distribute_ip_addresses(void);
int get_interface_ip_and_netmask(const char *, in_addr_t *, in_addr_t *);
void handle_signal(int sig);
void log_close(void);
void log_init(void);
void log_message(int, const char *, ...);
void log_perror(const char *);
int open_message(const unsigned char *, struct dcarp_message *);
int process_received_message(const struct dcarp_message *,
    const struct sockaddr_in *);
struct evp_aead_ctx_st *read_keyfile(const char *);
int seal_message(const struct dcarp_message *, unsigned char *);
int receive_message(void);
int send_message(const struct dcarp_message *);
void setup_multicast_socket(void);
void update_carp_state(int);
int validate_message(const struct dcarp_message *, const struct sockaddr_in *);
void log_rejected(const struct sockaddr_in *, const char *, ...)
    __attribute__((__format__ (printf, 2, 3)));

#endif // _DCARPD_H
