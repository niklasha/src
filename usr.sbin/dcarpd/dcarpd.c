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

#include <limits.h>
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
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/ip_carp.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <ifaddrs.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <poll.h>

#include "dcarpd.h"
#include "dhcpleased.h"

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

/* Resends the configuration every DCARP_INTERVAL seconds as master */
struct event send_timer;

/* What we last sent as master and applied as backup */
struct dcarp_config last_sent, last_applied;

/*
 * The generation of the configuration we hold, and the carp address and
 * netmask that go with it: to tell address changes from outside, e.g. by
 * dhcpleased, from our own, and to put the address back as backup.
 */
int64_t my_generation;
in_addr_t known_ip, known_mask;

/*
 * The DHCP lease time that goes with the generation, 0 if unknown; and
 * when dhcpleased last acknowledged the lease, by its monotonic clock, to
 * notice the next acknowledgement, e.g. of a renewal.
 */
uint32_t my_lease_time;
struct timespec lease_acked;
int64_t lease_acked_at;		/* the same, by our wall clock */

/*
 * Whether to ask dhcpleased for the lease: not after it gave a wrong
 * answer, or none, until SIGHUP.  Its control messages are internal to
 * it, and we ask with IMSG_CTL_SHOW_INTERFACE_INFO only: a dhcpleased
 * whose messages are numbered otherwise might take ours for
 * IMSG_CTL_SEND_REQUEST and request its lease anew.  Look again when
 * dhcpleased.h changes.
 */
volatile sig_atomic_t lease_asking = 1;
_Static_assert(IMSG_CTL_SHOW_INTERFACE_INFO == 2 &&
    IMSG_CTL_SEND_REQUEST == 3, "dhcpleased's control messages changed");

/* Puts the address back as backup, a moment after its removal */
struct event restore_timer;
void restore_timer_callback(int, short, void *);

/*
 * The backup gateway, -g, of the member we last took a configuration
 * from: ours to use while we are backup.  Kept in the state file.
 */
in_addr_t learned_backup_gw;

/*
 * The provider's gateway we last took or sent: a backup that becomes
 * master still routes via the old master, not through the carp interface,
 * and announces this one until it has a route of its own there.
 */
in_addr_t learned_gw;

/* Whether we hold a demotion of the carp interface's groups: no address */
int demoted;

/*
 * The groups we demoted, so that we lift exactly our own demotion: the
 * interface may join or leave groups meanwhile (egress follows the default
 * route), and another program may lift a group's demotion.
 */
#define DEMOTED_MAX	16
char demoted_groups[DEMOTED_MAX][IFNAMSIZ];
int ndemoted;

/*
 * How often the -x hook was asked to run, the one running, whether it must
 * run again when that one exits, and the reaper of its processes
 */
unsigned int hook_runs;
pid_t hook_pid;
int hook_pending;
struct event sigchld_event;

void sigchld_callback(int, short, void *);

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

int config_matches(const struct dcarp_config *config,
    const struct dcarp_message *message) {
	return (config->valid && config->carp_ip == message->carp_ip &&
	    config->netmask == message->netmask &&
	    config->gateway_ip == message->gateway_ip &&
	    config->backup_gateway == message->backup_gateway &&
	    config->generation == message->generation &&
	    config->lease_time == message->lease_time);
}

void config_record(struct dcarp_config *config,
    const struct dcarp_message *message) {
	config->valid = 1;
	config->carp_ip = message->carp_ip;
	config->netmask = message->netmask;
	config->gateway_ip = message->gateway_ip;
	config->backup_gateway = message->backup_gateway;
	config->generation = message->generation;
	config->lease_time = message->lease_time;
}

const char *carp_state_name(int state) {
	static const char *names[] = { "INIT", "BACKUP", "MASTER" };

	if (state < CARP_STATE_INIT || state > CARP_STATE_MASTER)
		return ("INIT");
	return (names[state]);
}

void update_carp_state(int new_state) {
	unsigned int runs;

	if (new_state != current_carp_state) {
		current_carp_state = new_state;
		log_message(LOG_INFO, "CARP state changed to %s",
		    carp_state_name(current_carp_state));

		/*
		 * Report the first message sent in the new state, and apply
		 * the master's configuration again as a new backup: routes
		 * may have been changed while we were master.
		 */
		last_sent.valid = 0;
		last_applied.valid = 0;

		/*
		 * Let the hook route for the new state.  As master, sending
		 * writes the state file, which runs it already, and so does
		 * putting the address back as backup: back without it, e.g.
		 * removed while the interface was down.
		 */
		runs = hook_runs;
		if (new_state == CARP_STATE_MASTER) {
			distribute_ip_addresses();
		} else if (new_state == CARP_STATE_BACKUP) {
			restore_address();
			update_demote();
		}
		if (hook_runs == runs)
			run_hook();
	}
}

/*
 * Run the -x program, with the state file and our carp state, without
 * waiting for it: when the configuration we hold or our state changes, so
 * that it can set the routes.  This matters with more than two members,
 * where the master changes while a backup stays backup.  One at a time,
 * lest an older run set its routes last: while one runs, the next one
 * waits for it, and gets the state of then.
 */
void run_hook(void) {
	if (global_options.hook == NULL)
		return;
	hook_runs++;
	if (hook_pid != 0)
		hook_pending = 1;
	else
		start_hook();
}

void start_hook(void) {
	char *argv[4];
	pid_t pid;

	argv[0] = global_options.hook;
	argv[1] = global_options.state_file;
	argv[2] = (char *)carp_state_name(current_carp_state);
	argv[3] = NULL;

	switch (pid = fork()) {
	case -1:
		log_perror("fork");
		return;
	case 0:
		/* We ignore it, lest dhcpleased going away kill us */
		signal(SIGPIPE, SIG_DFL);
		execv(argv[0], argv);
		log_perror(argv[0]);
		_exit(127);
	default:
		hook_pid = pid;
		log_message(LOG_DEBUG, "running %s %s %s (pid %d)", argv[0],
		    argv[1], argv[2], (int)pid);
	}
}

/* Reap the hook, report it if it failed, and start the one waiting */
void sigchld_callback(int sig, short event, void *arg) {
	pid_t pid;
	int status;

	while ((pid = waitpid(WAIT_ANY, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			log_message(LOG_WARNING, "%s (pid %d) exited with %d",
			    global_options.hook, (int)pid,
			    WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			log_message(LOG_WARNING, "%s (pid %d) killed by "
			    "signal %d", global_options.hook, (int)pid,
			    WTERMSIG(status));
		if (pid != hook_pid)
			continue;
		hook_pid = 0;
		if (hook_pending) {
			hook_pending = 0;
			start_hook();
		}
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
	static int no_address;
	struct dcarp_message message;
	char carp_ip_str[INET_ADDRSTRLEN];
	char netmask_str[INET_ADDRSTRLEN];
	char gateway_ip_str[INET_ADDRSTRLEN];
	char backup_gw_str[INET_ADDRSTRLEN];
	uint32_t demote;
	int rv;

	memset(&message, 0, sizeof(message));
	message.message_type = htonl(MSG_TYPE_IP_DISTRIBUTION);

	/* Called every DCARP_INTERVAL seconds: complain only once */
	if (get_interface_ip_and_netmask(global_options.interface_name, &message.carp_ip, &message.netmask) != 0) {
		if (!no_address)
			log_message(LOG_ERR, "Failed to retrieve IP and netmask for interface %s, not sending until it has one", global_options.interface_name);
		no_address = 1;
		return (0);
	}
	no_address = 0;

	/*
	 * The gateway of the carp network, which the provider gives us, for
	 * the backups to use when they become master: that of our default
	 * route through the carp interface, or none.  And our own address on
	 * the members' other network, -g, for them to use while they are
	 * backup; main() has checked it.  As a backup become master we may
	 * still route via the old one: then the gateway learned from it, if
	 * it is on our carp network.
	 */
	if (get_default_gateway(&message.gateway_ip) == 0)
		learned_gw = message.gateway_ip;
	else if ((learned_gw & message.netmask) ==
	    (message.carp_ip & message.netmask))
		message.gateway_ip = learned_gw;
	else
		message.gateway_ip = INADDR_ANY;
	if (global_options.gateway_ip != NULL)
		inet_pton(AF_INET, global_options.gateway_ip,
		    &message.backup_gateway);

	/* A bind or a renewal of the DHCP lease is a new generation */
	lease_update(message.carp_ip);
	message.sender = htobe64(my_sender);
	message.sequence = htobe64(++my_sequence);
	message.timestamp = htobe64(time(NULL));
	message.generation = htobe64(my_generation);
	message.lease_time = htonl(my_lease_time);
	if (get_carp_priority(global_options.interface_name, &demote,
	    &message.advbase, &message.advskew) != 0)
		return (-1);
	message.demote = htonl(demote);

	rv = send_message(&message);
	if (rv != 0)
		return (rv);

	/* Log the resends of an unchanged configuration only with -v */
	if (config_matches(&last_sent, &message)) {
		log_message(LOG_DEBUG, "resent unchanged configuration on %s "
		    "(sequence %llu)", global_options.sync_interface,
		    (unsigned long long)my_sequence);
		return (0);
	}
	inet_ntop(AF_INET, &message.carp_ip, carp_ip_str, sizeof(carp_ip_str));
	inet_ntop(AF_INET, &message.netmask, netmask_str, sizeof(netmask_str));
	inet_ntop(AF_INET, &message.gateway_ip, gateway_ip_str,
	    sizeof(gateway_ip_str));
	inet_ntop(AF_INET, &message.backup_gateway, backup_gw_str,
	    sizeof(backup_gw_str));
	log_message(LOG_INFO, "sent %s netmask %s gateway %s backup gateway "
	    "%s on %s (sender %016llx sequence %llu generation %lld "
	    "lease %u priority %u/%u/%u)", carp_ip_str, netmask_str,
	    message.gateway_ip != INADDR_ANY ? gateway_ip_str : "none",
	    message.backup_gateway != INADDR_ANY ? backup_gw_str : "none",
	    global_options.sync_interface,
	    (unsigned long long)my_sender, (unsigned long long)my_sequence,
	    (long long)my_generation, my_lease_time, demote, message.advbase,
	    message.advskew);
	config_record(&last_sent, &message);
	/*
	 * Our own -g is no use to us: keep the backup gateway learned from
	 * the members that were master before, for when we are backup again.
	 */
	write_state_file(&message, learned_backup_gw);
	return (0);
}

/* Resend our configuration as master; the timer runs in all states */
void send_timer_callback(int fd, short event, void *arg) {
	struct timeval tv = { DCARP_INTERVAL, 0 };

	/* In case an address change went by unseen */
	if (current_carp_state == CARP_STATE_BACKUP &&
	    get_carp_interface_state(global_options.interface_name) ==
	    CARP_STATE_BACKUP)
		restore_address();
	update_demote();
	if (current_carp_state == CARP_STATE_MASTER)
		distribute_ip_addresses();
	evtimer_add(&send_timer, &tv);
}

int process_received_message(const struct dcarp_message *message,
    const struct sockaddr_in *from) {
	char carp_ip_str[INET_ADDRSTRLEN];
	char netmask_str[INET_ADDRSTRLEN];
	char gateway_ip_str[INET_ADDRSTRLEN];
	char backup_gw_str[INET_ADDRSTRLEN];
	char from_str[INET_ADDRSTRLEN];
	uint32_t demote, their_prio, my_prio;
	uint8_t advbase, advskew;
	int64_t gen;
	int better;

	switch (ntohl(message->message_type)) {
        case MSG_TYPE_IP_DISTRIBUTION:
		inet_ntop(AF_INET, &message->carp_ip, carp_ip_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &message->netmask, netmask_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &message->gateway_ip, gateway_ip_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &message->backup_gateway, backup_gw_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &from->sin_addr, from_str, INET_ADDRSTRLEN);

		/* Our own message, looped back */
		if (be64toh(message->sender) == my_sender)
			return (0);

		/*
		 * Whatever our state: the newest configuration wins, by the
		 * generation, the time its address was obtained.  So a backup
		 * that has become master because the master's address
		 * changed, and with it the carp authentication, takes the new
		 * address and returns to backup; and the master, while carp
		 * restarts after the change, does not take the old address
		 * back from it.
		 *
		 * Within one generation a backup takes it from whoever sends
		 * it: only a master sends, and carp has elected it, even if
		 * our priority is better, e.g. without preemption.  So does
		 * a member in INIT, which sends nothing, e.g. one without an
		 * address yet.  A master takes it only from a sender with a
		 * better carp(4) priority, the lower sender id breaking ties,
		 * which decides between masters that see each other's
		 * messages but not each other's advertisements.
		 */
		gen = (int64_t)be64toh(message->generation);
		their_prio = priority_key(ntohl(message->demote),
		    message->advbase, message->advskew);
		if (get_carp_priority(global_options.interface_name, &demote,
		    &advbase, &advskew) != 0)
			return (-1);
		my_prio = priority_key(demote, advbase, advskew);
		better = their_prio < my_prio || (their_prio == my_prio &&
		    be64toh(message->sender) < my_sender);
		if (gen < my_generation) {
			log_rejected(from, "older configuration %s gateway %s "
			    "(generation %lld, ours %lld)", carp_ip_str,
			    gateway_ip_str, (long long)gen,
			    (long long)my_generation);
			return (0);
		}
		if (gen == my_generation && !better &&
		    current_carp_state == CARP_STATE_MASTER) {
			if (config_matches(&last_applied, message))
				return (0);
			log_rejected(from, "configuration %s gateway %s from a "
			    "sender of no better priority (%u/%u/%u, ours "
			    "%u/%u/%u)", carp_ip_str, gateway_ip_str,
			    ntohl(message->demote), message->advbase,
			    message->advskew, demote, advbase, advskew);
			return (0);
		}
		my_generation = gen;
		my_lease_time = ntohl(message->lease_time);

		/*
		 * A master resends every DCARP_INTERVAL seconds; only a
		 * changed configuration is logged without -v and applied.
		 */
		if (config_matches(&last_applied, message)) {
			log_message(LOG_DEBUG, "Received IP distribution message "
			    "from %s (sender %016llx sequence %llu): CARP IP: %s, "
			    "Netmask: %s, Gateway IP: %s, Backup Gateway: %s, "
			    "unchanged", from_str,
			    (unsigned long long)be64toh(message->sender),
			    (unsigned long long)be64toh(message->sequence),
			    carp_ip_str, netmask_str, gateway_ip_str,
			    backup_gw_str);
			return (0);
		}
		log_message(LOG_INFO, "Received IP distribution message from %s "
		    "(sender %016llx sequence %llu generation %lld lease %u): "
		    "CARP IP: %s, Netmask: %s, Gateway IP: %s, Backup Gateway: "
		    "%s%s", from_str,
		    (unsigned long long)be64toh(message->sender),
		    (unsigned long long)be64toh(message->sequence),
		    (long long)gen, my_lease_time, carp_ip_str, netmask_str,
		    gateway_ip_str,
		    backup_gw_str, current_carp_state == CARP_STATE_BACKUP ? "" :
		    ", taking it although not backup");
		/*
		 * Set the address; the routes are left to ifstated(8) and
		 * the like, which find the gateway in the state file.
		 */
		if (global_options.dry_run) {
			log_message(LOG_WARNING, "Dry-run mode: Skipping network reconfiguration.");
		} else {
			/* Our own address change, not one from outside */
			known_ip = message->carp_ip;
			known_mask = message->netmask;
			/* On failure, the next resend tries again */
			if (configure_interface(global_options.interface_name, message->carp_ip, message->netmask) != 0)
				return (-1);
		}
		/* The sender's -g is our gateway while we are backup */
		learned_backup_gw = message->backup_gateway;
		if (message->gateway_ip != INADDR_ANY)
			learned_gw = message->gateway_ip;
		if (write_state_file(message, learned_backup_gw) != 0)
			return (-1);
		config_record(&last_applied, message);
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

/*
 * Make the given address the only IPv4 address of the interface.  carp(4)
 * authenticates its advertisements over all of them, so an old address
 * left as an alias keeps the backup from accepting the master's.  Every
 * change restarts carp on the interface, so change nothing if the address
 * is there already, and add the new address before removing the others:
 * without any address carp stays in INIT.
 */
int configure_interface(const char *interface, const in_addr_t ip, const in_addr_t netmask) {
	struct ifaddrs *ifaddr, *ifa;
	struct in_aliasreq ifra;
	char old_str[INET_ADDRSTRLEN];
	int sockfd, have = 0, others = 0, rv = 0;

	if (getifaddrs(&ifaddr) == -1) {
		log_perror("getifaddrs");
		return (-1);
	}
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET ||
		    strcmp(ifa->ifa_name, interface) != 0)
			continue;
		if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr == ip &&
		    ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr ==
		    netmask)
			have = 1;
		else
			others++;
	}
	if (have && others == 0) {
		freeifaddrs(ifaddr);
		return (0);
	}

	sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		log_perror("socket");
		freeifaddrs(ifaddr);
		return (-1);
	}

	if (!have && add_address(interface, ip, netmask) != 0) {
		rv = -1;
		goto out;
	}

	/* Remove the other addresses; one with our address got the netmask */
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET ||
		    strcmp(ifa->ifa_name, interface) != 0 ||
		    ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr == ip)
			continue;
		memset(&ifra, 0, sizeof(ifra));
		strlcpy(ifra.ifra_name, interface, sizeof(ifra.ifra_name));
		memcpy(&ifra.ifra_addr, ifa->ifa_addr, sizeof(struct sockaddr_in));
		inet_ntop(AF_INET,
		    &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, old_str,
		    INET_ADDRSTRLEN);
		if (ioctl(sockfd, SIOCDIFADDR, &ifra) < 0) {
			log_perror("ioctl SIOCDIFADDR");
			log_message(LOG_ERR, "%s: could not remove %s", interface,
			    old_str);
			rv = -1;
			continue;
		}
		log_message(LOG_NOTICE, "%s: removed %s", interface, old_str);
	}

out:
	close(sockfd);
	freeifaddrs(ifaddr);
	return (rv);
}

/* Add an address, with its netmask, to the interface */
int add_address(const char *interface, const in_addr_t ip,
    const in_addr_t netmask) {
	struct sockaddr_in *sin;
	struct in_aliasreq ifra;
	char carp_ip_str[INET_ADDRSTRLEN];
	char netmask_str[INET_ADDRSTRLEN];
	int sockfd, rv = 0;

	inet_ntop(AF_INET, &ip, carp_ip_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &netmask, netmask_str, INET_ADDRSTRLEN);
	sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		log_perror("socket");
		return (-1);
	}
	memset(&ifra, 0, sizeof(ifra));
	strlcpy(ifra.ifra_name, interface, sizeof(ifra.ifra_name));
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
		log_message(LOG_ERR, "IP: %s, Netmask: %s", carp_ip_str,
		    netmask_str);
		rv = -1;
	} else
		log_message(LOG_NOTICE, "%s: added %s netmask %s", interface,
		    carp_ip_str, netmask_str);
	close(sockfd);
	return (rv);
}

#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

/*
 * The gateway of our best default route, if that goes through the carp
 * interface: one dhcpleased added from the lease, or ifstated from our
 * state file.  dcarpd never changes routes itself.
 */
int get_default_gateway(in_addr_t *gateway_ip) {
	struct {
		struct rt_msghdr	hdr;
		struct sockaddr_in	dst;
		struct sockaddr_in	netmask;
	} rtmsg;
	static int seq;
	char buf[2048];
	struct rt_msghdr *rtm = (struct rt_msghdr *)buf;
	struct sockaddr *sa;
	char *cp;
	ssize_t n;
	int sockfd, i, rv = -1;

	sockfd = socket(AF_ROUTE, SOCK_RAW, AF_INET);
	if (sockfd < 0) {
		log_perror("socket");
		return (-1);
	}

	/*
	 * The kernel takes exactly one routing message per write(2), so the
	 * header and the sockaddrs, in RTA_* bit order, go out in one buffer.
	 * Destination and netmask 0.0.0.0/0: the default route.
	 */
	memset(&rtmsg, 0, sizeof(rtmsg));
	rtmsg.hdr.rtm_msglen = sizeof(rtmsg);
	rtmsg.hdr.rtm_hdrlen = sizeof(rtmsg.hdr);
	rtmsg.hdr.rtm_version = RTM_VERSION;
	rtmsg.hdr.rtm_type = RTM_GET;
	rtmsg.hdr.rtm_seq = ++seq;
	rtmsg.hdr.rtm_tableid = getrtable();
	rtmsg.hdr.rtm_addrs = RTA_DST | RTA_NETMASK;
	rtmsg.dst.sin_len = sizeof(rtmsg.dst);
	rtmsg.dst.sin_family = AF_INET;
	rtmsg.netmask.sin_len = sizeof(rtmsg.netmask);
	rtmsg.netmask.sin_family = AF_INET;

	if (write(sockfd, &rtmsg, sizeof(rtmsg)) == -1) {
		if (errno != ESRCH)	/* ESRCH: no default route */
			log_perror("RTM_GET default route");
		goto out;
	}
	do {
		n = read(sockfd, buf, sizeof(buf));
	} while (n > 0 && (rtm->rtm_version != RTM_VERSION ||
	    rtm->rtm_type != RTM_GET || rtm->rtm_seq != seq ||
	    rtm->rtm_pid != getpid()));
	if (n < (ssize_t)sizeof(*rtm) || rtm->rtm_errno != 0 ||
	    rtm->rtm_index != carp_ifindex || !(rtm->rtm_addrs & RTA_GATEWAY))
		goto out;

	cp = buf + rtm->rtm_hdrlen;
	for (i = 0; i < RTAX_MAX && cp < buf + n; i++) {
		if (!(rtm->rtm_addrs & (1 << i)))
			continue;
		sa = (struct sockaddr *)cp;
		if (i == RTAX_GATEWAY) {
			if (sa->sa_family == AF_INET) {
				*gateway_ip =
				    ((struct sockaddr_in *)sa)->sin_addr.s_addr;
				rv = 0;
			}
			break;
		}
		cp += ROUNDUP(sa->sa_len);
	}
out:
	close(sockfd);
	return (rv);
}

/*
 * Write the configuration we hold, as master or backup, for ifstated(8)
 * and other scripts to source: shell variable assignments, replaced
 * atomically.  The routes are theirs to set; this is what they need: the
 * gateway to use as master, and the one to use as backup.
 */
int write_state_file(const struct dcarp_message *message,
    in_addr_t backup_gateway) {
	char tmp[PATH_MAX];
	char carp_ip_str[INET_ADDRSTRLEN];
	char netmask_str[INET_ADDRSTRLEN];
	char gateway_ip_str[INET_ADDRSTRLEN] = "";
	char backup_gw_str[INET_ADDRSTRLEN] = "";
	char lease_str[16] = "", expires_str[24] = "";
	long long gen = (long long)be64toh(message->generation);
	uint32_t lease_time = ntohl(message->lease_time);
	FILE *f;
	int fd;

	inet_ntop(AF_INET, &message->carp_ip, carp_ip_str, sizeof(carp_ip_str));
	inet_ntop(AF_INET, &message->netmask, netmask_str, sizeof(netmask_str));
	if (message->gateway_ip != INADDR_ANY)
		inet_ntop(AF_INET, &message->gateway_ip, gateway_ip_str,
		    sizeof(gateway_ip_str));
	if (backup_gateway != INADDR_ANY)
		inet_ntop(AF_INET, &backup_gateway, backup_gw_str,
		    sizeof(backup_gw_str));
	/* The generation is when the lease was acknowledged */
	if (lease_time != 0) {
		snprintf(lease_str, sizeof(lease_str), "%u", lease_time);
		if (gen > 0 && gen <= LLONG_MAX - lease_time)
			snprintf(expires_str, sizeof(expires_str), "%lld",
			    gen + lease_time);
	}

	if (snprintf(tmp, sizeof(tmp), "%s.XXXXXXXXXX",
	    global_options.state_file) >= (int)sizeof(tmp)) {
		log_message(LOG_ERR, "state file name too long");
		return (-1);
	}
	if ((fd = mkstemp(tmp)) == -1) {
		log_perror(tmp);
		return (-1);
	}
	if (fchmod(fd, 0644) == -1 || (f = fdopen(fd, "w")) == NULL) {
		log_perror(tmp);
		close(fd);
		unlink(tmp);
		return (-1);
	}
	fprintf(f, "# %s, written by dcarpd(8): do not edit.\n"
	    "DCARP_INTERFACE=%s\n"
	    "DCARP_ADDRESS=%s\n"
	    "DCARP_NETMASK=%s\n"
	    "DCARP_GATEWAY=%s\n"
	    "DCARP_BACKUP_GATEWAY=%s\n"
	    "DCARP_GENERATION=%lld\n"
	    "DCARP_LEASE_TIME=%s\n"
	    "DCARP_LEASE_EXPIRES=%s\n", global_options.interface_name,
	    global_options.interface_name, carp_ip_str, netmask_str,
	    gateway_ip_str, backup_gw_str, gen, lease_str, expires_str);
	if (fflush(f) == EOF || fsync(fd) == -1) {
		log_perror(tmp);
		fclose(f);
		unlink(tmp);
		return (-1);
	}
	fclose(f);
	if (rename(tmp, global_options.state_file) == -1) {
		log_perror(global_options.state_file);
		unlink(tmp);
		return (-1);
	}
	log_message(LOG_INFO, "wrote %s: address %s netmask %s gateway %s "
	    "backup gateway %s generation %lld lease %s",
	    global_options.state_file, carp_ip_str, netmask_str,
	    gateway_ip_str[0] ? gateway_ip_str : "none",
	    backup_gw_str[0] ? backup_gw_str : "none", gen,
	    lease_str[0] ? lease_str : "none");
	run_hook();
	return (0);
}

/*
 * An address our state file holds from before, if any, e.g. the backup
 * gateway, the -g of the member we last took a configuration from:
 * started as master, we have heard from no other member yet, but need it
 * when we become backup.
 */
in_addr_t read_state_address(const char *name) {
	char line[128];
	size_t len = strlen(name);
	in_addr_t gw = INADDR_ANY;
	FILE *f;

	if ((f = fopen(global_options.state_file, "r")) == NULL)
		return (INADDR_ANY);
	while (fgets(line, sizeof(line), f) != NULL) {
		if (strncmp(line, name, len) != 0 || line[len] != '=')
			continue;
		line[strcspn(line, "\n")] = '\0';
		if (inet_pton(AF_INET, line + len + 1, &gw) != 1)
			gw = INADDR_ANY;
		break;
	}
	fclose(f);
	return (gw);
}

/* A number our state file holds from before, if any, else 0 */
long long read_state_number(const char *name, long long max) {
	char line[128];
	size_t len = strlen(name);
	const char *errstr;
	long long n = 0;
	FILE *f;

	if ((f = fopen(global_options.state_file, "r")) == NULL)
		return (0);
	while (fgets(line, sizeof(line), f) != NULL) {
		if (strncmp(line, name, len) != 0 || line[len] != '=')
			continue;
		line[strcspn(line, "\n")] = '\0';
		n = strtonum(line + len + 1, 0, max, &errstr);
		if (errstr != NULL)
			n = 0;
		break;
	}
	fclose(f);
	return (n);
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

/* Lower is better, ordered as carp(4) orders advertisements */
uint32_t priority_key(uint32_t demote, uint8_t advbase, uint8_t advskew) {
	return ((demote << 16) | (advbase << 8) | advskew);
}

/*
 * Our carp(4) priority: the demote count, summed over the interface's
 * groups like carp_group_demote_count() does, and advbase and advskew.
 */
int get_carp_priority(const char *if_name, uint32_t *demote, uint8_t *advbase,
    uint8_t *advskew) {
	struct ifgroupreq ifgr, ifga;
	struct ifg_req *ifg;
	struct carpreq carpr;
	struct ifreq ifr;
	unsigned int len;
	int sockfd, rv = -1;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		log_perror("socket");
		return (-1);
	}

	memset(&ifr, 0, sizeof(ifr));
	memset(&carpr, 0, sizeof(carpr));
	strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&carpr;
	if (ioctl(sockfd, SIOCGVH, &ifr) < 0) {
		log_perror("ioctl SIOCGVH");
		goto out;
	}
	*advbase = carpr.carpr_advbase;
	*advskew = carpr.carpr_advskews[0];

	memset(&ifgr, 0, sizeof(ifgr));
	strlcpy(ifgr.ifgr_name, if_name, sizeof(ifgr.ifgr_name));
	if (ioctl(sockfd, SIOCGIFGROUP, &ifgr) < 0) {
		log_perror("ioctl SIOCGIFGROUP");
		goto out;
	}
	len = ifgr.ifgr_len;
	if ((ifgr.ifgr_groups = calloc(1, len)) == NULL) {
		log_perror("calloc");
		goto out;
	}
	if (ioctl(sockfd, SIOCGIFGROUP, &ifgr) < 0) {
		log_perror("ioctl SIOCGIFGROUP");
		free(ifgr.ifgr_groups);
		goto out;
	}
	*demote = 0;
	for (ifg = ifgr.ifgr_groups; len >= sizeof(*ifg); ifg++,
	    len -= sizeof(*ifg)) {
		memset(&ifga, 0, sizeof(ifga));
		strlcpy(ifga.ifgr_name, ifg->ifgrq_group,
		    sizeof(ifga.ifgr_name));
		if (ioctl(sockfd, SIOCGIFGATTR, &ifga) == 0)
			*demote += ifga.ifgr_attrib.ifg_carp_demoted;
	}
	free(ifgr.ifgr_groups);
	if (*demote > 255)
		*demote = 255;
	rv = 0;
out:
	close(sockfd);
	return (rv);
}

/* Adjust the carp demote count of a group by adj */
static int group_demote(int sockfd, const char *group, int adj) {
	struct ifgroupreq ifga;

	memset(&ifga, 0, sizeof(ifga));
	strlcpy(ifga.ifgr_name, group, sizeof(ifga.ifgr_name));
	ifga.ifgr_attrib.ifg_carp_demoted = adj;
	return (ioctl(sockfd, SIOCSIFGATTR, &ifga));
}

/*
 * Demote every group the carp interface is in by one, as the kernel does
 * for a carp device whose link is down, and remember which we demoted.
 * Returns 0 if we hold a demotion of at least one group.
 */
int demote_groups(void) {
	struct ifgroupreq ifgr;
	struct ifg_req *ifg;
	unsigned int len;
	int i, sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		log_perror("socket");
		return (-1);
	}
	memset(&ifgr, 0, sizeof(ifgr));
	strlcpy(ifgr.ifgr_name, global_options.interface_name,
	    sizeof(ifgr.ifgr_name));
	if (ioctl(sockfd, SIOCGIFGROUP, &ifgr) < 0) {
		log_perror("ioctl SIOCGIFGROUP");
		goto out;
	}
	len = ifgr.ifgr_len;
	if ((ifgr.ifgr_groups = calloc(1, len)) == NULL) {
		log_perror("calloc");
		goto out;
	}
	if (ioctl(sockfd, SIOCGIFGROUP, &ifgr) < 0) {
		log_perror("ioctl SIOCGIFGROUP");
		free(ifgr.ifgr_groups);
		goto out;
	}
	for (ifg = ifgr.ifgr_groups; len >= sizeof(*ifg); ifg++,
	    len -= sizeof(*ifg)) {
		for (i = 0; i < ndemoted; i++)
			if (strcmp(demoted_groups[i], ifg->ifgrq_group) == 0)
				break;
		if (i < ndemoted)
			continue;
		if (ndemoted == DEMOTED_MAX) {
			log_message(LOG_ERR, "too many groups, not demoting %s",
			    ifg->ifgrq_group);
			continue;
		}
		if (group_demote(sockfd, ifg->ifgrq_group, 1) < 0) {
			log_perror("ioctl SIOCSIFGATTR");
			log_message(LOG_ERR, "could not demote group %s",
			    ifg->ifgrq_group);
			continue;
		}
		strlcpy(demoted_groups[ndemoted++], ifg->ifgrq_group,
		    sizeof(demoted_groups[0]));
	}
	free(ifgr.ifgr_groups);
out:
	close(sockfd);
	return (ndemoted > 0 ? 0 : -1);
}

/*
 * Lift the demotion of the groups we demoted.  A group whose demote count
 * is already 0 (EINVAL) or which is gone (ENOENT) had its demotion lifted
 * elsewhere: we hold none there any more.  Returns 0 once we hold none.
 */
int undemote_groups(void) {
	int i, j, sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		log_perror("socket");
		return (-1);
	}
	for (i = j = 0; i < ndemoted; i++) {
		if (group_demote(sockfd, demoted_groups[i], -1) == 0)
			continue;
		if (errno == EINVAL || errno == ENOENT) {
			log_message(LOG_NOTICE, "the demotion of group %s was "
			    "already lifted", demoted_groups[i]);
			continue;
		}
		log_perror("ioctl SIOCSIFGATTR");
		log_message(LOG_ERR, "could not undemote group %s",
		    demoted_groups[i]);
		if (j != i)
			memcpy(demoted_groups[j], demoted_groups[i],
			    sizeof(demoted_groups[0]));
		j++;
	}
	ndemoted = j;
	close(sockfd);
	return (ndemoted == 0 ? 0 : -1);
}

/*
 * carp(4) authenticates its advertisements over the addresses of the
 * interface, so a member without an address neither accepts the master's
 * advertisements nor sends any the others accept; it becomes master
 * beside the master.  Hold a demotion of the carp interface's groups while
 * it has no address, so that as master it takes the configuration, the
 * address, of a master that has one, which it rejects from a sender of no
 * better priority, and so that the others prefer another master.
 */
void update_demote(void) {
	in_addr_t ip, netmask;
	int has;

	if (global_options.dry_run)
		return;
	has = get_interface_ip_and_netmask(global_options.interface_name,
	    &ip, &netmask) == 0;
	if (!has && !demoted) {
		if (demote_groups() == 0) {
			demoted = 1;
			log_message(LOG_NOTICE, "%s has no address: demoted "
			    "its groups", global_options.interface_name);
		}
	} else if (has && demoted) {
		if (undemote_groups() == 0) {
			demoted = 0;
			log_message(LOG_NOTICE, "%s has an address: lifted the "
			    "demotion of its groups",
			    global_options.interface_name);
		}
	}
}

/* On exit, lest the demotion stay for good */
void lift_demote(void) {
	if (demoted && undemote_groups() == 0)
		demoted = 0;
}

/*
 * As backup, put back the address of the configuration we hold when the
 * carp interface has no IPv4 address, e.g. after dhcpleased removed it at
 * the expiry of a lease that it bound while we were master: carp(4)
 * authenticates its advertisements over the addresses, so without it we
 * would become master beside the master, or, left without any address, be
 * taken down.  Add it only: an address that turns up meanwhile is a new
 * one from outside.  The callers tell when we are backup; never as
 * master, where the address follows dhcpleased's lease.
 */
void restore_address(void) {
	char ip_str[INET_ADDRSTRLEN], netmask_str[INET_ADDRSTRLEN];
	in_addr_t ip, netmask;

	if (known_ip == INADDR_ANY || known_mask == INADDR_ANY ||
	    current_carp_state == CARP_STATE_MASTER ||
	    get_carp_interface_state(global_options.interface_name) ==
	    CARP_STATE_MASTER)
		return;
	/* Ours, or a new address from outside, is there */
	if (get_interface_ip_and_netmask(global_options.interface_name, &ip,
	    &netmask) == 0)
		return;
	inet_ntop(AF_INET, &known_ip, ip_str, sizeof(ip_str));
	inet_ntop(AF_INET, &known_mask, netmask_str, sizeof(netmask_str));
	if (global_options.dry_run) {
		log_message(LOG_WARNING, "Dry-run mode: not restoring %s on %s",
		    ip_str, global_options.interface_name);
		return;
	}
	log_message(LOG_NOTICE, "%s lost its address as backup: restoring %s "
	    "netmask %s", global_options.interface_name, ip_str, netmask_str);
	/* With the address, the kernel removed the routes through it */
	if (add_address(global_options.interface_name, known_ip,
	    known_mask) == 0)
		run_hook();
}

/*
 * After a removal as backup: put the address back, unless another one has
 * turned up meanwhile, which makes it a replacement from outside.
 */
void restore_timer_callback(int fd, short event, void *arg) {
	restore_address();
	update_demote();
}

/* Whether the interface has the given IPv4 address */
int interface_has_address(const char *if_name, in_addr_t ip) {
	struct ifaddrs *ifaddr, *ifa;
	int found = 0;

	if (getifaddrs(&ifaddr) == -1) {
		log_perror("getifaddrs");
		return (0);
	}
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr != NULL &&
		    ifa->ifa_addr->sa_family == AF_INET &&
		    strcmp(ifa->ifa_name, if_name) == 0 &&
		    ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr == ip) {
			found = 1;
			break;
		}
	}
	freeifaddrs(ifaddr);
	return (found);
}

/* A CLOCK_MONOTONIC time, e.g. dhcpleased's, as seconds since the epoch */
int64_t mono_to_wall(const struct timespec *mono) {
	struct timespec real, now, age, then;

	clock_gettime(CLOCK_REALTIME, &real);
	clock_gettime(CLOCK_MONOTONIC, &now);
	timespecsub(&now, mono, &age);
	timespecsub(&real, &age, &then);
	return (then.tv_sec + (then.tv_nsec >= 500000000));
}

/*
 * Ask dhcpleased(8) for its lease of the carp interface, as "dhcpleasectl
 * -l" does: with IMSG_CTL_SHOW_INTERFACE_INFO, never with
 * IMSG_CTL_SEND_REQUEST, which makes it request the lease anew.  The
 * answer is a struct ctl_engine_info, which is internal to dhcpleased:
 * take only one of the size in the dhcpleased.h we were built with.
 * Returns 0 with the answer, -1 and why not if there is none, or -2 and
 * why if the answer was wrong, or none came.
 */
int query_lease(struct ctl_engine_info *cei, char *why, size_t whylen) {
	const char *path = global_options.control_socket;
	struct timespec deadline, now, left;
	struct sockaddr_un sun;
	struct imsgbuf ibuf;
	struct imsg imsg;
	struct pollfd pfd;
	uint32_t if_index = carp_ifindex;
	size_t len;
	int fd, n, rv = -1;

	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1) {
		snprintf(why, whylen, "socket: %s", strerror(errno));
		return (-1);
	}
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		snprintf(why, whylen, "%s: %s", path, strerror(errno));
		close(fd);
		return (-1);
	}
	if (imsgbuf_init(&ibuf, fd) == -1) {
		snprintf(why, whylen, "imsgbuf_init: %s", strerror(errno));
		close(fd);
		return (-1);
	}
	if (imsg_compose(&ibuf, IMSG_CTL_SHOW_INTERFACE_INFO, 0, 0, -1,
	    &if_index, sizeof(if_index)) == -1 || imsgbuf_flush(&ibuf) == -1) {
		snprintf(why, whylen, "%s: %s", path, strerror(errno));
		goto out;
	}

	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += DCARP_LEASE_WAIT;
	while ((n = imsgbuf_get(&ibuf, &imsg)) == 0) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		timespecsub(&deadline, &now, &left);
		if (left.tv_sec < 0) {
			snprintf(why, whylen, "%s: no answer", path);
			rv = -2;
			goto out;
		}
		pfd.fd = fd;
		pfd.events = POLLIN;
		n = poll(&pfd, 1, left.tv_sec * 1000 + left.tv_nsec / 1000000);
		if (n == -1 && errno != EINTR) {
			snprintf(why, whylen, "poll: %s", strerror(errno));
			goto out;
		}
		if (n <= 0)
			continue;
		if ((n = imsgbuf_read(&ibuf)) == -1) {
			snprintf(why, whylen, "%s: %s", path, strerror(errno));
			goto out;
		}
		if (n == 0) {
			snprintf(why, whylen, "%s: closed", path);
			goto out;
		}
	}
	if (n == -1) {
		snprintf(why, whylen, "%s: %s", path, strerror(errno));
		rv = -2;
		goto out;
	}

	rv = -2;
	switch (imsg_get_type(&imsg)) {
	case IMSG_CTL_SHOW_INTERFACE_INFO:
		len = imsg_get_len(&imsg);
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (len != sizeof(*cei) ||
		    imsg_get_data(&imsg, cei, sizeof(*cei)) == -1)
			snprintf(why, whylen, "%s: answer of %zu bytes, "
			    "expected %zu: dhcpleased and dcarpd built from "
			    "different sources?", path, len, sizeof(*cei));
		else if (cei->if_index != carp_ifindex)
			snprintf(why, whylen, "%s: answer for interface index "
			    "%u, not %u", path, cei->if_index, carp_ifindex);
		else if (cei->request_time.tv_sec < 0 ||
		    cei->request_time.tv_nsec < 0 ||
		    cei->request_time.tv_nsec >= 1000000000 ||
		    timespeccmp(&cei->request_time, &now, >))
			snprintf(why, whylen, "%s: lease acknowledged in the "
			    "future", path);
		else {
			cei->state[sizeof(cei->state) - 1] = '\0';
			rv = 0;
		}
		break;
	case IMSG_CTL_END:
		snprintf(why, whylen, "dhcpleased does not handle %s",
		    global_options.interface_name);
		rv = -1;
		break;
	default:
		snprintf(why, whylen, "%s: answer of type %u", path,
		    imsg_get_type(&imsg));
		break;
	}
	imsg_free(&imsg);
out:
	imsgbuf_clear(&ibuf);
	close(fd);
	return (rv);
}

/*
 * As master: when dhcpleased last accepted an acknowledgement of the DHCP
 * lease of our carp address, at a bind or at a renewal.  A renewal keeps
 * the address, so only dhcpleased can tell of it.  Each acknowledgement is
 * a new generation, and the lease time from it on goes with it.  Without
 * an answer we keep what we hold, e.g. the configuration taken over from
 * the master before us, until our dhcpleased has the lease.  Why not is
 * logged once.
 */
void lease_update(in_addr_t carp_ip) {
	static char last[192];
	struct ctl_engine_info cei;
	char why[192], ip_str[INET_ADDRSTRLEN];
	int64_t acked, end;
	int first, rv;

	if (!lease_asking)
		return;
	if ((rv = query_lease(&cei, why, sizeof(why))) == -2) {
		lease_asking = 0;
		log_message(LOG_ERR, "no DHCP lease: %s; not asking dhcpleased "
		    "again until SIGHUP", why);
		last[0] = '\0';
		return;
	}
	if (rv == 0) {
		inet_ntop(AF_INET, &cei.requested_ip, ip_str, sizeof(ip_str));
		if ((strcmp(cei.state, "Bound") == 0 ||
		    strcmp(cei.state, "Renewing") == 0 ||
		    strcmp(cei.state, "Rebinding") == 0) &&
		    cei.requested_ip.s_addr == carp_ip && cei.lease_time != 0)
			why[0] = '\0';
		else
			snprintf(why, sizeof(why), "dhcpleased has %s for %s, "
			    "%s", ip_str, global_options.interface_name,
			    cei.state);
	}
	if (why[0] != '\0') {
		log_message(strcmp(why, last) == 0 ? LOG_DEBUG : LOG_INFO,
		    "no DHCP lease: %s", why);
		strlcpy(last, why, sizeof(last));
		return;
	}
	last[0] = '\0';

	if (timespeccmp(&cei.request_time, &lease_acked, !=)) {
		first = !timespecisset(&lease_acked);
		lease_acked = cei.request_time;
		acked = mono_to_wall(&cei.request_time);
		if (acked > time(NULL))		/* rounded up */
			acked = time(NULL);
		lease_acked_at = acked;
		log_message(LOG_INFO, "DHCP lease of %s on %s acknowledged at "
		    "%lld, for %u seconds", ip_str,
		    global_options.interface_name, (long long)acked,
		    cei.lease_time);
		/*
		 * A new generation, later than the one held even if that is
		 * ahead of our clock; but not for the acknowledgement we knew
		 * before we started, give or take its rounding.
		 */
		if (!first || acked > my_generation + 1) {
			my_generation = acked > my_generation ? acked :
			    my_generation + 1;
			log_message(LOG_INFO, "generation %lld from the DHCP "
			    "lease", (long long)my_generation);
		}
	}
	/* From the generation on, so that both give when the lease ends */
	end = lease_acked_at + cei.lease_time;
	if (end <= my_generation)
		my_lease_time = 0;
	else if (end - my_generation > UINT32_MAX)
		my_lease_time = UINT32_MAX;
	else
		my_lease_time = end - my_generation;
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
	case RTM_DELADDR: {
		struct ifa_msghdr *ifam = (struct ifa_msghdr *)msg;
		char ip_str[INET_ADDRSTRLEN];
		in_addr_t ip, netmask;

		if (n < sizeof(*ifam) || ifam->ifam_index != carp_ifindex)
			return;
		log_message(LOG_DEBUG, "Received %s for %s",
		    rtm->rtm_type == RTM_NEWADDR ? "RTM_NEWADDR" : "RTM_DELADDR",
		    global_options.interface_name);
		/*
		 * Removed as backup, unless replaced: put it back in a
		 * moment, without demoting us meanwhile.  carp(4) reports
		 * INIT only after this, if it was the last address.
		 */
		if (rtm->rtm_type == RTM_DELADDR &&
		    current_carp_state == CARP_STATE_BACKUP &&
		    known_ip != INADDR_ANY &&
		    get_interface_ip_and_netmask(global_options.interface_name,
		    &ip, &netmask) != 0 &&
		    !evtimer_pending(&restore_timer, NULL)) {
			struct timeval tv = { 0, DCARP_RESTORE_DELAY * 1000 };

			evtimer_add(&restore_timer, &tv);
		}
		if (!evtimer_pending(&restore_timer, NULL))
			update_demote();

		/*
		 * While the address we know is there, this is our own change
		 * or one in progress: a renewal may add the new address
		 * before removing the old, or the other way around.
		 */
		if (known_ip != INADDR_ANY &&
		    interface_has_address(global_options.interface_name,
		    known_ip))
			break;
		if (get_interface_ip_and_netmask(global_options.interface_name,
		    &ip, &netmask) != 0) {
			log_message(LOG_INFO, "%s has no address now",
			    global_options.interface_name);
			break;
		}

		/*
		 * A new address from outside, e.g. a new DHCP lease: a new
		 * generation, which wins over the old configuration
		 * wherever it is, also over one from a clock ahead of ours.
		 */
		known_ip = ip;
		known_mask = netmask;
		if (time(NULL) > my_generation)
			my_generation = time(NULL);
		else
			my_generation++;
		/* As master, dhcpleased may know its lease */
		my_lease_time = 0;
		inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
		log_message(LOG_INFO, "address of %s changed to %s, generation "
		    "%lld", global_options.interface_name, ip_str,
		    (long long)my_generation);

		/*
		 * As master, tell the backups now rather than at the next
		 * resend.  Changing the addresses of a carp(4) interface
		 * usually sends it through INIT, and it cannot send until
		 * it is master again; RTM_IFINFO for that follows, and we
		 * send then.  So ask the kernel rather than trusting our
		 * state, which the queued RTM_IFINFO has not updated yet.
		 */
		if (current_carp_state != CARP_STATE_MASTER)
			break;
		if (get_carp_interface_state(global_options.interface_name) !=
		    CARP_STATE_MASTER) {
			log_message(LOG_INFO, "sending when %s is master again",
			    global_options.interface_name);
			break;
		}
		distribute_ip_addresses();
		break;
	}
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
	sockfd = socket(PF_ROUTE, SOCK_RAW | SOCK_CLOEXEC, AF_UNSPEC);
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
	in_addr_t ip, netmask, held;
	int ch;

	while ((ch = getopt(argc, argv, "c:dnvf:i:g:k:s:x:")) != -1) {
		switch (ch) {
		case 'c':
			global_options.control_socket = optarg;
			break;
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
		case 'f':
			global_options.state_file = optarg;
			break;
		case 'x':
			global_options.hook = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0 || global_options.interface_name == NULL) {
		usage();
	}
	if (global_options.hook != NULL &&
	    (global_options.hook[0] != '/' ||
	    access(global_options.hook, X_OK) == -1)) {
		fprintf(stderr, "%s: -x %s: not an absolute path to an "
		    "executable\n", getprogname(), global_options.hook);
		usage();
	}
	if (global_options.control_socket == NULL)
		global_options.control_socket = _PATH_DHCPLEASED_SOCKET;
	else if (strlen(global_options.control_socket) >=
	    sizeof(((struct sockaddr_un *)NULL)->sun_path)) {
		fprintf(stderr, "%s: -c %s: name too long\n", getprogname(),
		    global_options.control_socket);
		usage();
	}
	if (global_options.gateway_ip != NULL) {
		struct in_addr gw;

		if (inet_pton(AF_INET, global_options.gateway_ip, &gw) != 1) {
			fprintf(stderr, "%s: -g %s: not an IPv4 address\n",
			    getprogname(), global_options.gateway_ip);
			usage();
		}
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

	/* By default /var/db/dcarpd/<interface>, creating the directory */
	if (global_options.state_file == NULL) {
		if (asprintf(&global_options.state_file, "%s/%s",
		    DCARP_STATE_DIR, global_options.interface_name) == -1) {
			log_perror("asprintf");
			goto err;
		}
		if (mkdir(DCARP_STATE_DIR, 0755) == -1 && errno != EEXIST) {
			log_perror(DCARP_STATE_DIR);
			goto err;
		}
	}
	learned_gw = read_state_address("DCARP_GATEWAY");
	learned_backup_gw = read_state_address("DCARP_BACKUP_GATEWAY");

	if (!global_options.foreground) {
		daemonize();
	}

	aead_ctx = read_keyfile(global_options.keyfile_path);
	if (aead_ctx == NULL)
		goto err;

	/*
	 * Start with the configuration held before, from the state file: its
	 * generation, and its address if the carp interface has none.  Without
	 * one, any configuration received from a master wins.  The time of a
	 * DHCP lease file is no generation: dhcpleased writes the file when it
	 * binds a lease, not when it renews it.
	 */
	held = read_state_address("DCARP_ADDRESS");
	if (get_interface_ip_and_netmask(global_options.interface_name, &ip,
	    &netmask) == 0) {
		known_ip = ip;
		known_mask = netmask;
	} else {
		known_ip = held;
		known_mask = read_state_address("DCARP_NETMASK");
	}
	if (known_ip != INADDR_ANY && known_ip == held) {
		my_generation = read_state_number("DCARP_GENERATION", LLONG_MAX);
		my_lease_time = read_state_number("DCARP_LEASE_TIME",
		    UINT32_MAX);
		log_message(LOG_INFO, "generation %lld from %s",
		    (long long)my_generation, global_options.state_file);
	} else
		log_message(LOG_INFO, "generation 0: %s holds no configuration "
		    "of the address of %s", global_options.state_file,
		    global_options.interface_name);
    
	signal(SIGINT, handle_signal);
	signal(SIGHUP, handle_signal);
	signal(SIGTERM, handle_signal);
	/* dhcpleased may go away while we ask it */
	signal(SIGPIPE, SIG_IGN);

	setup_multicast_socket();
	setup_routing_socket();

	event_init();

	/* Before the first message sent, which may start the hook */
	signal_set(&sigchld_event, SIGCHLD, sigchld_callback, NULL);
	signal_add(&sigchld_event, NULL);

	current_carp_state = get_carp_interface_state(global_options.interface_name);
	evtimer_set(&restore_timer, restore_timer_callback, NULL);

	/* As backup, put back the address held if it is gone */
	if (current_carp_state == CARP_STATE_BACKUP)
		restore_address();
	update_demote();

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

	// Create an event for the multicast socket
	struct event multicast_event;
	event_set(&multicast_event, global_multicast_socket, EV_READ | EV_PERSIST, multicast_callback, NULL);

	// Create an event for the routing socket
	struct event routing_event;
	event_set(&routing_event, routing_socket, EV_READ | EV_PERSIST, routing_callback, NULL);

	// Add the events
	event_add(&multicast_event, NULL);
	event_add(&routing_event, NULL);

	struct timeval send_interval = { DCARP_INTERVAL, 0 };
	evtimer_set(&send_timer, send_timer_callback, NULL);
	evtimer_add(&send_timer, &send_interval);

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
		lift_demote();
		close_multicast_socket();
		log_message(LOG_NOTICE, "terminated by SIGTERM");
		log_close();
		exit(EXIT_SUCCESS);
		break;
        case SIGHUP: {
		/* Ask dhcpleased again, after a wrong answer or none */
		lease_asking = 1;
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
	/* Close-on-exec: the -x hook must not inherit it */
	int sock = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
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

	fprintf(stderr, "usage: %s [-dnv] [-c control_socket] [-f state_file] "
	    "[-g backup_gateway]\n"
	    "              -i interface [-k key_file] [-s sync_interface] "
	    "[-x program]\n", __progname);
	exit(EXIT_FAILURE);
}
