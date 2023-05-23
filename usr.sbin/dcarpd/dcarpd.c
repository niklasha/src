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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/route.h>
#include <net/if.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <event.h>

#include "dcarpd.h"

void usage(void);

struct options global_options = {
    DEFAULT_KEY_FILE
};

int global_multicast_socket = -1;

// Global routing socket
int routing_socket = -1;

// Callback function for routing messages
void routing_callback(int fd, short event, void *arg) {
    char msg[2048];
    struct rt_msghdr *rtm = (struct rt_msghdr *)msg;

    ssize_t n = read(fd, msg, sizeof(msg));
    if (n < sizeof(*rtm)) {
        fprintf(stderr, "Error: routing message is too small (%zd bytes)\n", n);
        return;
    }

    switch (rtm->rtm_type) {
    case RTM_NEWADDR:
        printf("Received RTM_NEWADDR\n");
        // Handle RTM_NEWADDR
        break;
    case RTM_DELADDR:
        printf("Received RTM_DELADDR\n");
        // Handle RTM_DELADDR
        break;
    case RTM_IFINFO: {
        struct if_msghdr *ifm = (struct if_msghdr *)msg;

	if (n < sizeof(*ifm)) {
            perror("read");
	    return;
	}

        if (ifm->ifm_data.ifi_type != IFT_CARP) {
            return;
        }

	switch(ifm->ifm_data.ifi_link_state) {
        case LINK_STATE_UP:
            printf("Carp interface is in MASTER state\n");
            break;
        case LINK_STATE_DOWN:
            printf("Carp interface is in BACKUP state\n");
            break;
        default:
            printf("Carp interface is in UNKNOWN state\n");
            break;
	}
        break;
    }
    default:
        fprintf(stderr, "Received unexpected routing message type %d\n", rtm->rtm_type);
        break;
    }
}

void setup_routing_socket(void)
{
    int rtfilter;
    int sockfd;
    
    // Open the socket
    sockfd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (sockfd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set the message type filter
    rtfilter = ROUTE_FILTER(RTM_IFINFO) | ROUTE_FILTER(RTM_NEWADDR) | ROUTE_FILTER(RTM_DELADDR);
    if (setsockopt(sockfd, AF_ROUTE, ROUTE_MSGFILTER, &rtfilter, sizeof(rtfilter)) == -1) {
        perror("setsockopt(ROUTE_MSGFILTER)");
        exit(EXIT_FAILURE);
    }
    routing_socket = sockfd;
}

void multicast_callback(int fd, short event, void *arg) {
    // This function will be called when there is data to be read on the multicast socket
    printf("Multicast message received...\n");
    // Here we would add the code to handle the multicast message
}

int main(int argc, char *argv[]) {
    int ch;

    while ((ch = getopt(argc, argv, "di:g:v:k:")) != -1) {
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

    if (!global_options.foreground) {
        daemonize();
    }

    global_options.key = read_keyfile(global_options.keyfile_path);
    if (!global_options.key) {
        return EXIT_FAILURE;
    }
    
    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);
    signal(SIGTERM, handle_signal);

    setup_multicast_socket();
    setup_routing_socket();

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

    // Start the event loop
    event_dispatch();

    return EXIT_SUCCESS;
}

char *read_keyfile(const char *filename) {
    // Perform checks on the key file
    struct stat st;
    if (stat(filename, &st) < 0) {
        perror("stat");
        return NULL;
    }

    if (st.st_mode & (S_IRGRP | S_IROTH)) {
        fprintf(stderr, "Keyfile should not be readable by others\n");
        return NULL;
    }

    if (st.st_uid != 0) {
        fprintf(stderr, "Keyfile should be owned by root\n");
        return NULL;
    }

    // Open and read key file
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("fopen");
        return NULL;
    }

    char key[KEY_LENGTH + 1];
    int n;
    if ((n = fread(key, 1, KEY_LENGTH, f)) < 1) {
        fprintf(stderr, "Keyfile read error or key length is not correct\n");
        fclose(f);
        return NULL;
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

    return hash_str;
}

void daemonize() {
    if (daemon(1, 0) == -1) {
        perror("Error: daemon");
        exit(EXIT_FAILURE);
    }
}

void handle_signal(int signal)
{
    switch (signal) {
        case SIGTERM:
            close_multicast_socket(); // You need to implement this
            printf("dcarpd terminated\n");
            exit(EXIT_SUCCESS);
            break;
        case SIGHUP: {
            // Reread keyfile
            char *new_key = read_keyfile(global_options.keyfile_path);
            if (new_key) {
                free(global_options.key);
                global_options.key = new_key;
                printf("Keyfile reloaded successfully\n");
            } else {
                printf("Failed to reload keyfile. Using old key.\n");
            }
            break;
	}
        default:
            fprintf(stderr, "Unhandled signal (%d) %s\n", signal, strsignal(signal));
            break;
    }
}

void setup_multicast_socket() {
    struct ip_mreq mreq;
    struct sockaddr_in addr;
    int yes = 1;

    /* Create a UDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Error: socket");
        exit(EXIT_FAILURE);
    }

    /* Allow multiple sockets to use the same port number */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        perror("Error: setsockopt");
        close(sock);
        exit(EXIT_FAILURE);
    }

    /* Set up destination address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); /* receive multicast */
    addr.sin_port = htons(DCARP_MULTICAST_PORT);

    /* Bind to receive address */
    if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        perror("Error: bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    /* Use setsockopt() to request that the kernel join a multicast group */
    struct in_addr multicast_address;
    if (inet_aton(DCARP_MULTICAST_IP, &multicast_address) == 0) {
        perror("inet_aton");
        exit(EXIT_FAILURE);
    }

    mreq.imr_multiaddr.s_addr = multicast_address.s_addr;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("Error: setsockopt");
        close(sock);
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

    fprintf(stderr, "usage: %s [-d] [-v] -i interface -g gateway_ip [-k key_file]\n",
            __progname);

    exit(EXIT_FAILURE);
}
