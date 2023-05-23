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

#include <netinet/in.h>

#define DEFAULT_KEY_FILE "/etc/dcarp.key"
#define MAX_IP_LEN INET_ADDRSTRLEN
#define DCARP_MULTICAST_IP "224.0.0.18"
#define DCARP_MULTICAST_PORT 3522
#define KEY_LENGTH 32

struct options {
    char *keyfile_path;
    char *key;
    char *interface_name;
    char *gateway_ip;
    int foreground;
    int verbose;
};

void daemonize(void);
void setup_multicast_socket(void);
void close_multicast_socket(void);
void handle_signal(int sig);
char *read_keyfile(const char *);

#endif // _DCARPD_H
