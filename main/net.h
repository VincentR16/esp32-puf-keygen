/*
 * net.h - Minimal transport: WiFi station + one TCP connection.
 *
 * The protocol is line based: every message is one line of text ending
 * with '\n'; binary fields travel as hex. Security does not come from
 * here (WPA2 only protects the radio link): it comes from the PUF keys,
 * applied to the content of the lines.
 *
 * Credentials and server address are in wifi_secrets.h (git-ignored).
 */

#pragma once

#include <stddef.h>

/*
 * Join the WiFi network, then open a TCP connection to the server.
 * Blocks until both are up. Returns 0 on success, -1 on failure.
 * Must be called after the PUF snapshot has been taken.
 */
int net_connect(void);

/* Send one line; '\n' is added here. Returns 0 on success, -1 on error. */
int net_send_line(const char *line);

/*
 * Receive one line into buf (at most len - 1 chars, '\n' removed,
 * NUL-terminated). Returns the line length, or -1 on error, timeout
 * or a line too long for buf.
 */
int net_recv_line(char *buf, size_t len);

/* Close the TCP connection. */
void net_close(void);
