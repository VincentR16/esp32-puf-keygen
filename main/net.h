#pragma once

#include <stddef.h>

int net_connect(void);

/* Send one line; '\n' is added here. Returns 0 on success, -1 on error. */
int net_send_line(const char *line);


int net_recv_line(char *buf, size_t len);