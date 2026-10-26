

#pragma once

/* Configure the display, if any. Returns 0 on success. */
int display_init(void);

/* Show temperature (tenths of a degree C) and humidity (%). */
void display_show(int temp10, int hum);