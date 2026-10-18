/*
 * display.h - Shows the last valid reading.
 *
 * Two interchangeable implementations, chosen by CMakeLists.txt:
 *   display_oled.c  SSD1306 128x64 on I2C (local, not in the public repo)
 *   display_none.c  does nothing, for boards without a display
 *
 * Errors are never shown: the screen keeps the last valid reading.
 */

#pragma once

/* Configure the display, if any. Returns 0 on success. */
int display_init(void);

/* Show temperature (tenths of a degree C) and humidity (%). */
void display_show(int temp10, int hum);