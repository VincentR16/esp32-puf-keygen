/*
 * display_none.c - No display: every call does nothing.
 */

#include "display.h"

int display_init(void)
{
    return 0;
}

void display_show(int temp10, int hum)
{
    (void)temp10;
    (void)hum;
}