
#include "sensor.h"

int sensor_init(void)
{
    return 0;
}

int sensor_read(int *temp10, int *hum)
{
    static int n;
    n = (n + 1) % 10;
    *temp10 = 220 + n * 5;
    *hum = 40 + n;
    return 0;
}