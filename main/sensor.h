

#pragma once

/* Configure the hardware, if any. Returns 0 on success. */
int sensor_init(void);


int sensor_read(int *temp10, int *hum);