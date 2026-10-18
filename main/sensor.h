/*
 * sensor.h - The reading that the device encrypts and sends.
 *
 * Two interchangeable implementations, chosen by CMakeLists.txt:
 *   sensor_dht11.c  real DHT11 on GPIO4 (local, not in the public repo)
 *   sensor_fake.c   synthetic values, so the module builds without it
 */

#pragma once

/* Configure the hardware, if any. Returns 0 on success. */
int sensor_init(void);

/*
 * One reading: temperature in tenths of a degree C, humidity in %.
 * Returns 0 on success, a negative error code if the reading failed.
 */
int sensor_read(int *temp10, int *hum);