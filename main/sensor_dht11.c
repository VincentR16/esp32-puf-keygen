/*
 * sensor_dht11.c - DHT11 on GPIO4, bit-banged (local driver).
 *
 * Protocol: the host pulls the line low for >18 ms, then the sensor
 * answers with 80 us low + 80 us high and sends 40 bits. Every bit is
 * ~50 us low followed by a high pulse: ~26-28 us = 0, ~70 us = 1.
 * Bytes: humidity int, humidity dec, temperature int, temperature dec,
 * checksum (low 8 bits of the sum of the first four).
 */

#include <stdint.h>

#include "driver/gpio.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "sensor.h"

#define DHT_PIN  GPIO_NUM_4

/* Busy-wait until the line reaches `level`. Returns the elapsed us, or -1. */
static int wait_level(int level, int timeout_us)
{
    int64_t start = esp_timer_get_time();
    while (gpio_get_level(DHT_PIN) != level) {
        if (esp_timer_get_time() - start > timeout_us) {
            return -1;
        }
    }
    return (int)(esp_timer_get_time() - start);
}

int sensor_init(void)
{
    gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << DHT_PIN,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    return gpio_config(&cfg) == ESP_OK ? 0 : -1;
}

int sensor_read(int *temp10, int *hum)
{
    uint8_t data[5] = { 0 };
    int err = 0;

    /* Start signal: >18 ms low. */
    gpio_set_direction(DHT_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(DHT_PIN, 0);
    esp_rom_delay_us(25000);

    /* The bits are told apart by pulse length (tens of us): an interrupt
     * here (WiFi, timers) would stretch a pulse and corrupt the bit.
     * The window lasts ~4 ms. */
    taskDISABLE_INTERRUPTS();

    gpio_set_level(DHT_PIN, 1);
    esp_rom_delay_us(30);
    gpio_set_direction(DHT_PIN, GPIO_MODE_INPUT);

    if (wait_level(0, 200) < 0) {
        err = -1;                       /* no response */
    } else if (wait_level(1, 200) < 0) {
        err = -2;
    } else if (wait_level(0, 200) < 0) {
        err = -3;
    } else {
        for (int i = 0; i < 40; i++) {
            if (wait_level(1, 200) < 0) {
                err = -4;
                break;
            }
            int high = wait_level(0, 200);
            if (high < 0) {
                err = -5;
                break;
            }
            data[i / 8] <<= 1;
            if (high > 45) {            /* long high pulse = 1 */
                data[i / 8] |= 1;
            }
        }
    }

    taskENABLE_INTERRUPTS();

    if (err != 0) {
        return err;
    }
    if (((data[0] + data[1] + data[2] + data[3]) & 0xFF) != data[4]) {
        return -6;                      /* checksum */
    }

    *hum = data[0];
    /* data[3] holds tenths on newer DHT11s, 0 on older ones. */
    *temp10 = data[2] * 10 + (data[3] % 10);
    return 0;
}