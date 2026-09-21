/*
 * main.c — DHT11 + OLED SSD1306
 *
 * Legge temperatura e umidita' dal DHT11 e le mostra sul display.
 * Font 5x7 minimale, nessuna libreria grafica.
 */

#include <stdio.h>
#include <string.h>
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_timer.h"
#include "esp_rom_sys.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_vendor.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define DHT_PIN   GPIO_NUM_4
#define PIN_SDA   21
#define PIN_SCL   22
#define I2C_ADDR  0x3C
#define H_RES     128
#define V_RES     64
#define FB_SIZE   (H_RES * V_RES / 8)

/* 
   FONT 5x7
   Ogni carattere e' 5 byte, uno per colonna.
   Nel byte, il bit 0 e' la riga in alto, il bit 6 quella in basso.
  */

typedef struct {
    char c;
    uint8_t col[5];
} glyph_t;

static const glyph_t font[] = {
    {'0', {0x3E, 0x51, 0x49, 0x45, 0x3E}},
    {'1', {0x00, 0x42, 0x7F, 0x40, 0x00}},
    {'2', {0x42, 0x61, 0x51, 0x49, 0x46}},
    {'3', {0x21, 0x41, 0x45, 0x4B, 0x31}},
    {'4', {0x18, 0x14, 0x12, 0x7F, 0x10}},
    {'5', {0x27, 0x45, 0x45, 0x45, 0x39}},
    {'6', {0x3C, 0x4A, 0x49, 0x49, 0x30}},
    {'7', {0x01, 0x71, 0x09, 0x05, 0x03}},
    {'8', {0x36, 0x49, 0x49, 0x49, 0x36}},
    {'9', {0x06, 0x49, 0x49, 0x29, 0x1E}},
    {'C', {0x3E, 0x41, 0x41, 0x41, 0x22}},
    {'H', {0x7F, 0x08, 0x08, 0x08, 0x7F}},
    {'T', {0x01, 0x01, 0x7F, 0x01, 0x01}},
    {'%', {0x23, 0x13, 0x08, 0x64, 0x62}},
    {':', {0x00, 0x36, 0x36, 0x00, 0x00}},
    {'.', {0x00, 0x60, 0x60, 0x00, 0x00}},
    {'-', {0x08, 0x08, 0x08, 0x08, 0x08}},
    {'E', {0x7F, 0x49, 0x49, 0x49, 0x41}},
    {'R', {0x7F, 0x09, 0x19, 0x29, 0x46}},
    {' ', {0x00, 0x00, 0x00, 0x00, 0x00}},
};

#define FONT_LEN (sizeof(font) / sizeof(font[0]))

/* 
   DISEGNO NEL FRAMEBUFFER
 
   L'SSD1306 organizza la memoria in "pagine": ogni byte rappresenta
   8 pixel impilati in VERTICALE, non in orizzontale.
 
       indice byte = (y / 8) * 128 + x
       bit dentro il byte = y % 8
  */

static void set_pixel(uint8_t *fb, int x, int y)
{
    if (x < 0 || x >= H_RES || y < 0 || y >= V_RES) return;
    fb[(y / 8) * H_RES + x] |= (1 << (y % 8));
}

/* Disegna un carattere. scale=1 -> 5x7 px, scale=2 -> 10x14 px, ecc. */
static void draw_char(uint8_t *fb, int x, int y, char c, int scale)
{
    const uint8_t *cols = NULL;

    for (size_t i = 0; i < FONT_LEN; i++) {
        if (font[i].c == c) { cols = font[i].col; break; }
    }
    if (cols == NULL) return;   /* carattere non nel font: lo salta */

    for (int cx = 0; cx < 5; cx++) {
        for (int cy = 0; cy < 7; cy++) {
            if (cols[cx] & (1 << cy)) {
                /* con scale > 1 ogni pixel diventa un quadrato */
                for (int dx = 0; dx < scale; dx++) {
                    for (int dy = 0; dy < scale; dy++) {
                        set_pixel(fb, x + cx * scale + dx, y + cy * scale + dy);
                    }
                }
            }
        }
    }
}

static void draw_string(uint8_t *fb, int x, int y, const char *s, int scale)
{
    while (*s) {
        draw_char(fb, x, y, *s, scale);
        x += 6 * scale;          /* 5 px di glifo + 1 di spaziatura */
        s++;
    }
}

/* 
  DHT11
 */

static int wait_level(int level, int timeout_us)
{
    int64_t start = esp_timer_get_time();
    while (gpio_get_level(DHT_PIN) != level) {
        if (esp_timer_get_time() - start > timeout_us) return -1;
    }
    return (int)(esp_timer_get_time() - start);
}

static int dht_read(int *temp, int *hum)
{
    uint8_t data[5] = {0};
    int err = 0;

    gpio_set_direction(DHT_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(DHT_PIN, 0);
    esp_rom_delay_us(25000);

    taskDISABLE_INTERRUPTS();

    gpio_set_level(DHT_PIN, 1);
    esp_rom_delay_us(30);
    gpio_set_direction(DHT_PIN, GPIO_MODE_INPUT);

    if (wait_level(0, 200) < 0)      err = -1;
    else if (wait_level(1, 200) < 0) err = -2;
    else if (wait_level(0, 200) < 0) err = -3;
    else {
        for (int i = 0; i < 40; i++) {
            if (wait_level(1, 200) < 0) { err = -4; break; }
            int high = wait_level(0, 200);
            if (high < 0) { err = -5; break; }

            data[i / 8] <<= 1;
            if (high > 45) data[i / 8] |= 1;
        }
    }

    taskENABLE_INTERRUPTS();

    if (err != 0) return err;
    if (((data[0] + data[1] + data[2] + data[3]) & 0xFF) != data[4]) return -6;

    *hum  = data[0];
    *temp = data[2];
    return 0;
}

/* 
  MAIN
  */

static uint8_t fb[FB_SIZE];

void app_main(void)
{
    /* --- GPIO per il DHT11 --- */
    gpio_config_t gcfg = {
        .pin_bit_mask = 1ULL << DHT_PIN,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&gcfg);

    /* --- Bus I2C --- */
    i2c_master_bus_handle_t bus = NULL;
    i2c_master_bus_config_t bus_cfg = {
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .i2c_port = 0,
        .sda_io_num = PIN_SDA,
        .scl_io_num = PIN_SCL,
        .flags.enable_internal_pullup = true,
    };
    ESP_ERROR_CHECK(i2c_new_master_bus(&bus_cfg, &bus));

    /* --- Panel IO --- */
    esp_lcd_panel_io_handle_t io = NULL;
    esp_lcd_panel_io_i2c_config_t io_cfg = {
        .dev_addr = I2C_ADDR,
        .scl_speed_hz = 400000,
        .control_phase_bytes = 1,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
        .dc_bit_offset = 6,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_i2c(bus, &io_cfg, &io));

    /* --- Driver SSD1306 --- */
    esp_lcd_panel_handle_t panel = NULL;
    esp_lcd_panel_ssd1306_config_t ssd_cfg = { .height = V_RES };
    esp_lcd_panel_dev_config_t panel_cfg = {
        .bits_per_pixel = 1,
        .reset_gpio_num = -1,
        .vendor_config = &ssd_cfg,
    };

    ESP_ERROR_CHECK(esp_lcd_new_panel_ssd1306(io, &panel_cfg, &panel));
    ESP_ERROR_CHECK(esp_lcd_panel_reset(panel));
    ESP_ERROR_CHECK(esp_lcd_panel_init(panel));
    ESP_ERROR_CHECK(esp_lcd_panel_mirror(panel, true, true));
    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(panel, true));

    vTaskDelay(pdMS_TO_TICKS(2000));   /* il DHT11 vuole ~1s dopo l'accensione */

    char riga1[16], riga2[16];

    while (1) {
        int t = 0, h = 0;
        int err = dht_read(&t, &h);

        if (err == 0) {
            snprintf(riga1, sizeof(riga1), "T: %d C", t);
            snprintf(riga2, sizeof(riga2), "H: %d %%", h);
            printf("Temperatura: %d C   Umidita: %d %%\n", t, h);
        } else {
            snprintf(riga1, sizeof(riga1), "ERRORE");
            snprintf(riga2, sizeof(riga2), "%d", err);
            printf("Errore lettura DHT11: %d\n", err);
        }

        memset(fb, 0, sizeof(fb));
        draw_string(fb, 23, 16, riga1, 2);   /* scale 2 -> caratteri 10x14 */
        draw_string(fb, 23, 42, riga2, 2);
        esp_lcd_panel_draw_bitmap(panel, 0, 0, H_RES, V_RES, fb);

        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}