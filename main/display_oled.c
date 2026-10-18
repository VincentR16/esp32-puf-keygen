/*
 * display_oled.c - SSD1306 128x64 on I2C (SDA=21, SCL=22, address 0x3C).
 *
 * Minimal 5x7 font, no graphics library: the text is drawn into a
 * framebuffer and the whole framebuffer is sent to the panel.
 */

#include <stdio.h>
#include <string.h>

#include "driver/i2c_master.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_vendor.h"

#include "display.h"

#define PIN_SDA   21
#define PIN_SCL   22
#define I2C_ADDR  0x3C
#define H_RES     128
#define V_RES     64
#define FB_SIZE   (H_RES * V_RES / 8)
#define SCALE     2                 /* 5x7 glyphs drawn as 10x14 */

/*
 * FONT 5x7
 * Every character is 5 bytes, one per column.
 * In a byte, bit 0 is the top row and bit 6 the bottom one.
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

static esp_lcd_panel_handle_t panel;    /* NULL until display_init succeeds */
static uint8_t fb[FB_SIZE];

/*
 * DRAWING INTO THE FRAMEBUFFER
 *
 * The SSD1306 organizes its memory in "pages": every byte holds
 * 8 pixels stacked VERTICALLY, not horizontally.
 *     byte index   = (y / 8) * 128 + x
 *     bit in byte  = y % 8
 */
static void set_pixel(int x, int y)
{
    if (x < 0 || x >= H_RES || y < 0 || y >= V_RES) return;
    fb[(y / 8) * H_RES + x] |= (1 << (y % 8));
}

/* Draw one character. scale=1 -> 5x7 px, scale=2 -> 10x14 px, ... */
static void draw_char(int x, int y, char c, int scale)
{
    const uint8_t *cols = NULL;

    for (size_t i = 0; i < FONT_LEN; i++) {
        if (font[i].c == c) { cols = font[i].col; break; }
    }
    if (cols == NULL) return;       /* not in the font: skipped */

    for (int cx = 0; cx < 5; cx++) {
        for (int cy = 0; cy < 7; cy++) {
            if (cols[cx] & (1 << cy)) {
                /* with scale > 1 every pixel becomes a square */
                for (int dx = 0; dx < scale; dx++) {
                    for (int dy = 0; dy < scale; dy++) {
                        set_pixel(x + cx * scale + dx, y + cy * scale + dy);
                    }
                }
            }
        }
    }
}

/* Draw a string centred horizontally on the screen. */
static void draw_centered(int y, const char *s, int scale)
{
    int width = (int)strlen(s) * 6 * scale;     /* 5 px glyph + 1 px gap */
    int x = (H_RES - width) / 2;
    while (*s) {
        draw_char(x, y, *s, scale);
        x += 6 * scale;
        s++;
    }
}

int display_init(void)
{
    /* I2C bus */
    i2c_master_bus_handle_t bus = NULL;
    i2c_master_bus_config_t bus_cfg = {
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .i2c_port = 0,
        .sda_io_num = PIN_SDA,
        .scl_io_num = PIN_SCL,
        .flags.enable_internal_pullup = true,
    };
    if (i2c_new_master_bus(&bus_cfg, &bus) != ESP_OK) return -1;

    /* Panel IO */
    esp_lcd_panel_io_handle_t io = NULL;
    esp_lcd_panel_io_i2c_config_t io_cfg = {
        .dev_addr = I2C_ADDR,
        .scl_speed_hz = 400000,
        .control_phase_bytes = 1,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
        .dc_bit_offset = 6,
    };
    if (esp_lcd_new_panel_io_i2c(bus, &io_cfg, &io) != ESP_OK) return -1;

    /* SSD1306 driver */
    esp_lcd_panel_ssd1306_config_t ssd_cfg = { .height = V_RES };
    esp_lcd_panel_dev_config_t panel_cfg = {
        .bits_per_pixel = 1,
        .reset_gpio_num = -1,
        .vendor_config = &ssd_cfg,
    };
    if (esp_lcd_new_panel_ssd1306(io, &panel_cfg, &panel) != ESP_OK ||
        esp_lcd_panel_reset(panel) != ESP_OK ||
        esp_lcd_panel_init(panel) != ESP_OK ||
        esp_lcd_panel_mirror(panel, true, true) != ESP_OK ||   /* mounted rotated */
        esp_lcd_panel_disp_on_off(panel, true) != ESP_OK) {
        panel = NULL;
        return -1;
    }

    /* Start blank, until the first valid reading. */
    memset(fb, 0, sizeof(fb));
    esp_lcd_panel_draw_bitmap(panel, 0, 0, H_RES, V_RES, fb);
    return 0;
}

void display_show(int temp10, int hum)
{
    if (panel == NULL) {
        return;                     /* init failed: nothing to draw on */
    }

    /* 24 bytes: room for any int, so the compiler can prove no truncation */
    char line1[24], line2[24];
    snprintf(line1, sizeof(line1), "T: %d.%d C", temp10 / 10, temp10 % 10);
    snprintf(line2, sizeof(line2), "H: %d %%", hum);

    memset(fb, 0, sizeof(fb));
    draw_centered(16, line1, SCALE);
    draw_centered(42, line2, SCALE);
    esp_lcd_panel_draw_bitmap(panel, 0, 0, H_RES, V_RES, fb);
}