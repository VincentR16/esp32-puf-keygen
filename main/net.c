/*
 * net.c - Minimal transport: WiFi station + one TCP connection.
 * See net.h.
 */

#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "lwip/sockets.h"

#include "net.h"
#include "wifi_secrets.h"

#define WIFI_RETRIES      5
#define WIFI_TIMEOUT_MS   20000
#define TCP_TIMEOUT_S     10

#define BIT_CONNECTED     BIT0
#define BIT_FAILED        BIT1

static EventGroupHandle_t wifi_events;
static int retries;
static int sock = -1;

/* Called by the ESP-IDF event loop on WiFi and IP events. */
static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (retries < WIFI_RETRIES) {
            retries++;
            printf("WiFi: retry %d/%d\n", retries, WIFI_RETRIES);
            esp_wifi_connect();
        } else {
            xEventGroupSetBits(wifi_events, BIT_FAILED);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = (ip_event_got_ip_t *)data;
        printf("WiFi: connected, IP " IPSTR "\n", IP2STR(&ev->ip_info.ip));
        xEventGroupSetBits(wifi_events, BIT_CONNECTED);
    }
}

static int wifi_join(void)
{
    wifi_events = xEventGroupCreate();

    /* NVS is already initialized by boot.c (helper data). */
    if (esp_netif_init() != ESP_OK ||
        esp_event_loop_create_default() != ESP_OK) {
        return -1;
    }
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    if (esp_wifi_init(&init) != ESP_OK) {
        return -1;
    }
    /* Keep the WiFi configuration in RAM: nothing written to flash. */
    esp_wifi_set_storage(WIFI_STORAGE_RAM);

    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event, NULL);

    wifi_config_t cfg = { 0 };
    strncpy((char *)cfg.sta.ssid, WIFI_SSID, sizeof(cfg.sta.ssid));
    strncpy((char *)cfg.sta.password, WIFI_PASSWORD, sizeof(cfg.sta.password));
    cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;   /* refuse weaker networks */

    if (esp_wifi_set_mode(WIFI_MODE_STA) != ESP_OK ||
        esp_wifi_set_config(WIFI_IF_STA, &cfg) != ESP_OK ||
        esp_wifi_start() != ESP_OK) {
        return -1;
    }

    EventBits_t bits = xEventGroupWaitBits(wifi_events,
                                           BIT_CONNECTED | BIT_FAILED,
                                           pdFALSE, pdFALSE,
                                           pdMS_TO_TICKS(WIFI_TIMEOUT_MS));
    return (bits & BIT_CONNECTED) ? 0 : -1;
}

static int tcp_open(void)
{
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &addr.sin_addr) != 1) {
        printf("TCP: bad server IP '%s'\n", SERVER_IP);
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        return -1;
    }

    /* Do not wait forever for an answer. */
    struct timeval tv = { .tv_sec = TCP_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        printf("TCP: cannot connect to %s:%d\n", SERVER_IP, SERVER_PORT);
        net_close();
        return -1;
    }
    printf("TCP: connected to %s:%d\n", SERVER_IP, SERVER_PORT);
    return 0;
}

int net_connect(void)
{
    if (wifi_join() != 0) {
        printf("WiFi: cannot join '%s'\n", WIFI_SSID);
        return -1;
    }
    return tcp_open();
}

/* send() may write fewer bytes than asked: loop until all are out. */
static int send_all(const char *p, size_t len)
{
    while (len > 0) {
        int n = send(sock, p, len, 0);
        if (n <= 0) {
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int net_send_line(const char *line)
{
    if (sock < 0) {
        return -1;
    }
    if (send_all(line, strlen(line)) != 0 || send_all("\n", 1) != 0) {
        return -1;
    }
    return 0;
}

int net_recv_line(char *buf, size_t len)
{
    size_t n = 0;
    if (sock < 0 || len == 0) {
        return -1;
    }
    /* One byte at a time: simple, and the lines are short. */
    while (1) {
        char c;
        int r = recv(sock, &c, 1, 0);
        if (r <= 0) {
            return -1;              /* error, timeout or connection closed */
        }
        if (c == '\n') {
            break;
        }
        if (c == '\r') {
            continue;
        }
        if (n + 1 >= len) {
            return -1;              /* line too long */
        }
        buf[n++] = c;
    }
    buf[n] = '\0';
    return (int)n;
}

void net_close(void)
{
    if (sock >= 0) {
        close(sock);
        sock = -1;
    }
}
