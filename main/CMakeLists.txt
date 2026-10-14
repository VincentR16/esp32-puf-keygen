idf_component_register(
    SRCS "boot.c" "puf.c" "fuzzy.c" "crypto.c" "net.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES nvs_flash mbedtls esp_wifi esp_netif esp_event lwip
)