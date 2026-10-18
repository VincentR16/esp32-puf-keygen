
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/sensor_dht11.c")
    set(sensor_src "sensor_dht11.c")
else()
    set(sensor_src "sensor_fake.c")
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/display_oled.c")
    set(display_src "display_oled.c")
else()
    set(display_src "display_none.c")
endif()

idf_component_register(
    SRCS "boot.c" "puf.c" "fuzzy.c" "crypto.c" "net.c"
         "${sensor_src}" "${display_src}"
    INCLUDE_DIRS "."
    PRIV_REQUIRES nvs_flash mbedtls esp_wifi esp_netif esp_event lwip
                  esp_driver_gpio esp_timer esp_driver_i2c esp_lcd
)