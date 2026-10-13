idf_component_register(
    SRCS "boot.c" "puf.c" "crypto.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES nvs_flash mbedtls
)