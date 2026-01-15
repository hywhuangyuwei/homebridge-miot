idf_component_register(SRCS "main.c" "led_control.c" "miot.c"
                    INCLUDE_DIRS "."
                    REQUIRES lwip mbedtls esp_timer esp_http_server nvs_flash esp_wifi esp_event esp_netif)
