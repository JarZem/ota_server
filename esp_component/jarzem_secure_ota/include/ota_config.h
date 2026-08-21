#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OTA_CONFIG_MAX_PAYLOAD_LEN 254
#define OTA_CONFIG_MAX_SSID_LEN    32
#define OTA_CONFIG_MAX_PASSWORD_LEN 64
#define OTA_CONFIG_MAX_HOST_LEN    64
#define OTA_CONFIG_CODE_LEN        3
#define OTA_CONFIG_TOKEN_LEN       16
#define OTA_CONFIG_MAX_TOKEN_LEN   32
#define OTA_CONFIG_MAX_VERSION_LEN 32
#define OTA_CONFIG_SHA256_LEN      32

typedef struct {
    char ssid[OTA_CONFIG_MAX_SSID_LEN + 1];
    char password[OTA_CONFIG_MAX_PASSWORD_LEN + 1];
    char host[OTA_CONFIG_MAX_HOST_LEN + 1];
    char code[OTA_CONFIG_CODE_LEN + 1];
    char token[OTA_CONFIG_MAX_TOKEN_LEN + 1];
} ota_config_t;

esp_err_t ota_config_parse_payload(const char *payload, size_t payload_len, ota_config_t *config);
void ota_config_clear(ota_config_t *config);

#ifdef __cplusplus
}
#endif
