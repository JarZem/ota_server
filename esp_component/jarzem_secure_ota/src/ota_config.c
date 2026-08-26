#include "ota_config.h"

#include <string.h>
#include "esp_check.h"

static const char *TAG = "ota_config";

static void secure_bzero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len-- > 0) *p++ = 0;
}

void ota_config_clear(ota_config_t *config)
{
    if (config != NULL) secure_bzero(config, sizeof(*config));
}

static bool code_is_valid(const char *code)
{
    for (size_t i = 0; i < OTA_CONFIG_CODE_LEN; ++i) {
        const char c = code[i];
        const bool digit = c >= '0' && c <= '9';
        const bool upper = c >= 'A' && c <= 'Z';
        const bool lower = c >= 'a' && c <= 'z';
        if (!digit && !upper && !lower) return false;
    }
    return code[OTA_CONFIG_CODE_LEN] == '\0';
}

static bool token_is_valid(const char *token)
{
    for (size_t i = 0; i < OTA_CONFIG_TOKEN_LEN; ++i) {
        const char c = token[i];
        const bool digit = c >= '0' && c <= '9';
        const bool upper = c >= 'A' && c <= 'Z';
        const bool lower = c >= 'a' && c <= 'z';
        const bool base64url = c == '-' || c == '_';
        if (!digit && !upper && !lower && !base64url) return false;
    }
    return token[OTA_CONFIG_TOKEN_LEN] == '\0';
}

static esp_err_t copy_field(const char *payload, size_t start, size_t end,
                            char *dst, size_t dst_size)
{
    ESP_RETURN_ON_FALSE(end > start, ESP_ERR_INVALID_SIZE, TAG, "invalid payload: empty field");
    const size_t len = end - start;
    ESP_RETURN_ON_FALSE(len < dst_size, ESP_ERR_INVALID_SIZE, TAG, "invalid payload: field too long");
    memcpy(dst, payload + start, len);
    dst[len] = '\0';
    return ESP_OK;
}

esp_err_t ota_config_parse_payload(const char *payload, size_t payload_len, ota_config_t *config)
{
    ESP_RETURN_ON_FALSE(payload != NULL && config != NULL, ESP_ERR_INVALID_ARG, TAG, "invalid payload: null input");
    ESP_RETURN_ON_FALSE(payload_len > 0 && payload_len <= OTA_CONFIG_MAX_PAYLOAD_LEN,
                        ESP_ERR_INVALID_SIZE, TAG, "invalid payload: length");

    ota_config_t parsed = {0};
    size_t separators[4] = {0};
    size_t separator_count = 0;
    for (size_t i = 0; i < payload_len; ++i) {
        if (payload[i] == '|') {
            ESP_RETURN_ON_FALSE(separator_count < 4, ESP_ERR_INVALID_ARG, TAG, "invalid payload: too many fields");
            separators[separator_count++] = i;
        }
    }
    ESP_RETURN_ON_FALSE(separator_count == 4, ESP_ERR_INVALID_ARG, TAG, "invalid payload: field count");

    esp_err_t ret = ESP_OK;
    ESP_GOTO_ON_ERROR(copy_field(payload, 0, separators[0], parsed.ssid, sizeof(parsed.ssid)), cleanup, TAG, "invalid SSID");
    ESP_GOTO_ON_ERROR(copy_field(payload, separators[0] + 1, separators[1], parsed.password, sizeof(parsed.password)), cleanup, TAG, "invalid password");
    ESP_GOTO_ON_ERROR(copy_field(payload, separators[1] + 1, separators[2], parsed.host, sizeof(parsed.host)), cleanup, TAG, "invalid host");
    ESP_GOTO_ON_ERROR(copy_field(payload, separators[2] + 1, separators[3], parsed.code, sizeof(parsed.code)), cleanup, TAG, "invalid firmware code");
    ESP_GOTO_ON_ERROR(copy_field(payload, separators[3] + 1, payload_len, parsed.token, sizeof(parsed.token)), cleanup, TAG, "invalid token");
    ESP_GOTO_ON_FALSE(strlen(parsed.code) == OTA_CONFIG_CODE_LEN && code_is_valid(parsed.code), ESP_ERR_INVALID_ARG, cleanup, TAG, "invalid payload: firmware code");
    ESP_GOTO_ON_FALSE(strlen(parsed.token) == OTA_CONFIG_TOKEN_LEN && token_is_valid(parsed.token), ESP_ERR_INVALID_ARG, cleanup, TAG, "invalid payload: token");
    *config = parsed;
cleanup:
    if (ret != ESP_OK) ota_config_clear(&parsed);
    return ret;
}
