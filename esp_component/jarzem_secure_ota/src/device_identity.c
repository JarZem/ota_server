#include "device_identity.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "device_credentials.h"
#include "esp_check.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "nvs.h"
#include "nwk/esp_zigbee_nwk.h"

#define OTA_SEC_NAMESPACE "ota_sec"
#define DEVICE_ENROLLMENT_COUNTER_NVS_KEY "enroll_counter"
#define DEVICE_KEY_ID_V1 1

static const char *TAG = "device_identity";
static uint8_t s_public_key[DEVICE_ENC_PUBLIC_KEY_LEN];
static uint16_t s_key_id = DEVICE_KEY_ID_V1;
static bool s_initialized;

static esp_err_t open_sec_nvs(nvs_open_mode_t mode, nvs_handle_t *handle)
{
    return nvs_open(OTA_SEC_NAMESPACE, mode, handle);
}

esp_err_t device_identity_init(void)
{
    if (s_initialized) return ESP_OK;
    ESP_RETURN_ON_ERROR(device_credentials_init(), TAG, "embedded device credentials unavailable");
    ESP_RETURN_ON_ERROR(device_credentials_get_public_key_uncompressed(s_public_key),
                        TAG, "device public key unavailable");
    s_initialized = true;
    ESP_LOGI(TAG, "device certificate public key ready, key_id=%u", (unsigned)s_key_id);
    return ESP_OK;
}

esp_err_t device_identity_get_device_id(char device_id[DEVICE_ID_MAX_LEN])
{
    ESP_RETURN_ON_FALSE(device_id != NULL, ESP_ERR_INVALID_ARG, TAG, "missing device_id buffer");
    esp_zb_ieee_addr_t ieee;
    esp_zb_get_long_address(ieee);
    snprintf(device_id, DEVICE_ID_MAX_LEN, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             ieee[7], ieee[6], ieee[5], ieee[4], ieee[3], ieee[2], ieee[1], ieee[0]);
    return ESP_OK;
}

esp_err_t device_identity_get_public_key(uint8_t public_key[DEVICE_ENC_PUBLIC_KEY_LEN])
{
    ESP_RETURN_ON_ERROR(device_identity_init(), TAG, "identity not available");
    memcpy(public_key, s_public_key, DEVICE_ENC_PUBLIC_KEY_LEN);
    return ESP_OK;
}

esp_err_t device_identity_get_public_key_fingerprint(uint8_t fingerprint[DEVICE_PUBLIC_KEY_FINGERPRINT_LEN])
{
    ESP_RETURN_ON_FALSE(fingerprint != NULL, ESP_ERR_INVALID_ARG, TAG, "missing fingerprint buffer");
    ESP_RETURN_ON_ERROR(device_identity_init(), TAG, "identity not available");
    if (mbedtls_sha256(s_public_key, DEVICE_ENC_PUBLIC_KEY_LEN, fingerprint, 0) != 0) return ESP_FAIL;
    return ESP_OK;
}

uint16_t device_identity_get_key_id(void)
{
    return s_key_id;
}

esp_err_t device_identity_get_enrollment_counter(uint64_t *counter)
{
    ESP_RETURN_ON_FALSE(counter != NULL, ESP_ERR_INVALID_ARG, TAG, "missing enrollment counter");
    nvs_handle_t handle;
    ESP_RETURN_ON_ERROR(open_sec_nvs(NVS_READONLY, &handle), TAG, "open secure NVS failed");
    uint64_t value = 0;
    esp_err_t err = nvs_get_u64(handle, DEVICE_ENROLLMENT_COUNTER_NVS_KEY, &value);
    nvs_close(handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        *counter = 0;
        return ESP_OK;
    }
    if (err == ESP_OK) *counter = value;
    return err;
}

esp_err_t device_identity_next_enrollment_counter(uint64_t *counter)
{
    ESP_RETURN_ON_FALSE(counter != NULL, ESP_ERR_INVALID_ARG, TAG, "missing enrollment counter");
    nvs_handle_t handle;
    ESP_RETURN_ON_ERROR(open_sec_nvs(NVS_READWRITE, &handle), TAG, "open secure NVS failed");
    uint64_t value = 0;
    esp_err_t err = nvs_get_u64(handle, DEVICE_ENROLLMENT_COUNTER_NVS_KEY, &value);
    if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
    if (err == ESP_OK) {
        value++;
        err = nvs_set_u64(handle, DEVICE_ENROLLMENT_COUNTER_NVS_KEY, value);
    }
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    if (err == ESP_OK) *counter = value;
    return err;
}
