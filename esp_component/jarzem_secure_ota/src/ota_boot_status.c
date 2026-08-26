#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "device_credentials.h"
#include "device_identity.h"
#include "esp_app_desc.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_zigbee_core.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "jarzem_secure_ota.h"
#include "mbedtls/base64.h"
#include "zigbee_ota_cluster.h"
#include "zcl/esp_zigbee_zcl_common.h"

static const char *TAG = "ota_boot_status";
#define STATUS_WAIT_ATTEMPTS 60
#define STATUS_RETRY_MS 5000
#define STATUS_SIGNATURE_B64_MAX 96

static bool s_status_task_started;

static bool network_ready(void)
{
    if (esp_zb_bdb_is_factory_new()) return false;
    const uint16_t short_addr = esp_zb_get_short_address();
    return short_addr != 0x0000 && short_addr != 0xfffe && short_addr != 0xffff;
}

static esp_err_t base64url_encode(const uint8_t *input, size_t input_len, char *out, size_t out_size)
{
    unsigned char encoded[128];
    size_t written = 0;
    int ret = mbedtls_base64_encode(encoded, sizeof(encoded), &written, input, input_len);
    if (ret != 0) return ESP_ERR_INVALID_SIZE;
    while (written > 0 && encoded[written - 1] == '=') --written;
    if (written + 1 > out_size) return ESP_ERR_INVALID_SIZE;
    for (size_t i = 0; i < written; ++i) {
        out[i] = encoded[i] == '+' ? '-' : encoded[i] == '/' ? '_' : (char)encoded[i];
    }
    out[written] = '\0';
    return ESP_OK;
}

static esp_err_t send_payload(const char *payload)
{
    const size_t len = strlen(payload);
    if (len == 0 || len > ZIGBEE_OTA_COMMAND_PAYLOAD_MAX) return ESP_ERR_INVALID_SIZE;
    uint8_t wire[ZIGBEE_OTA_COMMAND_PAYLOAD_MAX + 1];
    wire[0] = (uint8_t)len;
    memcpy(&wire[1], payload, len);

    esp_zb_zcl_custom_cluster_cmd_req_t cmd = {0};
    cmd.zcl_basic_cmd.dst_addr_u.addr_short = 0x0000;
    cmd.zcl_basic_cmd.dst_endpoint = 1;
    cmd.zcl_basic_cmd.src_endpoint = ZIGBEE_OTA_ENDPOINT;
    cmd.address_mode = ESP_ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    cmd.cluster_id = ZIGBEE_OTA_CLUSTER_ID;
    cmd.profile_id = ESP_ZB_AF_HA_PROFILE_ID;
    cmd.direction = ESP_ZB_ZCL_CMD_DIRECTION_TO_CLI;
    cmd.custom_cmd_id = ZIGBEE_OTA_CMD_FROM_DEVICE_ID;
    cmd.data.type = ESP_ZB_ZCL_ATTR_TYPE_SET;
    cmd.data.size = len + 1;
    cmd.data.value = wire;

    jarzem_ota_hook_radio_critical_enter();
    if (!esp_zb_lock_acquire(portMAX_DELAY)) {
        jarzem_ota_hook_radio_critical_exit();
        return ESP_ERR_TIMEOUT;
    }
    (void)esp_zb_zcl_custom_cluster_cmd_req(&cmd);
    esp_zb_lock_release();
    jarzem_ota_hook_radio_critical_exit();
    jarzem_ota_hook_tx_to_ha();
    return ESP_OK;
}

static esp_err_t send_status(void)
{
    ESP_RETURN_ON_ERROR(device_credentials_init(), TAG, "device credentials unavailable");
    char device_id[DEVICE_ID_MAX_LEN] = {0};
    ESP_RETURN_ON_ERROR(device_identity_get_device_id(device_id), TAG, "device identity unavailable");
    uint64_t counter = 0;
    ESP_RETURN_ON_ERROR(device_identity_next_enrollment_counter(&counter), TAG, "STATUS counter update failed");

    const esp_app_desc_t *app = esp_app_get_description();
    if (app == NULL || app->version[0] == '\0' || strchr(app->version, '|') != NULL)
        return ESP_ERR_INVALID_VERSION;

    char canonical[160];
    int n = snprintf(canonical, sizeof(canonical), "S|%s|%" PRIu64 "|%s", device_id, counter, app->version);
    if (n <= 0 || n >= (int)sizeof(canonical)) return ESP_ERR_INVALID_SIZE;

    uint8_t signature_raw[DEVICE_CREDENTIAL_SIGNATURE_RAW_LEN];
    ESP_RETURN_ON_ERROR(device_credentials_sign_raw64((const uint8_t *)canonical, (size_t)n, signature_raw),
                        TAG, "STATUS signing failed");
    char signature_b64[STATUS_SIGNATURE_B64_MAX];
    ESP_RETURN_ON_ERROR(base64url_encode(signature_raw, sizeof(signature_raw), signature_b64, sizeof(signature_b64)),
                        TAG, "STATUS signature encoding failed");

    char payload[ZIGBEE_OTA_COMMAND_PAYLOAD_MAX + 1];
    n = snprintf(payload, sizeof(payload), "S|%" PRIu64 "|%s|%s", counter, app->version, signature_b64);
    if (n <= 0 || n > ZIGBEE_OTA_COMMAND_PAYLOAD_MAX) return ESP_ERR_INVALID_SIZE;
    ESP_LOGI(TAG, "sending signed boot STATUS counter=%" PRIu64 " fw=%s bytes=%d", counter, app->version, n);
    return send_payload(payload);
}

static void status_task(void *arg)
{
    (void)arg;
    for (unsigned attempt = 0; attempt < STATUS_WAIT_ATTEMPTS; ++attempt) {
        if (network_ready()) {
            const esp_err_t err = send_status();
            if (err == ESP_OK) break;
            ESP_LOGW(TAG, "STATUS send failed: %s", esp_err_to_name(err));
        }
        vTaskDelay(pdMS_TO_TICKS(STATUS_RETRY_MS));
    }
    s_status_task_started = false;
    vTaskDelete(NULL);
}

void ota_boot_status_schedule(void)
{
    if (s_status_task_started) return;
    s_status_task_started = true;
    if (xTaskCreate(status_task, "ota_status", 4096, NULL, 5, NULL) != pdPASS)
        s_status_task_started = false;
}
