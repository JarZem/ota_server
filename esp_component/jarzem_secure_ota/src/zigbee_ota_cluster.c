#include "zigbee_ota_cluster.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device_credentials.h"
#include "device_identity.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_zigbee_core.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"
#include "ota_check_auth.h"
#include "ota_config.h"
#include "ota_secure_session.h"
#include "ota_service.h"
#include "status_led.h"
#include "zigbee_ota_control.h"
#include "zcl/esp_zigbee_zcl_common.h"

static const char *TAG = "zigbee_ota_cluster";
#define HELLO_WAIT_ATTEMPTS 30
#define HELLO_SIGNATURE_B64_MAX 96
#define HELLO_RETRY_MS 120000
#define DIAG_PING "D|PING"
#define DIAG_PONG "D|PONG"
#define DIAG_LEN_PREFIX "D|LEN|"
#define DIAG_STOP "D|STOP"
#define DIAG_LEN_MIN 6
#define DIAG_LEN_MAX 100
#define DIAG_REPEAT_MS 20000
#define OTA_BINARY_CHALLENGE_LEN (OTA_SECURE_RANDOM_LEN + DEVICE_CREDENTIAL_SIGNATURE_RAW_LEN)

static uint8_t s_ota_payload_attr[ZIGBEE_OTA_ZCL_STRING_CAPACITY + 1];
static bool s_hello_task_started;
static bool s_diag_task_started;
static bool s_len_test_task_started;
static uint32_t s_hello_delay_ms;
static volatile size_t s_len_test_payload_len;

static bool zigbee_ota_network_identity_valid(void)
{
    if (esp_zb_bdb_is_factory_new()) return false;
    const uint16_t short_addr = esp_zb_get_short_address();
    return short_addr != 0x0000 && short_addr != 0xfffe && short_addr != 0xffff;
}

static esp_err_t base64url_encode(const uint8_t *input, size_t input_len, char *out, size_t out_size)
{
    if (input == NULL || out == NULL || out_size < 2) return ESP_ERR_INVALID_ARG;
    size_t written = 0;
    int ret = mbedtls_base64_encode((unsigned char *)out, out_size, &written, input, input_len);
    if (ret != 0 || written >= out_size) return ESP_ERR_INVALID_SIZE;
    for (size_t i = 0; i < written; ++i) { if (out[i] == '+') out[i] = '-'; else if (out[i] == '/') out[i] = '_'; }
    while (written > 0 && out[written - 1] == '=') --written;
    out[written] = '\0'; return ESP_OK;
}

static esp_err_t zigbee_ota_send_command_payload(const char *payload)
{
    if (payload == NULL) return ESP_ERR_INVALID_ARG;
    const size_t payload_len = strlen(payload);
    if (payload_len == 0 || payload_len > ZIGBEE_OTA_COMMAND_PAYLOAD_MAX || payload_len > 254) return ESP_ERR_INVALID_SIZE;
    uint8_t wire[ZIGBEE_OTA_COMMAND_PAYLOAD_MAX + 1]; wire[0] = (uint8_t)payload_len; memcpy(&wire[1], payload, payload_len);
    esp_zb_zcl_custom_cluster_cmd_req_t cmd = {0};
    cmd.zcl_basic_cmd.dst_addr_u.addr_short = 0x0000; cmd.zcl_basic_cmd.dst_endpoint = 1; cmd.zcl_basic_cmd.src_endpoint = ZIGBEE_OTA_ENDPOINT;
    cmd.address_mode = ESP_ZB_APS_ADDR_MODE_16_ENDP_PRESENT; cmd.cluster_id = ZIGBEE_OTA_CLUSTER_ID; cmd.profile_id = ESP_ZB_AF_HA_PROFILE_ID;
    cmd.direction = ESP_ZB_ZCL_CMD_DIRECTION_TO_CLI; cmd.custom_cmd_id = ZIGBEE_OTA_CMD_FROM_DEVICE_ID;
    cmd.data.type = ESP_ZB_ZCL_ATTR_TYPE_SET; cmd.data.size = payload_len + 1; cmd.data.value = wire;
    if (!esp_zb_lock_acquire(portMAX_DELAY)) return ESP_ERR_TIMEOUT;
    const uint8_t tsn = esp_zb_zcl_custom_cluster_cmd_req(&cmd); esp_zb_lock_release();
    ESP_LOGI(TAG, "OTA custom command tx cluster=0x%04x cmd=0x%02x bytes=%u tsn=0x%02x payload=%s", ZIGBEE_OTA_CLUSTER_ID, ZIGBEE_OTA_CMD_FROM_DEVICE_ID, (unsigned)payload_len, tsn, payload);
    return ESP_OK;
}

esp_err_t zigbee_ota_publish_control_state(bool enabled, uint8_t status)
{
    char payload[16]; const int n = snprintf(payload, sizeof(payload), "T|%u|%02X", enabled ? 1U : 0U, (unsigned)status);
    return n <= 0 || n >= (int)sizeof(payload) ? ESP_ERR_INVALID_SIZE : zigbee_ota_send_command_payload(payload);
}

esp_err_t zigbee_ota_report_download_complete(void)
{
    char payload[OTA_CHECK_COMPLETION_MAX_LEN]; ESP_RETURN_ON_ERROR(ota_check_auth_build_completion(payload), TAG, "no OTA grant completion to report");
    esp_err_t err = zigbee_ota_send_command_payload(payload); if (err == ESP_OK) { ota_check_auth_clear_active_grant(); ESP_LOGI(TAG, "OTA download completion reported payload=%s", payload); } return err;
}

static void zigbee_ota_ack_task(void *arg)
{
    char *ack = (char *)arg;
    if (ack != NULL) { vTaskDelay(pdMS_TO_TICKS(50)); const esp_err_t err = zigbee_ota_send_command_payload(ack); if (err == ESP_OK) status_led_indicate_provision_step(); ESP_LOGI(TAG, "R response TX state=%s bytes=%u result=%s payload=%s", ota_secure_session_state_name(), (unsigned)strlen(ack), esp_err_to_name(err), ack); memset(ack, 0, strlen(ack)); free(ack); }
    vTaskDelete(NULL);
}

static void schedule_secure_ack(const char *ack)
{
    char *copy = strdup(ack); if (copy == NULL) return;
    if (xTaskCreate(zigbee_ota_ack_task, "zb_auth_ack", 3072, copy, 5, NULL) != pdPASS) { memset(copy, 0, strlen(copy)); free(copy); }
}

static bool process_secure_protocol(const char *payload)
{
    if (payload == NULL) return false;
    if ((strncmp(payload, "A|", 2) == 0 || strncmp(payload, "P|", 2) == 0) && !zigbee_ota_control_is_enabled()) { ESP_LOGW(TAG, "secure provisioning frame dropped: Enable OTA=0"); return true; }
    if (strncmp(payload, "A|", 2) == 0) {
        char ack[OTA_SECURE_ACK_MAX_LEN]; const esp_err_t err = ota_secure_session_accept_challenge(payload, ack);
        if (err != ESP_OK) { ESP_LOGW(TAG, "A dropped/rejected state=%s result=%s", ota_secure_session_state_name(), esp_err_to_name(err)); return true; }
        status_led_indicate_provision_step(); schedule_secure_ack(ack); memset(ack, 0, sizeof(ack)); return true;
    }
    if (strncmp(payload, "P|", 2) == 0) {
        const esp_err_t err = ota_secure_session_accept_provisioning(payload);
        if (err != ESP_OK) ESP_LOGW(TAG, "P dropped/rejected state=%s result=%s", ota_secure_session_state_name(), esp_err_to_name(err));
        else { status_led_indicate_provision_step(); zigbee_ota_control_set_status(ZIGBEE_OTA_STATUS_PROVISIONING_COMPLETE); zigbee_ota_control_set_enabled(false); ESP_LOGI(TAG, "P complete state=%s; provisioning finished; Enable OTA -> 0", ota_secure_session_state_name()); }
        return true;
    }
    if (strncmp(payload, "A1|", 3) == 0 || strncmp(payload, "P1|", 3) == 0 || strncmp(payload, "R1|", 3) == 0) return true;
    return false;
}

static void zigbee_ota_diag_task(void *arg)
{
    (void)arg; vTaskDelay(pdMS_TO_TICKS(100)); (void)zigbee_ota_send_command_payload(DIAG_PONG); s_diag_task_started = false; vTaskDelete(NULL);
}

static void zigbee_ota_len_test_task(void *arg)
{
    (void)arg; unsigned iteration = 0;
    while (s_len_test_payload_len != 0) {
        const size_t len = s_len_test_payload_len; char test[DIAG_LEN_MAX + 1]; int prefix = snprintf(test, sizeof(test), "D|L%03u|", (unsigned)len); size_t used = prefix > 0 ? (size_t)prefix : 0; if (used > len) used = len;
        for (size_t i = used; i < len; ++i) test[i] = (char)('A' + (i % 26)); test[len] = '\0'; ++iteration; (void)zigbee_ota_send_command_payload(test);
        for (unsigned elapsed = 0; elapsed < DIAG_REPEAT_MS && s_len_test_payload_len != 0; elapsed += 100) vTaskDelay(pdMS_TO_TICKS(100));
    }
    s_len_test_task_started = false; vTaskDelete(NULL);
}

typedef struct { size_t len; char payload[OTA_CONFIG_MAX_PAYLOAD_LEN + 1]; } ota_check_task_arg_t;

static void ota_check_task(void *arg)
{
    ota_check_task_arg_t *ctx = (ota_check_task_arg_t *)arg; if (ctx == NULL) { vTaskDelete(NULL); return; }
    vTaskDelay(pdMS_TO_TICKS(100)); char request[OTA_CONFIG_MAX_PAYLOAD_LEN + 1]; size_t request_len = 0;
    const esp_err_t err = ota_check_auth_prepare_request(ctx->payload, ctx->len, request, sizeof(request), &request_len);
    if (err == ESP_ERR_INVALID_VERSION) { zigbee_ota_control_set_status(ZIGBEE_OTA_STATUS_FW_SKIPPED); ESP_LOGI(TAG, "OTA CHECK valid but firmware is not newer; skipped"); }
    else if (err != ESP_OK) { zigbee_ota_control_set_status(err == ESP_ERR_INVALID_CRC ? ZIGBEE_OTA_STATUS_FW_VERIFY_ERROR : ZIGBEE_OTA_STATUS_FW_UPDATE_ERROR); ESP_LOGW(TAG, "OTA CHECK rejected: %s", esp_err_to_name(err)); }
    else { zigbee_ota_control_set_status(ZIGBEE_OTA_STATUS_FW_UPDATE_STARTED); if (!ota_service_request_payload(request, request_len)) { zigbee_ota_control_set_status(ZIGBEE_OTA_STATUS_FW_UPDATE_ERROR); ESP_LOGW(TAG, "OTA CHECK accepted but OTA request queue is busy/full"); } }
    memset(ctx, 0, sizeof(*ctx)); free(ctx); vTaskDelete(NULL);
}

static bool schedule_ota_check(const char *payload, size_t payload_len)
{
    if (payload == NULL || payload_len < 3 || strncmp(payload, "C|", 2) != 0) return false;
    if (payload_len > OTA_CONFIG_MAX_PAYLOAD_LEN) return true;
    ota_check_task_arg_t *ctx = calloc(1, sizeof(*ctx)); if (ctx == NULL) { zigbee_ota_control_set_status(ZIGBEE_OTA_STATUS_FW_UPDATE_ERROR); return true; }
    memcpy(ctx->payload, payload, payload_len); ctx->payload[payload_len] = '\0'; ctx->len = payload_len;
    if (xTaskCreate(ota_check_task, "ota_check", 6144, ctx, 5, NULL) != pdPASS) { memset(ctx, 0, sizeof(*ctx)); free(ctx); zigbee_ota_control_set_status(ZIGBEE_OTA_STATUS_FW_UPDATE_ERROR); }
    return true;
}

static bool zigbee_ota_process_payload(const char *payload, size_t payload_len)
{
    if (payload == NULL || payload_len == 0) return true;
    ESP_LOGI(TAG, "MQTT/ZIGBEE RX endpoint=%u state=%s bytes=%u payload=%.*s", ZIGBEE_OTA_ENDPOINT, ota_secure_session_state_name(), (unsigned)payload_len, (int)payload_len, payload);
    if (schedule_ota_check(payload, payload_len)) return true;
    if (process_secure_protocol(payload)) return true;
    if (strcmp(payload, DIAG_PING) == 0) { if (!s_diag_task_started) { s_diag_task_started = true; if (xTaskCreate(zigbee_ota_diag_task, "zb_ota_diag", 3072, NULL, 5, NULL) != pdPASS) s_diag_task_started = false; } return true; }
    if (strcmp(payload, DIAG_STOP) == 0) { s_len_test_payload_len = 0; return true; }
    if (strncmp(payload, DIAG_LEN_PREFIX, strlen(DIAG_LEN_PREFIX)) == 0) {
        char *end = NULL; unsigned long requested = strtoul(payload + strlen(DIAG_LEN_PREFIX), &end, 10);
        if (end == payload + strlen(DIAG_LEN_PREFIX) || *end != '\0' || requested < DIAG_LEN_MIN || requested > DIAG_LEN_MAX) return true;
        s_len_test_payload_len = (size_t)requested;
        if (!s_len_test_task_started) { s_len_test_task_started = true; if (xTaskCreate(zigbee_ota_len_test_task, "zb_ota_len", 3072, NULL, 5, NULL) != pdPASS) { s_len_test_task_started = false; s_len_test_payload_len = 0; } }
        return true;
    }
    if (!ota_service_request_payload(payload, payload_len)) ESP_LOGW(TAG, "OTA ERROR: request ignored: busy or queue full");
    return true;
}

static esp_err_t process_binary_downlink(const uint8_t *body, size_t len)
{
    if (body == NULL || len == 0) return ESP_ERR_INVALID_ARG;
    if (len <= ZIGBEE_OTA_COMMAND_PAYLOAD_MAX && (body[0] == 'D' || body[0] == 'C')) { char text[ZIGBEE_OTA_COMMAND_PAYLOAD_MAX + 1]; memcpy(text, body, len); text[len] = '\0'; zigbee_ota_process_payload(text, len); return ESP_OK; }
    if (!zigbee_ota_control_is_enabled()) return ESP_ERR_INVALID_STATE;
    const ota_secure_state_t state = ota_secure_session_state(); char text[OTA_SECURE_PROVISION_MAX_WIRE_LEN + 1];
    if (state == OTA_SEC_STATE_WAIT_CHALLENGE) {
        if (len != OTA_BINARY_CHALLENGE_LEN) return ESP_ERR_INVALID_SIZE; char random_b64[16], sig_b64[96];
        ESP_RETURN_ON_ERROR(base64url_encode(body, OTA_SECURE_RANDOM_LEN, random_b64, sizeof(random_b64)), TAG, "A random encode failed");
        ESP_RETURN_ON_ERROR(base64url_encode(body + OTA_SECURE_RANDOM_LEN, DEVICE_CREDENTIAL_SIGNATURE_RAW_LEN, sig_b64, sizeof(sig_b64)), TAG, "A signature encode failed");
        const int n = snprintf(text, sizeof(text), "A|%s|%s", random_b64, sig_b64); if (n <= 0 || n >= (int)sizeof(text)) return ESP_ERR_INVALID_SIZE; zigbee_ota_process_payload(text, (size_t)n); return ESP_OK;
    }
    if (state == OTA_SEC_STATE_WAIT_PROVISIONING) {
        char encrypted_b64[OTA_SECURE_PROVISION_MAX_WIRE_LEN]; ESP_RETURN_ON_ERROR(base64url_encode(body, len, encrypted_b64, sizeof(encrypted_b64)), TAG, "P encoding failed");
        const int n = snprintf(text, sizeof(text), "P|%s", encrypted_b64); if (n <= 0 || n >= (int)sizeof(text)) return ESP_ERR_INVALID_SIZE; zigbee_ota_process_payload(text, (size_t)n); return ESP_OK;
    }
    return ESP_ERR_INVALID_STATE;
}

static esp_err_t send_secure_hello(void)
{
    if (!zigbee_ota_control_is_enabled()) return ESP_ERR_INVALID_STATE;
    ESP_RETURN_ON_ERROR(device_credentials_init(), TAG, "device credentials unavailable");
    char device_id[DEVICE_ID_MAX_LEN] = {0}; ESP_RETURN_ON_ERROR(device_identity_get_device_id(device_id), TAG, "device identity unavailable");
    uint64_t counter = 0; ESP_RETURN_ON_ERROR(device_identity_next_enrollment_counter(&counter), TAG, "HELLO counter update failed");
    char canonical[96]; int canonical_len = snprintf(canonical, sizeof(canonical), "H|%s|%" PRIu64, device_id, counter); if (canonical_len <= 0 || (size_t)canonical_len >= sizeof(canonical)) return ESP_ERR_INVALID_SIZE;
    uint8_t signature_raw[DEVICE_CREDENTIAL_SIGNATURE_RAW_LEN]; ESP_RETURN_ON_ERROR(device_credentials_sign_raw64((const uint8_t *)canonical, (size_t)canonical_len, signature_raw), TAG, "HELLO signing failed");
    char signature_b64[HELLO_SIGNATURE_B64_MAX]; ESP_RETURN_ON_ERROR(base64url_encode(signature_raw, sizeof(signature_raw), signature_b64, sizeof(signature_b64)), TAG, "HELLO signature encoding failed");
    char payload[ZIGBEE_OTA_HELLO_FRAME_MAX + 1]; int payload_len = snprintf(payload, sizeof(payload), "H|%" PRIu64 "|%s", counter, signature_b64); if (payload_len <= 0 || payload_len > ZIGBEE_OTA_HELLO_FRAME_MAX) return ESP_ERR_INVALID_SIZE;
    ESP_RETURN_ON_ERROR(ota_secure_session_begin_hello(counter), TAG, "cannot enter WAIT_CHALLENGE");
    ESP_LOGI(TAG, "HELLO sending counter=%" PRIu64 " state=%s bytes=%d endpoint=%u cluster=0x%04x", counter, ota_secure_session_state_name(), payload_len, ZIGBEE_OTA_ENDPOINT, ZIGBEE_OTA_CLUSTER_ID);
    return zigbee_ota_send_command_payload(payload);
}

static void zigbee_ota_hello_task(void *arg)
{
    (void)arg; if (s_hello_delay_ms > 0) vTaskDelay(pdMS_TO_TICKS(s_hello_delay_ms));
    while (zigbee_ota_control_is_enabled() && !ota_secure_session_is_provisioned()) {
        bool network_ready = false;
        for (unsigned attempt = 1; attempt <= HELLO_WAIT_ATTEMPTS && zigbee_ota_control_is_enabled(); ++attempt) { if (zigbee_ota_network_identity_valid()) { network_ready = true; break; } vTaskDelay(pdMS_TO_TICKS(1000)); }
        if (!zigbee_ota_control_is_enabled()) break;
        ota_secure_session_reset_for_retry(); zigbee_ota_control_set_status(ZIGBEE_OTA_STATUS_PROVISIONING_STARTED);
        if (network_ready) { const esp_err_t err = send_secure_hello(); if (err == ESP_OK) status_led_indicate_provision_step(); if (err != ESP_OK) zigbee_ota_control_set_status(ZIGBEE_OTA_STATUS_PROVISIONING_ERROR); }
        else zigbee_ota_control_set_status(ZIGBEE_OTA_STATUS_PROVISIONING_ERROR);
        for (unsigned elapsed = 0; elapsed < HELLO_RETRY_MS; elapsed += 1000) { if (!zigbee_ota_control_is_enabled() || ota_secure_session_is_provisioned()) break; vTaskDelay(pdMS_TO_TICKS(1000)); }
        if (!zigbee_ota_control_is_enabled() || ota_secure_session_is_provisioned()) break;
        zigbee_ota_control_set_status(ZIGBEE_OTA_STATUS_PROVISIONING_TIMEOUT); ota_secure_session_reset_for_retry();
    }
    if (!zigbee_ota_control_is_enabled()) ota_secure_session_reset_for_retry(); s_hello_task_started = false; vTaskDelete(NULL);
}

void zigbee_ota_schedule_hello(uint32_t delay_ms)
{
    if (!zigbee_ota_control_is_enabled() || s_hello_task_started) return; s_hello_delay_ms = delay_ms; s_hello_task_started = true;
    if (xTaskCreate(zigbee_ota_hello_task, "zb_ota_hello", 4096, NULL, 5, NULL) != pdPASS) { s_hello_task_started = false; zigbee_ota_control_set_status(ZIGBEE_OTA_STATUS_PROVISIONING_ERROR); }
}

esp_err_t zigbee_ota_cluster_add_attrs(esp_zb_attribute_list_t *cluster)
{
    s_ota_payload_attr[0] = 0; const uint8_t access = ESP_ZB_ZCL_ATTR_ACCESS_READ_WRITE | ESP_ZB_ZCL_ATTR_ACCESS_REPORTING | ESP_ZB_ZCL_ATTR_MANUF_SPEC;
    esp_err_t err = esp_zb_cluster_add_manufacturer_attr(cluster, ZIGBEE_OTA_CLUSTER_ID, ZIGBEE_OTA_CONFIG_ATTR_ID, ZIGBEE_OTA_MANUFACTURER_CODE, ESP_ZB_ZCL_ATTR_TYPE_OCTET_STRING, access, s_ota_payload_attr);
    if (err == ESP_OK) { ESP_RETURN_ON_ERROR(ota_secure_session_init(), TAG, "secure OTA session init failed"); ota_service_init(); }
    return err;
}

bool zigbee_ota_cluster_handle_set_attr(const esp_zb_zcl_set_attr_value_message_t *message)
{
    if (message == NULL || message->info.status != ESP_ZB_ZCL_STATUS_SUCCESS || message->info.dst_endpoint != ZIGBEE_OTA_ENDPOINT || message->info.cluster != ZIGBEE_OTA_CLUSTER_ID || message->attribute.id != ZIGBEE_OTA_CONFIG_ATTR_ID) return false;
    status_led_indicate_ha_command(); const esp_zb_zcl_attribute_data_t *data = &message->attribute.data;
    if (data->value == NULL || data->type != ESP_ZB_ZCL_ATTR_TYPE_OCTET_STRING || data->size < 1) return true;
    const uint8_t *zcl = (const uint8_t *)data->value; const size_t len = zcl[0]; if (len == 0 || len + 1 > data->size) return true;
    const esp_err_t err = process_binary_downlink(&zcl[1], len); if (err != ESP_OK) ESP_LOGW(TAG, "binary downlink rejected result=%s", esp_err_to_name(err)); return true;
}

bool zigbee_ota_cluster_handle_custom_cmd(const esp_zb_zcl_custom_cluster_command_message_t *message)
{
    if (message == NULL || message->info.status != ESP_ZB_ZCL_STATUS_SUCCESS || message->info.dst_endpoint != ZIGBEE_OTA_ENDPOINT || message->info.cluster != ZIGBEE_OTA_CLUSTER_ID || message->info.command.id != ZIGBEE_OTA_CMD_TO_DEVICE_ID) return false;
    status_led_indicate_ha_command(); if (message->data.value == NULL || message->data.size < 2) return true;
    const uint8_t *wire = (const uint8_t *)message->data.value; const size_t len = wire[0]; if (len == 0 || len > OTA_CONFIG_MAX_PAYLOAD_LEN || len + 1 > message->data.size) return true;
    char payload[OTA_CONFIG_MAX_PAYLOAD_LEN + 1]; memcpy(payload, &wire[1], len); payload[len] = '\0'; return zigbee_ota_process_payload(payload, len);
}
