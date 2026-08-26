#include "ota_service.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "esp_app_desc.h"
#include "esp_app_format.h"
#include "esp_check.h"
#include "esp_http_client.h"
#include "esp_image_format.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "fatal_error.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"
#include "ota_config.h"
#include "ota_wifi.h"
#include "device_identity.h"
#include "ota_secure_session.h"
#include "storage.h"

#define OTA_REQUEST_QUEUE_LENGTH 1
#define OTA_TASK_STACK_SIZE 12288
#define OTA_BUFFER_SIZE 4096
#define OTA_HTTP_TIMEOUT_MS 300000
#define OTA_URL_MAX_LEN (OTA_CONFIG_MAX_HOST_LEN + OTA_CONFIG_CODE_LEN + 32)
#define OTA_AUTH_HEADER_MAX_LEN (OTA_CONFIG_MAX_TOKEN_LEN + 16)
#define OTA_SHA256_HEX_LEN 64
#define OTA_SHA256_HEADER "X-Firmware-SHA256"
#define OTA_SUCCESS_REPORT_DELAY_MS 1200

static const char *TAG = "ota_service";
typedef struct { char payload[OTA_CONFIG_MAX_PAYLOAD_LEN + 1]; size_t payload_len; } ota_payload_request_t;
typedef struct { char sha256_hex[OTA_SHA256_HEX_LEN + 1]; } ota_http_context_t;

extern const char ota_server_ca_bundle_pem_start[] asm("_binary_ota_server_ca_bundle_pem_start");
extern const char ota_server_ca_bundle_pem_end[] asm("_binary_ota_server_ca_bundle_pem_end");

static QueueHandle_t s_request_queue;
static ota_state_t s_state = OTA_STATE_IDLE;
static uint8_t s_progress;
static esp_err_t s_last_error = ESP_OK;
static bool s_running;

static uint16_t runtime_port(void)
{
    ota_secure_provisioning_t provisioning = {0};
    if (ota_secure_session_load_provisioning(&provisioning) != ESP_OK || provisioning.ota_port == 0) {
        memset(&provisioning, 0, sizeof(provisioning));
        return 0;
    }
    const uint16_t port = provisioning.ota_port;
    memset(&provisioning, 0, sizeof(provisioning));
    return port;
}

#if CONFIG_APP_INSECURE_LEGACY_PROVISIONING
static esp_err_t parse_prefixed_provisioning(const ota_payload_request_t *request, ota_config_t *config)
{
    if (request->payload_len < 3 || request->payload[0] != 'P' || request->payload[1] != '|') return ESP_ERR_INVALID_ARG;
    return ota_config_parse_payload(&request->payload[2], request->payload_len - 2, config);
}
#endif

static esp_err_t load_config_for_ota_check(const ota_payload_request_t *request, ota_config_t *config)
{
    if (request->payload_len < 4 || request->payload[0] != 'C' || request->payload[1] != '|') return ESP_ERR_INVALID_ARG;
    const char *token = &request->payload[2];
    const size_t token_len = request->payload_len - 2;
    if (token_len != OTA_CONFIG_TOKEN_LEN) return ESP_ERR_INVALID_SIZE;
    if (!storage_load_ota_config(config)) return ESP_ERR_NOT_FOUND;
    if (strncmp(token, config->token, OTA_CONFIG_MAX_TOKEN_LEN) != 0) { ota_config_clear(config); return ESP_ERR_INVALID_RESPONSE; }
    ESP_LOGI(TAG, "OTA_CHECK accepted: stored config token verified");
    return ESP_OK;
}

static esp_err_t http_event_handler(esp_http_client_event_t *event)
{
    if (event == NULL || event->event_id != HTTP_EVENT_ON_HEADER || event->user_data == NULL || event->header_key == NULL || event->header_value == NULL) return ESP_OK;
    ota_http_context_t *ctx = (ota_http_context_t *)event->user_data;
    if (strcasecmp(event->header_key, OTA_SHA256_HEADER) == 0) strlcpy(ctx->sha256_hex, event->header_value, sizeof(ctx->sha256_hex));
    return ESP_OK;
}

static size_t cert_pem_len(void) { const ptrdiff_t len = ota_server_ca_bundle_pem_end - ota_server_ca_bundle_pem_start; return len > 0 ? (size_t)len : 0; }
const char *ota_service_get_cert_pem(void) { return ota_server_ca_bundle_pem_start; }
void ota_service_get_cert_bundle_info(size_t *bundle_len, size_t *cert_count)
{
    const char *pem = ota_server_ca_bundle_pem_start; const size_t len = cert_pem_len(); size_t count = 0; const char marker[] = "-----BEGIN CERTIFICATE-----"; const size_t marker_len = sizeof(marker) - 1;
    for (size_t i = 0; i + marker_len <= len; ++i) if (memcmp(&pem[i], marker, marker_len) == 0) { ++count; i += marker_len - 1; }
    if (bundle_len != NULL) *bundle_len = len; if (cert_count != NULL) *cert_count = count;
}

static void set_state(ota_state_t state) { s_state = state; ESP_LOGI(TAG, "OTA state=%d", (int)state); }

static esp_err_t validate_first_block(const uint8_t *data, int len, const esp_partition_t *target)
{
    const size_t header_len = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t);
    if (len < (int)header_len) return ESP_ERR_INVALID_SIZE;
    const esp_image_header_t *image_header = (const esp_image_header_t *)data;
    const esp_app_desc_t *new_app = (const esp_app_desc_t *)(data + sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t));
    const esp_app_desc_t *running_app = esp_app_get_description();
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (image_header->magic != ESP_IMAGE_HEADER_MAGIC) return ESP_ERR_INVALID_ARG;
    if (image_header->chip_id != CONFIG_IDF_FIRMWARE_CHIP_ID) return ESP_ERR_INVALID_VERSION;
    if (image_header->segment_count == 0 || image_header->segment_count > ESP_IMAGE_MAX_SEGMENTS) return ESP_ERR_INVALID_ARG;
    if (target == running) return ESP_ERR_INVALID_STATE;
    ESP_LOGI(TAG, "New firmware project=%s version=%s", new_app->project_name, new_app->version);
    ESP_LOGI(TAG, "Running firmware project=%s version=%s", running_app->project_name, running_app->version);
#if !CONFIG_APP_OTA_ALLOW_SAME_VERSION
    if (strncmp(new_app->version, running_app->version, sizeof(new_app->version)) == 0) {
#if CONFIG_APP_OTA_DRY_RUN
        ESP_LOGW(TAG, "OTA DRY-RUN: same version accepted for verification");
#else
        return ESP_ERR_INVALID_VERSION;
#endif
    }
#endif
    return ESP_OK;
}

static void get_device_id(char device_id[24]) { if (device_identity_get_device_id(device_id) != ESP_OK) strlcpy(device_id, "unknown", 24); }

static esp_err_t build_https_url(const ota_config_t *config, char url[OTA_URL_MAX_LEN])
{
    const uint16_t port = runtime_port();
    if (port == 0) return ESP_ERR_INVALID_STATE;
    const int written = snprintf(url, OTA_URL_MAX_LEN, "https://%s:%u/%s", config->host, (unsigned)port, config->code);
    return written < 0 || written >= OTA_URL_MAX_LEN ? ESP_ERR_INVALID_SIZE : ESP_OK;
}

static int hex_value(char c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'A' && c <= 'F') return c - 'A' + 10; if (c >= 'a' && c <= 'f') return c - 'a' + 10; return -1; }
static esp_err_t parse_sha256_hex(const char *hex, uint8_t out[OTA_CONFIG_SHA256_LEN])
{
    ESP_RETURN_ON_FALSE(hex != NULL, ESP_ERR_INVALID_ARG, TAG, "missing SHA256 header");
    ESP_RETURN_ON_FALSE(strlen(hex) == OTA_SHA256_HEX_LEN, ESP_ERR_INVALID_SIZE, TAG, "invalid SHA256 header length");
    for (size_t i = 0; i < OTA_CONFIG_SHA256_LEN; ++i) { const int hi = hex_value(hex[i * 2]), lo = hex_value(hex[i * 2 + 1]); ESP_RETURN_ON_FALSE(hi >= 0 && lo >= 0, ESP_ERR_INVALID_ARG, TAG, "invalid SHA256 header hex"); out[i] = (uint8_t)((hi << 4) | lo); }
    return ESP_OK;
}

static esp_err_t download_and_install(const ota_config_t *config)
{
    uint8_t buffer[OTA_BUFFER_SIZE]; esp_ota_handle_t ota_handle = 0; bool ota_started = false; esp_http_client_handle_t client = NULL; esp_err_t ret = ESP_OK;
    char url[OTA_URL_MAX_LEN], auth_header[OTA_AUTH_HEADER_MAX_LEN], device_id[24]; ota_http_context_t http_ctx = {0}; mbedtls_sha256_context sha_ctx;
    uint8_t actual_sha256[OTA_CONFIG_SHA256_LEN], expected_sha256[OTA_CONFIG_SHA256_LEN]; bool sha_started = false;
#if CONFIG_APP_OTA_DRY_RUN
    const bool dry_run = true;
#else
    const bool dry_run = false;
#endif
    ESP_RETURN_ON_ERROR(build_https_url(config, url), TAG, "invalid OTA URL"); get_device_id(device_id);
    const esp_http_client_config_t http_config = {.url = url, .cert_pem = ota_server_ca_bundle_pem_start, .timeout_ms = OTA_HTTP_TIMEOUT_MS, .keep_alive_enable = false, .event_handler = http_event_handler, .user_data = &http_ctx};
    client = esp_http_client_init(&http_config); if (client == NULL) return ESP_ERR_NO_MEM;
    int written = snprintf(auth_header, sizeof(auth_header), "Bearer %s", config->token); if (written < 0 || written >= (int)sizeof(auth_header)) { ret = ESP_ERR_INVALID_SIZE; goto cleanup; }
    ESP_GOTO_ON_ERROR(esp_http_client_set_header(client, "Authorization", auth_header), cleanup, TAG, "set Authorization header failed");
    ESP_GOTO_ON_ERROR(esp_http_client_set_header(client, "X-Device-ID", device_id), cleanup, TAG, "set X-Device-ID header failed");
    ret = esp_http_client_open(client, 0); if (ret != ESP_OK) goto cleanup;
    const int64_t content_length = esp_http_client_fetch_headers(client); const int status_code = esp_http_client_get_status_code(client); if (status_code != 200) { ret = ESP_FAIL; goto cleanup; }
    if (http_ctx.sha256_hex[0] == '\0') { ret = ESP_ERR_NOT_FOUND; goto cleanup; }
    ret = parse_sha256_hex(http_ctx.sha256_hex, expected_sha256); if (ret != ESP_OK) goto cleanup;
    const esp_partition_t *running = esp_ota_get_running_partition(); const esp_partition_t *target = esp_ota_get_next_update_partition(NULL);
    if (target == NULL) { ret = ESP_ERR_NOT_FOUND; goto cleanup; } if (target == running) { ret = ESP_ERR_INVALID_STATE; goto cleanup; }
    if (content_length > 0 && content_length > (int64_t)target->size) { ret = ESP_ERR_INVALID_SIZE; goto cleanup; }
    if (!dry_run) { ret = esp_ota_begin(target, content_length > 0 ? (size_t)content_length : OTA_SIZE_UNKNOWN, &ota_handle); if (ret != ESP_OK) goto cleanup; ota_started = true; }
    mbedtls_sha256_init(&sha_ctx); sha_started = true; mbedtls_sha256_starts(&sha_ctx, 0);
    int64_t total_read = 0; bool first_block = true;
    while (true) {
        const int read_len = esp_http_client_read(client, (char *)buffer, sizeof(buffer));
        if (read_len < 0) { ret = ESP_FAIL; goto cleanup; }
        if (read_len == 0) { if (esp_http_client_is_complete_data_received(client)) break; vTaskDelay(pdMS_TO_TICKS(20)); continue; }
        if (first_block) { first_block = false; ret = validate_first_block(buffer, read_len, target); if (ret != ESP_OK) goto cleanup; }
        if (mbedtls_sha256_update(&sha_ctx, buffer, (size_t)read_len) != 0) { ret = ESP_FAIL; goto cleanup; }
        if (!dry_run) { ret = esp_ota_write(ota_handle, buffer, read_len); if (ret != ESP_OK) goto cleanup; }
        total_read += read_len; if (content_length > 0) s_progress = (uint8_t)((total_read * 100) / content_length);
    }
    if (content_length > 0 && total_read != content_length) { ret = ESP_ERR_INVALID_SIZE; goto cleanup; }
    set_state(OTA_STATE_VERIFYING);
    if (mbedtls_sha256_finish(&sha_ctx, actual_sha256) != 0) { ret = ESP_FAIL; goto cleanup; }
    sha_started = false; mbedtls_sha256_free(&sha_ctx);
    if (memcmp(actual_sha256, expected_sha256, OTA_CONFIG_SHA256_LEN) != 0) { ret = ESP_ERR_INVALID_CRC; goto cleanup; }
    if (dry_run) { set_state(OTA_STATE_SUCCESS); s_progress = 100; goto cleanup; }
    ret = esp_ota_end(ota_handle); ota_started = false; if (ret != ESP_OK) goto cleanup;
    esp_app_desc_t partition_desc = {0}; ret = esp_ota_get_partition_description(target, &partition_desc); if (ret != ESP_OK) goto cleanup;
    ret = esp_ota_set_boot_partition(target); if (ret != ESP_OK) goto cleanup;
    set_state(OTA_STATE_SUCCESS);
    s_progress = 100;
    ESP_LOGI(TAG, "OTA success: allowing status/LED completion report before reboot into firmware %s", partition_desc.version);
    vTaskDelay(pdMS_TO_TICKS(OTA_SUCCESS_REPORT_DELAY_MS));
    ESP_LOGI(TAG, "OTA: rebooting into firmware %s", partition_desc.version);
    esp_restart();
cleanup:
    memset(auth_header, 0, sizeof(auth_header)); memset(actual_sha256, 0, sizeof(actual_sha256)); memset(expected_sha256, 0, sizeof(expected_sha256));
    if (sha_started) mbedtls_sha256_free(&sha_ctx); if (ota_started) esp_ota_abort(ota_handle); if (client != NULL) { esp_http_client_close(client); esp_http_client_cleanup(client); } return ret;
}

static void ota_task(void *arg)
{
    (void)arg; ota_payload_request_t request; ota_config_t config;
    while (true) {
        if (xQueueReceive(s_request_queue, &request, portMAX_DELAY) != pdTRUE) continue;
        s_running = true; s_progress = 0; s_last_error = ESP_OK; memset(&config, 0, sizeof(config)); esp_err_t err = ESP_OK;
        if (request.payload_len >= 2 && request.payload[1] == '|') {
            if (request.payload[0] == 'P') {
#if CONFIG_APP_INSECURE_LEGACY_PROVISIONING
                err = parse_prefixed_provisioning(&request, &config); memset(&request, 0, sizeof(request)); if (err == ESP_OK && storage_save_ota_config(&config)) set_state(OTA_STATE_IDLE); else set_state(OTA_STATE_FAILED); ota_config_clear(&config); s_running = false; continue;
#else
                memset(&request, 0, sizeof(request)); s_last_error = ESP_ERR_NOT_SUPPORTED; set_state(OTA_STATE_FAILED); s_running = false; continue;
#endif
            }
            if (request.payload[0] == 'C') err = load_config_for_ota_check(&request, &config); else err = ESP_ERR_INVALID_ARG;
        } else err = ota_config_parse_payload(request.payload, request.payload_len, &config);
        memset(&request, 0, sizeof(request));
        if (err != ESP_OK) { s_last_error = err; set_state(OTA_STATE_FAILED); s_running = false; continue; }
        (void)ota_wifi_scan_log(config.ssid);
        set_state(OTA_STATE_CONNECTING_WIFI); err = ota_wifi_connect(config.ssid, config.password);
        if (err == ESP_OK) { set_state(OTA_STATE_DOWNLOADING); err = download_and_install(&config); }
        ota_wifi_disconnect(); ota_config_clear(&config);
        if (err != ESP_OK) { s_last_error = err; set_state(OTA_STATE_FAILED); }
        s_running = false;
    }
}

void ota_service_init(void)
{
    s_request_queue = xQueueCreate(OTA_REQUEST_QUEUE_LENGTH, sizeof(ota_payload_request_t)); FATAL_ERROR_IF(s_request_queue == NULL, "Cannot create OTA request queue");
    if (xTaskCreate(ota_task, "ota_task", OTA_TASK_STACK_SIZE, NULL, 5, NULL) != pdPASS) fatal_error_restart(TAG, "Cannot create OTA task", ESP_ERR_NO_MEM);
}

bool ota_service_request_start(void) { return false; }
bool ota_service_request_payload(const char *payload, size_t payload_len)
{
    if (s_request_queue == NULL || s_running || payload == NULL || payload_len == 0 || payload_len > OTA_CONFIG_MAX_PAYLOAD_LEN) return false;
    ota_payload_request_t request = {0}; memcpy(request.payload, payload, payload_len); request.payload[payload_len] = '\0'; request.payload_len = payload_len;
    if (xQueueSend(s_request_queue, &request, 0) != pdTRUE) { memset(&request, 0, sizeof(request)); return false; }
    memset(&request, 0, sizeof(request)); set_state(OTA_STATE_PENDING); return true;
}
ota_state_t ota_service_get_state(void) { return s_state; }
uint8_t ota_service_get_progress(void) { return s_progress; }
esp_err_t ota_service_get_last_error(void) { return s_last_error; }

void ota_service_confirm_app_valid_after_boot(bool self_test_ok)
{
    const esp_partition_t *running = esp_ota_get_running_partition(); esp_ota_img_states_t ota_state; esp_err_t err = esp_ota_get_state_partition(running, &ota_state);
    if (err != ESP_OK || ota_state != ESP_OTA_IMG_PENDING_VERIFY) return;
    if (self_test_ok) FATAL_ERROR_CHECK(esp_ota_mark_app_valid_cancel_rollback()); else FATAL_ERROR_CHECK(esp_ota_mark_app_invalid_rollback_and_reboot());
}