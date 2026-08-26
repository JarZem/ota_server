#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    OTA_STATE_IDLE,
    OTA_STATE_PENDING,
    OTA_STATE_CONNECTING_WIFI,
    OTA_STATE_DOWNLOADING,
    OTA_STATE_VERIFYING,
    OTA_STATE_SUCCESS,
    OTA_STATE_FAILED
} ota_state_t;

void ota_service_init(void);
bool ota_service_request_start(void);
bool ota_service_request_payload(const char *payload, size_t payload_len);
ota_state_t ota_service_get_state(void);
uint8_t ota_service_get_progress(void);
esp_err_t ota_service_get_last_error(void);
const char *ota_service_get_cert_pem(void);
void ota_service_get_cert_bundle_info(size_t *bundle_len, size_t *cert_count);
void ota_service_confirm_app_valid_after_boot(bool self_test_ok);

#ifdef __cplusplus
}
#endif
