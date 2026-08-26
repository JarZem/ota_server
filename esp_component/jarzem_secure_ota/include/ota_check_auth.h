#pragma once

#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OTA_CHECK_COMPLETION_MAX_LEN 16

esp_err_t ota_check_auth_snapshot_provisioning_context(void);
esp_err_t ota_check_auth_prepare_request(const char *payload, size_t payload_len,
                                         char *out_request, size_t out_size,
                                         size_t *out_len);
esp_err_t ota_check_auth_build_completion(char out[OTA_CHECK_COMPLETION_MAX_LEN]);
void ota_check_auth_clear_active_grant(void);

#ifdef __cplusplus
}
#endif
