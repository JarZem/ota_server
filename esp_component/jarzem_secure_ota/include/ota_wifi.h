#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t ota_wifi_connect(const char *ssid, const char *password);
esp_err_t ota_wifi_scan_log(const char *target_ssid);
void ota_wifi_disconnect(void);

#ifdef __cplusplus
}
#endif
