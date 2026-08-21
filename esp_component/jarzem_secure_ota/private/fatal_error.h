#pragma once

#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"

static inline void fatal_error_restart(const char *tag, const char *message, esp_err_t err)
{
    ESP_LOGE(tag != NULL ? tag : "jarzem_ota", "%s: %s", message != NULL ? message : "fatal error", esp_err_to_name(err));
    esp_restart();
}

#define FATAL_ERROR_CHECK(expr) do { \
    esp_err_t _jarzem_ota_err = (expr); \
    if (_jarzem_ota_err != ESP_OK) fatal_error_restart("jarzem_ota", #expr, _jarzem_ota_err); \
} while (0)

#define FATAL_ERROR_IF(cond, message) do { \
    if (cond) fatal_error_restart("jarzem_ota", (message), ESP_FAIL); \
} while (0)
