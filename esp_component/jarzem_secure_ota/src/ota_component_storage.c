#include "storage.h"

#include <string.h>
#include "esp_log.h"
#include "nvs.h"

#define OTA_STORAGE_NAMESPACE "jarzem_ota"
#define OTA_CONFIG_KEY "download_cfg"

static const char *TAG = "ota_component_store";

bool storage_load_ota_config(ota_config_t *config)
{
    if (config == NULL) return false;
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(OTA_STORAGE_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) return false;
    size_t size = sizeof(*config);
    err = nvs_get_blob(handle, OTA_CONFIG_KEY, config, &size);
    nvs_close(handle);
    if (err != ESP_OK || size != sizeof(*config)) {
        ota_config_clear(config);
        return false;
    }
    return true;
}

bool storage_save_ota_config(const ota_config_t *config)
{
    if (config == NULL) return false;
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(OTA_STORAGE_NAMESPACE, NVS_READWRITE, &handle);
    if (err == ESP_OK) err = nvs_set_blob(handle, OTA_CONFIG_KEY, config, sizeof(*config));
    if (err == ESP_OK) err = nvs_commit(handle);
    if (handle != 0) nvs_close(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "OTA runtime config save failed: %s", esp_err_to_name(err));
        return false;
    }
    return true;
}
