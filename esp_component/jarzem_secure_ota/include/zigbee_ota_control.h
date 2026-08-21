#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_zigbee_attribute.h"
#include "esp_zigbee_endpoint.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZIGBEE_OTA_CONTROL_ENDPOINT           11
#define ZIGBEE_OTA_ENABLE_CLUSTER_ID          0xfc01
#define ZIGBEE_OTA_STATUS_CLUSTER_ID          0xfc02
#define ZIGBEE_OTA_CONTROL_MANUFACTURER_CODE  0x1234
#define ZIGBEE_OTA_ENABLE_ATTR_ID             0x0000
#define ZIGBEE_OTA_STATUS_ATTR_ID             0x0000

typedef enum {
    ZIGBEE_OTA_STATUS_FLAG_ERROR               = 0x80,
    ZIGBEE_OTA_STATUS_FLAG_PROVISIONING        = 0x40,
    ZIGBEE_OTA_STATUS_FLAG_FIRMWARE            = 0x20,
    ZIGBEE_OTA_STATUS_FLAG_VERIFY              = 0x10,
    ZIGBEE_OTA_STATUS_FLAG_SKIPPED             = 0x08,
    ZIGBEE_OTA_STATUS_FLAG_TIMEOUT             = 0x04,
    ZIGBEE_OTA_STATUS_FLAG_FINISHED            = 0x02,
    ZIGBEE_OTA_STATUS_FLAG_STARTED             = 0x01,
    ZIGBEE_OTA_STATUS_IDLE                     = 0x00,
    ZIGBEE_OTA_STATUS_PROVISIONING_STARTED     = 0x41,
    ZIGBEE_OTA_STATUS_PROVISIONING_COMPLETE    = 0x42,
    ZIGBEE_OTA_STATUS_PROVISIONING_ERROR       = 0xC2,
    ZIGBEE_OTA_STATUS_PROVISIONING_TIMEOUT     = 0xC6,
    ZIGBEE_OTA_STATUS_FW_UPDATE_STARTED        = 0x21,
    ZIGBEE_OTA_STATUS_FW_UPDATE_COMPLETE       = 0x22,
    ZIGBEE_OTA_STATUS_FW_UPDATE_ERROR          = 0xA2,
    ZIGBEE_OTA_STATUS_FW_VERIFY_ERROR          = 0xB2,
    ZIGBEE_OTA_STATUS_FW_SKIPPED               = 0x2A,
} zigbee_ota_status_t;

esp_err_t zigbee_ota_control_add_endpoint(esp_zb_ep_list_t *ep_list);
bool zigbee_ota_control_handle_set_attr(const esp_zb_zcl_set_attr_value_message_t *message);
bool zigbee_ota_control_is_enabled(void);
void zigbee_ota_control_set_enabled(bool enabled);
void zigbee_ota_control_set_status(zigbee_ota_status_t status);
uint8_t zigbee_ota_control_get_status(void);

#ifdef __cplusplus
}
#endif
