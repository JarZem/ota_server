#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_zigbee_attribute.h"
#include "esp_zigbee_cluster.h"
#include "zcl/esp_zigbee_zcl_command.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZIGBEE_OTA_CLUSTER_ID                    0xfc00
#define ZIGBEE_OTA_MANUFACTURER_CODE             0x1234
#define ZIGBEE_OTA_CONFIG_ATTR_ID                0x0001
#define ZIGBEE_OTA_ENDPOINT                      10
#define ZIGBEE_OTA_CMD_TO_DEVICE_ID              0x04
#define ZIGBEE_OTA_CMD_FROM_DEVICE_ID            0x11
#define ZIGBEE_OTA_ZCL_STRING_CAPACITY           120
#define ZIGBEE_OTA_COMMAND_PAYLOAD_MAX           100
#define ZIGBEE_OTA_HELLO_FRAME_MAX               100

esp_err_t zigbee_ota_cluster_add_attrs(esp_zb_attribute_list_t *cluster);
void zigbee_ota_schedule_hello(uint32_t delay_ms);
esp_err_t zigbee_ota_report_download_complete(void);
esp_err_t zigbee_ota_publish_control_state(bool enabled, uint8_t status);
bool zigbee_ota_cluster_handle_set_attr(const esp_zb_zcl_set_attr_value_message_t *message);
bool zigbee_ota_cluster_handle_custom_cmd(const esp_zb_zcl_custom_cluster_command_message_t *message);

#ifdef __cplusplus
}
#endif
