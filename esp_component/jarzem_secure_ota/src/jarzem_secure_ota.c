#include "jarzem_secure_ota.h"

#include "esp_check.h"
#include "esp_log.h"
#include "esp_zigbee_cluster.h"
#include "ha/esp_zigbee_ha_standard.h"
#include "zigbee_ota_cluster.h"
#include "zigbee_ota_control.h"

static const char *TAG = "jarzem_secure_ota";
static jarzem_ota_project_action_handler_t s_project_handler;
static bool s_endpoints_added;

__attribute__((weak)) void jarzem_ota_hook_rx_from_ha(void) {}
__attribute__((weak)) void jarzem_ota_hook_provision_step(void) {}

static esp_err_t add_transport_endpoint(esp_zb_ep_list_t *ep_list)
{
    esp_zb_cluster_list_t *clusters = esp_zb_zcl_cluster_list_create();
    ESP_RETURN_ON_FALSE(clusters != NULL, ESP_ERR_NO_MEM, TAG, "OTA transport cluster list allocation failed");

    esp_zb_basic_cluster_cfg_t basic_cfg = {
        .zcl_version = ESP_ZB_ZCL_BASIC_ZCL_VERSION_DEFAULT_VALUE,
        .power_source = ESP_ZB_ZCL_BASIC_POWER_SOURCE_DC_SOURCE,
    };
    esp_zb_attribute_list_t *basic = esp_zb_basic_cluster_create(&basic_cfg);
    ESP_RETURN_ON_FALSE(basic != NULL, ESP_ERR_NO_MEM, TAG, "OTA transport Basic cluster allocation failed");
    ESP_RETURN_ON_ERROR(
        esp_zb_cluster_list_add_basic_cluster(clusters, basic, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE),
        TAG, "OTA transport Basic cluster add failed");

    esp_zb_attribute_list_t *transport = esp_zb_zcl_attr_list_create(ZIGBEE_OTA_CLUSTER_ID);
    ESP_RETURN_ON_FALSE(transport != NULL, ESP_ERR_NO_MEM, TAG, "OTA transport cluster allocation failed");
    ESP_RETURN_ON_ERROR(zigbee_ota_cluster_add_attrs(transport), TAG, "OTA transport attributes add failed");
    ESP_RETURN_ON_ERROR(
        esp_zb_cluster_list_add_custom_cluster(clusters, transport, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE),
        TAG, "OTA transport cluster add failed");

    const esp_zb_endpoint_config_t cfg = {
        .endpoint = ZIGBEE_OTA_ENDPOINT,
        .app_profile_id = ESP_ZB_AF_HA_PROFILE_ID,
        .app_device_id = 0xff01,
        .app_device_version = 0,
    };
    return esp_zb_ep_list_add_ep(ep_list, clusters, cfg);
}

static esp_err_t add_ota_endpoints(esp_zb_ep_list_t *ep_list)
{
    if (s_endpoints_added) return ESP_OK;
    ESP_RETURN_ON_FALSE(ep_list != NULL, ESP_ERR_INVALID_ARG, TAG, "application endpoint list is NULL");
    ESP_RETURN_ON_ERROR(add_transport_endpoint(ep_list), TAG, "OTA endpoint 10 registration failed");
    ESP_RETURN_ON_ERROR(zigbee_ota_control_add_endpoint(ep_list), TAG, "OTA endpoint 11 registration failed");
    s_endpoints_added = true;
    ESP_LOGI(TAG, "OTA owns Zigbee endpoint %u cluster=0x%04x and endpoint %u clusters=0x%04x/0x%04x",
             ZIGBEE_OTA_ENDPOINT, ZIGBEE_OTA_CLUSTER_ID,
             ZIGBEE_OTA_CONTROL_ENDPOINT, ZIGBEE_OTA_ENABLE_CLUSTER_ID, ZIGBEE_OTA_STATUS_CLUSTER_ID);
    return ESP_OK;
}

esp_err_t jarzem_ota_device_register(esp_zb_ep_list_t *application_endpoints)
{
    ESP_RETURN_ON_ERROR(add_ota_endpoints(application_endpoints), TAG, "could not add OTA endpoints");
    return esp_zb_device_register(application_endpoints);
}

static esp_err_t ota_action_handler(esp_zb_core_action_callback_id_t callback_id, const void *message)
{
    switch (callback_id) {
        case ESP_ZB_CORE_SET_ATTR_VALUE_CB_ID: {
            const esp_zb_zcl_set_attr_value_message_t *set =
                (const esp_zb_zcl_set_attr_value_message_t *)message;
            if (zigbee_ota_control_handle_set_attr(set) || zigbee_ota_cluster_handle_set_attr(set)) {
                return ESP_OK;
            }
            break;
        }
        case ESP_ZB_CORE_CMD_CUSTOM_CLUSTER_REQ_CB_ID:
            if (zigbee_ota_cluster_handle_custom_cmd(
                    (const esp_zb_zcl_custom_cluster_command_message_t *)message)) {
                return ESP_OK;
            }
            break;
        default:
            break;
    }
    return s_project_handler != NULL ? s_project_handler(callback_id, message) : ESP_OK;
}

void jarzem_ota_action_handler_register(jarzem_ota_project_action_handler_t project_handler)
{
    s_project_handler = project_handler;
    esp_zb_core_action_handler_register(ota_action_handler);
}
