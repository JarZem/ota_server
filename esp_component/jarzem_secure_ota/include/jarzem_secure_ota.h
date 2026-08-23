#pragma once

#include "esp_err.h"
#include "esp_zigbee_core.h"
#include "esp_zigbee_endpoint.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef esp_err_t (*jarzem_ota_project_action_handler_t)(esp_zb_core_action_callback_id_t callback_id,
                                                         const void *message);

/*
 * Register the application's endpoint list after adding the OTA-owned endpoints.
 * OTA owns endpoint 10 (secure transport) and endpoint 11 (control/status).
 */
esp_err_t jarzem_ota_device_register(esp_zb_ep_list_t *application_endpoints);

/*
 * Register one Zigbee action trampoline. OTA messages are handled first;
 * all messages not owned by OTA are passed unchanged to project_handler.
 */
void jarzem_ota_action_handler_register(jarzem_ota_project_action_handler_t project_handler);

/* Optional project UI hooks. Weak no-op implementations are provided by OTA. */
void jarzem_ota_hook_rx_from_ha(void);
void jarzem_ota_hook_tx_to_ha(void);
void jarzem_ota_hook_provision_step(void);

/*
 * OTA custom-cluster uplinks pass through this wrapper. This keeps TX activity
 * indication at the transport boundary instead of inside provisioning/CHECK logic.
 */
uint8_t jarzem_ota_custom_cluster_cmd_req(esp_zb_zcl_custom_cluster_cmd_req_t *cmd);
#define esp_zb_zcl_custom_cluster_cmd_req(cmd) jarzem_ota_custom_cluster_cmd_req(cmd)

/*
 * Optional RF-critical hooks. A project may use them to suspend nonessential
 * peripherals (for example WS2812/RMT output) while OTA Zigbee RX/TX is active.
 * Implementations must support nested enter/exit pairs.
 */
void jarzem_ota_hook_radio_critical_enter(void);
void jarzem_ota_hook_radio_critical_exit(void);

#ifdef __cplusplus
}
#endif
