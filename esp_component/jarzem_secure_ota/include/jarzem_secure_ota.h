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
void jarzem_ota_hook_provision_step(void);

#ifdef __cplusplus
}
#endif
