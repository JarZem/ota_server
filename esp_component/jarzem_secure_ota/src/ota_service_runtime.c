/*
 * Keep the HTTPS port exclusively in authenticated provisioning data.
 * ota_service.c historically referenced CONFIG_APP_OTA_SERVER_PORT; this
 * wrapper deliberately replaces that expression with the current NVS value.
 */
#include <stdint.h>
#include <string.h>

#include "esp_err.h"
#include "ota_secure_session.h"

static uint16_t jarzem_ota_runtime_port(void)
{
    ota_secure_provisioning_t provisioning = {0};
    if (ota_secure_session_load_provisioning(&provisioning) != ESP_OK ||
        provisioning.ota_port == 0) {
        memset(&provisioning, 0, sizeof(provisioning));
        return 0;
    }

    const uint16_t port = provisioning.ota_port;
    memset(&provisioning, 0, sizeof(provisioning));
    return port;
}

#ifdef CONFIG_APP_OTA_SERVER_PORT
#undef CONFIG_APP_OTA_SERVER_PORT
#endif
#define CONFIG_APP_OTA_SERVER_PORT jarzem_ota_runtime_port()

#include "ota_service.c"
