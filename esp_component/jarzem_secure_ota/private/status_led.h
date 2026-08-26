#pragma once

#include "jarzem_secure_ota.h"

#define status_led_indicate_ha_command() jarzem_ota_hook_rx_from_ha()
#define status_led_indicate_provision_step() jarzem_ota_hook_provision_step()
