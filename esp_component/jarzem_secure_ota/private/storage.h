#pragma once

#include <stdbool.h>
#include "ota_config.h"

bool storage_load_ota_config(ota_config_t *config);
bool storage_save_ota_config(const ota_config_t *config);
