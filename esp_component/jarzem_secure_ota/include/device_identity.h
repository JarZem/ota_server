#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define DEVICE_ID_MAX_LEN 24
#define DEVICE_ENC_PUBLIC_KEY_LEN 65
#define DEVICE_PUBLIC_KEY_FINGERPRINT_LEN 32

esp_err_t device_identity_init(void);
esp_err_t device_identity_get_device_id(char device_id[DEVICE_ID_MAX_LEN]);
esp_err_t device_identity_get_public_key(uint8_t public_key[DEVICE_ENC_PUBLIC_KEY_LEN]);
esp_err_t device_identity_get_public_key_fingerprint(uint8_t fingerprint[DEVICE_PUBLIC_KEY_FINGERPRINT_LEN]);
uint16_t device_identity_get_key_id(void);
esp_err_t device_identity_get_enrollment_counter(uint64_t *counter);
esp_err_t device_identity_next_enrollment_counter(uint64_t *counter);
