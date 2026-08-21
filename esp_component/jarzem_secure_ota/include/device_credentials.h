#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEVICE_CREDENTIAL_PUBLIC_KEY_MAX_DER 128
#define DEVICE_CREDENTIAL_PUBLIC_KEY_UNCOMPRESSED_LEN 65
#define DEVICE_CREDENTIAL_SIGNATURE_MAX_DER 80
#define DEVICE_CREDENTIAL_SIGNATURE_RAW_LEN 64
#define DEVICE_CREDENTIAL_ECDH_SECRET_LEN 32

esp_err_t device_credentials_init(void);
esp_err_t device_credentials_get_certificate_der(const uint8_t **der, size_t *der_len);
esp_err_t device_credentials_get_public_key_der(uint8_t *out, size_t out_size, size_t *written);
esp_err_t device_credentials_get_public_key_uncompressed(uint8_t out[DEVICE_CREDENTIAL_PUBLIC_KEY_UNCOMPRESSED_LEN]);
esp_err_t device_credentials_sign(const uint8_t *data, size_t data_len,
                                  uint8_t *signature_der, size_t signature_size,
                                  size_t *signature_len);
esp_err_t device_credentials_sign_raw64(const uint8_t *data, size_t data_len,
                                        uint8_t signature[DEVICE_CREDENTIAL_SIGNATURE_RAW_LEN]);
esp_err_t device_credentials_verify_ota_server_certificate(void);
esp_err_t device_credentials_verify_ota_signature_raw64(
    const uint8_t *data, size_t data_len,
    const uint8_t signature[DEVICE_CREDENTIAL_SIGNATURE_RAW_LEN]);
esp_err_t device_credentials_derive_ota_ecdh_secret(uint8_t out[DEVICE_CREDENTIAL_ECDH_SECRET_LEN]);
const char *device_credentials_get_root_ca_pem(size_t *length);
const char *device_credentials_get_ota_server_cert_pem(size_t *length);

#ifdef __cplusplus
}
#endif
