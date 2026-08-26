#include "device_credentials.h"

#include <stdbool.h>
#include <string.h>

#include "esp_check.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/private_access.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"

static const char *TAG = "device_credentials";

extern const char device_cert_pem_start[] asm("_binary_device_cert_pem_start");
extern const char device_cert_pem_end[] asm("_binary_device_cert_pem_end");
extern const char device_private_pem_start[] asm("_binary_device_private_pem_start");
extern const char device_private_pem_end[] asm("_binary_device_private_pem_end");
extern const char root_ca_cert_pem_start[] asm("_binary_root_ca_cert_pem_start");
extern const char root_ca_cert_pem_end[] asm("_binary_root_ca_cert_pem_end");
extern const char ota_server_cert_pem_start[] asm("_binary_ota_server_cert_pem_start");
extern const char ota_server_cert_pem_end[] asm("_binary_ota_server_cert_pem_end");

static mbedtls_x509_crt s_cert;
static mbedtls_pk_context s_private_key;
static mbedtls_x509_crt s_root_ca;
static mbedtls_x509_crt s_ota_server_cert;
static bool s_initialized;
static bool s_server_trust_initialized;

static int esp_rng(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

esp_err_t device_credentials_init(void)
{
    if (s_initialized) return ESP_OK;

    mbedtls_x509_crt_init(&s_cert);
    mbedtls_pk_init(&s_private_key);

    const size_t cert_len = (size_t)(device_cert_pem_end - device_cert_pem_start);
    const size_t key_len = (size_t)(device_private_pem_end - device_private_pem_start);

    int ret = mbedtls_x509_crt_parse(&s_cert, (const unsigned char *)device_cert_pem_start, cert_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "device certificate parse failed: -0x%04x", (unsigned)-ret);
        return ESP_FAIL;
    }

    ret = mbedtls_pk_parse_key(&s_private_key,
                               (const unsigned char *)device_private_pem_start,
                               key_len, NULL, 0, esp_rng, NULL);
    if (ret != 0) {
        ESP_LOGE(TAG, "device private key parse failed: -0x%04x", (unsigned)-ret);
        return ESP_FAIL;
    }

    ret = mbedtls_pk_check_pair(&s_cert.pk, &s_private_key, esp_rng, NULL);
    if (ret != 0) {
        ESP_LOGE(TAG, "device certificate/private key mismatch: -0x%04x", (unsigned)-ret);
        return ESP_FAIL;
    }
    if (!mbedtls_pk_can_do(&s_private_key, MBEDTLS_PK_ECKEY)) {
        ESP_LOGE(TAG, "device private key is not an EC key");
        return ESP_ERR_NOT_SUPPORTED;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "device certificate/private key ready cert_der_len=%u", (unsigned)s_cert.raw.len);
    return ESP_OK;
}

static esp_err_t init_server_trust(void)
{
    if (s_server_trust_initialized) return ESP_OK;

    mbedtls_x509_crt_init(&s_root_ca);
    mbedtls_x509_crt_init(&s_ota_server_cert);

    const size_t ca_len = (size_t)(root_ca_cert_pem_end - root_ca_cert_pem_start);
    const size_t server_len = (size_t)(ota_server_cert_pem_end - ota_server_cert_pem_start);

    int ret = mbedtls_x509_crt_parse(&s_root_ca,
                                     (const unsigned char *)root_ca_cert_pem_start,
                                     ca_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "root CA parse failed: -0x%04x", (unsigned)-ret);
        return ESP_FAIL;
    }

    ret = mbedtls_x509_crt_parse(&s_ota_server_cert,
                                 (const unsigned char *)ota_server_cert_pem_start,
                                 server_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "OTA server certificate parse failed: -0x%04x", (unsigned)-ret);
        return ESP_FAIL;
    }

    uint32_t flags = 0;
    ret = mbedtls_x509_crt_verify(&s_ota_server_cert,
                                  &s_root_ca,
                                  NULL,
                                  NULL,
                                  &flags,
                                  NULL,
                                  NULL);
    if (ret != 0 || flags != 0) {
        ESP_LOGE(TAG, "OTA server certificate CA verification failed ret=-0x%04x flags=0x%08lx",
                 ret < 0 ? (unsigned)-ret : 0U,
                 (unsigned long)flags);
        return ESP_ERR_INVALID_CRC;
    }

    if (!mbedtls_pk_can_do(&s_ota_server_cert.pk, MBEDTLS_PK_ECKEY)) {
        ESP_LOGE(TAG, "OTA server certificate key is not EC");
        return ESP_ERR_NOT_SUPPORTED;
    }

    s_server_trust_initialized = true;
    ESP_LOGI(TAG, "OTA server certificate verified against embedded root CA");
    return ESP_OK;
}

esp_err_t device_credentials_verify_ota_server_certificate(void)
{
    ESP_RETURN_ON_ERROR(device_credentials_init(), TAG, "device credentials unavailable");
    return init_server_trust();
}

esp_err_t device_credentials_derive_ota_ecdh_secret(
    uint8_t out[DEVICE_CREDENTIAL_ECDH_SECRET_LEN])
{
    ESP_RETURN_ON_FALSE(out != NULL, ESP_ERR_INVALID_ARG, TAG, "missing ECDH output");
    ESP_RETURN_ON_ERROR(device_credentials_init(), TAG, "device credentials unavailable");
    ESP_RETURN_ON_ERROR(init_server_trust(), TAG, "OTA server certificate not trusted");

    mbedtls_ecp_keypair *device_ec = mbedtls_pk_ec(s_private_key);
    mbedtls_ecp_keypair *server_ec = mbedtls_pk_ec(s_ota_server_cert.pk);
    ESP_RETURN_ON_FALSE(device_ec != NULL && server_ec != NULL,
                        ESP_ERR_NOT_SUPPORTED, TAG, "ECDH requires EC keys");
    ESP_RETURN_ON_FALSE(device_ec->MBEDTLS_PRIVATE(grp).id == server_ec->MBEDTLS_PRIVATE(grp).id,
                        ESP_ERR_INVALID_STATE, TAG, "ECDH curve mismatch");
    ESP_RETURN_ON_FALSE(device_ec->MBEDTLS_PRIVATE(grp).id == MBEDTLS_ECP_DP_SECP256R1,
                        ESP_ERR_NOT_SUPPORTED, TAG, "ECDH requires P-256");

    mbedtls_mpi shared;
    mbedtls_mpi_init(&shared);
    int ret = mbedtls_ecdh_compute_shared(&device_ec->MBEDTLS_PRIVATE(grp),
                                          &shared,
                                          &server_ec->MBEDTLS_PRIVATE(Q),
                                          &device_ec->MBEDTLS_PRIVATE(d),
                                          esp_rng,
                                          NULL);
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&shared, out, DEVICE_CREDENTIAL_ECDH_SECRET_LEN);
    }
    mbedtls_mpi_free(&shared);

    if (ret != 0) {
        memset(out, 0, DEVICE_CREDENTIAL_ECDH_SECRET_LEN);
        ESP_LOGE(TAG, "ECDH shared secret derivation failed: -0x%04x", (unsigned)-ret);
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t device_credentials_get_certificate_der(const uint8_t **der, size_t *der_len)
{
    ESP_RETURN_ON_FALSE(der != NULL && der_len != NULL, ESP_ERR_INVALID_ARG, TAG, "invalid certificate output");
    ESP_RETURN_ON_ERROR(device_credentials_init(), TAG, "credentials unavailable");
    *der = s_cert.raw.p;
    *der_len = s_cert.raw.len;
    return ESP_OK;
}

esp_err_t device_credentials_get_public_key_der(uint8_t *out, size_t out_size, size_t *written)
{
    ESP_RETURN_ON_FALSE(out != NULL && written != NULL, ESP_ERR_INVALID_ARG, TAG, "invalid public key output");
    ESP_RETURN_ON_ERROR(device_credentials_init(), TAG, "credentials unavailable");
    unsigned char temp[DEVICE_CREDENTIAL_PUBLIC_KEY_MAX_DER];
    int len = mbedtls_pk_write_pubkey_der(&s_cert.pk, temp, sizeof(temp));
    if (len <= 0 || (size_t)len > out_size) return ESP_ERR_INVALID_SIZE;
    memcpy(out, temp + sizeof(temp) - len, (size_t)len);
    *written = (size_t)len;
    return ESP_OK;
}

esp_err_t device_credentials_get_public_key_uncompressed(uint8_t out[DEVICE_CREDENTIAL_PUBLIC_KEY_UNCOMPRESSED_LEN])
{
    ESP_RETURN_ON_FALSE(out != NULL, ESP_ERR_INVALID_ARG, TAG, "missing public key output");
    ESP_RETURN_ON_ERROR(device_credentials_init(), TAG, "credentials unavailable");
    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(s_cert.pk);
    ESP_RETURN_ON_FALSE(ec != NULL, ESP_ERR_NOT_SUPPORTED, TAG, "certificate key is not EC");
    out[0] = 0x04;
    if (mbedtls_mpi_write_binary(&ec->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), out + 1, 32) != 0 ||
        mbedtls_mpi_write_binary(&ec->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), out + 33, 32) != 0) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t device_credentials_sign(const uint8_t *data, size_t data_len,
                                  uint8_t *signature_der, size_t signature_size,
                                  size_t *signature_len)
{
    ESP_RETURN_ON_FALSE(data != NULL && data_len > 0 && signature_der != NULL && signature_len != NULL,
                        ESP_ERR_INVALID_ARG, TAG, "invalid sign arguments");
    ESP_RETURN_ON_ERROR(device_credentials_init(), TAG, "credentials unavailable");
    uint8_t hash[32];
    if (mbedtls_sha256(data, data_len, hash, 0) != 0) return ESP_FAIL;
    size_t out_len = 0;
    int ret = mbedtls_pk_sign(&s_private_key, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                              signature_der, signature_size, &out_len, esp_rng, NULL);
    if (ret != 0) {
        ESP_LOGE(TAG, "signature failed: -0x%04x", (unsigned)-ret);
        return ESP_FAIL;
    }
    *signature_len = out_len;
    return ESP_OK;
}

esp_err_t device_credentials_sign_raw64(const uint8_t *data, size_t data_len,
                                        uint8_t signature[DEVICE_CREDENTIAL_SIGNATURE_RAW_LEN])
{
    ESP_RETURN_ON_FALSE(data != NULL && data_len > 0 && signature != NULL,
                        ESP_ERR_INVALID_ARG, TAG, "invalid raw sign arguments");
    ESP_RETURN_ON_ERROR(device_credentials_init(), TAG, "credentials unavailable");

    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(s_private_key);
    ESP_RETURN_ON_FALSE(ec != NULL, ESP_ERR_NOT_SUPPORTED, TAG, "private key is not EC");

    uint8_t hash[32];
    if (mbedtls_sha256(data, data_len, hash, 0) != 0) return ESP_FAIL;

    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = mbedtls_ecdsa_sign(&ec->MBEDTLS_PRIVATE(grp),
                                 &r,
                                 &s,
                                 &ec->MBEDTLS_PRIVATE(d),
                                 hash,
                                 sizeof(hash),
                                 esp_rng,
                                 NULL);
    if (ret == 0) ret = mbedtls_mpi_write_binary(&r, signature, 32);
    if (ret == 0) ret = mbedtls_mpi_write_binary(&s, signature + 32, 32);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    if (ret != 0) {
        ESP_LOGE(TAG, "raw ECDSA signature failed: -0x%04x", (unsigned)-ret);
        memset(signature, 0, DEVICE_CREDENTIAL_SIGNATURE_RAW_LEN);
        return ESP_FAIL;
    }
    return ESP_OK;
}

const char *device_credentials_get_root_ca_pem(size_t *length)
{
    if (length != NULL) *length = (size_t)(root_ca_cert_pem_end - root_ca_cert_pem_start);
    return root_ca_cert_pem_start;
}

const char *device_credentials_get_ota_server_cert_pem(size_t *length)
{
    if (length != NULL) *length = (size_t)(ota_server_cert_pem_end - ota_server_cert_pem_start);
    return ota_server_cert_pem_start;
}
