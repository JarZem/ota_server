#include "device_credentials.h"

#include <string.h>

#include "esp_check.h"
#include "esp_log.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/private_access.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"

static const char *TAG = "device_cred_verify";

esp_err_t device_credentials_verify_ota_signature_raw64(
    const uint8_t *data, size_t data_len,
    const uint8_t signature[DEVICE_CREDENTIAL_SIGNATURE_RAW_LEN])
{
    ESP_RETURN_ON_FALSE(data != NULL && data_len > 0 && signature != NULL,
                        ESP_ERR_INVALID_ARG, TAG, "invalid verify arguments");
    ESP_RETURN_ON_ERROR(device_credentials_verify_ota_server_certificate(), TAG,
                        "OTA server certificate is not trusted");

    size_t cert_len = 0;
    const char *cert_pem = device_credentials_get_ota_server_cert_pem(&cert_len);
    ESP_RETURN_ON_FALSE(cert_pem != NULL && cert_len > 0,
                        ESP_ERR_INVALID_STATE, TAG, "OTA server certificate missing");

    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int ret = mbedtls_x509_crt_parse(&cert, (const unsigned char *)cert_pem, cert_len);
    if (ret != 0 || !mbedtls_pk_can_do(&cert.pk, MBEDTLS_PK_ECKEY)) {
        mbedtls_x509_crt_free(&cert);
        return ESP_FAIL;
    }

    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(cert.pk);
    uint8_t hash[32];
    if (mbedtls_sha256(data, data_len, hash, 0) != 0) {
        mbedtls_x509_crt_free(&cert);
        return ESP_FAIL;
    }

    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    ret = mbedtls_mpi_read_binary(&r, signature, 32);
    if (ret == 0) ret = mbedtls_mpi_read_binary(&s, signature + 32, 32);
    if (ret == 0) {
        ret = mbedtls_ecdsa_verify(&ec->MBEDTLS_PRIVATE(grp), hash, sizeof(hash),
                                   &ec->MBEDTLS_PRIVATE(Q), &r, &s);
    }
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_x509_crt_free(&cert);
    memset(hash, 0, sizeof(hash));

    if (ret != 0) {
        ESP_LOGE(TAG, "OTA ECDSA signature verification failed: -0x%04x", (unsigned)-ret);
        return ESP_ERR_INVALID_CRC;
    }
    return ESP_OK;
}
