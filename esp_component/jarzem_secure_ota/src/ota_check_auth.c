#include "ota_check_auth.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device_credentials.h"
#include "device_identity.h"
#include "esp_app_desc.h"
#include "esp_check.h"
#include "esp_log.h"
#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "nvs.h"
#include "ota_config.h"
#include "ota_secure_session.h"
#include "storage.h"

#define OTA_SEC_NAMESPACE "ota_sec"
#define OTA_SEC_STATE_KEY "state_v2"
#define OTA_SEC_STATE_MAGIC 0x53543231u
#define OTA_SEC_PROVISIONED_STATE 3u
#define OTA_CHECK_NAMESPACE "ota_check"
#define OTA_CHECK_CONTEXT_KEY "context_v1"
#define OTA_CHECK_GRANT_KEY "grant_v1"
#define OTA_CHECK_GRANT_MAGIC 0x4f434731u
#define OTA_CHECK_RANDOM_LEN 8
#define OTA_CHECK_RANDOM_B64_LEN 11
#define OTA_CHECK_MAC_LEN 16
#define OTA_CHECK_MAC_B64_LEN 22
#define OTA_CHECK_TOKEN_RAW_LEN 12
#define OTA_CHECK_TOKEN_B64_LEN 16
#define OTA_CHECK_MAX_VERSION_LEN 32

static const char *TAG = "ota_check_auth";
static const char KDF_DOMAIN[] = "JaroslavZemanESP|provisioning-v1|";
static const char CHECK_KEY_DOMAIN[] = "JaroslavZemanESP|ota-check-key-v1|";
static const char TOKEN_KEY_DOMAIN[] = "JaroslavZemanESP|ota-download-token-key-v1|";
static const char CHECK_MAC_DOMAIN[] = "JaroslavZemanESP|ota-check-v1|";
static const char TOKEN_DOMAIN[] = "JaroslavZemanESP|ota-download-token-v1|";

typedef struct {
    uint32_t magic;
    uint8_t state;
    uint8_t reserved[3];
    uint64_t counter;
    uint8_t random[OTA_CHECK_RANDOM_LEN];
} ota_secure_state_nvs_t;

typedef struct {
    uint32_t magic;
    uint8_t random[OTA_CHECK_RANDOM_LEN];
} ota_check_grant_nvs_t;

static void put_u64_be(uint8_t out[8], uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) {
        out[7 - i] = (uint8_t)(value >> (i * 8));
    }
}

static esp_err_t hmac_sha256(const uint8_t *key, size_t key_len,
                             const uint8_t *data, size_t data_len,
                             uint8_t out[32])
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    return mbedtls_md_hmac(md, key, key_len, data, data_len, out) == 0 ? ESP_OK : ESP_FAIL;
}

static esp_err_t base64url_decode_exact(const char *input, size_t input_len,
                                        uint8_t *out, size_t out_len)
{
    if (input == NULL || strlen(input) != input_len) {
        return ESP_ERR_INVALID_ARG;
    }

    char padded[64];
    if (input_len + 4 >= sizeof(padded)) {
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(padded, input, input_len);
    size_t padded_len = input_len;

    for (size_t i = 0; i < padded_len; ++i) {
        if (padded[i] == '-') {
            padded[i] = '+';
        } else if (padded[i] == '_') {
            padded[i] = '/';
        } else if (!isalnum((unsigned char)padded[i])) {
            return ESP_ERR_INVALID_ARG;
        }
    }

    while ((padded_len % 4) != 0) {
        padded[padded_len++] = '=';
    }

    size_t written = 0;
    int ret = mbedtls_base64_decode(out, out_len, &written,
                                    (const unsigned char *)padded, padded_len);
    memset(padded, 0, sizeof(padded));
    if (ret != 0 || written != out_len) {
        memset(out, 0, out_len);
        return ESP_ERR_INVALID_SIZE;
    }
    return ESP_OK;
}

static esp_err_t base64url_encode(const uint8_t *input, size_t input_len,
                                  char *out, size_t out_size)
{
    if (input == NULL || out == NULL || out_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    unsigned char padded[64];
    size_t written = 0;
    int ret = mbedtls_base64_encode(padded, sizeof(padded), &written,
                                    input, input_len);
    if (ret != 0 || written >= sizeof(padded)) {
        memset(padded, 0, sizeof(padded));
        return ESP_ERR_INVALID_SIZE;
    }

    while (written > 0 && padded[written - 1] == '=') {
        --written;
    }
    if (written + 1 > out_size) {
        memset(padded, 0, sizeof(padded));
        return ESP_ERR_INVALID_SIZE;
    }

    for (size_t i = 0; i < written; ++i) {
        char ch = (char)padded[i];
        if (ch == '+') {
            ch = '-';
        } else if (ch == '/') {
            ch = '_';
        }
        out[i] = ch;
    }
    out[written] = '\0';
    memset(padded, 0, sizeof(padded));
    return ESP_OK;
}

static bool valid_context(const ota_secure_state_nvs_t *ctx)
{
    return ctx != NULL &&
           ctx->magic == OTA_SEC_STATE_MAGIC &&
           ctx->state == OTA_SEC_PROVISIONED_STATE &&
           ctx->counter > 0;
}

static esp_err_t read_context_blob(const char *ns, const char *key,
                                   ota_secure_state_nvs_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(out, 0, sizeof(*out));
    nvs_handle_t h;
    esp_err_t err = nvs_open(ns, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return err;
    }

    size_t size = sizeof(*out);
    err = nvs_get_blob(h, key, out, &size);
    nvs_close(h);
    if (err != ESP_OK || size != sizeof(*out) || !valid_context(out)) {
        memset(out, 0, sizeof(*out));
        return err == ESP_OK ? ESP_ERR_INVALID_STATE : err;
    }
    return ESP_OK;
}

static esp_err_t persist_context(const ota_secure_state_nvs_t *ctx)
{
    if (!valid_context(ctx)) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t h;
    ESP_RETURN_ON_ERROR(nvs_open(OTA_CHECK_NAMESPACE, NVS_READWRITE, &h),
                        TAG, "open context NVS failed");

    esp_err_t err = nvs_set_blob(h, OTA_CHECK_CONTEXT_KEY, ctx, sizeof(*ctx));
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

esp_err_t ota_check_auth_snapshot_provisioning_context(void)
{
    ota_secure_state_nvs_t ctx;
    ESP_RETURN_ON_ERROR(read_context_blob(OTA_SEC_NAMESPACE, OTA_SEC_STATE_KEY, &ctx),
                        TAG, "successful provisioning context missing");

    esp_err_t err = persist_context(&ctx);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "durable OTA context stored counter=%llu",
                 (unsigned long long)ctx.counter);
    }
    memset(&ctx, 0, sizeof(ctx));
    return err;
}

static esp_err_t load_persisted_context(ota_secure_state_nvs_t *out)
{
    esp_err_t err = read_context_blob(OTA_CHECK_NAMESPACE, OTA_CHECK_CONTEXT_KEY, out);
    if (err == ESP_OK) {
        return ESP_OK;
    }

    err = read_context_blob(OTA_SEC_NAMESPACE, OTA_SEC_STATE_KEY, out);
    if (err != ESP_OK) {
        return err;
    }

    ESP_LOGW(TAG, "OTA durable context missing; recovering it from last provisioning state");
    (void)persist_context(out);
    return ESP_OK;
}

static esp_err_t derive_session_key(const ota_secure_state_nvs_t *ctx, uint8_t out[32])
{
    uint8_t shared[DEVICE_CREDENTIAL_ECDH_SECRET_LEN];
    ESP_RETURN_ON_ERROR(device_credentials_derive_ota_ecdh_secret(shared), TAG, "ECDH failed");

    char device_id[DEVICE_ID_MAX_LEN];
    ESP_RETURN_ON_ERROR(device_identity_get_device_id(device_id), TAG, "device id unavailable");

    uint8_t material[128];
    size_t pos = 0;
    const size_t dlen = strlen(KDF_DOMAIN);
    const size_t idlen = strlen(device_id);
    memcpy(material + pos, KDF_DOMAIN, dlen);
    pos += dlen;
    memcpy(material + pos, device_id, idlen);
    pos += idlen;
    put_u64_be(material + pos, ctx->counter);
    pos += 8;
    memcpy(material + pos, ctx->random, sizeof(ctx->random));
    pos += sizeof(ctx->random);

    esp_err_t err = hmac_sha256(shared, sizeof(shared), material, pos, out);
    memset(shared, 0, sizeof(shared));
    memset(material, 0, sizeof(material));
    return err;
}

static esp_err_t derive_subkey(const uint8_t session_key[32], const char *domain,
                               uint8_t out[32])
{
    return hmac_sha256(session_key, 32, (const uint8_t *)domain, strlen(domain), out);
}

static bool version_is_newer(const char *offered, const char *running)
{
    const char *a = offered;
    const char *b = running;
    bool numeric = true;

    while (*a || *b) {
        char *end_a = NULL;
        char *end_b = NULL;
        unsigned long va = strtoul(a, &end_a, 10);
        unsigned long vb = strtoul(b, &end_b, 10);

        if (end_a == a || end_b == b) {
            numeric = false;
            break;
        }
        if (va != vb) {
            return va > vb;
        }

        a = (*end_a == '.') ? end_a + 1 : end_a;
        b = (*end_b == '.') ? end_b + 1 : end_b;
        if ((*a && !isdigit((unsigned char)*a)) ||
            (*b && !isdigit((unsigned char)*b))) {
            numeric = false;
            break;
        }
    }

    if (numeric) {
        return false;
    }
    return strcmp(offered, running) > 0;
}

static esp_err_t persist_active_grant(const uint8_t random[OTA_CHECK_RANDOM_LEN])
{
    ota_check_grant_nvs_t rec = {.magic = OTA_CHECK_GRANT_MAGIC};
    memcpy(rec.random, random, sizeof(rec.random));

    nvs_handle_t h;
    ESP_RETURN_ON_ERROR(nvs_open(OTA_CHECK_NAMESPACE, NVS_READWRITE, &h),
                        TAG, "open grant NVS failed");

    esp_err_t err = nvs_set_blob(h, OTA_CHECK_GRANT_KEY, &rec, sizeof(rec));
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    memset(&rec, 0, sizeof(rec));
    return err;
}

static esp_err_t load_active_grant(uint8_t random[OTA_CHECK_RANDOM_LEN])
{
    ota_check_grant_nvs_t rec;
    nvs_handle_t h;
    ESP_RETURN_ON_ERROR(nvs_open(OTA_CHECK_NAMESPACE, NVS_READONLY, &h),
                        TAG, "open grant NVS failed");

    size_t size = sizeof(rec);
    esp_err_t err = nvs_get_blob(h, OTA_CHECK_GRANT_KEY, &rec, &size);
    nvs_close(h);
    if (err != ESP_OK || size != sizeof(rec) || rec.magic != OTA_CHECK_GRANT_MAGIC) {
        memset(&rec, 0, sizeof(rec));
        return err == ESP_OK ? ESP_ERR_INVALID_STATE : err;
    }

    memcpy(random, rec.random, OTA_CHECK_RANDOM_LEN);
    memset(&rec, 0, sizeof(rec));
    return ESP_OK;
}

void ota_check_auth_clear_active_grant(void)
{
    nvs_handle_t h;
    if (nvs_open(OTA_CHECK_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        (void)nvs_erase_key(h, OTA_CHECK_GRANT_KEY);
        (void)nvs_commit(h);
        nvs_close(h);
    }
}

esp_err_t ota_check_auth_prepare_request(const char *payload, size_t payload_len,
                                         char *out_request, size_t out_size,
                                         size_t *out_len)
{
    if (payload == NULL || out_request == NULL || out_len == NULL || payload_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (payload_len >= 128) {
        return ESP_ERR_INVALID_SIZE;
    }

    char work[128];
    memcpy(work, payload, payload_len);
    work[payload_len] = '\0';
    char *save = NULL;
    char *kind = strtok_r(work, "|", &save);
    char *version = strtok_r(NULL, "|", &save);
    char *code = strtok_r(NULL, "|", &save);
    char *random_b64 = strtok_r(NULL, "|", &save);
    char *mac_b64 = strtok_r(NULL, "|", &save);

    if (kind == NULL || strcmp(kind, "C") != 0 || version == NULL ||
        code == NULL || random_b64 == NULL || mac_b64 == NULL ||
        strtok_r(NULL, "|", &save) != NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (strlen(version) == 0 || strlen(version) > OTA_CHECK_MAX_VERSION_LEN ||
        strlen(code) != OTA_CONFIG_CODE_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }
    for (size_t i = 0; i < OTA_CONFIG_CODE_LEN; ++i) {
        if (!isalnum((unsigned char)code[i])) {
            return ESP_ERR_INVALID_ARG;
        }
    }

    uint8_t grant_random[OTA_CHECK_RANDOM_LEN];
    uint8_t received_mac[OTA_CHECK_MAC_LEN];
    ESP_RETURN_ON_ERROR(base64url_decode_exact(random_b64, OTA_CHECK_RANDOM_B64_LEN,
                                                grant_random, sizeof(grant_random)),
                        TAG, "CHECK random invalid");
    ESP_RETURN_ON_ERROR(base64url_decode_exact(mac_b64, OTA_CHECK_MAC_B64_LEN,
                                                received_mac, sizeof(received_mac)),
                        TAG, "CHECK MAC invalid");

    ota_secure_state_nvs_t ctx;
    ESP_RETURN_ON_ERROR(load_persisted_context(&ctx), TAG, "provisioning context missing");

    uint8_t session_key[32];
    uint8_t check_key[32];
    uint8_t token_key[32];
    ESP_RETURN_ON_ERROR(derive_session_key(&ctx, session_key), TAG, "session key derivation failed");
    ESP_RETURN_ON_ERROR(derive_subkey(session_key, CHECK_KEY_DOMAIN, check_key), TAG, "check key derivation failed");
    ESP_RETURN_ON_ERROR(derive_subkey(session_key, TOKEN_KEY_DOMAIN, token_key), TAG, "token key derivation failed");

    uint8_t canonical[128];
    size_t pos = 0;
    memcpy(canonical + pos, CHECK_MAC_DOMAIN, strlen(CHECK_MAC_DOMAIN));
    pos += strlen(CHECK_MAC_DOMAIN);
    memcpy(canonical + pos, version, strlen(version));
    pos += strlen(version);
    canonical[pos++] = '|';
    memcpy(canonical + pos, code, strlen(code));
    pos += strlen(code);
    canonical[pos++] = '|';
    memcpy(canonical + pos, grant_random, sizeof(grant_random));
    pos += sizeof(grant_random);

    uint8_t mac[32];
    ESP_RETURN_ON_ERROR(hmac_sha256(check_key, sizeof(check_key), canonical, pos, mac),
                        TAG, "CHECK HMAC failed");
    if (memcmp(mac, received_mac, OTA_CHECK_MAC_LEN) != 0) {
        ESP_LOGE(TAG, "OTA CHECK rejected: MAC mismatch");
        return ESP_ERR_INVALID_CRC;
    }

    const esp_app_desc_t *running = esp_app_get_description();
    if (!version_is_newer(version, running->version)) {
        ESP_LOGI(TAG, "OTA CHECK authenticated but skipped: offered=%s running=%s",
                 version, running->version);
        return ESP_ERR_INVALID_VERSION;
    }

    char device_id[DEVICE_ID_MAX_LEN];
    ESP_RETURN_ON_ERROR(device_identity_get_device_id(device_id), TAG, "device id unavailable");

    pos = 0;
    memcpy(canonical + pos, TOKEN_DOMAIN, strlen(TOKEN_DOMAIN));
    pos += strlen(TOKEN_DOMAIN);
    memcpy(canonical + pos, device_id, strlen(device_id));
    pos += strlen(device_id);
    canonical[pos++] = '|';
    memcpy(canonical + pos, version, strlen(version));
    pos += strlen(version);
    canonical[pos++] = '|';
    memcpy(canonical + pos, code, strlen(code));
    pos += strlen(code);
    canonical[pos++] = '|';
    memcpy(canonical + pos, grant_random, sizeof(grant_random));
    pos += sizeof(grant_random);

    uint8_t token_digest[32];
    ESP_RETURN_ON_ERROR(hmac_sha256(token_key, sizeof(token_key), canonical, pos, token_digest),
                        TAG, "token HMAC failed");

    char token[OTA_CONFIG_MAX_TOKEN_LEN + 1];
    ESP_RETURN_ON_ERROR(base64url_encode(token_digest, OTA_CHECK_TOKEN_RAW_LEN,
                                         token, sizeof(token)),
                        TAG, "token encode failed");
    if (strlen(token) != OTA_CHECK_TOKEN_B64_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }

    ota_secure_provisioning_t provision;
    ESP_RETURN_ON_ERROR(ota_secure_session_load_provisioning(&provision),
                        TAG, "stored provisioning unavailable");

    ota_config_t config = {0};
    strlcpy(config.ssid, provision.ssid, sizeof(config.ssid));
    strlcpy(config.password, provision.password, sizeof(config.password));
    strlcpy(config.host, provision.ota_host, sizeof(config.host));
    strlcpy(config.code, code, sizeof(config.code));
    strlcpy(config.token, token, sizeof(config.token));

    if (!storage_save_ota_config(&config)) {
        return ESP_FAIL;
    }
    ESP_RETURN_ON_ERROR(persist_active_grant(grant_random), TAG, "grant persist failed");

    int n = snprintf(out_request, out_size, "C|%s", token);
    if (n <= 0 || (size_t)n >= out_size) {
        return ESP_ERR_INVALID_SIZE;
    }
    *out_len = (size_t)n;

    ESP_LOGI(TAG, "OTA CHECK accepted offered=%s running=%s code=%s token_len=%u",
             version, running->version, code, (unsigned)strlen(token));

    memset(&ctx, 0, sizeof(ctx));
    memset(session_key, 0, sizeof(session_key));
    memset(check_key, 0, sizeof(check_key));
    memset(token_key, 0, sizeof(token_key));
    memset(mac, 0, sizeof(mac));
    memset(token_digest, 0, sizeof(token_digest));
    memset(&provision, 0, sizeof(provision));
    memset(&config, 0, sizeof(config));
    memset(canonical, 0, sizeof(canonical));
    return ESP_OK;
}

esp_err_t ota_check_auth_build_completion(char out[OTA_CHECK_COMPLETION_MAX_LEN])
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t random[OTA_CHECK_RANDOM_LEN];
    ESP_RETURN_ON_ERROR(load_active_grant(random), TAG, "no active OTA grant");

    char random_b64[OTA_CHECK_RANDOM_B64_LEN + 1];
    ESP_RETURN_ON_ERROR(base64url_encode(random, sizeof(random), random_b64, sizeof(random_b64)),
                        TAG, "completion random encode failed");

    int n = snprintf(out, OTA_CHECK_COMPLETION_MAX_LEN, "F|%s", random_b64);
    memset(random, 0, sizeof(random));
    return (n > 0 && n < OTA_CHECK_COMPLETION_MAX_LEN) ? ESP_OK : ESP_ERR_INVALID_SIZE;
}
