#include "ota_secure_session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device_credentials.h"
#include "device_identity.h"
#include "esp_check.h"
#include "esp_log.h"
#include "mbedtls/base64.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "nvs.h"

#define OTA_SEC_NAMESPACE "ota_sec"
#define OTA_SEC_STATE_KEY "state_v2"
#define OTA_SEC_PROVISION_KEY "prov_v2"
#define OTA_SEC_STATE_MAGIC 0x53543231u
#define OTA_SEC_PROVISION_MAGIC 0x50563231u
#define OTA_SEC_SIG_B64URL_LEN 86
#define OTA_SEC_SIG_B64_PADDED_LEN 88
#define OTA_SEC_RANDOM_B64URL_LEN 11
#define OTA_SEC_GCM_TAG_LEN 16
#define OTA_SEC_GCM_NONCE_LEN 12
#define OTA_SEC_MAX_BINARY_WIRE 96
#define OTA_SEC_MAX_PLAINTEXT 96

static const char *TAG = "ota_secure_session";
static const char KDF_DOMAIN[] = "JaroslavZemanESP|provisioning-v1|";
static const char NONCE_DOMAIN[] = "JaroslavZemanESP|provisioning-nonce-v1|";

typedef struct { uint32_t magic; uint8_t state; uint8_t reserved[3]; uint64_t counter; uint8_t random[OTA_SECURE_RANDOM_LEN]; } state_nvs_t;
typedef struct { uint32_t magic; ota_secure_provisioning_t config; } provision_nvs_t;

static ota_secure_state_t s_state = OTA_SEC_STATE_IDLE;
static uint64_t s_counter;
static uint8_t s_random[OTA_SECURE_RANDOM_LEN];
static uint8_t s_session_key[32];

static void put_u64_be(uint8_t out[8], uint64_t value) { for (unsigned i = 0; i < 8; ++i) out[7 - i] = (uint8_t)(value >> (i * 8)); }
static uint16_t get_u16_be(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }

static esp_err_t hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[32])
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) return ESP_ERR_NOT_SUPPORTED;
    return mbedtls_md_hmac(md, key, key_len, data, data_len, out) == 0 ? ESP_OK : ESP_FAIL;
}

static esp_err_t base64url_encode(const uint8_t *input, size_t input_len, char *out, size_t out_size)
{
    if (input == NULL || out == NULL || out_size < 2) return ESP_ERR_INVALID_ARG;
    size_t written = 0;
    int ret = mbedtls_base64_encode((unsigned char *)out, out_size, &written, input, input_len);
    if (ret != 0 || written >= out_size) return ESP_ERR_INVALID_SIZE;
    for (size_t i = 0; i < written; ++i) { if (out[i] == '+') out[i] = '-'; else if (out[i] == '/') out[i] = '_'; }
    while (written > 0 && out[written - 1] == '=') --written;
    out[written] = '\0';
    return ESP_OK;
}

static esp_err_t base64url_decode_exact(const char *input, size_t input_len, uint8_t *out, size_t out_len)
{
    if (input == NULL || out == NULL || strlen(input) != input_len) return ESP_ERR_INVALID_ARG;
    char padded[160];
    if (input_len + 4 >= sizeof(padded)) return ESP_ERR_INVALID_SIZE;
    memcpy(padded, input, input_len);
    size_t padded_len = input_len;
    for (size_t i = 0; i < padded_len; ++i) {
        if (padded[i] == '-') padded[i] = '+'; else if (padded[i] == '_') padded[i] = '/';
        else if (!((padded[i] >= 'A' && padded[i] <= 'Z') || (padded[i] >= 'a' && padded[i] <= 'z') || (padded[i] >= '0' && padded[i] <= '9'))) return ESP_ERR_INVALID_ARG;
    }
    while ((padded_len % 4) != 0) padded[padded_len++] = '=';
    size_t written = 0;
    const int ret = mbedtls_base64_decode(out, out_len, &written, (const unsigned char *)padded, padded_len);
    memset(padded, 0, sizeof(padded));
    if (ret != 0 || written != out_len) { memset(out, 0, out_len); return ESP_ERR_INVALID_SIZE; }
    return ESP_OK;
}

static esp_err_t base64url_decode_variable(const char *input, uint8_t *out, size_t out_size, size_t *written)
{
    if (input == NULL || out == NULL || written == NULL) return ESP_ERR_INVALID_ARG;
    const size_t input_len = strlen(input);
    if (input_len == 0 || input_len + 4 >= 192) return ESP_ERR_INVALID_SIZE;
    char padded[192]; memcpy(padded, input, input_len); size_t padded_len = input_len;
    for (size_t i = 0; i < padded_len; ++i) {
        if (padded[i] == '-') padded[i] = '+'; else if (padded[i] == '_') padded[i] = '/';
        else if (!((padded[i] >= 'A' && padded[i] <= 'Z') || (padded[i] >= 'a' && padded[i] <= 'z') || (padded[i] >= '0' && padded[i] <= '9'))) return ESP_ERR_INVALID_ARG;
    }
    while ((padded_len % 4) != 0) padded[padded_len++] = '=';
    size_t out_len = 0;
    const int ret = mbedtls_base64_decode(out, out_size, &out_len, (const unsigned char *)padded, padded_len);
    memset(padded, 0, sizeof(padded));
    if (ret != 0) return ESP_ERR_INVALID_SIZE;
    *written = out_len; return ESP_OK;
}

static esp_err_t device_id(char out[DEVICE_ID_MAX_LEN]) { memset(out, 0, DEVICE_ID_MAX_LEN); return device_identity_get_device_id(out); }

static esp_err_t persist_state(void)
{
    state_nvs_t rec = {.magic = OTA_SEC_STATE_MAGIC, .state = (uint8_t)s_state, .counter = s_counter};
    memcpy(rec.random, s_random, sizeof(rec.random));
    nvs_handle_t h; ESP_RETURN_ON_ERROR(nvs_open(OTA_SEC_NAMESPACE, NVS_READWRITE, &h), TAG, "open state NVS failed");
    esp_err_t err = nvs_set_blob(h, OTA_SEC_STATE_KEY, &rec, sizeof(rec)); if (err == ESP_OK) err = nvs_commit(h); nvs_close(h); memset(&rec, 0, sizeof(rec)); return err;
}

static esp_err_t persist_provisioning(const ota_secure_provisioning_t *config)
{
    provision_nvs_t rec = {.magic = OTA_SEC_PROVISION_MAGIC, .config = *config};
    nvs_handle_t h; ESP_RETURN_ON_ERROR(nvs_open(OTA_SEC_NAMESPACE, NVS_READWRITE, &h), TAG, "open provisioning NVS failed");
    esp_err_t err = nvs_set_blob(h, OTA_SEC_PROVISION_KEY, &rec, sizeof(rec)); if (err == ESP_OK) err = nvs_commit(h); nvs_close(h); memset(&rec, 0, sizeof(rec)); return err;
}

static esp_err_t derive_session_key(uint64_t counter, const uint8_t random[OTA_SECURE_RANDOM_LEN], uint8_t out[32])
{
    uint8_t shared[DEVICE_CREDENTIAL_ECDH_SECRET_LEN]; ESP_RETURN_ON_ERROR(device_credentials_derive_ota_ecdh_secret(shared), TAG, "ECDH failed");
    char id[DEVICE_ID_MAX_LEN]; ESP_RETURN_ON_ERROR(device_id(id), TAG, "device id unavailable");
    uint8_t material[128]; size_t pos = 0; const size_t dlen = strlen(KDF_DOMAIN), ilen = strlen(id);
    memcpy(material + pos, KDF_DOMAIN, dlen); pos += dlen; memcpy(material + pos, id, ilen); pos += ilen; put_u64_be(material + pos, counter); pos += 8; memcpy(material + pos, random, OTA_SECURE_RANDOM_LEN); pos += OTA_SECURE_RANDOM_LEN;
    const esp_err_t err = hmac_sha256(shared, sizeof(shared), material, pos, out); memset(shared, 0, sizeof(shared)); memset(material, 0, sizeof(material)); return err;
}

static esp_err_t build_challenge_canonical(uint64_t counter, const uint8_t random[OTA_SECURE_RANDOM_LEN], uint8_t *out, size_t out_size, size_t *out_len)
{
    char id[DEVICE_ID_MAX_LEN]; ESP_RETURN_ON_ERROR(device_id(id), TAG, "device id unavailable");
    int n = snprintf((char *)out, out_size, "A|%s|%llu|", id, (unsigned long long)counter); if (n <= 0 || (size_t)n + OTA_SECURE_RANDOM_LEN > out_size) return ESP_ERR_INVALID_SIZE;
    memcpy(out + n, random, OTA_SECURE_RANDOM_LEN); *out_len = (size_t)n + OTA_SECURE_RANDOM_LEN; return ESP_OK;
}

static esp_err_t build_response_canonical(uint64_t counter, const uint8_t random[OTA_SECURE_RANDOM_LEN], uint8_t *out, size_t out_size, size_t *out_len)
{
    char id[DEVICE_ID_MAX_LEN]; ESP_RETURN_ON_ERROR(device_id(id), TAG, "device id unavailable");
    int n = snprintf((char *)out, out_size, "R|%s|%llu|", id, (unsigned long long)counter); if (n <= 0 || (size_t)n + OTA_SECURE_RANDOM_LEN + 3 > out_size) return ESP_ERR_INVALID_SIZE;
    memcpy(out + n, random, OTA_SECURE_RANDOM_LEN); memcpy(out + n + OTA_SECURE_RANDOM_LEN, "|OK", 3); *out_len = (size_t)n + OTA_SECURE_RANDOM_LEN + 3; return ESP_OK;
}

static esp_err_t build_nonce_aad(uint8_t nonce[OTA_SEC_GCM_NONCE_LEN], uint8_t *aad, size_t aad_size, size_t *aad_len)
{
    char id[DEVICE_ID_MAX_LEN]; ESP_RETURN_ON_ERROR(device_id(id), TAG, "device id unavailable");
    uint8_t material[128]; size_t pos = 0; const size_t ndlen = strlen(NONCE_DOMAIN), ilen = strlen(id);
    memcpy(material + pos, NONCE_DOMAIN, ndlen); pos += ndlen; memcpy(material + pos, id, ilen); pos += ilen; put_u64_be(material + pos, s_counter); pos += 8; memcpy(material + pos, s_random, sizeof(s_random)); pos += sizeof(s_random);
    uint8_t hash[32]; ESP_RETURN_ON_ERROR(hmac_sha256(s_session_key, sizeof(s_session_key), material, pos, hash), TAG, "nonce KDF failed"); memcpy(nonce, hash, OTA_SEC_GCM_NONCE_LEN);
    int n = snprintf((char *)aad, aad_size, "P|%s|%llu|", id, (unsigned long long)s_counter); if (n <= 0 || (size_t)n + sizeof(s_random) > aad_size) return ESP_ERR_INVALID_SIZE;
    memcpy(aad + n, s_random, sizeof(s_random)); *aad_len = (size_t)n + sizeof(s_random); memset(material, 0, sizeof(material)); memset(hash, 0, sizeof(hash)); return ESP_OK;
}

static esp_err_t parse_provision_plaintext(const uint8_t *plain, size_t len, ota_secure_provisioning_t *config)
{
    if (plain == NULL || config == NULL || len < 9) return ESP_ERR_INVALID_ARG; memset(config, 0, sizeof(*config)); size_t pos = 0;
    if (plain[pos++] != 1) return ESP_ERR_NOT_SUPPORTED; config->wifi_security = plain[pos++]; config->wifi_channel = plain[pos++];
    const uint8_t ssid_len = plain[pos++], pass_len = plain[pos++], host_type = plain[pos++], host_len = plain[pos++];
    if (ssid_len == 0 || ssid_len > OTA_SECURE_SSID_MAX_LEN || pass_len > OTA_SECURE_PASSWORD_MAX_LEN || host_len == 0 || host_len > OTA_SECURE_HOST_MAX_LEN) return ESP_ERR_INVALID_SIZE;
    if (config->wifi_channel != 0 && (config->wifi_channel < 1 || config->wifi_channel > 14)) return ESP_ERR_INVALID_ARG;
    if (pos + ssid_len + pass_len + host_len + 2 != len) return ESP_ERR_INVALID_SIZE;
    memcpy(config->ssid, plain + pos, ssid_len); pos += ssid_len; memcpy(config->password, plain + pos, pass_len); pos += pass_len;
    if (host_type == 1) { if (host_len != 4) return ESP_ERR_INVALID_SIZE; snprintf(config->ota_host, sizeof(config->ota_host), "%u.%u.%u.%u", plain[pos], plain[pos + 1], plain[pos + 2], plain[pos + 3]); pos += 4; }
    else if (host_type == 0) { memcpy(config->ota_host, plain + pos, host_len); pos += host_len; } else return ESP_ERR_INVALID_ARG;
    config->ota_port = get_u16_be(plain + pos); return config->ota_port == 0 ? ESP_ERR_INVALID_ARG : ESP_OK;
}

esp_err_t ota_secure_session_init(void)
{
    memset(s_random, 0, sizeof(s_random)); memset(s_session_key, 0, sizeof(s_session_key)); s_counter = 0; s_state = OTA_SEC_STATE_IDLE;
    ota_secure_provisioning_t cfg; if (ota_secure_session_load_provisioning(&cfg) == ESP_OK) s_state = OTA_SEC_STATE_PROVISIONED; memset(&cfg, 0, sizeof(cfg)); ESP_LOGI(TAG, "state=%s", ota_secure_session_state_name()); return ESP_OK;
}

esp_err_t ota_secure_session_begin_hello(uint64_t counter)
{
    if (s_state != OTA_SEC_STATE_IDLE) { ESP_LOGW(TAG, "HELLO state transition rejected current=%s", ota_secure_session_state_name()); return ESP_ERR_INVALID_STATE; }
    if (counter == 0) return ESP_ERR_INVALID_ARG; s_counter = counter; memset(s_random, 0, sizeof(s_random)); memset(s_session_key, 0, sizeof(s_session_key)); s_state = OTA_SEC_STATE_WAIT_CHALLENGE;
    ESP_RETURN_ON_ERROR(persist_state(), TAG, "persist WAIT_CHALLENGE failed"); ESP_LOGI(TAG, "state IDLE -> WAIT_CHALLENGE counter=%llu", (unsigned long long)counter); return ESP_OK;
}

esp_err_t ota_secure_session_accept_challenge(const char *payload, char response_out[OTA_SECURE_ACK_MAX_LEN])
{
    if (payload == NULL || response_out == NULL) return ESP_ERR_INVALID_ARG; response_out[0] = '\0';
    if (s_state != OTA_SEC_STATE_WAIT_CHALLENGE) { ESP_LOGW(TAG, "A replay/out-of-order dropped state=%s", ota_secure_session_state_name()); return ESP_ERR_INVALID_STATE; }
    char work[OTA_SECURE_PROVISION_MAX_WIRE_LEN + 1]; const size_t len = strlen(payload); if (len > OTA_SECURE_PROVISION_MAX_WIRE_LEN) return ESP_ERR_INVALID_SIZE; memcpy(work, payload, len + 1);
    char *save = NULL, *kind = strtok_r(work, "|", &save), *random_text = strtok_r(NULL, "|", &save), *sig_text = strtok_r(NULL, "|", &save);
    if (kind == NULL || strcmp(kind, "A") != 0 || random_text == NULL || sig_text == NULL || strtok_r(NULL, "|", &save) != NULL) return ESP_ERR_INVALID_ARG;
    uint8_t random[OTA_SECURE_RANDOM_LEN], signature[DEVICE_CREDENTIAL_SIGNATURE_RAW_LEN];
    ESP_RETURN_ON_ERROR(base64url_decode_exact(random_text, OTA_SEC_RANDOM_B64URL_LEN, random, sizeof(random)), TAG, "challenge random invalid");
    ESP_RETURN_ON_ERROR(base64url_decode_exact(sig_text, OTA_SEC_SIG_B64URL_LEN, signature, sizeof(signature)), TAG, "challenge signature invalid");
    uint8_t canonical[128]; size_t canonical_len = 0; ESP_RETURN_ON_ERROR(build_challenge_canonical(s_counter, random, canonical, sizeof(canonical), &canonical_len), TAG, "challenge canonical failed");
    ESP_RETURN_ON_ERROR(device_credentials_verify_ota_signature_raw64(canonical, canonical_len, signature), TAG, "challenge OTA signature rejected");
    uint8_t key[32]; ESP_RETURN_ON_ERROR(derive_session_key(s_counter, random, key), TAG, "session key derivation failed");
    size_t response_len = 0; ESP_RETURN_ON_ERROR(build_response_canonical(s_counter, random, canonical, sizeof(canonical), &response_len), TAG, "response canonical failed");
    uint8_t response_sig[DEVICE_CREDENTIAL_SIGNATURE_RAW_LEN]; ESP_RETURN_ON_ERROR(device_credentials_sign_raw64(canonical, response_len, response_sig), TAG, "R signing failed");
    char response_b64[OTA_SEC_SIG_B64_PADDED_LEN + 1]; ESP_RETURN_ON_ERROR(base64url_encode(response_sig, sizeof(response_sig), response_b64, sizeof(response_b64)), TAG, "R encoding failed");
    if (strlen(response_b64) != OTA_SEC_SIG_B64URL_LEN) return ESP_ERR_INVALID_SIZE; const int n = snprintf(response_out, OTA_SECURE_ACK_MAX_LEN, "R|%s", response_b64); if (n <= 0 || n >= OTA_SECURE_ACK_MAX_LEN) return ESP_ERR_INVALID_SIZE;
    memcpy(s_random, random, sizeof(s_random)); memcpy(s_session_key, key, sizeof(s_session_key)); s_state = OTA_SEC_STATE_WAIT_PROVISIONING; esp_err_t persist_err = persist_state();
    if (persist_err != ESP_OK) { s_state = OTA_SEC_STATE_WAIT_CHALLENGE; memset(s_random, 0, sizeof(s_random)); memset(s_session_key, 0, sizeof(s_session_key)); response_out[0] = '\0'; return persist_err; }
    ESP_LOGI(TAG, "A verified: CA=OK ECDSA=OK ECDH=OK; state WAIT_CHALLENGE -> WAIT_PROVISIONING counter=%llu", (unsigned long long)s_counter);
    memset(random, 0, sizeof(random)); memset(signature, 0, sizeof(signature)); memset(response_sig, 0, sizeof(response_sig)); memset(key, 0, sizeof(key)); memset(canonical, 0, sizeof(canonical)); return ESP_OK;
}

esp_err_t ota_secure_session_accept_provisioning(const char *payload)
{
    if (payload == NULL || strncmp(payload, "P|", 2) != 0) return ESP_ERR_INVALID_ARG;
    if (s_state != OTA_SEC_STATE_WAIT_PROVISIONING) { ESP_LOGW(TAG, "P replay/out-of-order dropped state=%s", ota_secure_session_state_name()); return ESP_ERR_INVALID_STATE; }
    if (strlen(payload) > OTA_SECURE_PROVISION_MAX_WIRE_LEN) return ESP_ERR_INVALID_SIZE;
    uint8_t binary[OTA_SEC_MAX_BINARY_WIRE]; size_t binary_len = 0; ESP_RETURN_ON_ERROR(base64url_decode_variable(payload + 2, binary, sizeof(binary), &binary_len), TAG, "P base64 invalid");
    if (binary_len <= OTA_SEC_GCM_TAG_LEN) return ESP_ERR_INVALID_SIZE; const size_t cipher_len = binary_len - OTA_SEC_GCM_TAG_LEN; if (cipher_len > OTA_SEC_MAX_PLAINTEXT) return ESP_ERR_INVALID_SIZE;
    uint8_t nonce[OTA_SEC_GCM_NONCE_LEN], aad[128]; size_t aad_len = 0; ESP_RETURN_ON_ERROR(build_nonce_aad(nonce, aad, sizeof(aad), &aad_len), TAG, "P crypto context failed");
    uint8_t plain[OTA_SEC_MAX_PLAINTEXT]; mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm); int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, s_session_key, 256);
    if (ret == 0) ret = mbedtls_gcm_auth_decrypt(&gcm, cipher_len, nonce, sizeof(nonce), aad, aad_len, binary + cipher_len, OTA_SEC_GCM_TAG_LEN, binary, plain); mbedtls_gcm_free(&gcm);
    if (ret != 0) { ESP_LOGE(TAG, "P rejected: AES-GCM authentication failed"); return ESP_ERR_INVALID_CRC; }
    ota_secure_provisioning_t cfg; esp_err_t err = parse_provision_plaintext(plain, cipher_len, &cfg); if (err == ESP_OK) err = persist_provisioning(&cfg); if (err == ESP_OK) { s_state = OTA_SEC_STATE_PROVISIONED; err = persist_state(); }
    if (err == ESP_OK) { ESP_LOGI(TAG, "P verified+stored; state WAIT_PROVISIONING -> PROVISIONED ssid=%s ota=%s:%u security=%u channel=%u password_len=%u", cfg.ssid, cfg.ota_host, (unsigned)cfg.ota_port, (unsigned)cfg.wifi_security, (unsigned)cfg.wifi_channel, (unsigned)strlen(cfg.password)); memset(s_session_key, 0, sizeof(s_session_key)); memset(s_random, 0, sizeof(s_random)); }
    memset(&cfg, 0, sizeof(cfg)); memset(binary, 0, sizeof(binary)); memset(plain, 0, sizeof(plain)); memset(nonce, 0, sizeof(nonce)); memset(aad, 0, sizeof(aad)); return err;
}

void ota_secure_session_reset_for_retry(void)
{
    if (s_state == OTA_SEC_STATE_PROVISIONED) return; ESP_LOGW(TAG, "session timeout/reset state=%s -> IDLE", ota_secure_session_state_name()); s_state = OTA_SEC_STATE_IDLE; s_counter = 0; memset(s_random, 0, sizeof(s_random)); memset(s_session_key, 0, sizeof(s_session_key)); (void)persist_state();
}

void ota_secure_session_begin_reprovisioning(void)
{
    ESP_LOGI(TAG, "new provisioning requested: current session state=%s -> IDLE; last valid provisioning and OTA CHECK context retained", ota_secure_session_state_name());
    s_state = OTA_SEC_STATE_IDLE; s_counter = 0; memset(s_random, 0, sizeof(s_random)); memset(s_session_key, 0, sizeof(s_session_key)); (void)persist_state();
}

ota_secure_state_t ota_secure_session_state(void) { return s_state; }
const char *ota_secure_session_state_name(void) { switch (s_state) { case OTA_SEC_STATE_IDLE: return "IDLE"; case OTA_SEC_STATE_WAIT_CHALLENGE: return "WAIT_CHALLENGE"; case OTA_SEC_STATE_WAIT_PROVISIONING: return "WAIT_PROVISIONING"; case OTA_SEC_STATE_PROVISIONED: return "PROVISIONED"; default: return "UNKNOWN"; } }
bool ota_secure_session_is_provisioned(void) { return s_state == OTA_SEC_STATE_PROVISIONED; }

esp_err_t ota_secure_session_load_provisioning(ota_secure_provisioning_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG; memset(out, 0, sizeof(*out)); nvs_handle_t h; esp_err_t err = nvs_open(OTA_SEC_NAMESPACE, NVS_READONLY, &h); if (err != ESP_OK) return err;
    provision_nvs_t rec; size_t size = sizeof(rec); err = nvs_get_blob(h, OTA_SEC_PROVISION_KEY, &rec, &size); nvs_close(h);
    if (err != ESP_OK || size != sizeof(rec) || rec.magic != OTA_SEC_PROVISION_MAGIC) { memset(&rec, 0, sizeof(rec)); return err == ESP_OK ? ESP_ERR_INVALID_SIZE : err; }
    *out = rec.config; memset(&rec, 0, sizeof(rec)); return ESP_OK;
}
