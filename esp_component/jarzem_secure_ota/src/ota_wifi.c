#include "ota_wifi.h"

#include <stdlib.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_event.h"
#include "esp_check.h"
#include "esp_coexist.h"
#include "esp_ieee802154.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_phy_init.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "nvs.h"

#define OTA_WIFI_CONNECTED_BIT BIT0
#define OTA_WIFI_FAIL_BIT BIT1
#define OTA_WIFI_SCAN_START_BIT BIT2
#define OTA_WIFI_MAX_RETRIES 8
#define OTA_WIFI_TIMEOUT_MS 45000
#define OTA_WIFI_SCAN_START_TIMEOUT_MS 5000
#define OTA_WIFI_MAX_SCAN_RECORDS 32

static const char *TAG = "ota_wifi";
static EventGroupHandle_t s_wifi_events;
static esp_netif_t *s_wifi_netif;
static esp_event_handler_instance_t s_wifi_any_id_handler;
static esp_event_handler_instance_t s_ip_got_ip_handler;
static int s_retry_count;
static bool s_started;
static bool s_disconnect_requested;
static bool s_coex_prepared;
static bool s_i154_quieted;
static bool s_i154_disabled_for_wifi;
static wifi_ap_record_t s_scan_records[OTA_WIFI_MAX_SCAN_RECORDS];

static const char *i154_state_name(esp_ieee802154_state_t state)
{
    switch (state) {
        case ESP_IEEE802154_RADIO_DISABLE: return "DISABLE";
        case ESP_IEEE802154_RADIO_IDLE: return "IDLE";
        case ESP_IEEE802154_RADIO_SLEEP: return "SLEEP";
        case ESP_IEEE802154_RADIO_RECEIVE: return "RECEIVE";
        case ESP_IEEE802154_RADIO_TRANSMIT: return "TRANSMIT";
        default: return "UNKNOWN";
    }
}

static void log_i154_state(const char *prefix)
{
    ESP_LOGI(TAG, "%s IEEE802.15.4 state=%s(%d) channel=%u rx_when_idle=%d",
             prefix, i154_state_name(esp_ieee802154_get_state()), esp_ieee802154_get_state(),
             esp_ieee802154_get_channel(), esp_ieee802154_get_rx_when_idle());
}

static void ota_wifi_prepare_radio_for_wifi(const char *context)
{
#if CONFIG_ESP_COEX_SW_COEXIST_ENABLE && CONFIG_SOC_IEEE802154_SUPPORTED
    const esp_ieee802154_state_t state = esp_ieee802154_get_state();
    s_i154_quieted = false;
    s_i154_disabled_for_wifi = false;
    ESP_LOGW(TAG, "%s: preparing shared ESP32-C6 RF for WiFi", context);
    log_i154_state("before WiFi:");
    if (state == ESP_IEEE802154_RADIO_DISABLE) return;
    esp_err_t err = esp_coex_wifi_i154_enable();
    ESP_LOGI(TAG, "esp_coex_wifi_i154_enable -> %s", esp_err_to_name(err));
    esp_coex_ieee802154_txrx_pti_set(IEEE802154_LOW);
    esp_coex_ieee802154_ack_pti_set(IEEE802154_LOW);
    (void)esp_ieee802154_set_rx_when_idle(false);
    (void)esp_ieee802154_sleep();
    vTaskDelay(pdMS_TO_TICKS(50));
    if (esp_ieee802154_get_state() != ESP_IEEE802154_RADIO_DISABLE) {
        err = esp_ieee802154_disable();
        s_i154_disabled_for_wifi = err == ESP_OK;
    }
    esp_coex_ieee802154_status_disable();
    s_i154_quieted = true;
#else
    (void)context;
#endif
}

static void ota_wifi_restore_radio_after_wifi(const char *context)
{
#if CONFIG_ESP_COEX_SW_COEXIST_ENABLE && CONFIG_SOC_IEEE802154_SUPPORTED
    if (!s_i154_quieted) return;
    ESP_LOGW(TAG, "%s: restoring IEEE802.15.4 after WiFi", context);
    esp_coex_ieee802154_status_enable();
    esp_coex_ieee802154_txrx_pti_set(IEEE802154_LOW);
    esp_coex_ieee802154_ack_pti_set(IEEE802154_HIGH);
    if (s_i154_disabled_for_wifi) {
        (void)esp_ieee802154_enable();
        s_i154_disabled_for_wifi = false;
    }
    (void)esp_ieee802154_set_rx_when_idle(true);
    s_i154_quieted = false;
#else
    (void)context;
#endif
}

static const char *authmode_name(wifi_auth_mode_t authmode)
{
    switch (authmode) {
        case WIFI_AUTH_OPEN: return "open";
        case WIFI_AUTH_WPA_PSK: return "wpa";
        case WIFI_AUTH_WPA2_PSK: return "wpa2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "wpa/wpa2";
        case WIFI_AUTH_WPA3_PSK: return "wpa3";
        case WIFI_AUTH_WPA2_WPA3_PSK: return "wpa2/wpa3";
        default: return "other";
    }
}

static const char *disconnect_reason_name(uint8_t reason)
{
    switch (reason) {
        case WIFI_REASON_AUTH_EXPIRE: return "AUTH_EXPIRE";
        case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT: return "4WAY_HANDSHAKE_TIMEOUT";
        case WIFI_REASON_HANDSHAKE_TIMEOUT: return "HANDSHAKE_TIMEOUT";
        case WIFI_REASON_NO_AP_FOUND: return "NO_AP_FOUND";
        case WIFI_REASON_AUTH_FAIL: return "AUTH_FAIL";
        case WIFI_REASON_ASSOC_FAIL: return "ASSOC_FAIL";
        case WIFI_REASON_CONNECTION_FAIL: return "CONNECTION_FAIL";
        default: return "OTHER";
    }
}

static esp_err_t reset_persistent_wifi_rf_state(void)
{
    nvs_handle_t net80211 = 0;
    esp_err_t err = nvs_open("nvs.net80211", NVS_READWRITE, &net80211);
    if (err == ESP_OK) {
        err = nvs_erase_all(net80211);
        if (err == ESP_OK) err = nvs_commit(net80211);
        nvs_close(net80211);
    } else if (err == ESP_ERR_NVS_NOT_FOUND) {
        err = ESP_OK;
    }
    esp_err_t phy_err = esp_phy_erase_cal_data_in_nvs();
    if (phy_err == ESP_ERR_NVS_NOT_FOUND) phy_err = ESP_OK;
    return err != ESP_OK ? err : phy_err;
}

static esp_err_t configure_wifi_rf(void)
{
    wifi_country_t country = {.cc = "CZ", .schan = 1, .nchan = 13, .max_tx_power = 78, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    ESP_RETURN_ON_ERROR(esp_wifi_set_storage(WIFI_STORAGE_RAM), TAG, "WiFi storage failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "WiFi STA mode failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_country(&country), TAG, "WiFi country failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N), TAG, "WiFi protocol failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT20), TAG, "WiFi bandwidth failed");
    return ESP_OK;
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    (void)arg;
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *event = (const wifi_event_sta_disconnected_t *)event_data;
        const uint8_t reason = event != NULL ? event->reason : 0;
        ESP_LOGW(TAG, "WiFi disconnected reason=%u %s", reason, disconnect_reason_name(reason));
        if (s_disconnect_requested) return;
        if (s_retry_count < OTA_WIFI_MAX_RETRIES) {
            ++s_retry_count;
            if (esp_wifi_connect() != ESP_OK && s_wifi_events != NULL) xEventGroupSetBits(s_wifi_events, OTA_WIFI_FAIL_BIT);
        } else if (s_wifi_events != NULL) {
            xEventGroupSetBits(s_wifi_events, OTA_WIFI_FAIL_BIT);
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        s_retry_count = 0;
        if (s_wifi_events != NULL) xEventGroupSetBits(s_wifi_events, OTA_WIFI_CONNECTED_BIT);
    }
}

static bool choose_target_from_scan(const char *ssid, uint16_t count, wifi_ap_record_t *selected)
{
    if (count == 0) return false;
    memset(s_scan_records, 0, sizeof(s_scan_records));
    uint16_t returned = count > OTA_WIFI_MAX_SCAN_RECORDS ? OTA_WIFI_MAX_SCAN_RECORDS : count;
    if (esp_wifi_scan_get_ap_records(&returned, s_scan_records) != ESP_OK) return false;
    bool found = false;
    for (uint16_t i = 0; i < returned; ++i) {
        if (strcmp((const char *)s_scan_records[i].ssid, ssid) != 0) continue;
        if (!found || s_scan_records[i].rssi > selected->rssi) {
            *selected = s_scan_records[i];
            found = true;
        }
    }
    return found;
}

static esp_err_t select_target_ap(const char *ssid, wifi_ap_record_t *selected)
{
    memset(selected, 0, sizeof(*selected));
    wifi_scan_config_t scan = {.ssid = NULL, .bssid = NULL, .channel = 0, .show_hidden = true, .scan_type = WIFI_SCAN_TYPE_ACTIVE};
    scan.scan_time.active.min = 120;
    scan.scan_time.active.max = 1500;
    ESP_RETURN_ON_ERROR(esp_wifi_scan_start(&scan, true), TAG, "WiFi scan failed");
    uint16_t count = 0;
    ESP_RETURN_ON_ERROR(esp_wifi_scan_get_ap_num(&count), TAG, "WiFi scan count failed");
    if (!choose_target_from_scan(ssid, count, selected)) return ESP_ERR_NOT_FOUND;
    ESP_LOGI(TAG, "selected AP ssid='%s' channel=%u rssi=%d auth=%s", selected->ssid, selected->primary, selected->rssi, authmode_name(selected->authmode));
    return ESP_OK;
}

esp_err_t ota_wifi_connect(const char *ssid, const char *password)
{
    if (ssid == NULL || ssid[0] == '\0') return ESP_ERR_INVALID_STATE;
    ota_wifi_prepare_radio_for_wifi("connect");
    s_coex_prepared = true;
    esp_err_t err = esp_netif_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return err;
    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return err;
    s_wifi_events = xEventGroupCreate();
    if (s_wifi_events == NULL) return ESP_ERR_NO_MEM;
    s_wifi_netif = esp_netif_create_default_wifi_sta();
    if (s_wifi_netif == NULL) return ESP_ERR_NO_MEM;
    wifi_init_config_t init_config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_RETURN_ON_ERROR(reset_persistent_wifi_rf_state(), TAG, "reset persistent WiFi/RF state failed");
    ESP_RETURN_ON_ERROR(esp_wifi_init(&init_config), TAG, "esp_wifi_init failed");
    ESP_RETURN_ON_ERROR(configure_wifi_rf(), TAG, "configure WiFi RF failed");
    ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, &s_wifi_any_id_handler), TAG, "register WIFI_EVENT failed");
    ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL, &s_ip_got_ip_handler), TAG, "register IP_EVENT failed");
    s_retry_count = 0;
    s_disconnect_requested = false;
    ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "esp_wifi_start failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_ps(WIFI_PS_NONE), TAG, "esp_wifi_set_ps failed");
    (void)esp_wifi_set_max_tx_power(78);
    s_started = true;

    wifi_ap_record_t selected = {0};
    ESP_RETURN_ON_ERROR(select_target_ap(ssid, &selected), TAG, "target WiFi AP not found");
    wifi_config_t cfg = {0};
    strlcpy((char *)cfg.sta.ssid, ssid, sizeof(cfg.sta.ssid));
    if (password != NULL) strlcpy((char *)cfg.sta.password, password, sizeof(cfg.sta.password));
    memcpy(cfg.sta.bssid, selected.bssid, sizeof(selected.bssid));
    cfg.sta.bssid_set = true;
    cfg.sta.channel = selected.primary;
    cfg.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    cfg.sta.threshold.authmode = WIFI_AUTH_WPA_PSK;
    cfg.sta.sae_pwe_h2e = WPA3_SAE_PWE_UNSPECIFIED;
    cfg.sta.failure_retry_cnt = 1;
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &cfg), TAG, "esp_wifi_set_config failed");
    ESP_RETURN_ON_ERROR(esp_wifi_connect(), TAG, "esp_wifi_connect failed");

    EventBits_t bits = xEventGroupWaitBits(s_wifi_events, OTA_WIFI_CONNECTED_BIT | OTA_WIFI_FAIL_BIT, pdFALSE, pdFALSE, pdMS_TO_TICKS(OTA_WIFI_TIMEOUT_MS));
    return (bits & OTA_WIFI_CONNECTED_BIT) != 0 ? ESP_OK : ESP_ERR_TIMEOUT;
}

esp_err_t ota_wifi_scan_log(const char *target_ssid)
{
    (void)target_ssid;
    return ESP_ERR_NOT_SUPPORTED;
}

void ota_wifi_disconnect(void)
{
    if (s_started) {
        s_disconnect_requested = true;
        (void)esp_wifi_disconnect();
        (void)esp_wifi_stop();
    }
    if (s_wifi_any_id_handler != NULL) {
        (void)esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, s_wifi_any_id_handler);
        s_wifi_any_id_handler = NULL;
    }
    if (s_ip_got_ip_handler != NULL) {
        (void)esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, s_ip_got_ip_handler);
        s_ip_got_ip_handler = NULL;
    }
    if (s_started) {
        (void)esp_wifi_deinit();
        s_started = false;
    }
    if (s_wifi_netif != NULL) {
        esp_netif_destroy_default_wifi(s_wifi_netif);
        s_wifi_netif = NULL;
    }
    if (s_wifi_events != NULL) {
        vEventGroupDelete(s_wifi_events);
        s_wifi_events = NULL;
    }
    if (s_coex_prepared) {
        ota_wifi_restore_radio_after_wifi("disconnect");
        s_coex_prepared = false;
    }
    s_disconnect_requested = false;
}
