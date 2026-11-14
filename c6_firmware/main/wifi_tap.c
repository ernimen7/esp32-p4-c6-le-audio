/*
 * Cyberdeck bench tap of the access point's answers to this station (see wifi_tap.h).
 *
 * The station keeps working in promiscuous mode (ESP-IDF allows both); the filter passes management frames only and
 * the callback keeps the few that are addressed to this station.
 */
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"

#include "wifi_tap.h"

static const char *TAG = "wifi_tap";

#define TAP_KEPT     24u
#define MAC_HDR_LEN  24u
#define FCS_LEN      4u

#define SUBTYPE_ASSOC_RSP   0x01u
#define SUBTYPE_REASSOC_RSP 0x03u
#define SUBTYPE_DISASSOC    0x0Au
#define SUBTYPE_AUTH        0x0Bu
#define SUBTYPE_DEAUTH      0x0Cu

static wifi_tap_rec_t s_rec[TAP_KEPT];
static uint32_t s_wr;
static uint32_t s_rd;
static wifi_tap_stats_t s_stats;
static uint8_t s_mac[6];
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

/* Wi-Fi task. */
static void rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
	if (type != WIFI_PKT_MGMT) {
		return;
	}
	const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
	const uint8_t *f   = p->payload;
	const uint32_t len = p->rx_ctrl.sig_len;
	s_stats.mgmt++;
	if (len < MAC_HDR_LEN + FCS_LEN || (f[0] & 0x0Cu) != 0u) {
		return;
	}
	const uint8_t subtype = (uint8_t)(f[0] >> 4);
	if (subtype != SUBTYPE_ASSOC_RSP && subtype != SUBTYPE_REASSOC_RSP && subtype != SUBTYPE_DISASSOC &&
	    subtype != SUBTYPE_AUTH && subtype != SUBTYPE_DEAUTH) {
		return;
	}
	if (memcmp(f + 4, s_mac, sizeof(s_mac)) != 0) { /* address 1 = receiver */
		return;
	}

	wifi_tap_rec_t r = {
		.subtype = subtype,
		.rssi    = (int8_t)p->rx_ctrl.rssi,
		.chan    = (uint8_t)p->rx_ctrl.channel,
		.len     = (uint16_t)len,
	};
	memcpy(r.bssid, f + 16, sizeof(r.bssid)); /* address 3 */
	const uint32_t body = len - MAC_HDR_LEN - FCS_LEN;
	memcpy(r.body, f + MAC_HDR_LEN, body < sizeof(r.body) ? body : sizeof(r.body));

	portENTER_CRITICAL(&s_mux);
	s_stats.matched++;
	if (s_wr - s_rd >= TAP_KEPT) {
		s_stats.dropped++;
	} else {
		s_rec[s_wr % TAP_KEPT] = r;
		s_wr++;
	}
	portEXIT_CRITICAL(&s_mux);
}

static void on_sta_start(void *arg, esp_event_base_t base, int32_t id, void *data)
{
	(void)arg;
	(void)base;
	(void)id;
	(void)data;
	const wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
	esp_err_t err = esp_wifi_get_mac(WIFI_IF_STA, s_mac);
	if (err == ESP_OK) {
		err = esp_wifi_set_promiscuous_filter(&filter);
	}
	if (err == ESP_OK) {
		err = esp_wifi_set_promiscuous_rx_cb(rx_cb);
	}
	if (err == ESP_OK) {
		err = esp_wifi_set_promiscuous(true);
	}
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "the Wi-Fi tap did not start: %s", esp_err_to_name(err));
		return;
	}
	ESP_LOGW(TAG, "BENCH WI-FI TAP: management frames addressed to this station go to the CIS trace");
}

void wifi_tap_init(void)
{
	const esp_err_t err = esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_START, on_sta_start,
			NULL, NULL);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "no station-start handler for the Wi-Fi tap: %s", esp_err_to_name(err));
	}
}

bool wifi_tap_pop(wifi_tap_rec_t *out)
{
	bool have = false;
	portENTER_CRITICAL(&s_mux);
	if (out != NULL && s_rd != s_wr) {
		*out = s_rec[s_rd % TAP_KEPT];
		s_rd++;
		have = true;
	}
	portEXIT_CRITICAL(&s_mux);
	return have;
}

void wifi_tap_get_stats(wifi_tap_stats_t *out)
{
	if (out != NULL) {
		portENTER_CRITICAL(&s_mux);
		*out = s_stats;
		portEXIT_CRITICAL(&s_mux);
	}
}
