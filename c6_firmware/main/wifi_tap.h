/*
 * Cyberdeck bench tap (guard test image only, CONFIG_CYBERDECK_WIFI_TAP): the management frames an access point
 * sends to this station while it logs in - authentication (with the SAE status code), association response,
 * deauthentication, disassociation.
 *
 * The host only gets a reason code from the Wi-Fi stack (2 = authentication expired covers a wrong password, an
 * access point that never answers and an SAE exchange it refuses). The frames show which of these it is.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
	uint8_t  subtype;  /* 802.11 management subtype: 1/3 (re)association response, 10 disassociation,
	                      11 authentication, 12 deauthentication */
	int8_t   rssi;
	uint8_t  chan;
	uint8_t  bssid[6];
	uint16_t len;      /* frame length as received, with the FCS */
	uint8_t  body[10]; /* first bytes after the 24-byte header, zero-padded */
} wifi_tap_rec_t;

typedef struct {
	uint32_t mgmt;     /* management frames heard: proof that the tap runs */
	uint32_t matched;  /* frames of the listed subtypes addressed to this station */
	uint32_t dropped;  /* matched frames not kept (buffer full) */
} wifi_tap_stats_t;

/* Starts listening at every station start. Call once, after the default event loop exists. */
void wifi_tap_init(void);
/* Oldest record not read yet; false when there is none. Any task. */
bool wifi_tap_pop(wifi_tap_rec_t *out);
void wifi_tap_get_stats(wifi_tap_stats_t *out);
