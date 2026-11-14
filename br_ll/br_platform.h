/*
 * Soft-BR (Software-Defined Bluetooth Classic Basic Rate, 1 Msps GFSK) platform contract.
 *
 * Zero ESP-IDF dependencies: implemented by either the ESP32-C6 Mode-0 radio adapter
 * (c6_firmware/main/br_c6_*.c) or the discrete-event air simulator (br_ll/sim/).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum raw bytes placed in C6 Mode-0 TX buffer (TXD_PAYLOAD <= 248 bytes) or captured in RX. */
#define BR_RAW_BUF_MAX 255u

typedef enum {
	BR_TX_MODE_IN_PAYLOAD = 0, /* AA=0x55555555, start 64 us early, full SyncWord+Trailer+Hdr+Payload in TXD_PAYLOAD */
	BR_TX_MODE_DIRECT_AA  = 1, /* AA=sw_air[31:0], TXD_HDR=sw_air[39:32], TXD_LEN=N, TXD_PAYLOAD[0..1]=sw_air[55:40] */
} br_tx_mode_t;

/* Single Mode-0 TX slot descriptor handed to the platform radio. */
typedef struct {
	uint32_t anchor_us;             /* Nominal Bluetooth slot boundary (controller us clock); radio subtracts lead if needed */
	uint16_t lead_us;               /* Early air start before anchor_us (64 us for TX_IN_PAYLOAD, 4 us for DIRECT_AA) */
	uint16_t duration_us;           /* Expected air duration for scheduler reservation */
	uint8_t  chan_1mhz;             /* 0..78 -> 2402 + chan_1mhz MHz */
	uint32_t access_addr;           /* 32-bit AA written into ls[12] */
	uint8_t  tx_hdr;                /* Byte 0 of C6 TXD descriptor */
	uint8_t  tx_len;                /* Byte 1 of C6 TXD descriptor (number of payload bytes following) */
	uint8_t  tx_payload[BR_RAW_BUF_MAX];
	bool     crc_preset_set;        /* The modem's 24-bit CRC register starts from crc_preset for this packet */
	uint32_t crc_preset;            /* (false: the adapter's fixed value, the 24 bits after the payload carry nothing) */
	uint32_t slot_tag;              /* Opaque engine tag returned in completion callback */
} br_radio_tx_req_t;

/* Single Mode-0 RX slot descriptor handed to the platform radio. */
typedef struct {
	uint32_t anchor_us;             /* Nominal Bluetooth RX slot boundary (controller us clock) */
	uint16_t rx_sync_win_us;        /* Syncword correlation search window (sch+28 low u16), e.g. 48..96 us */
	uint16_t max_duration_us;       /* Scheduler reservation duration from anchor_us (e.g. 200 us ID, 500 us FHS/ACL) */
	uint8_t  chan_1mhz;             /* 0..78 -> 2402 + chan_1mhz MHz */
	uint32_t access_addr;           /* Low 32 bits of target 64-bit SyncWord (GIAC, DAC, or Master CAC) */
	bool     id_only;               /* True when expecting 68-bit ID packet (Page Slave Response / FHS ACK) */
	uint32_t slot_tag;              /* Opaque engine tag returned in completion callback */
} br_radio_rx_req_t;

/* Result of a scheduled RX slot reported back to the engine. */
typedef struct {
	bool     skipped;               /* True if BLE/Wi-Fi scheduler preempted this slot */
	bool     sync_matched;          /* True if hardware correlated access_addr inside rx_sync_win_us */
	int8_t   rssi_dbm;              /* Measured RSSI in dBm (-127 if unavailable) */
	uint32_t rx_timestamp_us;       /* Controller us clock when syncword matched */
	uint8_t  rx_hdr;                /* Captured C6 RXD byte 0 (for normal packet: sw_air[39:32]) */
	uint8_t  rx_len;                /* Captured C6 RXD byte 1 (for normal packet: sw_air[47:40]) */
	uint16_t raw_len;               /* Number of valid bytes in raw_payload[] */
	const uint8_t *raw_payload;     /* Captured bytes immediately following rx_len on air */
} br_radio_rx_ind_t;

typedef struct {
	uint32_t sched_lead_us;         /* Minimum lead time ahead of now_us() required to insert a slot */
	uint8_t  max_pipelined_slots;   /* Number of concurrent TX/RX slots radio can queue (C6: 4) */
	bool     supports_gauss_scale;  /* True if 1M GFSK h=0.32 filter scaling knob is available */
} br_radio_caps_t;

typedef struct {
	uint8_t  kind;
	uint8_t  code;
	uint16_t arg16;
	uint32_t v[4];
} br_trace_t;

typedef struct {
	void *ctx;
	/* Queue a single TX slot, a single RX slot, or an atomic TX+RX slot pair. 0 = queued, <0 = busy/too late. */
	int (*schedule_tx)(void *ctx, const br_radio_tx_req_t *tx);
	int (*schedule_rx)(void *ctx, const br_radio_rx_req_t *rx);
	int (*schedule_tx_rx)(void *ctx, const br_radio_tx_req_t *tx, const br_radio_rx_req_t *rx);
	void (*cancel_all)(void *ctx);
	void (*radio_caps)(void *ctx, br_radio_caps_t *out);
	void (*set_gauss_bt05)(void *ctx, bool enable);

	/* Deliver an H4 packet (0x04 HCI Event or 0x02 ACL RX) up to ESP32-P4 host. */
	void (*hci_to_host)(void *ctx, const uint8_t *h4, uint16_t len);

	uint32_t (*now_us)(void *ctx);
	void (*random)(void *ctx, uint8_t *buf, uint16_t len);
	void (*timer_start)(void *ctx, uint32_t delay_us);
	void (*timer_stop)(void *ctx);
	void (*log)(void *ctx, int level, const char *msg);
	void (*trace)(void *ctx, const br_trace_t *tr);
} br_platform_ops_t;

#ifdef __cplusplus
}
#endif
