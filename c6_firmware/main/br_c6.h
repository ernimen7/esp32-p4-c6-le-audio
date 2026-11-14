/*
 * Cyberdeck Soft-BR: ESP32-C6 adapter (libble_app.a, ESP-IDF 5.5.5) for the Bluetooth Classic
 * Basic Rate (1 Msps GFSK) baseband engine from br_ll/.
 *
 * Architecture: docs/bt-classic-soft-br.md.
 * Runs inside the controller's LL task via a static ble_npl_event (zero extra libble_app.a hooks,
 * zero BLE connection/buffer pool consumption, verify_hooks.py RESULT: PASS).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "sdkconfig.h"

#include "br_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- API for slave_bt.c ---- */
int br_c6_init(void);
void br_c6_deinit(void);
/* H4 packet from host (h4[0] = type). Returns true if consumed exclusively by Soft-BR. */
bool br_c6_h2c(const uint8_t *h4, uint16_t len);
/* H4 packet from BLE controller to host. Returns true if consumed. */
bool br_c6_c2h(uint8_t *h4, uint16_t len);

/* Implemented in slave_bt.c */
int slave_bt_send_to_host(const uint8_t *h4, uint16_t len);

/* ---- Internal adapter interface (LL task only) ---- */
bool br_c6_on(void);
br_engine_t *br_c6_engine_ll(void);
void br_c6_live_mark(bool live);

/* br_c6_radio.c */
int br_c6_radio_init(void);
void br_c6_radio_reset(void);
int br_c6_schedule_tx(void *ctx, const br_radio_tx_req_t *req);
int br_c6_schedule_rx(void *ctx, const br_radio_rx_req_t *req);
int br_c6_schedule_tx_rx(void *ctx, const br_radio_tx_req_t *tx_req, const br_radio_rx_req_t *rx_req);
void br_c6_cancel_all(void *ctx);
void br_c6_radio_caps(void *ctx, br_radio_caps_t *out);
void br_c6_set_gauss_bt05(void *ctx, bool enable);
uint32_t br_c6_now_us(void *ctx);
/* Collects the RX slots whose scheduled end has passed and reports them to the engine: the controller does not
 * report the end of a raw RX item by itself. LL task only; br_c6_core.c calls it on every wake. */
void br_c6_radio_service(void);

/* br_c6_core.c: wakes the LL task after delay_us for br_c6_radio_service (replaces an earlier wake). LL task only. */
void br_c6_rx_timer_arm(uint32_t delay_us);

/* How an RX schedule item is filled in (br_c6_radio.c, insert_rx_slot). Only the first has run under the engine;
 * the bench probes of the self-test image compare all four on live packets. */
typedef enum {
	BR_RX_RECIPE_STOCK = 0,         /* no RX window in the link state, item word 7 = 0x000F0000 | sync window */
	BR_RX_RECIPE_WINDOW_SHORT_ITEM, /* RX window in the link state, word 7 = 255, item ends 1 tick after its start */
	BR_RX_RECIPE_WINDOW,            /* RX window in the link state, word 7 = 255, item ends with the window */
	BR_RX_RECIPE_WORD7,             /* no RX window, word 7 = 255, item ends with the window */
	BR_RX_RECIPE_COUNT
} br_c6_rx_recipe_t;
/* The recipe for the engine's RX slots from now on. LL task only. */
void br_c6_radio_set_rx_recipe(uint8_t recipe);
/* Slots that wait for an ID packet: with the short limit on the packet length (true, the default) or without it,
 * waiting for the baseband to finish the bytes the sync word asks for. LL task only; bench comparison. */
void br_c6_radio_set_id_rx_limit(bool limit);

/* Where the LL task is inside the adapter; kept across a chip reset. */
enum {
	BR_AT_IDLE = 0,     /* outside the adapter */
	BR_AT_ADAPTER,      /* in br_c6_radio.c, outside the calls below */
	BR_AT_SCHED_INSERT, /* in r_ble_lll_sched_insert */
	BR_AT_SCHED_DELETE, /* in r_ble_lll_sched_delete_by_sm_num_and_type */
	BR_AT_PHY_DISABLE,  /* in r_ble_phy_disable */
	BR_AT_ENGINE,       /* in the engine's TX/RX completion handler */
};
typedef struct {
	uint32_t magic;
	uint32_t ll_tick;      /* controller clock at the last br_c6_radio_service pass */
	uint32_t esp_us;       /* esp_timer at the same moment (low 32 bits) */
	uint32_t service_runs;
	uint32_t tx_done;
	uint8_t  where;        /* BR_AT_* */
} br_c6_last_t;
/* The record the previous run left (false: none, or the reset did not keep the memory). */
bool br_c6_radio_prev_last(br_c6_last_t *out);
/* The same record straight from the kept memory, before br_c6_radio_init has taken it. */
bool br_c6_radio_kept_last(br_c6_last_t *out);

/* Radio adapter counters (LL task): scheduler inserts, executed slots and the last captured RX for bench tests. */
typedef struct {
	uint32_t insert_ok;
	uint32_t insert_fail;
	uint32_t insert_late;  /* items not given to the scheduler: their start was too close or had passed */
	uint32_t tx_done;
	uint32_t rx_done;
	uint32_t rx_captured;  /* RX slots with bytes received after the access address */
	uint32_t skipped;      /* slots the scheduler skipped or pre-empted */
	uint32_t cap_seq;      /* bumps on every capture below */
	int8_t   cap_rssi;
	uint8_t  cap_len;
	uint8_t  cap_hdr;
	uint8_t  cap_chan;
	uint8_t  cap_raw[16];
	int32_t  cap_late_us;  /* its time stamp minus the slot boundary the engine asked for */
	uint32_t rx_collected; /* RX slots taken back by br_c6_radio_service after their end */
	uint32_t rx_overrun;   /* of those: still on the air 600 us past the end, radio stopped */
	uint32_t retired;      /* slots given up for good (the baseband kept pointing at them) */
	uint32_t service_runs; /* br_c6_radio_service passes */
	uint32_t rx_not_due;   /* of those: looks at an RX slot that could not be taken back yet */
	uint32_t rx_timer_arms;
	uint32_t rx_stamp_only; /* RX slots with a reception time stamp but no bytes after the access address */
	uint32_t rx_linked;    /* looks at an ended RX slot whose item the controller still had in its queue */
	uint32_t slot_linked;  /* free slots passed over for the same reason when a new item was built */
} br_c6_radio_stats_t;
void br_c6_radio_get_stats(br_c6_radio_stats_t *out);
/* Times an executed Soft-BR item was not handed back to the controller's recycle pass because the baseband still
 * pointed at it (br_c6_radio.c, r_ble_lll_sched_pop_executed_sch). LL task. */
uint32_t br_c6_radio_pop_held(void);

#if CONFIG_CYBERDECK_BR_SELFTEST
/* Bench probes of the raw schedule items (self-test image only, LL task). */
typedef struct {
	uint8_t  idx;
	bool     is_tx;
	bool     probe;
	bool     hw_current; /* the baseband's state register points at this slot's item */
	uint32_t late_us;    /* time past the slot's scheduled end */
	uint32_t sch0;       /* schedule item word 0 (next item, flags) */
	uint32_t sch_flags;  /* schedule item bytes 52..55 (list bookkeeping) */
	uint32_t sch_off;    /* the slot's schedule item, as the 20-bit offset the baseband uses */
	uint32_t hw_cur;
	uint32_t hw_state;
} br_c6_stuck_t;
/* First busy slot that is 20 ms or more past its scheduled end: br_c6_radio_service did not take it back. */
bool br_c6_st_stuck(br_c6_stuck_t *out);
/* Step 1: collect an item the baseband has finished, or ask the scheduler to drop one still running.
 * Step 2: radio stop, the slot is retired. Returns true when the slot is free again. */
bool br_c6_st_force(uint8_t idx, uint8_t step, uint16_t *deleted);
/* A lone RX item 3 ms + start_in_us from now, built with the given br_c6_rx_recipe_t; the engine is not told about
 * it, its result waits for br_c6_st_probe_pop. 0 = queued. */
int br_c6_st_lone_rx(uint8_t probe_no, uint8_t recipe, uint8_t chan_1mhz, uint32_t access_addr, uint16_t dur_us,
		uint32_t start_in_us, bool id_only);
typedef struct {
	uint8_t  probe;
	uint8_t  recipe;
	bool     held;     /* the baseband still ran the item 600 us past its end: the radio was stopped */
	bool     skipped;  /* the scheduler never ran it, or it was stopped */
	uint32_t status;   /* RX buffer +12 after the window (0x00FFFFFF before it) */
	uint32_t stamp;    /* RX buffer +16 after the window (0 before it) */
	uint32_t data[2];  /* RX buffer +28 .. +35: the eight bytes after the access address (0 before the window) */
} br_c6_probe_t;
/* Oldest probe result not read yet. */
bool br_c6_st_probe_pop(br_c6_probe_t *out);
#endif

#ifdef __cplusplus
}
#endif
