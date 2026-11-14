/*
 * Soft-BR Master Link Controller Engine (br_engine).
 *
 * Drives Inquiry, Page, Master Page Response, New Connection Poll, and Active ACL (DM1/DH1/DH3 + ARQ + E0 + AFH),
 * bridging HCI Classic + Vendor 0xFC31 ('BRC6') to the ESP32-P4 host.
 */
#pragma once

#include "br_air.h"
#include "br_crypto.h"
#include "br_hop.h"
#include "br_platform.h"
#include "br_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BR_MAX_INQ_CACHE    24u
#define BR_LMP_TX_QUEUE     8u
#define BR_ACL_TX_CREDITS   12u
#define BR_ACL_SDU_MAX      672u
#define BR_ACL_RX_REASM_MAX 1024u

typedef enum {
	BR_STATE_IDLE = 0,
	BR_STATE_INQUIRY,
	BR_STATE_PAGE,
	BR_STATE_PAGE_MASTER_RSP,
	BR_STATE_NEW_CONN_POLL,
	BR_STATE_CONNECTED,
} br_state_t;

typedef struct {
	uint32_t slots_tx;
	uint32_t slots_rx;
	uint32_t slots_skipped;
	uint32_t rx_sync_ok;
	uint32_t rx_hec_ok;
	uint32_t rx_hec_err;
	uint32_t rx_crc_ok;
	uint32_t rx_crc_err;
	uint32_t tx_acks;
	uint32_t tx_naks;
	uint32_t tx_retrans;
	uint32_t lmp_tx_cnt;
	uint32_t lmp_rx_cnt;
	uint32_t acl_sdu_tx;
	uint32_t acl_sdu_rx;
	uint32_t pairs_lost;        /* TX+RX pairs whose RX report never came and the timer gave them up */
} br_diag_stats_t;

typedef struct {
	br_tx_mode_t tx_mode;
	bool         gauss_bt05;
	uint8_t      dh3_max_bytes;     /* 27..183 (default 168; <=27 forces DH1-only) */
	uint8_t      poll_interval_slots; /* Keepalive POLL spacing in slots (default 24 = 15 ms) */
	bool         prefer_fec_dm;     /* Force DM1/DM3 2/3-FEC when link has high NAK rate */
	bool         id_ends_with_sync; /* ID packets end with the sync word (br_air_build_id_tx); bench comparison */
} br_knobs_t;

typedef struct br_engine br_engine_t;

/* Allocate/initialize inside caller-provided storage (zero heap inside engine). */
size_t br_engine_storage_size(void);
br_engine_t *br_engine_init(void *storage, size_t storage_bytes,
		const br_platform_ops_t *ops, const uint8_t seed_mac[6]);
void br_engine_reset(br_engine_t *eng);

/* Radio callbacks (invoked from LL task / simulator event loop when scheduled slots finish). */
void br_engine_on_tx_done(br_engine_t *eng, uint32_t slot_tag, bool skipped);
void br_engine_on_rx_done(br_engine_t *eng, uint32_t slot_tag, const br_radio_rx_ind_t *ind);
void br_engine_on_timer(br_engine_t *eng);

/* Host-to-Controller H4 filter:
 * Returns true if `h4[0..len-1]` belongs to Soft-BR (consumed by br_engine),
 * or false if it belongs to stock BLE / CIS and must be passed through! */
bool br_engine_hci_from_host(br_engine_t *eng, const uint8_t *h4, uint16_t len);

/* Inspection helpers for tests/diagnostics. */
br_state_t br_engine_get_state(const br_engine_t *eng);
void br_engine_get_bdaddr(const br_engine_t *eng, uint8_t out_bdaddr[6]);
uint32_t br_engine_get_clk(const br_engine_t *eng);
void br_engine_get_stats(const br_engine_t *eng, br_diag_stats_t *out);

/* How far the page handshakes got since the engine was created (bench trace; not part of br_diag_stats_t, whose
 * layout the host reads). */
typedef struct {
	uint16_t id_answers; /* ID answers to a page that started the master response */
	uint16_t fhs_tx;     /* FHS packets queued in the master response */
	uint16_t fhs_acks;   /* second ID answers: the device took the FHS */
	uint16_t polls_tx;   /* first POLL packets queued on the new connection */
} br_page_progress_t;
void br_engine_get_page_progress(const br_engine_t *eng, br_page_progress_t *out);

/* How long the engine's packets take to build on this platform, from choosing the slot to handing the pair over
 * (bench trace; not part of br_diag_stats_t). */
typedef struct {
	uint16_t late_pairs;  /* pairs that were ready too late for their slot and were not handed over */
	uint16_t longest_us;  /* longest build so far */
	uint16_t allowance_us; /* what the engine currently allows for a build when it chooses a slot */
} br_build_times_t;
void br_engine_get_build_times(const br_engine_t *eng, br_build_times_t *out);

/* How the engine sends data on the link, and what it has seen on the way there (not part of br_diag_stats_t).
 * BR_VS_GET_DIAG returns the same values after the build times, in this order, 16-bit values low byte first. */
typedef struct {
	uint8_t  tx_max_slots;   /* longest ACL packet the peer allows, in slots */
	uint8_t  tx_size_level;  /* 0 what the peer allows, 1 one slot, 2 one short slot */
	uint8_t  tx_flushes;     /* frames started again in smaller packets */
	uint8_t  size_strikes;   /* times a packet size went unanswered twice while the peer was there */
	uint16_t probes;         /* POLLs sent to find out whether the peer is there at all */
	uint16_t pairs_refused;  /* pairs the platform did not take */
	uint16_t silent_run_max; /* longest run of pairs on the air with no answer (BR_VS_GET_DIAG starts it again) */
} br_link_diag_t;
void br_engine_get_link_diag(const br_engine_t *eng, br_link_diag_t *out);

/* A stretch in which the peer answered nothing: BR_GAP_MIN_PAIRS or more pairs on the air in a row. Sound trial 11
 * had one of 9 to 20 pairs in every second; when they start and how long they last says where they come from. */
#define BR_GAP_MIN_PAIRS 3u
#define BR_GAP_LOG       16u
typedef struct {
	uint32_t start_us; /* the last answer before the gap, on the platform's clock */
	uint16_t len_100us; /* from that answer to the next one, in units of 100 us */
	uint16_t pairs;    /* pairs on the air in between that got no answer */
} br_gap_t;
/* Copies out the gaps recorded since the last call (at most BR_GAP_LOG), forgets them, and returns their number;
 * *missed is the number of further gaps there was no room for. */
uint8_t br_engine_take_gaps(br_engine_t *eng, br_gap_t out[BR_GAP_LOG], uint16_t *missed);

/* Pairs on the air and pairs answered, per RF channel (0..78), since the connection began. Both counts of a
 * channel are halved when one reaches 255, so their ratio stays. */
#define BR_NUM_CHANNELS 79u
void br_engine_get_chan_stats(const br_engine_t *eng, uint8_t tried[BR_NUM_CHANNELS], uint8_t heard[BR_NUM_CHANNELS]);

#ifdef __cplusplus
}
#endif
