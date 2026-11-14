/*
 * Unit tests for br_engine HCI coexistence filter, Inquiry/Page state machine, and Vendor 0xFC31 API.
 */
#include "br_engine.h"
#include <stdio.h>
#include <string.h>

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); \
		return 1; \
	} \
} while (0)

typedef struct {
	uint32_t          now;
	br_radio_tx_req_t last_tx;
	br_radio_rx_req_t last_rx;
	bool              has_pair;
	uint16_t          evt_cnt;
	uint8_t           last_evt[260];
	uint16_t          last_evt_len;
	uint32_t          pairs;
	bool              timer_armed;
	uint32_t          timer_at;
	uint32_t          build_us;  /* time that passes between the engine choosing a slot and handing the pair over */
	int32_t           min_slack; /* least time left, at a hand-over, before the scheduler must have the TX item */
} mock_plat_t;

#define MOCK_SCHED_LEAD_US 192u

static int m_sched_tx(void *ctx, const br_radio_tx_req_t *tx)
{
	mock_plat_t *m = (mock_plat_t *)ctx;
	m->last_tx = *tx;
	return 0;
}
static int m_sched_rx(void *ctx, const br_radio_rx_req_t *rx)
{
	mock_plat_t *m = (mock_plat_t *)ctx;
	m->last_rx = *rx;
	return 0;
}
static int m_sched_tx_rx(void *ctx, const br_radio_tx_req_t *tx, const br_radio_rx_req_t *rx)
{
	mock_plat_t *m = (mock_plat_t *)ctx;
	m->last_tx  = *tx;
	m->last_rx  = *rx;
	m->has_pair = true;
	const int32_t slack = (int32_t)(tx->anchor_us - tx->lead_us - MOCK_SCHED_LEAD_US - m->now);
	if (m->pairs == 0u || slack < m->min_slack) {
		m->min_slack = slack;
	}
	m->pairs++;
	return 0;
}
static void m_cancel(void *ctx) { ((mock_plat_t *)ctx)->has_pair = false; }
static void m_caps(void *ctx, br_radio_caps_t *out)
{
	/* The engine asks for the lead while it chooses the slot: what it does after that takes build_us. */
	((mock_plat_t *)ctx)->now += ((mock_plat_t *)ctx)->build_us;
	out->sched_lead_us       = MOCK_SCHED_LEAD_US;
	out->max_pipelined_slots = 4u;
	out->supports_gauss_scale = true;
}
static void m_hci_to_host(void *ctx, const uint8_t *h4, uint16_t len)
{
	mock_plat_t *m = (mock_plat_t *)ctx;
	m->evt_cnt++;
	m->last_evt_len = len;
	memcpy(m->last_evt, h4, len);
}
static uint32_t m_now(void *ctx) { return ((mock_plat_t *)ctx)->now; }
static void m_rand(void *ctx, uint8_t *b, uint16_t n) { (void)ctx; memset(b, 0x42, n); }
static void m_tstart(void *ctx, uint32_t d)
{
	mock_plat_t *m = (mock_plat_t *)ctx;
	m->timer_armed = true;
	m->timer_at    = m->now + d;
}
static void m_tstop(void *ctx) { ((mock_plat_t *)ctx)->timer_armed = false; }

/* Second sound trial, 2026-11-10: building an encrypted packet took 0.4 to 1.5 ms on the ESP32-C6 (E0 alone was
 * measured at 368 us for 30 bytes and 977 us for 340), the engine chose its slot only 110 us further than the
 * scheduler's lead, and the first 3-slot packet reached the controller's scheduler after its own start: the chip
 * hung in the scheduler's queue walk. A pair that is ready too late must not be handed over, and the engine must
 * learn how long its packets take so that the next one is on time. */
static int test_a_pair_built_too_late_is_not_handed_over(void)
{
	mock_plat_t mp;
	memset(&mp, 0, sizeof(mp));
	mp.now      = 10000u;
	mp.build_us = 1500u; /* about what a 3-slot packet took: later than the next free slot after a report */
	br_platform_ops_t ops = {
		.ctx            = &mp,
		.schedule_tx    = m_sched_tx,
		.schedule_rx    = m_sched_rx,
		.schedule_tx_rx = m_sched_tx_rx,
		.cancel_all     = m_cancel,
		.radio_caps     = m_caps,
		.hci_to_host    = m_hci_to_host,
		.now_us         = m_now,
		.random         = m_rand,
		.timer_start    = m_tstart,
		.timer_stop     = m_tstop,
	};
	static uint8_t storage[12288];
	const uint8_t seed[6] = {0x24, 0x6F, 0x28, 0xAA, 0xBB, 0xCC};
	br_engine_t *eng = br_engine_init(storage, sizeof(storage), &ops, seed);
	CHECK(eng != NULL, "engine for the slow-build test");

	const uint8_t inq_cmd[] = {0x01, 0x01, 0x04, 0x05, 0x33, 0x8B, 0x9E, 0x04, 0x00};
	CHECK(br_engine_hci_from_host(eng, inq_cmd, sizeof(inq_cmd)), "inquiry accepted");
	for (int step = 0; step < 60; step++) {
		if (mp.has_pair) {
			mp.has_pair = false;
			mp.now      = mp.last_rx.anchor_us + 600u; /* the RX slot is reported empty after its end */
			br_radio_rx_ind_t ind;
			memset(&ind, 0, sizeof(ind));
			br_engine_on_rx_done(eng, mp.last_rx.slot_tag, &ind);
		} else if (mp.timer_armed) {
			mp.timer_armed = false;
			mp.now         = mp.timer_at;
			br_engine_on_timer(eng);
		} else {
			break;
		}
	}
	if (mp.pairs < 20u || mp.min_slack < 0) {
		fprintf(stderr, "slow build: %u pairs handed over, least slack %d us\n", (unsigned)mp.pairs, (int)mp.min_slack);
	}
	CHECK(mp.min_slack >= 0, "no pair is handed over after the scheduler should have had its TX item");
	CHECK(mp.pairs >= 20u, "the engine keeps going once it knows how long a packet takes to build");
	br_build_times_t bt;
	memset(&bt, 0, sizeof(bt));
	br_engine_get_build_times(eng, &bt);
	CHECK(bt.late_pairs <= 3u, "at most the first pairs are late: then the engine has learnt");
	CHECK(bt.longest_us >= 1500u, "the longest build is on record");
	return 0;
}

int main(void)
{
	if (test_a_pair_built_too_late_is_not_handed_over() != 0) {
		return 1;
	}
	mock_plat_t mp;
	memset(&mp, 0, sizeof(mp));
	mp.now = 10000u;

	br_platform_ops_t ops = {
		.ctx            = &mp,
		.schedule_tx    = m_sched_tx,
		.schedule_rx    = m_sched_rx,
		.schedule_tx_rx = m_sched_tx_rx,
		.cancel_all     = m_cancel,
		.radio_caps     = m_caps,
		.hci_to_host    = m_hci_to_host,
		.now_us         = m_now,
		.random         = m_rand,
		.timer_start    = m_tstart,
		.timer_stop     = m_tstop,
	};

	uint8_t storage[12288];
	CHECK(br_engine_storage_size() <= sizeof(storage), "Engine fits in static storage");
	const uint8_t seed[6] = {0x24, 0x6F, 0x28, 0xAA, 0xBB, 0xCC};
	br_engine_t *eng = br_engine_init(storage, sizeof(storage), &ops, seed);
	CHECK(eng != NULL, "Engine initialized");

	/* 1. BLE HCI commands & BLE ACL handles must NOT be consumed by Soft-BR! */
	const uint8_t ble_adv_cmd[] = {0x01, 0x0A, 0x20, 0x01, 0x01}; /* HCI_LE_Set_Advertising_Enable */
	CHECK(!br_engine_hci_from_host(eng, ble_adv_cmd, sizeof(ble_adv_cmd)), "BLE command passes through");
	const uint8_t cis_vs_cmd[] = {0x01, 0x30, 0xFC, 0x05, 'C', 'I', 'S', '5', 0x01};
	CHECK(!br_engine_hci_from_host(eng, cis_vs_cmd, sizeof(cis_vs_cmd)), "CIS 0xFC30 command passes through");
	const uint8_t ble_acl[] = {0x02, 0x01, 0x20, 0x04, 0x00, 1, 2, 3, 4}; /* BLE handle 0x0001 */
	CHECK(!br_engine_hci_from_host(eng, ble_acl, sizeof(ble_acl)), "BLE ACL handle 0x0001 passes through");

	/* 2. Vendor 0xFC31 PING is consumed and returns our derived Classic BD_ADDR */
	const uint8_t ping_cmd[] = {0x01, 0x31, 0xFC, 0x05, 'B', 'R', 'C', '6', BR_VS_PING};
	CHECK(br_engine_hci_from_host(eng, ping_cmd, sizeof(ping_cmd)), "BRC6 PING consumed");
	CHECK(mp.evt_cnt == 1u && mp.last_evt[1] == BR_HCI_EVT_CMD_COMPLETE, "PING Command Complete");

	/* 3. HCI_Inquiry starts slot scheduling and HCI_Inquiry_Cancel returns cleanly to IDLE */
	const uint8_t inq_cmd[] = {0x01, 0x01, 0x04, 0x05, 0x33, 0x8B, 0x9E, 0x04, 0x00};
	CHECK(br_engine_hci_from_host(eng, inq_cmd, sizeof(inq_cmd)), "HCI_Inquiry consumed");
	CHECK(br_engine_get_state(eng) == BR_STATE_INQUIRY && mp.has_pair, "Inquiry scheduled TX+RX pair");

	/* HCI_Reset resets Soft-BR AND returns false so stock BLE controller also receives HCI_Reset */
	const uint8_t rst_cmd[] = {0x01, 0x03, 0x0C, 0x00};
	CHECK(!br_engine_hci_from_host(eng, rst_cmd, sizeof(rst_cmd)), "HCI_Reset forwarded after resetting BR");
	CHECK(br_engine_get_state(eng) == BR_STATE_IDLE, "Engine back to IDLE after HCI_Reset");

	/* 4. A radio that never reports the RX slot (first run on the ESP32-C6, 2026-11-10) must not stop the engine
	 * for good: once the pair is over the timer gives it up, the next pair goes out, and the inquiry still ends
	 * on time with Inquiry Complete. */
	const uint8_t inq_1s28[] = {0x01, 0x01, 0x04, 0x05, 0x33, 0x8B, 0x9E, 0x01, 0x00};
	mp.pairs = 0u;
	CHECK(br_engine_hci_from_host(eng, inq_1s28, sizeof(inq_1s28)), "second HCI_Inquiry consumed");
	const uint32_t inq_start = mp.now;
	CHECK(mp.pairs == 1u && mp.has_pair, "first pair of the second inquiry queued");
	const uint32_t rx_end = mp.last_rx.anchor_us + mp.last_rx.max_duration_us;
	CHECK(mp.timer_armed && (int32_t)(mp.timer_at - rx_end) >= 0, "timer armed to the end of the queued pair");
	CHECK((int32_t)(mp.timer_at - rx_end) <= 5000, "a lost pair costs at most a few slots");

	const uint32_t first_tag = mp.last_rx.slot_tag;
	mp.now      = mp.timer_at;
	mp.has_pair = false; /* the radio said nothing */
	br_engine_on_timer(eng);
	CHECK(mp.pairs == 2u && mp.has_pair, "the next pair goes out after a lost RX report");
	CHECK((int32_t)(mp.last_tx.anchor_us - mp.now) > 0, "the next pair lies in the future");
	br_diag_stats_t ds;
	br_engine_get_stats(eng, &ds);
	CHECK(ds.pairs_lost == 1u, "the lost pair is counted");

	/* The report of the pair that was given up arrives after all: it must not end the pair now in flight. */
	br_radio_rx_ind_t late;
	memset(&late, 0, sizeof(late));
	br_engine_on_rx_done(eng, first_tag, &late);
	CHECK(mp.pairs == 2u, "a late report of a given-up pair queues nothing");

	/* A timer wake before the pair is over changes nothing. */
	br_engine_on_timer(eng);
	CHECK(mp.pairs == 2u, "an early timer wake does not give the pair up");

	mp.now      = inq_start + 1280000u + 10000u;
	mp.has_pair = false;
	br_engine_on_timer(eng);
	CHECK(br_engine_get_state(eng) == BR_STATE_IDLE, "inquiry ends on time without any RX report");
	CHECK(mp.last_evt[0] == 0x04 && mp.last_evt[1] == BR_HCI_EVT_INQUIRY_COMPLETE, "Inquiry Complete sent");

	printf("test_engine: OK\n");
	return 0;
}
