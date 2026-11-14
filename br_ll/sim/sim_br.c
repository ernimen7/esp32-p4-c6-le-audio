/*
 * End-to-End Discrete-Event Over-the-Air Simulator for Soft-BR (`br_ll`).
 *
 * Models a realistic off-the-shelf Bluetooth Classic A2DP Speaker (Inquiry Scan -> Page Scan ->
 * Slave Page Response -> Active ACL Slave with E0 encryption, AFH, and L2CAP/AVDTP media sink)
 * communicating over a noisy 79-channel 1-MHz physical medium (packet drops, single-bit RF errors,
 * BLE coexistence slot preemptions, and crystal bit-slip) against `br_engine` running C6 Mode-0 framing!
 */
#include "br_engine.h"
#include <stdio.h>
#include <string.h>

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		fprintf(stderr, "SIM FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); \
		return 1; \
	} \
} while (0)

typedef enum {
	SPK_SCANNING = 0,
	SPK_PAGE_WAIT_FHS,
	SPK_CONNECTED,
} spk_state_t;

typedef struct {
	spk_state_t state;
	uint8_t     bd_addr[6];
	uint32_t    lap;
	uint8_t     uap;
	uint16_t    nap;
	uint32_t    ulap;
	uint64_t    dac_sw;
	uint32_t    clkn_offset_ticks; /* Speaker free-running clock offset relative to Master */
	uint32_t    frozen_clkn;
	uint8_t     n_prs;

	/* Master piconet parameters learned from FHS */
	uint8_t     master_bdaddr[6];
	uint32_t    master_lap;
	uint8_t     master_uap;
	uint32_t    master_ulap;
	uint64_t    master_cac_sw;
	int32_t     master_clk_diff;
	uint8_t     lt_addr;

	/* Active ACL Slave ARQ + Encryption + AFH */
	uint8_t     last_master_seqn;
	uint8_t     arqn_to_master;
	uint8_t     tx_seqn;
	bool        enc_on;
	uint8_t     kc_prime[16];
	br_afh_state_t afh;
	bool        afh_pending;
	uint32_t    afh_instant_clk;
	uint8_t     afh_map[10];

	bool        has_pending_lmp_reply;
	uint8_t     pending_lmp[17];
	uint8_t     pending_lmp_len;

	uint32_t    l2cap_bytes_rx;
	uint32_t    l2cap_pkts_rx;
	uint32_t    multislot_rx;   /* new 3-slot packets taken from the Central */
	bool        deaf_to_3_slot; /* as the speaker of sound trials 3 to 6 looked: a 3-slot packet gets no answer */
	bool        acks_polls;     /* breaks the ARQN rule: every POLL is answered with ACK */
	uint16_t    reasm_expected;
	uint16_t    reasm_got;
} sim_speaker_t;

typedef struct {
	uint32_t          now_us;
	uint32_t          prng;
	uint8_t           drop_pct;      /* Simulated packet loss / Wi-Fi collision rate */
	uint8_t           coex_skip_pct; /* Simulated BLE scheduler preemption rate */
	int8_t            bit_slip;

	bool              has_pair;
	br_radio_tx_req_t pend_tx;
	br_radio_rx_req_t pend_rx;
	bool              has_timer;
	uint32_t          timer_fire_us;
	/* Sound trial 8, 2026-11-11: after nine seconds of 3-slot packets the link fell to short 1-slot packets and
	 * stayed there. Two things that are not the peer refusing a packet size: nothing gets through in either
	 * direction for a while, and the radio does not take the engine's pairs for a while. */
	bool              outage;          /* between outage_from_us and outage_until_us the speaker hears nothing */
	uint32_t          outage_from_us;
	uint32_t          outage_until_us;
	uint32_t          refuse_left;     /* pairs the radio still refuses */
	/* The stutter of 2026-11-12: a link that carried 3-slot packets fell to 1-slot ones 100 s into a stream and
	 * stayed there, too slow for the sound. The counters of the healthy link show how: about twice a second twelve
	 * transmissions in a row go unanswered and the POLL after them is answered, because the stretches without an
	 * answer are about as long as twelve transmissions take. Two such stretches back to back looked like a speaker
	 * that does not take the packet size. `slice_stage`: 0 none, 1 the first stretch (ends at the engine's POLL),
	 * 2 back for that POLL, 3 the second stretch, as many pairs as the first. Nothing else is lost meanwhile. */
	uint8_t           slice_stage;
	uint16_t          slice_pairs;
	uint16_t          slice_left;
	/* A speaker that takes no 3-slot packet for a while (range, interference) and then takes them again. */
	bool              fade;
	uint32_t          fade_until_us;

	/* Host event tracking */
	bool              got_inq_result;
	uint8_t           found_bdaddr[6];
	uint16_t          found_clk_off;
	bool              got_inq_complete;
	bool              got_conn_complete;
	uint8_t           conn_status;
	bool              got_enc_on;
	uint32_t          nocp_credits_returned;
	uint32_t          lmp_rx_events;

	sim_speaker_t     spk;
} sim_world_t;

static uint32_t sim_rand32(sim_world_t *w)
{
	uint32_t x = w->prng;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	w->prng = x;
	return x;
}

static void spk_e0_cb(void *ctx, uint8_t *buf, size_t len)
{
	/* Re-use e0 context layout: [0]=kc_prime, [1]=master_bd, [2]=clk */
	void **arr = (void **)ctx;
	uint32_t clk = *(uint32_t *)arr[2];
	br_crypto_e0_xor((const uint8_t *)arr[0], (const uint8_t *)arr[1], clk, buf, len);
}

static int sim_sched_tx(void *ctx, const br_radio_tx_req_t *tx) { (void)ctx; (void)tx; return 0; }
static int sim_sched_rx(void *ctx, const br_radio_rx_req_t *rx) { (void)ctx; (void)rx; return 0; }
static int sim_sched_tx_rx(void *ctx, const br_radio_tx_req_t *tx, const br_radio_rx_req_t *rx)
{
	sim_world_t *w = (sim_world_t *)ctx;
	if (w->refuse_left > 0u) {
		w->refuse_left--;
		return -1;
	}
	w->pend_tx  = *tx;
	w->pend_rx  = *rx;
	w->has_pair = true;
	return 0;
}
static void sim_cancel(void *ctx) { ((sim_world_t *)ctx)->has_pair = false; }
static void sim_caps(void *ctx, br_radio_caps_t *out)
{
	(void)ctx;
	out->sched_lead_us        = 192u;
	out->max_pipelined_slots  = 4u;
	out->supports_gauss_scale = true;
}
static uint32_t sim_now(void *ctx) { return ((sim_world_t *)ctx)->now_us; }
static void sim_random(void *ctx, uint8_t *buf, uint16_t len)
{
	sim_world_t *w = (sim_world_t *)ctx;
	for (uint16_t i = 0; i < len; i++) {
		buf[i] = (uint8_t)(sim_rand32(w) & 0xFFu);
	}
}
static void sim_tstart(void *ctx, uint32_t delay_us)
{
	sim_world_t *w = (sim_world_t *)ctx;
	w->has_timer     = true;
	w->timer_fire_us = w->now_us + delay_us;
}
static void sim_tstop(void *ctx) { ((sim_world_t *)ctx)->has_timer = false; }

static void sim_hci_to_host(void *ctx, const uint8_t *h4, uint16_t len)
{
	sim_world_t *w = (sim_world_t *)ctx;
	if (len < 3u || h4[0] != BR_H4_EVT) {
		return;
	}
	uint8_t evt = h4[1];
	const uint8_t *p = &h4[3];
	if (evt == BR_HCI_EVT_INQUIRY_RESULT_RSSI && h4[2] >= 15u) {
		w->got_inq_result = true;
		memcpy(w->found_bdaddr, &p[1], 6);
		w->found_clk_off = (uint16_t)((uint16_t)p[12] | ((uint16_t)p[13] << 8));
	} else if (evt == BR_HCI_EVT_INQUIRY_COMPLETE) {
		w->got_inq_complete = true;
	} else if (evt == BR_HCI_EVT_CONN_COMPLETE && h4[2] >= 11u) {
		w->got_conn_complete = true;
		w->conn_status       = p[0];
	} else if (evt == BR_HCI_EVT_NUM_COMP_PKTS && h4[2] >= 5u) {
		uint16_t c = (uint16_t)((uint16_t)p[3] | ((uint16_t)p[4] << 8));
		w->nocp_credits_returned += c;
	} else if (evt == BR_HCI_EVT_VENDOR && h4[2] >= 6u &&
	           p[0] == 'B' && p[1] == 'R' && p[2] == 'C' && p[3] == '6') {
		if (p[4] == BR_VSEVT_LMP_RX) {
			w->lmp_rx_events++;
		} else if (p[4] == BR_VSEVT_ENC_STATE && h4[2] >= 9u) {
			w->got_enc_on = (p[7] == 0u && p[8] == 1u);
		}
	}
}

/* Whether the staged stretches without an answer hide this packet of the Central from the speaker. */
static bool slice_hides(sim_world_t *w, bool is_poll)
{
	switch (w->slice_stage) {
	case 1u:
		if (!is_poll) {
			w->slice_pairs++;
			return true;
		}
		w->slice_stage = 2u;
		return false;
	case 2u:
		if (is_poll) {
			return false;
		}
		w->slice_stage = 3u;
		w->slice_left  = w->slice_pairs;
		/* fallthrough */
	case 3u:
		if (w->slice_left > 0u) {
			w->slice_left--;
			return true;
		}
		w->slice_stage = 0u;
		return false;
	default:
		return false;
	}
}

/* Decode full air packet at speaker receiver (no 46B single-slot limit on speaker side!) */
static bool speaker_decode_master_tx(const br_radio_tx_req_t *tx, uint64_t sw, uint8_t uap, uint8_t whiten_seed,
		br_payload_cipher_fn dec_fn, void *dec_ctx, br_rx_decoded_t *out)
{
	uint8_t air[300];
	size_t air_bits = 0;
	if (br_air_tx_to_bitstream(tx, air, sizeof(air), &air_bits) == 0u) {
		return false;
	}
	/* Locate 32-bit AA = sw[31:0] in air bitstream */
	uint32_t aa = (uint32_t)(sw & 0xFFFFFFFFULL);
	for (size_t pos = 0; pos + 32u <= air_bits; pos++) {
		uint32_t v = 0;
		for (uint8_t i = 0; i < 32u; i++) {
			size_t p = pos + i;
			if ((air[p >> 3] >> (p & 7u)) & 1u) {
				v |= (1u << i);
			}
		}
		if (v == aa) {
			size_t rem_bits = air_bits - (pos + 32u);
			size_t rem_bytes = (rem_bits + 7u) / 8u;
			if (rem_bytes < 2u) {
				return false;
			}
			uint8_t cap[260] = {0};
			for (size_t i = 0; i < rem_bits && (i >> 3) < sizeof(cap); i++) {
				size_t p = pos + 32u + i;
				if ((air[p >> 3] >> (p & 7u)) & 1u) {
					cap[i >> 3] |= (uint8_t)(1u << (i & 7u));
				}
			}
			br_radio_rx_ind_t ind = {
				.skipped = false, .sync_matched = true, .rssi_dbm = -48,
				.rx_timestamp_us = tx->anchor_us,
				.rx_hdr = cap[0], .rx_len = cap[1],
				.raw_len = (uint16_t)(rem_bytes - 2u),
				.raw_payload = &cap[2],
			};
			return br_air_extract_rx(sw, uap, whiten_seed, false, dec_fn, dec_ctx, &ind, out);
		}
	}
	return false;
}

static void step_air_pair(sim_world_t *w, br_engine_t *eng)
{
	br_radio_tx_req_t tx = w->pend_tx;
	br_radio_rx_req_t rx = w->pend_rx;
	w->has_pair = false;

	/* Advance simulation clock to TX anchor first; RX completion time depends on whether AA correlated
	 * (on C6 hardware, sch+28 rx_sync_win_us closes empty RX windows immediately after rx_sync_win_us!). */
	w->now_us = rx.anchor_us + (uint32_t)rx.rx_sync_win_us + 20u;

	/* Simulate occasional BLE coexistence preemption */
	if (w->coex_skip_pct > 0u && (sim_rand32(w) % 100u) < w->coex_skip_pct) {
		br_engine_on_tx_done(eng, tx.slot_tag, true);
		br_radio_rx_ind_t skip_ind;
		memset(&skip_ind, 0, sizeof(skip_ind));
		skip_ind.skipped = true;
		br_engine_on_rx_done(eng, rx.slot_tag, &skip_ind);
		return;
	}

	br_engine_on_tx_done(eng, tx.slot_tag, false);

	sim_speaker_t *s = &w->spk;
	uint32_t spk_clkn_tx = (((tx.anchor_us / 625u) * 2u) + s->clkn_offset_ticks) & 0x0FFFFFFFu;

	br_radio_rx_ind_t ind;
	memset(&ind, 0, sizeof(ind));
	ind.rssi_dbm = -47;
	uint8_t raw_rx_buf[256];
	memset(raw_rx_buf, 0, sizeof(raw_rx_buf));

	bool drop_tx = (w->drop_pct > 0u && (sim_rand32(w) % 100u) < w->drop_pct);
	bool drop_rx = (w->drop_pct > 0u && (sim_rand32(w) % 100u) < w->drop_pct);
	if (w->outage && (int32_t)(tx.anchor_us - w->outage_from_us) >= 0 &&
	    (int32_t)(tx.anchor_us - w->outage_until_us) < 0) {
		drop_tx = true;
	}
	if (w->slice_stage != 0u) {
		drop_tx = false; /* the staged stretches decide alone what gets through */
		drop_rx = false;
	}

	/* The speaker's ARQN bit (Core Spec Vol 2 Part B 7.6.1): "If, in any receive slot in the Peripheral ... no access
	 * code is detected ... then the ARQN bit shall be set to NAK"; a packet without CRC, a POLL too, leaves it "as it
	 * was prior to reception". Until sound trial 8 this model answered every POLL with ACK, which would acknowledge
	 * a packet the speaker never took as soon as the engine sends a POLL in its place. */
	bool spk_heard_header = false;
	if (!drop_tx) {
		if (s->state == SPK_SCANNING) {
			/* Speaker opens 11.25 ms R1 Inquiry Scan & Page Scan windows periodically */
			uint32_t slot_mod = (spk_clkn_tx >> 1) % 256u; /* Fast R0/R1 scan window in sim */
			uint64_t giac_sw = br_syncword_from_lap(BR_LAP_GIAC);
			br_rx_decoded_t mdec;

			/* Check Inquiry Scan */
			uint8_t inq_ch = br_hop_inquiry_scan(br_ulap(BR_LAP_GIAC, BR_DCI_UAP), spk_clkn_tx, 0u);
			if (slot_mod < 18u && tx.chan_1mhz == inq_ch &&
			    speaker_decode_master_tx(&tx, giac_sw, BR_DCI_UAP, 0x7Fu, NULL, NULL, &mdec) &&
			    mdec.is_id_pkt) {
				uint8_t xir = 0;
				uint8_t rsp_ch = br_hop_inquiry_rsp(br_ulap(BR_LAP_GIAC, BR_DCI_UAP), spk_clkn_tx, 0u, &xir);
				if (rsp_ch == rx.chan_1mhz && !drop_rx) {
					br_fhs_t fhs = {
						.parity34 = s->dac_sw & 0x3FFFFFFFFULL,
						.lap = s->lap, .eir = false, .sr = 1u, .sp = 2u,
						.uap = s->uap, .nap = s->nap,
						.class_of_device = 0x240414u, /* Loudspeaker */
						.lt_addr = 0u,
						.clk27_2 = ((spk_clkn_tx + 2u) >> 2) & 0x03FFFFFFu,
						.page_scan_mode = 0u,
					};
					uint8_t fhs18[18];
					br_fhs_pack(&fhs, fhs18);
					br_pkt_hdr_t fhdr = {.lt_addr = 0, .type = BR_PKT_FHS, .flow = 1, .arqn = 0, .seqn = 0};
					br_radio_tx_req_t stx;
					br_air_build_packet_tx(giac_sw, BR_DCI_UAP, br_whiten_seed_x(xir),
							&fhdr, fhs18, 18u, NULL, NULL, rsp_ch, rx.anchor_us, BR_TX_MODE_IN_PAYLOAD, &stx);
					uint8_t air[300];
					size_t air_bits = 0;
					br_air_tx_to_bitstream(&stx, air, sizeof(air), &air_bits);
					if (br_air_bitstream_to_c6_rx(air, air_bits, giac_sw, false, w->bit_slip,
							&ind.rx_hdr, &ind.rx_len, raw_rx_buf, &ind.raw_len)) {
						ind.sync_matched = true;
						ind.raw_payload  = raw_rx_buf;
					}
				}
			}

			/* Check Page Scan */
			uint8_t pg_ch = br_hop_page_scan(s->ulap, spk_clkn_tx);
			if (slot_mod >= 32u && slot_mod < 50u && tx.chan_1mhz == pg_ch &&
			    speaker_decode_master_tx(&tx, s->dac_sw, s->uap, 0x7Fu, NULL, NULL, &mdec) &&
			    mdec.is_id_pkt) {
				s->frozen_clkn = spk_clkn_tx & ~0x03u;
				uint8_t rsp_ch = br_hop_slave_page_rsp(s->ulap, s->frozen_clkn | 2u, 0u);
				if (rsp_ch == rx.chan_1mhz && !drop_rx) {
					br_radio_tx_req_t stx;
					br_air_build_id_tx(s->dac_sw, rsp_ch, rx.anchor_us, BR_TX_MODE_IN_PAYLOAD, false, &stx);
					uint8_t air[300];
					size_t air_bits = 0;
					br_air_tx_to_bitstream(&stx, air, sizeof(air), &air_bits);
					if (br_air_bitstream_to_c6_rx(air, air_bits, s->dac_sw, true, w->bit_slip,
							&ind.rx_hdr, &ind.rx_len, raw_rx_buf, &ind.raw_len)) {
						ind.sync_matched = true;
						ind.raw_payload  = raw_rx_buf;
						s->state         = SPK_PAGE_WAIT_FHS;
						s->n_prs         = 1u;
					}
				}
			}
		} else if (s->state == SPK_PAGE_WAIT_FHS) {
			uint32_t frames_since_id = ((spk_clkn_tx - s->frozen_clkn) & 0x0FFFFFFFu) >> 2;
			if (frames_since_id > 8u) {
				/* Core Spec §8.4.3.1 pagerespTO = 8 slots/frames: return to Page Scan */
				s->state = SPK_SCANNING;
			} else {
				s->n_prs = (uint8_t)(frames_since_id & 0x1Fu);
				uint8_t exp_ch = br_hop_slave_page_rsp(s->ulap, s->frozen_clkn, s->n_prs);
				uint8_t xprs   = (uint8_t)((((s->frozen_clkn >> 12) & 0x1Fu) + s->n_prs) & 0x1Fu);
				br_rx_decoded_t mdec;
				if (tx.chan_1mhz == exp_ch &&
				    speaker_decode_master_tx(&tx, s->dac_sw, s->uap, br_whiten_seed_x(xprs), NULL, NULL, &mdec) &&
				    mdec.crc_ok && mdec.hdr.type == BR_PKT_FHS && mdec.body_len == 18u) {
					br_fhs_t fhs;
					br_fhs_unpack(mdec.body, &fhs);
					br_parts_to_bdaddr(fhs.lap, fhs.uap, fhs.nap, s->master_bdaddr);
					s->master_lap      = fhs.lap;
					s->master_uap      = fhs.uap;
					s->master_ulap     = br_ulap(fhs.lap, fhs.uap);
					s->master_cac_sw   = br_syncword_from_lap(fhs.lap);
					s->lt_addr         = fhs.lt_addr;
					uint32_t m_clk     = (fhs.clk27_2 << 2);
					s->master_clk_diff = (int32_t)(m_clk - spk_clkn_tx);

					uint8_t ack_ch = br_hop_slave_page_rsp(s->ulap, s->frozen_clkn | 2u, s->n_prs);
					if (ack_ch == rx.chan_1mhz && !drop_rx) {
						br_radio_tx_req_t stx;
						br_air_build_id_tx(s->dac_sw, ack_ch, rx.anchor_us, BR_TX_MODE_IN_PAYLOAD, false, &stx);
						uint8_t air[300];
						size_t air_bits = 0;
						br_air_tx_to_bitstream(&stx, air, sizeof(air), &air_bits);
						if (br_air_bitstream_to_c6_rx(air, air_bits, s->dac_sw, true, w->bit_slip,
								&ind.rx_hdr, &ind.rx_len, raw_rx_buf, &ind.raw_len)) {
							ind.sync_matched     = true;
							ind.raw_payload      = raw_rx_buf;
							s->state             = SPK_CONNECTED;
							s->last_master_seqn  = 0xFFu;
							s->arqn_to_master    = 0u;
							s->tx_seqn           = 0u;
						}
					}
				}
			}
		} else if (s->state == SPK_CONNECTED) {
			uint32_t m_clk_tx = ((uint32_t)((int32_t)spk_clkn_tx + s->master_clk_diff)) & 0x0FFFFFFCu;
			if (s->afh_pending && ((int32_t)((m_clk_tx - s->afh_instant_clk) << 4) >> 4) >= 0) {
				s->afh_pending = false;
				(void)br_afh_init(&s->afh, s->afh_map);
			}
			uint8_t exp_ch = br_hop_connection(s->master_ulap, m_clk_tx, &s->afh);
			if (tx.chan_1mhz == exp_ch) {
				void *e0_arr[3] = {s->kc_prime, s->master_bdaddr, &m_clk_tx};
				br_rx_decoded_t mdec;
				bool ok = speaker_decode_master_tx(&tx, s->master_cac_sw, s->master_uap,
						br_whiten_seed_clk(m_clk_tx),
						s->enc_on ? spk_e0_cb : NULL, s->enc_on ? e0_arr : NULL, &mdec);
				const bool fading = w->fade && (int32_t)(tx.anchor_us - w->fade_until_us) < 0;
				if (ok && mdec.hec_ok && (s->deaf_to_3_slot || fading) && br_pkt_is_multislot(mdec.hdr.type)) {
					ok = false;
				}
				if (ok && mdec.hec_ok && w->slice_stage != 0u && slice_hides(w, mdec.hdr.type == BR_PKT_POLL)) {
					ok = false;
				}
				if (ok && mdec.hec_ok && mdec.hdr.lt_addr == s->lt_addr) {
					bool send_reply = false;
					spk_heard_header = true;
					if (!br_pkt_has_crc(mdec.hdr.type)) {
						if (mdec.hdr.type == BR_PKT_POLL) {
							send_reply = true;
							if (s->acks_polls) {
								s->arqn_to_master = 1u;
							}
						}
					} else if (!mdec.crc_ok) {
						s->arqn_to_master = 0u;
						send_reply = true;
					} else {
						s->arqn_to_master = 1u;
						send_reply = true;
						if (mdec.hdr.seqn != s->last_master_seqn) {
							s->last_master_seqn = mdec.hdr.seqn;
							bool ms = br_pkt_is_multislot(mdec.hdr.type);
							if (ms) {
								s->multislot_rx++;
							}
							uint8_t llid = 0, fl = 0, hb = 0;
							uint16_t plen = 0;
							if (br_acl_hdr_unpack(ms, mdec.body, mdec.body_len, &llid, &fl, &plen, &hb)) {
								const uint8_t *pay = &mdec.body[hb];
								if (llid == BR_LLID_LMP && plen >= 1u) {
									uint8_t op = (uint8_t)(pay[0] >> 1);
									if (op == 17u && plen == 17u) {
										/* LMP_start_encryption_req: Slave enables E0 and replies LMP_accepted(17) encrypted! */
										s->enc_on = true;
										s->pending_lmp[0] = (uint8_t)((3u << 1) | 0u);
										s->pending_lmp[1] = 17u;
										s->pending_lmp_len = 2u;
										s->has_pending_lmp_reply = true;
									} else if (op == 60u && plen == 16u) {
										uint32_t inst27 = (uint32_t)pay[1] | ((uint32_t)pay[2] << 8) |
										                  ((uint32_t)pay[3] << 16) | ((uint32_t)pay[4] << 24);
										s->afh_instant_clk = (inst27 << 1) & 0x0FFFFFFCu;
										memcpy(s->afh_map, &pay[6], 10);
										s->afh_pending = (pay[5] != 0u);
									} else {
										s->pending_lmp[0] = (uint8_t)((3u << 1) | 0u);
										s->pending_lmp[1] = op;
										s->pending_lmp_len = 2u;
										s->has_pending_lmp_reply = true;
									}
								} else if (llid == BR_LLID_L2CAP_START && plen >= 4u) {
									uint16_t l2 = (uint16_t)((uint16_t)pay[0] | ((uint16_t)pay[1] << 8));
									s->reasm_expected = (uint16_t)(4u + l2);
									s->reasm_got      = plen;
									if (s->reasm_got >= s->reasm_expected) {
										s->l2cap_pkts_rx++;
										s->l2cap_bytes_rx += l2;
									}
								} else if (llid == BR_LLID_L2CAP_CONT) {
									s->reasm_got = (uint16_t)(s->reasm_got + plen);
									if (s->reasm_expected > 0u && s->reasm_got >= s->reasm_expected) {
										s->l2cap_pkts_rx++;
										s->l2cap_bytes_rx += (uint32_t)(s->reasm_expected - 4u);
										s->reasm_expected = 0u;
									}
								}
							}
						}
					}

					uint8_t slots = br_pkt_slot_count(mdec.hdr.type);
					uint32_t m_clk_rx = (m_clk_tx + (uint32_t)slots * 2u) & 0x0FFFFFFFu;
					/* Same channel mechanism of AFH (Core Spec Vol 2 Part B 2.6.4.7): "the Peripheral responds with
					 * its packet on the same RF channel that was used by the Central to address that Peripheral",
					 * after a 3-slot packet too. Until the sixth sound trial this model, like the engine, took the
					 * channel of the Central slot just before the answer, which is another one after a 3-slot
					 * packet: the engine listened where no speaker answers. */
					uint8_t rsp_ch = s->afh.enabled ? exp_ch : br_hop_connection(s->master_ulap, m_clk_rx, &s->afh);

					if (send_reply && rsp_ch == rx.chan_1mhz && !drop_rx) {
						br_radio_tx_req_t stx;
						if (s->has_pending_lmp_reply) {
							s->has_pending_lmp_reply = false;
							s->tx_seqn ^= 1u;
							uint8_t body[20];
							uint8_t ah[2];
							br_acl_hdr_pack(false, BR_LLID_LMP, 1u, s->pending_lmp_len, ah);
							body[0] = ah[0];
							memcpy(&body[1], s->pending_lmp, s->pending_lmp_len);
							br_pkt_hdr_t sh = {
								.lt_addr = s->lt_addr, .type = BR_PKT_DM1,
								.flow = 1u, .arqn = s->arqn_to_master, .seqn = s->tx_seqn,
							};
							void *e0_r[3] = {s->kc_prime, s->master_bdaddr, &m_clk_rx};
							br_air_build_packet_tx(s->master_cac_sw, s->master_uap,
									br_whiten_seed_clk(m_clk_rx), &sh,
									body, (uint16_t)(1u + s->pending_lmp_len),
									s->enc_on ? spk_e0_cb : NULL, s->enc_on ? e0_r : NULL,
									rsp_ch, rx.anchor_us, BR_TX_MODE_IN_PAYLOAD, &stx);
						} else {
							br_pkt_hdr_t sh = {
								.lt_addr = s->lt_addr, .type = BR_PKT_NULL,
								.flow = 1u, .arqn = s->arqn_to_master, .seqn = s->tx_seqn,
							};
							br_air_build_packet_tx(s->master_cac_sw, s->master_uap,
									br_whiten_seed_clk(m_clk_rx), &sh,
									NULL, 0u, NULL, NULL,
									rsp_ch, rx.anchor_us, BR_TX_MODE_IN_PAYLOAD, &stx);
						}
						uint8_t air[300];
						size_t air_bits = 0;
						br_air_tx_to_bitstream(&stx, air, sizeof(air), &air_bits);
						/* Flip 1 random RF bit to exercise C6 FEC1/3 & FEC2/3 error correction! */
						if (air_bits > 160u) {
							air[15] ^= 0x02u;
						}
						if (br_air_bitstream_to_c6_rx(air, air_bits, s->master_cac_sw, false, w->bit_slip,
								&ind.rx_hdr, &ind.rx_len, raw_rx_buf, &ind.raw_len)) {
							ind.sync_matched = true;
							ind.raw_payload  = raw_rx_buf;
						}
					}
				}
			}
		}
	}

	if (s->state == SPK_CONNECTED && !spk_heard_header) {
		s->arqn_to_master = 0u;
	}
	if (ind.sync_matched) {
		w->now_us = rx.anchor_us + (rx.id_only ? 90u : 430u);
	}
	br_engine_on_rx_done(eng, rx.slot_tag, &ind);
}

static void pump_until(sim_world_t *w, br_engine_t *eng, uint32_t max_steps, const bool *stop_flag)
{
	for (uint32_t step = 0; step < max_steps; step++) {
		if (stop_flag && *stop_flag) {
			return;
		}
		if (w->has_pair) {
			step_air_pair(w, eng);
		} else if (w->has_timer) {
			w->now_us    = w->timer_fire_us;
			w->has_timer = false;
			br_engine_on_timer(eng);
		} else {
			break;
		}
	}
}

int main(int argc, char **argv)
{
	sim_world_t w;
	memset(&w, 0, sizeof(w));
	/* "no-3-slot": the speaker allows 3-slot packets and then answers none of them. The stream has to reach it
	 * all the same, in 1-slot packets, after the engine has given the 3-slot ones up. */
	/* "no-3-slot-poll-ack": the same speaker, and it answers every POLL with ACK against the rule. Not one frame may
	 * be lost for that. */
	/* "no-3-slot-long": the same speaker for four seconds of stream. The engine tries the full size again after a
	 * while, finds the speaker as deaf as before and waits longer before the next try. */
	const bool poll_ack  = (argc > 1 && strcmp(argv[1], "no-3-slot-poll-ack") == 0);
	const bool deaf_long = (argc > 1 && strcmp(argv[1], "no-3-slot-long") == 0);
	const bool no_3_slot = poll_ack || deaf_long || (argc > 1 && strcmp(argv[1], "no-3-slot") == 0);
	w.spk.deaf_to_3_slot = no_3_slot;
	w.spk.acks_polls     = poll_ack;
	/* "outage": 400 ms in which the speaker hears nothing at all. "busy-radio": the radio refuses 40 pairs in a
	 * row. Neither says anything about 3-slot packets, and the stream must go on in them afterwards. */
	const bool outage     = (argc > 1 && strcmp(argv[1], "outage") == 0);
	const bool busy_radio = (argc > 1 && strcmp(argv[1], "busy-radio") == 0);
	/* "slices": two stretches without an answer back to back, the first ending just as the engine asks whether the
	 * speaker is there (see slice_stage). The speaker takes 3-slot packets; the stream must stay in them. */
	const bool slices = (argc > 1 && strcmp(argv[1], "slices") == 0);
	/* "3-slot-fade": half a second in which the speaker takes no 3-slot packet. The stream goes on in 1-slot
	 * packets and returns to 3-slot ones afterwards. */
	const bool fade = (argc > 1 && strcmp(argv[1], "3-slot-fade") == 0);
	w.now_us        = 50000u;
	w.prng          = 0xC0FFEE11u;
	w.drop_pct      = 5u;  /* 5% random RF packet loss */
	w.coex_skip_pct = 4u;  /* 4% BLE scheduler preemption */
	w.bit_slip      = 1;   /* +1 bit crystal sampling offset */

	/* Configure simulated JBL/Sony-style Bluetooth Classic speaker */
	const uint8_t spk_mac[6] = {0x5C, 0xFB, 0x7C, 0x33, 0x44, 0x02};
	memcpy(w.spk.bd_addr, spk_mac, 6);
	br_bdaddr_to_parts(spk_mac, &w.spk.lap, &w.spk.uap, &w.spk.nap);
	w.spk.ulap              = br_ulap(w.spk.lap, w.spk.uap);
	w.spk.dac_sw            = br_syncword_from_lap(w.spk.lap);
	w.spk.clkn_offset_ticks = 0x00027410u;

	br_platform_ops_t ops = {
		.ctx            = &w,
		.schedule_tx    = sim_sched_tx,
		.schedule_rx    = sim_sched_rx,
		.schedule_tx_rx = sim_sched_tx_rx,
		.cancel_all     = sim_cancel,
		.radio_caps     = sim_caps,
		.hci_to_host    = sim_hci_to_host,
		.now_us         = sim_now,
		.random         = sim_random,
		.timer_start    = sim_tstart,
		.timer_stop     = sim_tstop,
	};

	uint8_t eng_mem[12288];
	const uint8_t c6_seed[6] = {0x60, 0x55, 0xF9, 0x12, 0x34, 0x56};
	br_engine_t *eng = br_engine_init(eng_mem, sizeof(eng_mem), &ops, c6_seed);
	CHECK(eng != NULL, "br_engine_init");

	/* Phase 1: Over-the-Air GIAC Inquiry -> Speaker discovery */
	const uint8_t hci_inq[] = {0x01, 0x01, 0x04, 0x05, 0x33, 0x8B, 0x9E, 0x04, 0x01};
	CHECK(br_engine_hci_from_host(eng, hci_inq, sizeof(hci_inq)), "Start Inquiry");
	pump_until(&w, eng, 8000u, &w.got_inq_complete);
	CHECK(w.got_inq_result && memcmp(w.found_bdaddr, spk_mac, 6) == 0,
	      "Speaker discovered over the air via GIAC Inquiry + FHS");

	/* Phase 2: Over-the-Air Page (using discovered BD_ADDR + clock_offset) -> FHS -> POLL -> Connected! */
	uint8_t hci_conn[17] = {0x01, 0x05, 0x04, 13u};
	memcpy(&hci_conn[4], w.found_bdaddr, 6);
	hci_conn[10] = 0x18u;
	hci_conn[11] = 0xCCu; /* DM1/DH1/DM3/DH3 */
	hci_conn[12] = 0x01u; /* R1 */
	hci_conn[13] = 0x00u;
	uint16_t clk_off_valid = (uint16_t)(w.found_clk_off | 0x8000u);
	hci_conn[14] = (uint8_t)(clk_off_valid & 0xFFu);
	hci_conn[15] = (uint8_t)((clk_off_valid >> 8) & 0xFFu);
	hci_conn[16] = 0x00u;

	CHECK(br_engine_hci_from_host(eng, hci_conn, sizeof(hci_conn)), "Start Create_Connection");
	pump_until(&w, eng, 8000u, &w.got_conn_complete);
	CHECK(w.got_conn_complete && w.conn_status == 0x00u && br_engine_get_state(eng) == BR_STATE_CONNECTED,
	      "ACL Connection established over the air");

	/* Phase 3: LMP exchange + Atomic Baseband E0 Encryption Startup */
	const uint8_t kc_test[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
	memcpy(w.spk.kc_prime, kc_test, 16);
	uint8_t vs_enc[4 + 39];
	vs_enc[0] = 0x01u; vs_enc[1] = 0x31u; vs_enc[2] = 0xFCu; vs_enc[3] = 39u;
	vs_enc[4] = 'B'; vs_enc[5] = 'R'; vs_enc[6] = 'C'; vs_enc[7] = '6';
	vs_enc[8] = BR_VS_START_ENC;
	vs_enc[9] = 0x00u; vs_enc[10] = 0x0Bu;
	memset(&vs_enc[11], 0xA5, 16); /* EN_RAND */
	memcpy(&vs_enc[27], kc_test, 16);
	CHECK(br_engine_hci_from_host(eng, vs_enc, sizeof(vs_enc)), "Start E0 Encryption");
	pump_until(&w, eng, 500u, &w.got_enc_on);
	CHECK(w.got_enc_on && w.spk.enc_on, "Atomic E0 Encryption active in both directions");

	/* Phase 4: AFH Channel Map Switch */
	uint8_t vs_afh[4 + 18];
	vs_afh[0] = 0x01u; vs_afh[1] = 0x31u; vs_afh[2] = 0xFCu; vs_afh[3] = 18u;
	vs_afh[4] = 'B'; vs_afh[5] = 'R'; vs_afh[6] = 'C'; vs_afh[7] = '6';
	vs_afh[8] = BR_VS_SET_AFH;
	vs_afh[9] = 0x00u; vs_afh[10] = 0x0Bu;
	vs_afh[11] = 1u;
	memset(&vs_afh[12], 0xFF, 10);
	vs_afh[12] = 0x00u; /* Mask out channels 0..7 (Wi-Fi avoidance) */
	vs_afh[21] = 0x7Fu;
	CHECK(br_engine_hci_from_host(eng, vs_afh, sizeof(vs_afh)), "Schedule AFH");

	/* Phase 4b: "After a new connection ... the value shall be 1 slot" (Core Spec Vol 2 Part C 4.1.10). Until the
	 * host passes on that the peer allows more, a frame that would fit one DH3 goes out in 1-slot packets. Third
	 * sound trial, 2026-11-11: the engine sent DH3 without asking; the speaker answered none of them and the link
	 * timed out four seconds into the stream. */
	{
		uint8_t h4_acl[5 + 104];
		h4_acl[0] = BR_H4_ACL;
		h4_acl[1] = 0x00u;
		h4_acl[2] = 0x2Bu;
		h4_acl[3] = 104u;
		h4_acl[4] = 0u;
		h4_acl[5] = 100u;
		h4_acl[6] = 0u;
		h4_acl[7] = 0x41u;
		h4_acl[8] = 0x00u;
		memset(&h4_acl[9], 0x5A, 100u);
		CHECK(br_engine_hci_from_host(eng, h4_acl, sizeof(h4_acl)), "Queue a 104-byte frame before multi-slot is allowed");
		while (w.nocp_credits_returned < 1u) {
			bool never = false;
			pump_until(&w, eng, 4u, &never);
		}
		CHECK(w.spk.l2cap_pkts_rx == 1u, "the frame arrives whole");
		CHECK(w.spk.multislot_rx == 0u, "no 3-slot packet before the peer allows them");
		const uint8_t allow3[] = { 0x01u, 0x31u, 0xFCu, 0x06u, 'B', 'R', 'C', '6', BR_VS_SET_TX_SLOTS, 3u };
		CHECK(br_engine_hci_from_host(eng, allow3, sizeof(allow3)), "the host passes on LMP_max_slot 3");
	}
	const uint32_t credits0 = w.nocp_credits_returned;
	const uint32_t pkts0    = w.spk.l2cap_pkts_rx;
	const uint32_t bytes0   = w.spk.l2cap_bytes_rx;

	/* Phase 5: Stream 40 encrypted A2DP SBC media packets (~360 B each -> 3 DH3 fragments per L2CAP SDU)
	 * under 5% RF packet loss + 4% BLE preemption + 1-bit crystal slip! */
	uint32_t start_us = w.now_us;
	const uint32_t target_sdus = fade ? 200u : deaf_long ? 120u : 40u;
	uint32_t sent_sdus = 0u;
	bool busy_radio_done = false;
	bool slices_done     = false;
	bool fade_done       = false;
	uint32_t tail_from_us = 0u; /* the last 40 frames of the stream, for the rate the link ends at */
	uint32_t tail_bytes0  = 0u;
	while (w.nocp_credits_returned - credits0 < target_sdus) {
		uint32_t in_flight = sent_sdus - (w.nocp_credits_returned - credits0);
		while (sent_sdus < target_sdus && in_flight < 8u) {
			uint16_t l2_payload = 320u; /* e.g., 4 Joint-Stereo SBC frames + 13B RTP/AVDTP */
			uint16_t acl_len    = (uint16_t)(4u + l2_payload);
			uint8_t h4_acl[5 + 324];
			h4_acl[0] = BR_H4_ACL;
			h4_acl[1] = 0x00u;
			h4_acl[2] = 0x2Bu; /* handle 0x0B00 | PB=10 */
			h4_acl[3] = (uint8_t)(acl_len & 0xFFu);
			h4_acl[4] = (uint8_t)((acl_len >> 8) & 0xFFu);
			h4_acl[5] = (uint8_t)(l2_payload & 0xFFu);
			h4_acl[6] = (uint8_t)((l2_payload >> 8) & 0xFFu);
			h4_acl[7] = 0x41u;
			h4_acl[8] = 0x00u; /* CID 0x0041 */
			for (uint16_t i = 0; i < l2_payload; i++) {
				h4_acl[9u + i] = (uint8_t)((sent_sdus + i) & 0xFFu);
			}
			CHECK(br_engine_hci_from_host(eng, h4_acl, (uint16_t)(5u + acl_len)), "Queue A2DP SDU");
			sent_sdus++;
			in_flight++;
		}
		if (w.nocp_credits_returned - credits0 == 10u && outage && !w.outage) {
			w.outage          = true;
			w.outage_from_us  = w.now_us;
			w.outage_until_us = w.now_us + 400000u;
		}
		if (w.nocp_credits_returned - credits0 == 10u && busy_radio && !busy_radio_done) {
			busy_radio_done = true;
			w.refuse_left   = 40u;
		}
		if (w.nocp_credits_returned - credits0 == 10u && slices && !slices_done) {
			slices_done   = true;
			w.slice_stage = 1u;
		}
		if (w.nocp_credits_returned - credits0 == 10u && fade && !fade_done) {
			fade_done       = true;
			w.fade          = true;
			w.fade_until_us = w.now_us + 500000u;
		}
		if (tail_from_us == 0u && w.nocp_credits_returned - credits0 >= target_sdus - 40u) {
			tail_from_us = w.now_us;
			tail_bytes0  = w.spk.l2cap_bytes_rx;
		}
		bool never = false;
		pump_until(&w, eng, 4u, &never);
	}
	uint32_t elapsed_us = w.now_us - start_us;
	double kbps = ((double)(w.spk.l2cap_bytes_rx - bytes0) * 8.0 * 1000.0) / (double)elapsed_us;

	const double tail_kbps = ((double)(w.spk.l2cap_bytes_rx - tail_bytes0) * 8.0 * 1000.0) /
	                         (double)(w.now_us - tail_from_us);

	CHECK(w.spk.l2cap_pkts_rx - pkts0 == target_sdus, "All encrypted L2CAP A2DP media SDUs delivered losslessly via ARQ");
	CHECK(w.spk.l2cap_bytes_rx - bytes0 == target_sdus * 320u, "Exact L2CAP media byte count");
	if (no_3_slot) {
		CHECK(w.spk.multislot_rx == 0u, "the deaf speaker took no 3-slot packet");
	} else {
		CHECK(w.spk.multislot_rx > 0u, "3-slot packets carry the stream once they are allowed");
	}
	br_link_diag_t ld;
	br_engine_get_link_diag(eng, &ld);
	if (deaf_long) {
		if (ld.tx_size_level != 1u || ld.tx_flushes != 2u) {
			fprintf(stderr, "size level %u, %u flush(es), %u strike(s), %u probe(s)\n", (unsigned)ld.tx_size_level,
					(unsigned)ld.tx_flushes, (unsigned)ld.size_strikes, (unsigned)ld.probes);
		}
		CHECK(ld.tx_size_level == 1u && ld.tx_flushes == 2u,
				"the full size is tried again once in four seconds, given up again, and the next try waits longer");
	} else if (no_3_slot) {
		CHECK(ld.tx_size_level == 1u, "3-slot packets given up for 1-slot ones, and no further");
	} else if (fade) {
		if (ld.tx_size_level != 0u || ld.tx_flushes == 0u || tail_kbps <= 200.0) {
			fprintf(stderr, "size level %u, %u flush(es), %u strike(s), %u probe(s), last 40 frames at %.1f kbps\n",
					(unsigned)ld.tx_size_level, (unsigned)ld.tx_flushes, (unsigned)ld.size_strikes,
					(unsigned)ld.probes, tail_kbps);
		}
		CHECK(ld.tx_flushes >= 1u, "3-slot packets are given up while the speaker takes none");
		CHECK(ld.tx_size_level == 0u, "and they are back once the speaker takes them again");
		CHECK(tail_kbps > 200.0, "the stream ends at the rate of 3-slot packets");
	} else {
		if (ld.tx_size_level != 0u || ld.tx_flushes != 0u) {
			fprintf(stderr, "size level %u, %u flush(es), %u strike(s), %u probe(s), %u pair(s) refused\n",
					(unsigned)ld.tx_size_level, (unsigned)ld.tx_flushes, (unsigned)ld.size_strikes,
					(unsigned)ld.probes, (unsigned)ld.pairs_refused);
		}
		CHECK(ld.tx_size_level == 0u && ld.tx_flushes == 0u,
				"a speaker that takes 3-slot packets keeps getting them, whatever else happens to the link");
	}
	if (busy_radio) {
		CHECK(ld.pairs_refused >= 40u, "the pairs the radio refused are counted");
	}
	if (outage) {
		br_gap_t gaps[BR_GAP_LOG];
		uint16_t missed = 0u;
		const uint8_t n = br_engine_take_gaps(eng, gaps, &missed);
		uint32_t longest = 0u;
		uint16_t pairs   = 0u;
		for (uint8_t i = 0; i < n; i++) {
			if (gaps[i].len_100us > longest) {
				longest = gaps[i].len_100us;
				pairs   = gaps[i].pairs;
			}
		}
		if (longest < 4000u || longest > 4300u) {
			fprintf(stderr, "%u gap(s), %u missed, longest %u.%u ms in %u pairs\n", (unsigned)n, (unsigned)missed,
					(unsigned)(longest / 10u), (unsigned)(longest % 10u), (unsigned)pairs);
		}
		CHECK(longest >= 4000u && longest <= 4300u, "the 400 ms outage is on record with its length");
		CHECK(pairs >= 50u, "and with the pairs that went unanswered in it");
		CHECK(br_engine_take_gaps(eng, gaps, &missed) == 0u, "a gap is handed out once");
	}
	if (outage || busy_radio || slices) {
		CHECK(kbps > 100.0, "the stream picks up after the gap");
	} else if (!fade) {
		CHECK(kbps > (no_3_slot ? 60.0 : 260.0),
				"Sustained net A2DP throughput > 260 kbps (1-slot packets only: > 60) with 5% RF loss + 4% BLE coex");
	}

	br_diag_stats_t st;
	br_engine_get_stats(eng, &st);
	printf("SIM PASS%s: %u A2DP SDUs (%u B) over E0+AFH+DH3 in %.1f ms -> %.1f kbps net (retrans=%u, skipped=%u)\n",
			no_3_slot ? " (speaker deaf to 3-slot packets)" : outage ? " (400 ms outage)" :
			busy_radio ? " (radio refuses 40 pairs)" : slices ? " (two stretches without an answer)" :
			fade ? " (no 3-slot packets for 500 ms)" : "",
			(unsigned)(w.spk.l2cap_pkts_rx - pkts0), (unsigned)(w.spk.l2cap_bytes_rx - bytes0),
			(double)elapsed_us / 1000.0, kbps, (unsigned)st.tx_retrans, (unsigned)st.slots_skipped);
	return 0;
}
