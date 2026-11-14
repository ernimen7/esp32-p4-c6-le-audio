/*
 * Soft-BR Master Link Controller Engine (br_engine).
 */
#include "br_engine.h"
#include <string.h>

/* Opaque slot_tag encoding: [31:28] = phase, [27:0] = master clk at slot start */
#define TAG_MAKE(phase, clk28) ((((uint32_t)(phase) & 0x0Fu) << 28) | ((uint32_t)(clk28) & 0x0FFFFFFFu))
#define TAG_PHASE(tag)         (((uint32_t)(tag) >> 28) & 0x0Fu)
#define TAG_CLK(tag)           ((uint32_t)(tag) & 0x0FFFFFFFu)

enum {
	PHASE_INQ          = 1,
	PHASE_PAGE         = 2,
	PHASE_PAGE_RSP     = 3,
	PHASE_NEW_CONN     = 4,
	PHASE_ACL          = 5,
	PHASE_INQ_EIR      = 6,
};

typedef struct {
	bool    used;
	uint8_t bd_addr[6];
} inq_seen_t;

typedef struct {
	uint8_t len;
	uint8_t data[BR_MAX_DM1_BYTES];
} lmp_pdu_t;

typedef struct {
	bool     in_use;
	uint16_t len;
	uint16_t offset;
	uint8_t  data[BR_ACL_SDU_MAX];
} acl_sdu_slot_t;

typedef struct {
	const uint8_t *kc_prime;
	const uint8_t *master_bdaddr;
	uint32_t       clk;
} e0_cb_ctx_t;

struct br_engine {
	br_platform_ops_t ops;
	br_state_t        state;

	/* Local Master identity */
	uint8_t  local_bdaddr[6];
	uint32_t local_lap;
	uint8_t  local_uap;
	uint16_t local_nap;
	uint32_t local_ulap;
	uint64_t local_cac_sw;

	/* Master 28-bit piconet clock (steps by 4 every 1250 us) */
	uint32_t clk_ref;
	uint32_t clk_ref_us;
	uint32_t next_sched_clk;
	bool     pair_in_flight;
	uint32_t pair_rx_tag;       /* slot_tag of the RX slot that ends the pair in flight */
	uint32_t pair_deadline_us;  /* past this the pair is given up (br_engine_on_timer) */

	/* Runtime knobs & diagnostics */
	br_knobs_t      knobs;
	br_diag_stats_t stats;

	/* Inquiry state */
	uint32_t   inq_lap;
	uint32_t   inq_ulap;
	uint64_t   inq_sw;
	uint32_t   inq_end_us;
	uint8_t    inq_max_rsp;
	uint8_t    inq_rsp_cnt;
	uint8_t    inq_subtrain;      /* 0..3 -> S0=A[0..7], S1=A[8..15], S2=B[0..7], S3=B[8..15] */
	uint8_t    inq_idx8;          /* 0..7 within subtrain */
	uint32_t   inq_subtrain_switch_us;
	uint8_t    inq_last_x;
	br_fhs_t   inq_pending_eir_fhs;
	int8_t     inq_pending_eir_rssi;
	inq_seen_t inq_seen[BR_MAX_INQ_CACHE];

	/* Page / Connection setup state */
	uint8_t    peer_bdaddr[6];
	uint32_t   peer_lap;
	uint8_t    peer_uap;
	uint16_t   peer_nap;
	uint32_t   peer_ulap;
	uint64_t   peer_dac_sw;
	uint16_t   peer_clk_off;      /* bit 15 = valid, bits 14:0 = (CLKN[16:2] - CLK[16:2]) */
	uint32_t   page_deadline_us;
	uint8_t    page_subtrain;
	uint8_t    page_idx8;
	uint32_t   page_subtrain_switch_us;
	uint8_t    page_last_xp;
	br_page_progress_t page_progress;
	/* Time from choosing a slot to handing its pair over (see queue_pair): what the choice allows for it, for
	 * pairs without and with payload work, and the choice the pair being built was made with. */
	uint16_t   build_allow_us[2];
	uint8_t    build_class;
	uint32_t   pick_now_us;
	uint32_t   pick_lead_us;
	br_build_times_t build_times;
	uint8_t    page_frozen_xp;
	uint32_t   page_frozen_clk;
	uint8_t    page_n_prm;
	uint8_t    page_rsp_retries;
	uint8_t    new_conn_retries;
	bool       name_req_only;

	/* Active ACL link state (single active speaker/headphone link on handle 0x0B00) */
	uint8_t    lt_addr;           /* 1 */
	uint8_t    tx_seqn;           /* Current Master TX SEQN (toggled before each new data packet) */
	uint8_t    rx_expected_seqn;  /* Expected next Slave SEQN (starts at 1; init last_rx_seqn = 0xFF) */
	uint8_t    last_rx_seqn;
	uint8_t    peer_arqn_to_send; /* ARQN sent in our next TX header (1=ACK if last Slave CRC pkt was good, else 0) */
	bool       peer_flow_go;      /* FLOW bit from Slave baseband header */
	uint32_t   last_peer_rx_us;
	uint32_t   lsto_us;           /* Supervision timeout (default 5,000,000 us) */
	uint32_t   last_poll_clk;

	/* Current unacknowledged baseband packet for ARQ retransmission */
	bool       arq_waiting_ack;
	bool       arq_is_l2cap_frag;
	bool       arq_is_enc_start_lmp;
	uint8_t    arq_pkt_type;
	uint16_t   arq_body_len;
	uint8_t    arq_body[240];
	uint8_t    arq_naks_in_row;
	/* Giving up a packet size the peer does not take (see size_evidence): what the pair in flight carries and
	 * whether its TX slot ran, the transmissions of the data packet in flight that went unanswered in this round,
	 * whether the peer has just shown that it is there (the next round is the short one that decides), the rounds
	 * counted against each size class, the size level of this connection (0 what the peer allows, 1 one slot,
	 * 2 one short slot), when a lowered level ends and how often it was lowered since a multi-slot packet last got
	 * through. */
	uint8_t    pair_kind;
	bool       pair_tx_skipped;
	uint8_t    pair_chan;
	uint8_t    arq_unanswered;
	bool       arq_probe_due;
	bool       size_suspect;
	uint8_t    size_strikes[2];
	uint8_t    tx_size_level;
	uint8_t    size_hold_exp;
	uint32_t   size_retry_us;
	/* What happened on the way, for BR_VS_GET_DIAG and br_engine_get_link_diag. */
	uint8_t    tx_flushes;
	uint8_t    size_strikes_total;
	uint16_t   probes;
	uint16_t   pairs_refused;
	uint16_t   silent_run;
	uint16_t   silent_run_max;
	uint8_t    chan_tried[BR_NUM_CHANNELS];
	uint8_t    chan_heard[BR_NUM_CHANNELS];
	br_gap_t   gaps[BR_GAP_LOG];
	uint8_t    gap_count;
	uint16_t   gap_missed;

	/* LMP TX FIFO (LLID=3, priority over L2CAP) */
	lmp_pdu_t  lmp_q[BR_LMP_TX_QUEUE];
	uint8_t    lmp_head;
	uint8_t    lmp_tail;
	uint8_t    lmp_count;

	/* L2CAP ACL TX SDU ring (segmented into DH3/DH1 fragments) */
	acl_sdu_slot_t acl_q[BR_ACL_TX_CREDITS];
	uint8_t        acl_head;
	uint8_t        acl_tail;
	uint8_t        acl_count;

	/* L2CAP ACL RX reassembly buffer */
	bool     rx_reasm_active;
	uint16_t rx_reasm_expected;
	uint16_t rx_reasm_len;
	uint8_t  rx_reasm_buf[BR_ACL_RX_REASM_MAX];

	/* Baseband E0 Encryption state */
	bool     l2cap_paused_for_enc;
	/* Longest ACL packet the peer allows us, in slots. "After a new connection ... the value shall be 1 slot"
	 * (Core Spec Vol 2 Part C 4.1.10); the host raises it with BR_VS_SET_TX_SLOTS when the peer has sent
	 * LMP_max_slot or accepted LMP_max_slot_req. */
	uint8_t  tx_max_slots;
	bool     enc_rx_on;
	bool     enc_tx_on;
	uint8_t  kc_prime[16];

	/* Adaptive Frequency Hopping (AFH) */
	br_afh_state_t afh;
	bool           afh_pending;
	uint32_t       afh_instant_clk;
	uint8_t        afh_pending_map[10];
	bool           afh_pending_enable;
};

static void schedule_next_step(br_engine_t *e);

static void e0_cipher_adapter(void *ctx_ptr, uint8_t *buf, size_t len)
{
	const e0_cb_ctx_t *c = (const e0_cb_ctx_t *)ctx_ptr;
	br_crypto_e0_xor(c->kc_prime, c->master_bdaddr, c->clk, buf, len);
}

static void sync_clk_to_now(br_engine_t *e, uint32_t now_us)
{
	int32_t diff = (int32_t)(now_us - e->clk_ref_us);
	if (diff >= (int32_t)BR_TWO_SLOTS_US) {
		uint32_t frames = (uint32_t)diff / BR_TWO_SLOTS_US;
		e->clk_ref_us += frames * BR_TWO_SLOTS_US;
		e->clk_ref     = (e->clk_ref + frames * 4u) & 0x0FFFFFFFu;
	}
}

/* Convert an even Master CLK (`(clk & 3) == 0`) near `clk_ref` to controller us timestamp. */
static uint32_t clk_to_us(const br_engine_t *e, uint32_t clk)
{
	int32_t dclk = (int32_t)((clk - e->clk_ref) << 4) >> 4; /* sign-extend 28-bit delta */
	int32_t half_slots = dclk; /* 1 CLK tick = 312.5 us; for even slots dclk is multiple of 2 -> (dclk/2)*625 */
	return (uint32_t)((int32_t)e->clk_ref_us + (half_slots / 2) * (int32_t)BR_SLOT_US);
}

static void refresh_local_identity(br_engine_t *e, const uint8_t bd_addr[6])
{
	memcpy(e->local_bdaddr, bd_addr, 6);
	br_bdaddr_to_parts(bd_addr, &e->local_lap, &e->local_uap, &e->local_nap);
	e->local_ulap   = br_ulap(e->local_lap, e->local_uap);
	e->local_cac_sw = br_syncword_from_lap(e->local_lap);
}

size_t br_engine_storage_size(void)
{
	return sizeof(struct br_engine);
}

br_engine_t *br_engine_init(void *storage, size_t storage_bytes,
		const br_platform_ops_t *ops, const uint8_t seed_mac[6])
{
	if (!storage || storage_bytes < sizeof(struct br_engine) || !ops) {
		return NULL;
	}
	br_engine_t *e = (br_engine_t *)storage;
	memset(e, 0, sizeof(*e));
	e->ops = *ops;

	uint8_t derived[6];
	static const uint8_t default_seed[6] = {0x12u, 0x34u, 0x56u, 0x78u, 0x9Au, 0xBCu};
	br_derive_c6_bdaddr(seed_mac ? seed_mac : default_seed, 46u, derived);
	refresh_local_identity(e, derived);

	e->knobs.tx_mode             = BR_TX_MODE_IN_PAYLOAD;
	e->knobs.gauss_bt05          = false;
	e->knobs.dh3_max_bytes       = BR_DEFAULT_DH3_CAP;
	e->knobs.poll_interval_slots = 24u;
	e->knobs.prefer_fec_dm       = false;
	e->lsto_us                   = 5000000u;

	e->clk_ref_us = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : 0u;
	e->clk_ref    = 0x00001000u;
	return e;
}

void br_engine_reset(br_engine_t *e)
{
	if (!e) {
		return;
	}
	if (e->ops.cancel_all) {
		e->ops.cancel_all(e->ops.ctx);
	}
	if (e->ops.timer_stop) {
		e->ops.timer_stop(e->ops.ctx);
	}
	if (e->ops.set_gauss_bt05) {
		e->ops.set_gauss_bt05(e->ops.ctx, false);
	}
	e->state                = BR_STATE_IDLE;
	e->pair_in_flight       = false;
	e->arq_waiting_ack      = false;
	e->lmp_head = e->lmp_tail = e->lmp_count = 0;
	e->acl_head = e->acl_tail = e->acl_count = 0;
	e->rx_reasm_active      = false;
	e->l2cap_paused_for_enc = false;
	e->enc_rx_on            = false;
	e->enc_tx_on            = false;
	e->afh_pending          = false;
	memset(&e->afh, 0, sizeof(e->afh));
}

/* ==== HCI Event Helpers ==== */
static void send_hci_evt(br_engine_t *e, uint8_t evt_code, const uint8_t *params, uint8_t plen)
{
	uint8_t h4[260];
	h4[0] = BR_H4_EVT;
	h4[1] = evt_code;
	h4[2] = plen;
	if (plen > 0u && params != NULL) {
		memcpy(&h4[3], params, plen);
	}
	if (e->ops.hci_to_host) {
		e->ops.hci_to_host(e->ops.ctx, h4, (uint16_t)(3u + plen));
	}
}

static void send_cmd_status(br_engine_t *e, uint16_t opcode, uint8_t status)
{
	uint8_t p[4] = {
		status,
		1u,
		(uint8_t)(opcode & 0xFFu),
		(uint8_t)((opcode >> 8) & 0xFFu),
	};
	send_hci_evt(e, BR_HCI_EVT_CMD_STATUS, p, 4u);
}

static void send_cmd_complete(br_engine_t *e, uint16_t opcode, uint8_t status,
		const uint8_t *ret_extra, uint8_t extra_len)
{
	uint8_t p[252];
	p[0] = 1u;
	p[1] = (uint8_t)(opcode & 0xFFu);
	p[2] = (uint8_t)((opcode >> 8) & 0xFFu);
	p[3] = status;
	if (extra_len > 0u && ret_extra != NULL) {
		memcpy(&p[4], ret_extra, extra_len);
	}
	send_hci_evt(e, BR_HCI_EVT_CMD_COMPLETE, p, (uint8_t)(4u + extra_len));
}

static void send_conn_complete(br_engine_t *e, uint8_t status)
{
	uint8_t p[11];
	p[0] = status;
	p[1] = (uint8_t)(BR_ACL_HANDLE_BASE & 0xFFu);
	p[2] = (uint8_t)((BR_ACL_HANDLE_BASE >> 8) & 0xFFu);
	memcpy(&p[3], e->peer_bdaddr, 6);
	p[9]  = 0x01u; /* ACL link type */
	p[10] = 0x00u; /* Encryption initially off */
	send_hci_evt(e, BR_HCI_EVT_CONN_COMPLETE, p, sizeof(p));
}

static void send_disconn_complete(br_engine_t *e, uint8_t reason)
{
	uint8_t p[4] = {
		0x00u,
		(uint8_t)(BR_ACL_HANDLE_BASE & 0xFFu),
		(uint8_t)((BR_ACL_HANDLE_BASE >> 8) & 0xFFu),
		reason,
	};
	send_hci_evt(e, BR_HCI_EVT_DISCONN_COMPLETE, p, sizeof(p));
}

static void send_num_completed_pkts(br_engine_t *e, uint16_t count)
{
	uint8_t p[5] = {
		1u,
		(uint8_t)(BR_ACL_HANDLE_BASE & 0xFFu),
		(uint8_t)((BR_ACL_HANDLE_BASE >> 8) & 0xFFu),
		(uint8_t)(count & 0xFFu),
		(uint8_t)((count >> 8) & 0xFFu),
	};
	send_hci_evt(e, BR_HCI_EVT_NUM_COMP_PKTS, p, sizeof(p));
}

static void send_vendor_lmp_rx(br_engine_t *e, const uint8_t *lmp, uint8_t len)
{
	if (len == 0u || len > BR_MAX_DM1_BYTES) {
		return;
	}
	uint8_t p[8 + BR_MAX_DM1_BYTES];
	p[0] = BR_VENDOR_MAGIC_0;
	p[1] = BR_VENDOR_MAGIC_1;
	p[2] = BR_VENDOR_MAGIC_2;
	p[3] = BR_VENDOR_MAGIC_3;
	p[4] = BR_VSEVT_LMP_RX;
	p[5] = (uint8_t)(BR_ACL_HANDLE_BASE & 0xFFu);
	p[6] = (uint8_t)((BR_ACL_HANDLE_BASE >> 8) & 0xFFu);
	p[7] = len;
	memcpy(&p[8], lmp, len);
	send_hci_evt(e, BR_HCI_EVT_VENDOR, p, (uint8_t)(8u + len));
}

static void send_vendor_enc_state(br_engine_t *e, uint8_t status, bool enc_on)
{
	uint8_t p[9] = {
		BR_VENDOR_MAGIC_0, BR_VENDOR_MAGIC_1, BR_VENDOR_MAGIC_2, BR_VENDOR_MAGIC_3,
		BR_VSEVT_ENC_STATE,
		(uint8_t)(BR_ACL_HANDLE_BASE & 0xFFu),
		(uint8_t)((BR_ACL_HANDLE_BASE >> 8) & 0xFFu),
		status,
		enc_on ? 1u : 0u,
	};
	send_hci_evt(e, BR_HCI_EVT_VENDOR, p, sizeof(p));
}

static void deliver_acl_sdu_to_host(br_engine_t *e, const uint8_t *sdu, uint16_t len)
{
	if (len == 0u || len > BR_ACL_RX_REASM_MAX) {
		return;
	}
	uint8_t h4[5 + BR_ACL_RX_REASM_MAX];
	uint16_t handle_flags = (uint16_t)(BR_ACL_HANDLE_BASE | (0x02u << 12)); /* PB=10 (first auto-flush / complete L2CAP) */
	h4[0] = BR_H4_ACL;
	h4[1] = (uint8_t)(handle_flags & 0xFFu);
	h4[2] = (uint8_t)((handle_flags >> 8) & 0xFFu);
	h4[3] = (uint8_t)(len & 0xFFu);
	h4[4] = (uint8_t)((len >> 8) & 0xFFu);
	memcpy(&h4[5], sdu, len);
	e->stats.acl_sdu_rx++;
	if (e->ops.hci_to_host) {
		e->ops.hci_to_host(e->ops.ctx, h4, (uint16_t)(5u + len));
	}
}

static bool enqueue_lmp_tx(br_engine_t *e, const uint8_t *pdu, uint8_t len)
{
	if (len == 0u || len > BR_MAX_DM1_BYTES || e->lmp_count >= BR_LMP_TX_QUEUE) {
		return false;
	}
	e->lmp_q[e->lmp_tail].len = len;
	memcpy(e->lmp_q[e->lmp_tail].data, pdu, len);
	e->lmp_tail = (uint8_t)((e->lmp_tail + 1u) % BR_LMP_TX_QUEUE);
	e->lmp_count++;
	return true;
}

static void teardown_link_to_idle(br_engine_t *e, uint8_t disconn_reason, bool emit_disconn)
{
	br_state_t prev = e->state;
	if (e->ops.cancel_all) {
		e->ops.cancel_all(e->ops.ctx);
	}
	if (e->ops.timer_stop) {
		e->ops.timer_stop(e->ops.ctx);
	}
	if (e->ops.set_gauss_bt05) {
		e->ops.set_gauss_bt05(e->ops.ctx, false);
	}
	e->state                = BR_STATE_IDLE;
	e->pair_in_flight       = false;
	e->arq_waiting_ack      = false;
	e->lmp_head = e->lmp_tail = e->lmp_count = 0;
	e->acl_head = e->acl_tail = e->acl_count = 0;
	e->rx_reasm_active      = false;
	e->l2cap_paused_for_enc = false;
	e->enc_rx_on            = false;
	e->enc_tx_on            = false;
	e->afh_pending          = false;
	memset(&e->afh, 0, sizeof(e->afh));

	if (emit_disconn && prev == BR_STATE_CONNECTED) {
		send_disconn_complete(e, disconn_reason);
	}
}

/* ==== Earliest Schedulable Master-to-Slave Slot Picker ==== */
static uint32_t pick_next_master_clk(br_engine_t *e, uint32_t min_clk)
{
	uint32_t now = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : e->clk_ref_us;
	sync_clk_to_now(e, now);

	br_radio_caps_t caps;
	memset(&caps, 0, sizeof(caps));
	if (e->ops.radio_caps) {
		e->ops.radio_caps(e->ops.ctx, &caps);
	}
	/* Ensure anchor_us - 60 - sched_lead >= now + 50 us safety margin once the pair is built: the packet is put
	 * together after this choice, and with a payload to cipher that takes longer than the margin. */
	uint32_t lead_needed = caps.sched_lead_us + 110u;
	uint32_t earliest_us = now + lead_needed + e->build_allow_us[e->build_class];
	e->pick_now_us  = now;
	e->pick_lead_us = caps.sched_lead_us;

	uint32_t cand = e->clk_ref;
	while ((int32_t)(clk_to_us(e, cand) - earliest_us) < 0) {
		cand = (cand + 4u) & 0x0FFFFFFFu;
	}
	if (min_clk != 0u) {
		int32_t diff = (int32_t)((min_clk - cand) << 4) >> 4;
		if (diff > 0) {
			cand = min_clk & ~0x03u;
		}
	}
	return cand & ~0x03u;
}

/* ==== Build Next Active ACL Baseband Packet ==== */
static uint16_t one_slot_cap(uint8_t level)
{
	return (level >= 2u) ? BR_SHORT_DH1_BYTES : BR_MAX_DH1_BYTES;
}

/* What the pair in flight carries. */
enum {
	PAIR_OTHER = 0, /* a POLL of the idle link, or a pair from before the connection */
	PAIR_ARQ,       /* the packet that waits for its acknowledgement */
	PAIR_PROBE,     /* a POLL in that packet's place, to see whether the peer is there at all */
};

/* The size class of the data packet in flight: 0 a multi-slot packet, 1 a 1-slot packet longer than the short
 * one, 2 a packet with nothing smaller to fall back to. Level n of the connection sends no class below n. */
static uint8_t arq_size_class(const br_engine_t *e)
{
	if (br_pkt_is_multislot(e->arq_pkt_type)) {
		return 0u;
	}
	return ((uint16_t)(e->arq_body_len - 1u) > BR_SHORT_DH1_BYTES) ? 1u : 2u;
}

/* A packet size the peer does not take is given up for a smaller one, so that the link does not end in a
 * supervision timeout with the same packet still in flight (sound trials 3 to 6, 2026-11-11: 600 tries of one
 * 3-slot packet). That needs evidence about the size and not about the link: in sound trial 8 the first version,
 * 16 calls for a retransmission in a row, took a link that had carried 3-slot packets for nine seconds down to
 * short 1-slot packets for good, and the simulator shows it doing so when the radio refuses pairs or when nothing
 * at all gets through for a while. So:
 *  - only transmissions that were on the air count, and none while the peer's FLOW bit says STOP;
 *  - after BR_SIZE_ROUND_TRIES of them without an acknowledgement the engine asks whether the peer is there: an
 *    explicit NAK to the last one says so, otherwise one POLL goes out in the packet's place ("it requires a
 *    confirmation from the recipient", Core Spec Vol 2 Part B 6.5.1.3). Silence says the link is down and the
 *    round starts again;
 *  - an answer says only that the peer is back. On the speaker the stretches without any answer last about as
 *    long as twelve 3-slot transmissions take, so twice a second the POLL after such a round was answered, and on
 *    2026-11-12 two of them back to back took a stream that 3-slot packets carried well down to 1-slot packets,
 *    too slow for the sound, until the owner restarted the tablet. So the answer is followed by a short round of
 *    BR_SIZE_CONFIRM_TRIES: the peer is there, and a size it takes gets through now. Only when that round fails
 *    too and the peer answers again is it a strike against the size class;
 *  - a packet of the class acknowledged in its own pair clears the strikes: BR_SIZE_STRIKES in a row take the
 *    level down, for this connection only;
 *  - a lowered level is not for good, because what stopped the size may pass (distance, interference, or a
 *    verdict that was wrong after all): after BR_SIZE_HOLD_US the full size is tried again, and each time it
 *    fails again without a multi-slot packet getting through in between, the wait doubles, up to
 *    BR_SIZE_HOLD_US << BR_SIZE_HOLD_MAX_EXP. */
#define BR_SIZE_ROUND_TRIES   12u
#define BR_SIZE_CONFIRM_TRIES 4u
#define BR_SIZE_STRIKES       2u
#define BR_SIZE_HOLD_US       2000000u
#define BR_SIZE_HOLD_MAX_EXP  4u

static void size_strike(br_engine_t *e, uint8_t cls)
{
	e->arq_unanswered = 0u;
	if (e->size_strikes_total < 0xFFu) {
		e->size_strikes_total++;
	}
	e->size_strikes[cls]++;
	if (e->size_strikes[cls] < BR_SIZE_STRIKES) {
		return;
	}
	e->size_strikes[cls] = 0u;
	e->size_suspect      = false;
	if (e->tx_size_level < (uint8_t)(cls + 1u)) {
		e->tx_size_level = (uint8_t)(cls + 1u);
	}
	const uint32_t now = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : e->clk_ref_us;
	e->size_retry_us   = now + (BR_SIZE_HOLD_US << e->size_hold_exp);
	if (e->size_hold_exp < BR_SIZE_HOLD_MAX_EXP) {
		e->size_hold_exp++;
	}
}

/* The peer answered right after a round of unanswered transmissions: the first time it only starts the short
 * round, the second time in a row it counts against the size. */
static void size_peer_is_there(br_engine_t *e, uint8_t cls)
{
	e->arq_unanswered = 0u;
	if (e->size_suspect) {
		size_strike(e, cls);
	} else {
		e->size_suspect = true;
	}
}

/* A lowered size level ends when its time is up. Asked before every pair, so that a link without data for a long
 * time does not carry a stale deadline around the wrap of the microsecond clock. */
static void size_level_expire(br_engine_t *e)
{
	if (e->tx_size_level == 0u) {
		return;
	}
	const uint32_t now = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : e->clk_ref_us;
	if ((int32_t)(now - e->size_retry_us) < 0) {
		return;
	}
	e->tx_size_level = 0u;
	e->size_suspect  = false;
	memset(e->size_strikes, 0, sizeof(e->size_strikes));
}

/* `kind` and `cls` describe the pair that has just ended and the data packet that was in flight during it;
 * `heard` says whether the peer's header came back in it. */
static void size_evidence(br_engine_t *e, uint8_t kind, uint8_t cls, bool heard)
{
	if (kind == PAIR_PROBE) {
		e->arq_probe_due  = false;
		e->arq_unanswered = 0u;
		if (heard) {
			size_peer_is_there(e, cls);
		} else {
			e->size_suspect = false;
		}
		return;
	}
	if (kind != PAIR_ARQ) {
		return;
	}
	if (!e->arq_waiting_ack) {
		e->size_strikes[cls] = 0u; /* acknowledged in its own pair: this size gets through */
		e->size_suspect      = false;
		if (cls == 0u) {
			e->size_hold_exp = 0u;
		}
		return;
	}
	if (e->arq_unanswered < 0xFFu) {
		e->arq_unanswered++;
	}
	if (e->arq_unanswered < (e->size_suspect ? BR_SIZE_CONFIRM_TRIES : BR_SIZE_ROUND_TRIES)) {
		return;
	}
	if (heard) {
		size_peer_is_there(e, cls);
	} else {
		e->arq_probe_due = true;
	}
}

/* The frame of a data packet longer than the link now takes starts again in smaller packets. The way there is the
 * specification's flush (Core Spec Vol 2 Part B 7.6.2.2): "it shall replace the current packet with an ACL-U
 * continuation packet with the same sequence number as the current packet and length zero", and nothing else goes
 * out until that one is acknowledged. The frame then starts again from its first byte, as a new L2CAP message
 * ("the packet following the flush shall have a start packet indication", 7.6.3); the receiver drops the part it
 * had. */
static void flush_if_too_long(br_engine_t *e)
{
	if (!e->arq_is_l2cap_frag || e->acl_count == 0u || arq_size_class(e) >= e->tx_size_level) {
		return;
	}
	if (e->tx_flushes < 0xFFu) {
		e->tx_flushes++;
	}
	e->acl_q[e->acl_head].offset = 0u;
	uint8_t hdr[2];
	(void)br_acl_hdr_pack(false, BR_LLID_L2CAP_CONT, 1u, 0u, hdr);
	e->arq_body[0]       = hdr[0];
	e->arq_body_len      = 1u;
	e->arq_pkt_type      = BR_PKT_DM1;
	e->arq_is_l2cap_frag = false;
	e->arq_unanswered    = 0u;
	e->arq_probe_due     = false;
	e->size_suspect      = false;
}

static void prepare_next_acl_tx(br_engine_t *e, uint32_t tx_clk,
		br_pkt_hdr_t *out_hdr, uint8_t *out_body, uint16_t *out_body_len, bool *out_encrypt)
{
	/* Activate pending AFH map when instant is reached */
	if (e->afh_pending) {
		int32_t diff = (int32_t)((tx_clk - e->afh_instant_clk) << 4) >> 4;
		if (diff >= 0) {
			e->afh_pending = false;
			if (e->afh_pending_enable) {
				(void)br_afh_init(&e->afh, e->afh_pending_map);
			} else {
				e->afh.enabled = false;
			}
		}
	}

	size_level_expire(e);

	out_hdr->lt_addr = e->lt_addr;
	out_hdr->flow    = 1u;
	out_hdr->arqn    = e->peer_arqn_to_send;

	e->pair_kind = PAIR_OTHER;

	/* Retransmit unacknowledged packet if still waiting for ACK */
	if (e->arq_waiting_ack) {
		if (e->arq_probe_due) {
			/* See size_evidence. A POLL "does not affect the ARQN and SEQN fields"; it carries the SEQN of the
			 * packet it stands in for. */
			out_hdr->type = BR_PKT_POLL;
			out_hdr->seqn = e->tx_seqn;
			*out_body_len = 0u;
			*out_encrypt  = false;
			e->pair_kind  = PAIR_PROBE;
			if (e->probes < 0xFFFFu) {
				e->probes++;
			}
			return;
		}
		flush_if_too_long(e);
		e->pair_kind   = PAIR_ARQ;
		out_hdr->type  = e->arq_pkt_type;
		out_hdr->seqn  = e->tx_seqn;
		*out_body_len  = e->arq_body_len;
		memcpy(out_body, e->arq_body, e->arq_body_len);
		*out_encrypt   = e->enc_tx_on && !e->arq_is_enc_start_lmp;
		e->stats.tx_retrans++;
		return;
	}

	/* Priority 1: LMP PDU queue (only when no unacked L2CAP fragment is in flight) */
	if (e->lmp_count > 0u) {
		const lmp_pdu_t *lmp = &e->lmp_q[e->lmp_head];
		bool is_enc_req = ((lmp->data[0] >> 1) == 17u); /* LMP_start_encryption_req */

		uint8_t acl_hdr[2];
		uint16_t hb = br_acl_hdr_pack(false, BR_LLID_LMP, 1u, lmp->len, acl_hdr);
		e->arq_body[0] = acl_hdr[0];
		memcpy(&e->arq_body[hb], lmp->data, lmp->len);
		e->arq_body_len         = (uint16_t)(hb + lmp->len);
		e->arq_pkt_type         = BR_PKT_DM1;
		e->arq_is_l2cap_frag    = false;
		e->arq_is_enc_start_lmp = is_enc_req;
		e->arq_waiting_ack      = true;
		e->arq_naks_in_row      = 0;
		e->arq_unanswered       = 0;
		e->pair_kind            = PAIR_ARQ;

		e->lmp_head = (uint8_t)((e->lmp_head + 1u) % BR_LMP_TX_QUEUE);
		e->lmp_count--;
		e->stats.lmp_tx_cnt++;

		e->tx_seqn ^= 1u;
		out_hdr->type = e->arq_pkt_type;
		out_hdr->seqn = e->tx_seqn;
		*out_body_len = e->arq_body_len;
		memcpy(out_body, e->arq_body, e->arq_body_len);
		*out_encrypt  = e->enc_tx_on && !is_enc_req;
		return;
	}

	/* Priority 2: L2CAP ACL SDU fragment (when not paused for encryption handshake and Slave FLOW==GO) */
	if (!e->l2cap_paused_for_enc && e->peer_flow_go && e->acl_count > 0u) {
		acl_sdu_slot_t *sdu = &e->acl_q[e->acl_head];
		uint16_t rem = (uint16_t)(sdu->len - sdu->offset);
		uint8_t llid = (sdu->offset == 0u) ? BR_LLID_L2CAP_START : BR_LLID_L2CAP_CONT;

		uint16_t max_dh3 = (e->tx_max_slots >= 3u && e->tx_size_level == 0u) ? e->knobs.dh3_max_bytes
		                                                                    : BR_MAX_DH1_BYTES;
		if (max_dh3 > BR_MAX_DH3_BYTES) {
			max_dh3 = BR_MAX_DH3_BYTES;
		}
		bool use_fec = e->knobs.prefer_fec_dm;
		uint8_t pkt_type;
		uint16_t chunk;
		const uint16_t cap1 = use_fec ? BR_MAX_DM1_BYTES : one_slot_cap(e->tx_size_level);

		if (rem <= cap1) {
			pkt_type = use_fec ? BR_PKT_DM1 : BR_PKT_DH1;
			chunk    = rem;
		} else if (max_dh3 <= BR_MAX_DH1_BYTES) {
			pkt_type = use_fec ? BR_PKT_DM1 : BR_PKT_DH1;
			chunk    = cap1;
		} else {
			pkt_type = use_fec ? BR_PKT_DM3 : BR_PKT_DH3;
			uint16_t cap3 = use_fec ? BR_MAX_DM3_BYTES : max_dh3;
			chunk    = (rem > cap3) ? cap3 : rem;
		}

		bool multislot = br_pkt_is_multislot(pkt_type);
		uint8_t acl_hdr[2];
		uint16_t hb = br_acl_hdr_pack(multislot, llid, 1u, chunk, acl_hdr);
		memcpy(e->arq_body, acl_hdr, hb);
		memcpy(&e->arq_body[hb], &sdu->data[sdu->offset], chunk);
		sdu->offset = (uint16_t)(sdu->offset + chunk);

		e->arq_body_len         = (uint16_t)(hb + chunk);
		e->arq_pkt_type         = pkt_type;
		e->arq_is_l2cap_frag    = true;
		e->arq_is_enc_start_lmp = false;
		e->arq_waiting_ack      = true;
		e->arq_naks_in_row      = 0;
		e->arq_unanswered       = 0;
		e->pair_kind            = PAIR_ARQ;

		e->tx_seqn ^= 1u;
		out_hdr->type = pkt_type;
		out_hdr->seqn = e->tx_seqn;
		*out_body_len = e->arq_body_len;
		memcpy(out_body, e->arq_body, e->arq_body_len);
		*out_encrypt  = e->enc_tx_on;
		return;
	}

	/* Priority 3: Idle POLL keepalive */
	out_hdr->type = BR_PKT_POLL;
	out_hdr->seqn = e->tx_seqn;
	*out_body_len = 0u;
	*out_encrypt  = false;
}

/* ==== Master Slot Pair Scheduler ==== */

/* A queued pair ends with the platform's report of its RX slot, matched or not. A radio that loses the report must
 * not stop the engine for good (first run on the ESP32-C6, 2026-11-10: the raw RX item never came back and the
 * inquiry outlived its own time limit), so the timer is set past the end of the pair and gives it up. */
#define BR_PAIR_GUARD_US 2500u /* two frames: the platform's own report of the RX slot comes first */

/* A pair that is ready after the radio should have had it is not handed over: the controller's scheduler must
 * never get an item whose start has passed (second sound trial, 2026-11-10: the first 3-slot packet took about
 * 1.5 ms to cipher and pack, arrived late, and the chip hung in the scheduler's queue walk). The pair counts as
 * lost; what it carried goes out again like anything else that was not acknowledged. The measured time raises the
 * allowance at once and lets it sink slowly, so the next choice of a slot leaves room. */
static bool pair_built_in_time(br_engine_t *e, const br_radio_tx_req_t *tx)
{
	const uint32_t now      = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : e->clk_ref_us;
	const uint32_t built_us = now - e->pick_now_us;
	const uint32_t wanted   = built_us + built_us / 4u;
	uint16_t *allow = &e->build_allow_us[e->build_class];
	if (wanted >= *allow) {
		*allow = (wanted > 20000u) ? 20000u : (uint16_t)wanted;
	} else {
		*allow = (uint16_t)(((uint32_t)*allow * 15u + wanted) / 16u);
	}
	if (built_us > e->build_times.longest_us) {
		e->build_times.longest_us = (built_us > 0xFFFFu) ? 0xFFFFu : (uint16_t)built_us;
	}
	e->build_times.allowance_us = e->build_allow_us[1] > e->build_allow_us[0] ? e->build_allow_us[1]
	                                                                           : e->build_allow_us[0];
	if ((int32_t)(tx->anchor_us - tx->lead_us - e->pick_lead_us - now) >= 0) {
		return true;
	}
	e->build_times.late_pairs++;
	return false;
}

static void queue_pair(br_engine_t *e, const br_radio_tx_req_t *tx, const br_radio_rx_req_t *rx)
{
	if (!pair_built_in_time(e, tx)) {
		if (e->ops.timer_start) {
			e->ops.timer_start(e->ops.ctx, 50u);
		}
		return;
	}
	e->pair_in_flight  = true;
	e->pair_rx_tag     = rx->slot_tag;
	e->pair_tx_skipped = false;
	if (e->ops.schedule_tx_rx(e->ops.ctx, tx, rx) != 0) {
		e->pair_in_flight = false;
		if (e->pairs_refused < 0xFFFFu) {
			e->pairs_refused++;
		}
		if (e->ops.timer_start) {
			e->ops.timer_start(e->ops.ctx, 1250u);
		}
		return;
	}
	e->pair_deadline_us = rx->anchor_us + rx->max_duration_us + BR_PAIR_GUARD_US;
	if (e->ops.timer_start) {
		uint32_t now = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : e->clk_ref_us;
		e->ops.timer_start(e->ops.ctx, e->pair_deadline_us - now);
	}
}

static void schedule_next_step(br_engine_t *e)
{
	if (e->state == BR_STATE_IDLE || e->pair_in_flight) {
		return;
	}
	uint32_t now = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : e->clk_ref_us;
	sync_clk_to_now(e, now);
	e->build_class = 0u;

	if (e->state == BR_STATE_INQUIRY) {
		if ((int32_t)(now - e->inq_end_us) >= 0 ||
		    (e->inq_max_rsp > 0u && e->inq_rsp_cnt >= e->inq_max_rsp)) {
			teardown_link_to_idle(e, 0u, false);
			uint8_t status = 0x00u;
			send_hci_evt(e, BR_HCI_EVT_INQUIRY_COMPLETE, &status, 1u);
			return;
		}
		if ((int32_t)(now - e->inq_subtrain_switch_us) >= 0) {
			e->inq_subtrain = (uint8_t)((e->inq_subtrain + 1u) & 0x03u);
			e->inq_idx8     = 0u;
			e->inq_subtrain_switch_us = now + 640000u; /* 0.64 s per 8-ch subtrain */
		}

		uint32_t tx_clk = pick_next_master_clk(e, e->next_sched_clk);
		uint32_t tx_us  = clk_to_us(e, tx_clk);
		uint32_t rx_us  = tx_us + BR_SLOT_US;

		br_train_t train = (e->inq_subtrain < 2u) ? BR_TRAIN_A : BR_TRAIN_B;
		uint8_t idx16    = (uint8_t)(((e->inq_subtrain & 1u) * 8u) + (e->inq_idx8 & 7u));
		e->inq_idx8      = (uint8_t)((e->inq_idx8 + 1u) & 7u);

		uint8_t x_tx = 0;
		uint8_t ch_tx = br_hop_train_chan_tx(e->inq_ulap, tx_clk, train, idx16, &x_tx);
		uint8_t ch_rx = br_hop_train_chan_rx(e->inq_ulap, x_tx);
		e->inq_last_x = x_tx;

		br_radio_tx_req_t tx;
		br_air_build_id_tx(e->inq_sw, ch_tx, tx_us, e->knobs.tx_mode, e->knobs.id_ends_with_sync, &tx);
		tx.slot_tag = TAG_MAKE(PHASE_INQ, tx_clk);

		br_radio_rx_req_t rx;
		memset(&rx, 0, sizeof(rx));
		rx.anchor_us      = rx_us;
		rx.rx_sync_win_us = 80u;
		rx.max_duration_us = 500u;
		rx.chan_1mhz      = ch_rx;
		rx.access_addr    = (uint32_t)(e->inq_sw & 0xFFFFFFFFULL);
		rx.id_only        = false;
		rx.slot_tag       = TAG_MAKE(PHASE_INQ, (tx_clk + 2u) & 0x0FFFFFFFu);

		e->next_sched_clk = (tx_clk + 4u) & 0x0FFFFFFFu;
		queue_pair(e, &tx, &rx);
		return;
	}

	if (e->state == BR_STATE_PAGE) {
		if ((int32_t)(now - e->page_deadline_us) >= 0) {
			bool nr = e->name_req_only;
			uint8_t peer[6];
			memcpy(peer, e->peer_bdaddr, 6);
			teardown_link_to_idle(e, 0u, false);
			if (nr) {
				uint8_t p[255];
				memset(p, 0, sizeof(p));
				p[0] = 0x04u; /* Page Timeout */
				memcpy(&p[1], peer, 6);
				send_hci_evt(e, BR_HCI_EVT_REMOTE_NAME_COMPLETE, p, 255u);
			} else {
				memcpy(e->peer_bdaddr, peer, 6);
				send_conn_complete(e, 0x04u); /* Page Timeout */
			}
			return;
		}
		if ((int32_t)(now - e->page_subtrain_switch_us) >= 0) {
			e->page_subtrain = (uint8_t)((e->page_subtrain + 1u) & 0x03u);
			e->page_idx8     = 0u;
			e->page_subtrain_switch_us = now + 1280000u; /* 1.28 s >= R1 T_page_scan */
		}

		uint32_t tx_clk = pick_next_master_clk(e, e->next_sched_clk);
		uint32_t tx_us  = clk_to_us(e, tx_clk);
		uint32_t rx_us  = tx_us + BR_SLOT_US;

		uint32_t clke = tx_clk;
		if (e->peer_clk_off & 0x8000u) {
			clke = (tx_clk + (((uint32_t)(e->peer_clk_off & 0x7FFFu)) << 2)) & 0x0FFFFFFCu;
		}
		br_train_t train = (e->page_subtrain < 2u) ? BR_TRAIN_A : BR_TRAIN_B;
		/* Center S0 (idx 4..11 of Train A, where idx 8 == CLKE[16:12]!) so known clock_offset hits immediately! */
		static const uint8_t s_map[4][8] = {
			{ 4, 5, 6, 7, 8, 9,10,11}, /* S0: +-4 around CLKE[16:12] in Train A */
			{ 0, 1, 2, 3,12,13,14,15}, /* S1: outer 8 of Train A */
			{ 4, 5, 6, 7, 8, 9,10,11}, /* S2: center 8 of Train B */
			{ 0, 1, 2, 3,12,13,14,15}, /* S3: outer 8 of Train B */
		};
		uint8_t idx16 = s_map[e->page_subtrain & 3u][e->page_idx8 & 7u];
		e->page_idx8  = (uint8_t)((e->page_idx8 + 1u) & 7u);

		uint8_t xp = 0;
		uint8_t ch_tx = br_hop_train_chan_tx(e->peer_ulap, clke, train, idx16, &xp);
		uint8_t ch_rx = br_hop_train_chan_rx(e->peer_ulap, xp);
		e->page_last_xp = xp;

		br_radio_tx_req_t tx;
		br_air_build_id_tx(e->peer_dac_sw, ch_tx, tx_us, e->knobs.tx_mode, e->knobs.id_ends_with_sync, &tx);
		tx.slot_tag = TAG_MAKE(PHASE_PAGE, tx_clk);

		br_radio_rx_req_t rx;
		memset(&rx, 0, sizeof(rx));
		rx.anchor_us       = rx_us;
		rx.rx_sync_win_us  = 80u;
		rx.max_duration_us = 220u;
		rx.chan_1mhz       = ch_rx;
		rx.access_addr     = (uint32_t)(e->peer_dac_sw & 0xFFFFFFFFULL);
		rx.id_only         = true;
		rx.slot_tag        = TAG_MAKE(PHASE_PAGE, (tx_clk + 2u) & 0x0FFFFFFFu);

		e->next_sched_clk = (tx_clk + 4u) & 0x0FFFFFFFu;
		queue_pair(e, &tx, &rx);
		return;
	}

	if (e->state == BR_STATE_PAGE_MASTER_RSP) {
		if (e->page_rsp_retries >= 8u) {
			/* Fall back to Page train if Slave missed FHS */
			e->state = BR_STATE_PAGE;
			schedule_next_step(e);
			return;
		}
		uint32_t tx_clk = pick_next_master_clk(e, e->next_sched_clk);
		uint32_t tx_us  = clk_to_us(e, tx_clk);
		uint32_t rx_us  = tx_us + BR_SLOT_US;

		/* Compute N_prm from elapsed 1.25ms frames since matched Page ID TX so BLE slot skips never desync X_prm/X_prs! */
		uint32_t elapsed_frames = ((tx_clk - e->page_frozen_clk) & 0x0FFFFFFFu) >> 2;
		if (elapsed_frames > 8u || e->page_rsp_retries >= 8u) {
			e->state = BR_STATE_PAGE;
			schedule_next_step(e);
			return;
		}
		uint8_t n_prm = (uint8_t)(elapsed_frames & 0x1Fu);
		uint8_t xprm = 0;
		uint8_t ch_tx = br_hop_master_page_rsp_tx(e->peer_ulap, e->page_frozen_xp, n_prm, &xprm);
		uint8_t ch_rx = br_hop_master_page_rsp_rx(e->peer_ulap, e->page_frozen_xp, n_prm);

		br_fhs_t fhs;
		memset(&fhs, 0, sizeof(fhs));
		fhs.parity34        = e->local_cac_sw & 0x3FFFFFFFFULL;
		fhs.lap             = e->local_lap;
		fhs.eir             = false;
		fhs.sr              = 1u; /* R1 */
		fhs.sp              = 2u;
		fhs.uap             = e->local_uap;
		fhs.nap             = e->local_nap;
		fhs.class_of_device = 0x2C041Cu; /* Audio/Capturing + Rendering Portable Audio Source */
		fhs.lt_addr         = e->lt_addr;
		fhs.clk27_2         = (tx_clk >> 2) & 0x03FFFFFFu;
		fhs.page_scan_mode  = 0u;

		uint8_t fhs18[18];
		br_fhs_pack(&fhs, fhs18);

		br_pkt_hdr_t hdr = {
			.lt_addr = 0u, /* FHS header always uses LT_ADDR = 0 */
			.type    = BR_PKT_FHS,
			.flow    = 1u,
			.arqn    = 0u,
			.seqn    = 0u,
		};
		br_radio_tx_req_t tx;
		/* FHS in Master Page Response uses paged Slave's DAC, paged Slave's UAP, and 0x60|X_prm whitening! */
		br_air_build_packet_tx(e->peer_dac_sw, e->peer_uap, br_whiten_seed_x(xprm),
				&hdr, fhs18, 18u, NULL, NULL, ch_tx, tx_us, e->knobs.tx_mode, &tx);
		tx.slot_tag = TAG_MAKE(PHASE_PAGE_RSP, tx_clk);

		br_radio_rx_req_t rx;
		memset(&rx, 0, sizeof(rx));
		rx.anchor_us       = rx_us;
		rx.rx_sync_win_us  = 80u;
		rx.max_duration_us = 220u;
		rx.chan_1mhz       = ch_rx;
		rx.access_addr     = (uint32_t)(e->peer_dac_sw & 0xFFFFFFFFULL);
		rx.id_only         = true;
		rx.slot_tag        = TAG_MAKE(PHASE_PAGE_RSP, (tx_clk + 2u) & 0x0FFFFFFFu);

		e->page_n_prm       = (uint8_t)((e->page_n_prm + 1u) & 0x1Fu);
		e->page_rsp_retries++;
		e->page_progress.fhs_tx++;
		e->next_sched_clk   = (tx_clk + 4u) & 0x0FFFFFFFu;
		queue_pair(e, &tx, &rx);
		return;
	}

	if (e->state == BR_STATE_NEW_CONN_POLL) {
		if (e->new_conn_retries >= 32u) {
			uint8_t peer[6];
			memcpy(peer, e->peer_bdaddr, 6);
			teardown_link_to_idle(e, 0u, false);
			memcpy(e->peer_bdaddr, peer, 6);
			send_conn_complete(e, 0x3Eu); /* Connection Failed to be Established */
			return;
		}
		uint32_t tx_clk = pick_next_master_clk(e, e->next_sched_clk);
		uint32_t tx_us  = clk_to_us(e, tx_clk);
		uint32_t rx_clk = (tx_clk + 2u) & 0x0FFFFFFFu;
		uint32_t rx_us  = tx_us + BR_SLOT_US;

		uint8_t ch_tx = br_hop_connection_79(e->local_ulap, tx_clk);
		uint8_t ch_rx = br_hop_connection_79(e->local_ulap, rx_clk);

		br_pkt_hdr_t hdr = {
			.lt_addr = e->lt_addr,
			.type    = BR_PKT_POLL,
			.flow    = 1u,
			.arqn    = 0u,
			.seqn    = 1u,
		};
		br_radio_tx_req_t tx;
		br_air_build_packet_tx(e->local_cac_sw, e->local_uap, br_whiten_seed_clk(tx_clk),
				&hdr, NULL, 0u, NULL, NULL, ch_tx, tx_us, e->knobs.tx_mode, &tx);
		tx.slot_tag = TAG_MAKE(PHASE_NEW_CONN, tx_clk);

		br_radio_rx_req_t rx;
		memset(&rx, 0, sizeof(rx));
		rx.anchor_us       = rx_us;
		rx.rx_sync_win_us  = 80u;
		rx.max_duration_us = 500u;
		rx.chan_1mhz       = ch_rx;
		rx.access_addr     = (uint32_t)(e->local_cac_sw & 0xFFFFFFFFULL);
		rx.id_only         = false;
		rx.slot_tag        = TAG_MAKE(PHASE_NEW_CONN, rx_clk);

		e->new_conn_retries++;
		e->page_progress.polls_tx++;
		e->next_sched_clk = (tx_clk + 4u) & 0x0FFFFFFFu;
		queue_pair(e, &tx, &rx);
		return;
	}

	if (e->state == BR_STATE_CONNECTED) {
		if ((int32_t)(now - e->last_peer_rx_us) >= (int32_t)e->lsto_us) {
			teardown_link_to_idle(e, 0x08u, true); /* Connection Timeout */
			return;
		}

		bool has_work = e->arq_waiting_ack || (e->lmp_count > 0u) ||
		                (!e->l2cap_paused_for_enc && e->peer_flow_go && e->acl_count > 0u) ||
		                (e->peer_arqn_to_send == 1u);

		e->build_class = has_work ? 1u : 0u;
		uint32_t target_min_clk = e->next_sched_clk;
		if (!has_work) {
			uint32_t poll_step = (uint32_t)(e->knobs.poll_interval_slots & ~1u) * 2u;
			if (poll_step < 8u) {
				poll_step = 8u;
			}
			uint32_t poll_clk = (e->last_poll_clk + poll_step) & 0x0FFFFFFFu;
			int32_t wait_us = (int32_t)(clk_to_us(e, poll_clk) - now);
			if (wait_us > 3500) {
				/* Sleep between idle POLLs so BLE/Wi-Fi gets 100% uncontested radio time! */
				if (e->ops.timer_start) {
					e->ops.timer_start(e->ops.ctx, (uint32_t)(wait_us - 2000));
				}
				return;
			}
			target_min_clk = poll_clk;
		}

		uint32_t tx_clk = pick_next_master_clk(e, target_min_clk);
		uint32_t tx_us  = clk_to_us(e, tx_clk);

		br_pkt_hdr_t hdr;
		uint8_t body[240];
		uint16_t body_len = 0;
		bool do_enc = false;
		prepare_next_acl_tx(e, tx_clk, &hdr, body, &body_len, &do_enc);

		uint8_t slots = br_pkt_slot_count(hdr.type); /* 1 for POLL/DM1/DH1, 3 for DM3/DH3 */
		uint32_t rx_clk = (tx_clk + (uint32_t)slots * 2u) & 0x0FFFFFFFu;
		uint32_t rx_us  = tx_us + (uint32_t)slots * BR_SLOT_US;

		uint8_t ch_tx = br_hop_connection(e->local_ulap, tx_clk, &e->afh);
		/* Same channel mechanism of AFH (Core Spec Vol 2 Part B 2.6.4.7): "the Peripheral responds with its
		 * packet on the same RF channel that was used by the Central to address that Peripheral". After a
		 * 3-slot packet that is the packet's channel, not the one of the Central slot just before the answer,
		 * which br_hop_connection would give for rx_clk (sound trials 3 to 6: AFH went on when the stream
		 * started and no answer to a 3-slot packet was ever heard). */
		uint8_t ch_rx = e->afh.enabled ? ch_tx : br_hop_connection(e->local_ulap, rx_clk, &e->afh);

		e0_cb_ctx_t e0_tx = {
			.kc_prime      = e->kc_prime,
			.master_bdaddr = e->local_bdaddr,
			.clk           = tx_clk,
		};
		br_radio_tx_req_t tx;
		br_air_build_packet_tx(e->local_cac_sw, e->local_uap, br_whiten_seed_clk(tx_clk),
				&hdr, body, body_len,
				do_enc ? e0_cipher_adapter : NULL, do_enc ? &e0_tx : NULL,
				ch_tx, tx_us, e->knobs.tx_mode, &tx);
		tx.slot_tag = TAG_MAKE(PHASE_ACL, tx_clk);

		br_radio_rx_req_t rx;
		memset(&rx, 0, sizeof(rx));
		rx.anchor_us       = rx_us;
		rx.rx_sync_win_us  = 80u;
		rx.max_duration_us = 500u;
		rx.chan_1mhz       = ch_rx;
		rx.access_addr     = (uint32_t)(e->local_cac_sw & 0xFFFFFFFFULL);
		rx.id_only         = false;
		rx.slot_tag        = TAG_MAKE(PHASE_ACL, rx_clk);

		e->pair_chan = ch_tx;
		/* Clear one-shot ACK once sent in a scheduled Master TX */
		e->peer_arqn_to_send = 0u;
		e->last_poll_clk     = tx_clk;
		e->next_sched_clk    = (rx_clk + 2u) & 0x0FFFFFFFu;
		queue_pair(e, &tx, &rx);
	}
}

void br_engine_on_tx_done(br_engine_t *e, uint32_t slot_tag, bool skipped)
{
	(void)slot_tag;
	if (!e) {
		return;
	}
	if (skipped) {
		e->stats.slots_skipped++;
		e->pair_tx_skipped = true;
	} else {
		e->stats.slots_tx++;
	}
}

static void handle_inquiry_fhs(br_engine_t *e, uint32_t rx_clk, const br_fhs_t *fhs, int8_t rssi)
{
	uint8_t bd[6];
	br_parts_to_bdaddr(fhs->lap, fhs->uap, fhs->nap, bd);

	/* Deduplicate within current Inquiry window unless EIR needed */
	for (uint8_t i = 0; i < BR_MAX_INQ_CACHE; i++) {
		if (e->inq_seen[i].used && memcmp(e->inq_seen[i].bd_addr, bd, 6) == 0) {
			return;
		}
	}
	for (uint8_t i = 0; i < BR_MAX_INQ_CACHE; i++) {
		if (!e->inq_seen[i].used) {
			e->inq_seen[i].used = true;
			memcpy(e->inq_seen[i].bd_addr, bd, 6);
			break;
		}
	}

	uint16_t clk_off = (uint16_t)((fhs->clk27_2 - (rx_clk >> 2)) & 0x7FFFu);

	/* Emit Inquiry_Result_with_RSSI (0x22, 15 bytes) */
	uint8_t p[15];
	p[0] = 1u;
	memcpy(&p[1], bd, 6);
	p[7]  = fhs->sr;
	p[8]  = 0u;
	p[9]  = (uint8_t)(fhs->class_of_device & 0xFFu);
	p[10] = (uint8_t)((fhs->class_of_device >> 8) & 0xFFu);
	p[11] = (uint8_t)((fhs->class_of_device >> 16) & 0xFFu);
	p[12] = (uint8_t)(clk_off & 0xFFu);
	p[13] = (uint8_t)((clk_off >> 8) & 0xFFu);
	p[14] = (uint8_t)rssi;
	send_hci_evt(e, BR_HCI_EVT_INQUIRY_RESULT_RSSI, p, sizeof(p));
	e->inq_rsp_cnt++;
}

static void process_acl_ack(br_engine_t *e)
{
	if (!e->arq_waiting_ack) {
		return;
	}
	bool was_l2cap = e->arq_is_l2cap_frag;
	e->arq_waiting_ack      = false;
	e->arq_is_l2cap_frag    = false;
	e->arq_is_enc_start_lmp = false;
	e->arq_naks_in_row      = 0;
	e->arq_unanswered       = 0;
	e->arq_probe_due        = false;
	e->size_suspect         = false;
	e->stats.tx_acks++;

	if (was_l2cap && e->acl_count > 0u) {
		acl_sdu_slot_t *sdu = &e->acl_q[e->acl_head];
		if (sdu->offset >= sdu->len) {
			sdu->in_use = false;
			e->acl_head = (uint8_t)((e->acl_head + 1u) % BR_ACL_TX_CREDITS);
			e->acl_count--;
			e->stats.acl_sdu_tx++;
			send_num_completed_pkts(e, 1u);
		}
	}
}

static void handle_connected_rx(br_engine_t *e, uint32_t rx_clk, const br_radio_rx_ind_t *ind)
{
	e0_cb_ctx_t e0_rx = {
		.kc_prime      = e->kc_prime,
		.master_bdaddr = e->local_bdaddr,
		.clk           = rx_clk,
	};
	br_rx_decoded_t dec;
	bool ok = br_air_extract_rx(e->local_cac_sw, e->local_uap, br_whiten_seed_clk(rx_clk),
			false,
			e->enc_rx_on ? e0_cipher_adapter : NULL,
			e->enc_rx_on ? &e0_rx : NULL,
			ind, &dec);

	/* During encryption startup (enc_rx_on && !enc_tx_on), Slave might reject encryption unencrypted */
	if (ok && dec.hec_ok && !dec.crc_ok && e->enc_rx_on && !e->enc_tx_on) {
		br_rx_decoded_t unenc;
		if (br_air_extract_rx(e->local_cac_sw, e->local_uap, br_whiten_seed_clk(rx_clk),
				false, NULL, NULL, ind, &unenc) && unenc.crc_ok) {
			dec = unenc;
			ok  = true;
		}
	}

	if (!ok || !dec.hec_ok) {
		if (ind->sync_matched) {
			e->stats.rx_hec_err++;
		}
		return;
	}
	e->stats.rx_hec_ok++;
	e->last_peer_rx_us = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : e->clk_ref_us;
	e->peer_flow_go    = (dec.hdr.flow != 0u);

	/* Process Slave's ARQN feedback on our previous Master packet (valid whenever HEC passed!). The answer to a POLL
	 * sent in a packet's place (see size_evidence) only shows that the peer is there: a peer that sets ACK on every
	 * POLL would otherwise acknowledge a packet it never took, and one that has the packet acknowledges it again
	 * when it comes once more ("the ARQN bit shall be set to ACK and the payload shall be ignored", 7.6.1). */
	if (e->pair_kind == PAIR_PROBE) {
		/* neither an acknowledgement nor a refusal of the packet */
	} else if (dec.hdr.arqn == 1u) {
		process_acl_ack(e);
	} else if (e->arq_waiting_ack) {
		e->stats.tx_naks++;
		e->arq_naks_in_row++;
	}

	if (!br_pkt_has_crc(dec.hdr.type)) {
		/* NULL or POLL packet: POLL requires an explicit ACK/response even though no payload */
		if (dec.hdr.type == BR_PKT_POLL) {
			e->peer_arqn_to_send = 1u;
		}
		return;
	}

	if (!dec.crc_ok) {
		e->stats.rx_crc_err++;
		e->peer_arqn_to_send = 0u; /* NAK */
		return;
	}
	e->stats.rx_crc_ok++;
	e->peer_arqn_to_send = 1u; /* ACK */

	/* Filter duplicate Slave retransmissions via SEQN */
	if (dec.hdr.seqn == e->last_rx_seqn) {
		return;
	}
	e->last_rx_seqn = dec.hdr.seqn;

	bool multislot = br_pkt_is_multislot(dec.hdr.type);
	uint8_t llid = 0, aflow = 0, hb = 0;
	uint16_t plen = 0;
	if (!br_acl_hdr_unpack(multislot, dec.body, dec.body_len, &llid, &aflow, &plen, &hb)) {
		return;
	}
	(void)aflow;
	const uint8_t *pay = &dec.body[hb];
	if (plen == 0u) {
		return;
	}

	if (llid == BR_LLID_LMP) {
		e->stats.lmp_rx_cnt++;
		/* Check atomic E0 startup completion: LMP_accepted(17) or LMP_not_accepted(17, err) */
		if (e->l2cap_paused_for_enc && plen >= 2u) {
			uint8_t op = (uint8_t)(pay[0] >> 1);
			if (op == 3u && pay[1] == 17u) {
				e->enc_tx_on            = true;
				e->l2cap_paused_for_enc = false;
				send_vendor_enc_state(e, 0x00u, true);
			} else if (op == 4u && pay[1] == 17u) {
				uint8_t err = (plen >= 3u) ? pay[2] : 0x1Fu;
				e->enc_rx_on            = false;
				e->enc_tx_on            = false;
				e->l2cap_paused_for_enc = false;
				send_vendor_enc_state(e, err, false);
			}
		}
		send_vendor_lmp_rx(e, pay, (uint8_t)plen);
		return;
	}

	if (llid == BR_LLID_L2CAP_START) {
		if (plen < 4u) {
			e->rx_reasm_active = false;
			return;
		}
		uint16_t l2_len = (uint16_t)((uint16_t)pay[0] | ((uint16_t)pay[1] << 8));
		uint16_t total  = (uint16_t)(4u + l2_len);
		if (total > BR_ACL_RX_REASM_MAX) {
			e->rx_reasm_active = false;
			return;
		}
		uint16_t copy = (plen > total) ? total : plen;
		memcpy(e->rx_reasm_buf, pay, copy);
		e->rx_reasm_len      = copy;
		e->rx_reasm_expected = total;
		if (e->rx_reasm_len >= e->rx_reasm_expected) {
			e->rx_reasm_active = false;
			deliver_acl_sdu_to_host(e, e->rx_reasm_buf, e->rx_reasm_expected);
		} else {
			e->rx_reasm_active = true;
		}
	} else if (llid == BR_LLID_L2CAP_CONT && e->rx_reasm_active) {
		uint16_t space = (uint16_t)(e->rx_reasm_expected - e->rx_reasm_len);
		uint16_t copy  = (plen > space) ? space : plen;
		memcpy(&e->rx_reasm_buf[e->rx_reasm_len], pay, copy);
		e->rx_reasm_len = (uint16_t)(e->rx_reasm_len + copy);
		if (e->rx_reasm_len >= e->rx_reasm_expected) {
			e->rx_reasm_active = false;
			deliver_acl_sdu_to_host(e, e->rx_reasm_buf, e->rx_reasm_expected);
		}
	}
}

/* The end of a pair on the connection: the peer's packet, if one came, and what the pair says about the link. */
static void acl_pair_done(br_engine_t *e, uint32_t rx_clk, const br_radio_rx_ind_t *ind)
{
	const uint8_t  kind     = e->pair_kind;
	const bool     data_out = e->arq_waiting_ack && e->arq_is_l2cap_frag;
	const uint8_t  cls      = data_out ? arq_size_class(e) : 2u;
	const uint32_t heard0   = e->stats.rx_hec_ok;
	const uint32_t heard_at = e->last_peer_rx_us;

	if (ind->sync_matched) {
		handle_connected_rx(e, rx_clk, ind);
	}
	e->pair_kind = PAIR_OTHER;
	if (e->pair_tx_skipped) {
		return; /* nothing went out: the pair says nothing about the peer */
	}
	const bool heard = (e->stats.rx_hec_ok != heard0);

	const uint8_t ch = e->pair_chan;
	if (ch < BR_NUM_CHANNELS) {
		if (e->chan_tried[ch] == 0xFFu) {
			e->chan_tried[ch] >>= 1;
			e->chan_heard[ch] >>= 1;
		}
		e->chan_tried[ch]++;
		if (heard) {
			e->chan_heard[ch]++;
		}
	}
	if (heard) {
		if (e->silent_run >= BR_GAP_MIN_PAIRS) {
			if (e->gap_count < BR_GAP_LOG) {
				const uint32_t len = (e->last_peer_rx_us - heard_at) / 100u;
				br_gap_t *g  = &e->gaps[e->gap_count++];
				g->start_us  = heard_at;
				g->len_100us = (len > 0xFFFFu) ? 0xFFFFu : (uint16_t)len;
				g->pairs     = e->silent_run;
			} else if (e->gap_missed < 0xFFFFu) {
				e->gap_missed++;
			}
		}
		e->silent_run = 0u;
	} else {
		if (e->silent_run < 0xFFFFu) {
			e->silent_run++;
		}
		if (e->silent_run > e->silent_run_max) {
			e->silent_run_max = e->silent_run;
		}
	}
	if (data_out && cls < 2u && e->peer_flow_go) {
		size_evidence(e, kind, cls, heard);
	}
}

void br_engine_on_rx_done(br_engine_t *e, uint32_t slot_tag, const br_radio_rx_ind_t *ind)
{
	if (!e || !ind) {
		return;
	}
	if (!e->pair_in_flight || slot_tag != e->pair_rx_tag) {
		return; /* the report of a pair already given up: the pair in flight, if any, is another one */
	}
	e->pair_in_flight = false;

	if (ind->skipped) {
		e->stats.slots_skipped++;
		schedule_next_step(e);
		return;
	}
	e->stats.slots_rx++;
	if (ind->sync_matched) {
		e->stats.rx_sync_ok++;
	}

	uint8_t phase   = (uint8_t)TAG_PHASE(slot_tag);
	uint32_t rx_clk = TAG_CLK(slot_tag);

	if (phase == PHASE_INQ && e->state == BR_STATE_INQUIRY && ind->sync_matched) {
		br_rx_decoded_t dec;
		if (br_air_extract_rx(e->inq_sw, BR_DCI_UAP, br_whiten_seed_x(e->inq_last_x),
				true, NULL, NULL, ind, &dec) &&
		    dec.crc_ok && dec.hdr.type == BR_PKT_FHS && dec.body_len == 18u) {
			e->stats.rx_hec_ok++;
			e->stats.rx_crc_ok++;
			br_fhs_t fhs;
			br_fhs_unpack(dec.body, &fhs);
			handle_inquiry_fhs(e, rx_clk, &fhs, ind->rssi_dbm);
		}
	} else if (phase == PHASE_PAGE && e->state == BR_STATE_PAGE && ind->sync_matched) {
		br_rx_decoded_t dec;
		if (br_air_extract_rx(e->peer_dac_sw, e->peer_uap, 0x7Fu, false, NULL, NULL, ind, &dec) &&
		    dec.sync_ok) {
			/* Speaker replied with 68-bit ID(DAC)! Transition immediately to Master Page Response (FHS)! */
			e->page_progress.id_answers++;
			e->state            = BR_STATE_PAGE_MASTER_RSP;
			e->page_frozen_xp   = e->page_last_xp;
			e->page_frozen_clk  = (rx_clk - 2u) & 0x0FFFFFFCu;
			e->page_n_prm       = 1u;
			e->page_rsp_retries = 0u;
		}
	} else if (phase == PHASE_PAGE_RSP && e->state == BR_STATE_PAGE_MASTER_RSP && ind->sync_matched) {
		br_rx_decoded_t dec;
		if (br_air_extract_rx(e->peer_dac_sw, e->peer_uap, 0x7Fu, false, NULL, NULL, ind, &dec) &&
		    dec.sync_ok) {
			/* Speaker acknowledged FHS with second ID(DAC)! Switch to Master CAC + Connection hop! */
			e->page_progress.fhs_acks++;
			e->state            = BR_STATE_NEW_CONN_POLL;
			e->new_conn_retries = 0u;
		}
	} else if (phase == PHASE_NEW_CONN && e->state == BR_STATE_NEW_CONN_POLL && ind->sync_matched) {
		br_rx_decoded_t dec;
		if (br_air_extract_rx(e->local_cac_sw, e->local_uap, br_whiten_seed_clk(rx_clk),
				false, NULL, NULL, ind, &dec) && dec.hec_ok) {
			/* Connection established on Master CAC! */
			e->stats.rx_hec_ok++;
			e->state              = BR_STATE_CONNECTED;
			e->tx_max_slots       = 1u;
			e->tx_size_level      = 0u;
			e->size_hold_exp      = 0u;
			e->size_retry_us      = 0u;
			e->size_suspect       = false;
			e->tx_flushes         = 0u;
			e->arq_unanswered     = 0u;
			e->arq_probe_due      = false;
			e->pair_kind          = PAIR_OTHER;
			e->size_strikes_total = 0u;
			e->probes             = 0u;
			e->pairs_refused      = 0u;
			e->silent_run         = 0u;
			e->silent_run_max     = 0u;
			memset(e->size_strikes, 0, sizeof(e->size_strikes));
			memset(e->chan_tried, 0, sizeof(e->chan_tried));
			memset(e->chan_heard, 0, sizeof(e->chan_heard));
			e->gap_count  = 0u;
			e->gap_missed = 0u;
			e->tx_seqn            = 1u; /* Next new TX toggles to 0 or 1; POLL used 1 so first DM1 toggles to 0! */
			e->last_rx_seqn       = 0xFFu;
			e->peer_arqn_to_send  = 0u;
			e->peer_flow_go       = true;
			e->arq_waiting_ack    = false;
			e->last_peer_rx_us    = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : e->clk_ref_us;
			e->last_poll_clk      = rx_clk;
			send_conn_complete(e, 0x00u);

			/* Also process payload if Slave already piggybacked an LMP PDU in its first response! */
			if (br_pkt_has_crc(dec.hdr.type) && dec.crc_ok) {
				handle_connected_rx(e, rx_clk, ind);
			}
		}
	} else if (phase == PHASE_ACL && e->state == BR_STATE_CONNECTED) {
		acl_pair_done(e, rx_clk, ind);
	}

	schedule_next_step(e);
}

void br_engine_on_timer(br_engine_t *e)
{
	if (!e) {
		return;
	}
	if (e->pair_in_flight) {
		uint32_t now = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : e->clk_ref_us;
		if ((int32_t)(now - e->pair_deadline_us) < 0) {
			return; /* a wake left over from an earlier timer: the one set for this pair is still to come */
		}
		e->stats.pairs_lost++;
		e->pair_in_flight = false;
		if (e->ops.cancel_all) {
			e->ops.cancel_all(e->ops.ctx);
		}
	}
	schedule_next_step(e);
}

/* ==== Host-to-Controller HCI Command & ACL Handler ==== */
static void handle_vendor_brc6(br_engine_t *e, const uint8_t *param, uint8_t plen)
{
	uint8_t sub = param[4];
	switch (sub) {
	case BR_VS_PING: {
		uint32_t now = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : e->clk_ref_us;
		sync_clk_to_now(e, now);
		uint8_t ret[16];
		ret[0] = BR_VENDOR_MAGIC_0;
		ret[1] = BR_VENDOR_MAGIC_1;
		ret[2] = BR_VENDOR_MAGIC_2;
		ret[3] = BR_VENDOR_MAGIC_3;
		ret[4] = BR_VS_PING;
		ret[5] = (uint8_t)e->state;
		memcpy(&ret[6], e->local_bdaddr, 6);
		ret[12] = (uint8_t)(e->clk_ref & 0xFFu);
		ret[13] = (uint8_t)((e->clk_ref >> 8) & 0xFFu);
		ret[14] = (uint8_t)((e->clk_ref >> 16) & 0xFFu);
		ret[15] = (uint8_t)((e->clk_ref >> 24) & 0xFFu);
		send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x00u, ret, sizeof(ret));
		break;
	}
	case BR_VS_GET_DIAG: {
		/* The counters, then the build times (late pairs, longest build, allowance: three 16-bit values), then
		 * br_link_diag_t field by field. The longest silent run starts again with each answer. */
		uint8_t ret[5 + sizeof(br_diag_stats_t) + sizeof(br_build_times_t) + 10u];
		ret[0] = BR_VENDOR_MAGIC_0;
		ret[1] = BR_VENDOR_MAGIC_1;
		ret[2] = BR_VENDOR_MAGIC_2;
		ret[3] = BR_VENDOR_MAGIC_3;
		ret[4] = BR_VS_GET_DIAG;
		memcpy(&ret[5], &e->stats, sizeof(e->stats));
		memcpy(&ret[5 + sizeof(e->stats)], &e->build_times, sizeof(e->build_times));
		uint8_t *ld = &ret[5 + sizeof(e->stats) + sizeof(e->build_times)];
		ld[0] = e->tx_max_slots;
		ld[1] = e->tx_size_level;
		ld[2] = e->tx_flushes;
		ld[3] = e->size_strikes_total;
		ld[4] = (uint8_t)(e->probes & 0xFFu);
		ld[5] = (uint8_t)(e->probes >> 8);
		ld[6] = (uint8_t)(e->pairs_refused & 0xFFu);
		ld[7] = (uint8_t)(e->pairs_refused >> 8);
		ld[8] = (uint8_t)(e->silent_run_max & 0xFFu);
		ld[9] = (uint8_t)(e->silent_run_max >> 8);
		e->silent_run_max = e->silent_run;
		send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x00u, ret, sizeof(ret));
		break;
	}
	case BR_VS_GET_GAPS: {
		br_gap_t gaps[BR_GAP_LOG];
		uint16_t missed = 0u;
		const uint8_t n = br_engine_take_gaps(e, gaps, &missed);
		uint8_t ret[5 + 3 + 8u * BR_GAP_LOG];
		ret[0] = BR_VENDOR_MAGIC_0;
		ret[1] = BR_VENDOR_MAGIC_1;
		ret[2] = BR_VENDOR_MAGIC_2;
		ret[3] = BR_VENDOR_MAGIC_3;
		ret[4] = BR_VS_GET_GAPS;
		ret[5] = n;
		ret[6] = (uint8_t)(missed & 0xFFu);
		ret[7] = (uint8_t)(missed >> 8);
		for (uint8_t i = 0; i < n; i++) {
			uint8_t *g = &ret[8u + 8u * i];
			g[0] = (uint8_t)(gaps[i].start_us & 0xFFu);
			g[1] = (uint8_t)((gaps[i].start_us >> 8) & 0xFFu);
			g[2] = (uint8_t)((gaps[i].start_us >> 16) & 0xFFu);
			g[3] = (uint8_t)((gaps[i].start_us >> 24) & 0xFFu);
			g[4] = (uint8_t)(gaps[i].len_100us & 0xFFu);
			g[5] = (uint8_t)(gaps[i].len_100us >> 8);
			g[6] = (uint8_t)(gaps[i].pairs & 0xFFu);
			g[7] = (uint8_t)(gaps[i].pairs >> 8);
		}
		send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x00u, ret, (uint8_t)(8u + 8u * n));
		break;
	}
	case BR_VS_GET_CHAN_STATS: {
		uint8_t ret[5 + 2u * BR_NUM_CHANNELS];
		ret[0] = BR_VENDOR_MAGIC_0;
		ret[1] = BR_VENDOR_MAGIC_1;
		ret[2] = BR_VENDOR_MAGIC_2;
		ret[3] = BR_VENDOR_MAGIC_3;
		ret[4] = BR_VS_GET_CHAN_STATS;
		memcpy(&ret[5], e->chan_tried, BR_NUM_CHANNELS);
		memcpy(&ret[5 + BR_NUM_CHANNELS], e->chan_heard, BR_NUM_CHANNELS);
		send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x00u, ret, sizeof(ret));
		break;
	}
	case BR_VS_SET_KNOBS: {
		if (plen < 9u) {
			send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x12u, NULL, 0u);
			break;
		}
		e->knobs.tx_mode             = (param[5] != 0u) ? BR_TX_MODE_DIRECT_AA : BR_TX_MODE_IN_PAYLOAD;
		e->knobs.gauss_bt05          = (param[6] != 0u);
		e->knobs.dh3_max_bytes       = (param[7] >= 20u && param[7] <= BR_MAX_DH3_BYTES) ? param[7] : BR_DEFAULT_DH3_CAP;
		e->knobs.poll_interval_slots = (param[8] >= 4u) ? param[8] : 24u;
		if (plen >= 10u) {
			e->knobs.prefer_fec_dm = (param[9] != 0u);
		}
		if (plen >= 11u) {
			e->knobs.id_ends_with_sync = (param[10] != 0u);
		}
		if (e->ops.set_gauss_bt05 && e->state != BR_STATE_IDLE) {
			e->ops.set_gauss_bt05(e->ops.ctx, e->knobs.gauss_bt05);
		}
		send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x00u, NULL, 0u);
		break;
	}
	case BR_VS_SET_TX_SLOTS: {
		/* [magic4][0x0A][slots] */
		if (e->state != BR_STATE_CONNECTED || plen < 6u) {
			send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x0Cu, NULL, 0u);
			break;
		}
		e->tx_max_slots = (param[5] >= 3u) ? 3u : 1u;
		send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x00u, NULL, 0u);
		break;
	}
	case BR_VS_SEND_LMP: {
		/* [magic4][0x04][handle_lo][handle_hi][lmp_len][lmp_bytes...] */
		if (e->state != BR_STATE_CONNECTED || plen < 9u) {
			send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x0Cu, NULL, 0u);
			break;
		}
		uint8_t lmp_len = param[7];
		if (lmp_len == 0u || lmp_len > BR_MAX_DM1_BYTES || (uint16_t)(8u + lmp_len) > plen) {
			send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x12u, NULL, 0u);
			break;
		}
		if (!enqueue_lmp_tx(e, &param[8], lmp_len)) {
			send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x07u, NULL, 0u);
			break;
		}
		send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x00u, NULL, 0u);
		schedule_next_step(e);
		break;
	}
	case BR_VS_START_ENC: {
		/* [magic4][0x05][handle_lo][handle_hi][en_rand16][kc_prime16] (total 39 B) */
		if (e->state != BR_STATE_CONNECTED || plen < 39u) {
			send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x0Cu, NULL, 0u);
			break;
		}
		const uint8_t *en_rand  = &param[7];
		const uint8_t *kc_prime = &param[23];
		memcpy(e->kc_prime, kc_prime, 16);

		uint8_t pdu[17];
		pdu[0] = (uint8_t)((17u << 1) | 0u); /* LMP_start_encryption_req, TID=0 */
		memcpy(&pdu[1], en_rand, 16);
		if (!enqueue_lmp_tx(e, pdu, 17u)) {
			send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x07u, NULL, 0u);
			break;
		}
		e->l2cap_paused_for_enc = true;
		e->enc_rx_on            = true;
		e->enc_tx_on            = false;
		send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x00u, NULL, 0u);
		schedule_next_step(e);
		break;
	}
	case BR_VS_STOP_ENC: {
		e->enc_rx_on            = false;
		e->enc_tx_on            = false;
		e->l2cap_paused_for_enc = false;
		send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x00u, NULL, 0u);
		break;
	}
	case BR_VS_SET_AFH: {
		/* [magic4][0x07][handle_lo][handle_hi][mode][map10] (total 18 B) */
		if (e->state != BR_STATE_CONNECTED || plen < 18u) {
			send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x0Cu, NULL, 0u);
			break;
		}
		uint8_t mode = param[7];
		const uint8_t *map10 = &param[8];
		if (mode != 0u) {
			br_afh_state_t test_afh;
			if (!br_afh_init(&test_afh, map10)) {
				send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x12u, NULL, 0u);
				break;
			}
		}
		uint32_t now = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : e->clk_ref_us;
		sync_clk_to_now(e, now);
		uint32_t inst_clk = (e->clk_ref + 320u) & 0x0FFFFFFCu; /* ~100 ms ahead */
		uint32_t inst27   = (inst_clk >> 1) & 0x07FFFFFFu;

		uint8_t pdu[16];
		pdu[0] = (uint8_t)((60u << 1) | 0u); /* LMP_set_afh, TID=0 */
		pdu[1] = (uint8_t)(inst27 & 0xFFu);
		pdu[2] = (uint8_t)((inst27 >> 8) & 0xFFu);
		pdu[3] = (uint8_t)((inst27 >> 16) & 0xFFu);
		pdu[4] = (uint8_t)((inst27 >> 24) & 0xFFu);
		pdu[5] = (mode != 0u) ? 1u : 0u;
		memcpy(&pdu[6], map10, 10);
		pdu[15] &= 0x7Fu;

		if (!enqueue_lmp_tx(e, pdu, 16u)) {
			send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x07u, NULL, 0u);
			break;
		}
		e->afh_pending        = true;
		e->afh_instant_clk    = inst_clk;
		e->afh_pending_enable = (mode != 0u);
		memcpy(e->afh_pending_map, &pdu[6], 10);
		send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x00u, NULL, 0u);
		schedule_next_step(e);
		break;
	}
	case BR_VS_SET_BD_ADDR: {
		if (e->state != BR_STATE_IDLE || plen < 12u) {
			send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x0Cu, NULL, 0u);
			break;
		}
		uint8_t bd[6];
		if (param[11] != 0u) {
			br_derive_c6_bdaddr(&param[5], 46u, bd);
		} else {
			memcpy(bd, &param[5], 6);
		}
		refresh_local_identity(e, bd);
		send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x00u, bd, 6u);
		break;
	}
	case BR_VS_ABORT_ALL: {
		teardown_link_to_idle(e, 0x16u, true);
		send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x00u, NULL, 0u);
		break;
	}
	default:
		send_cmd_complete(e, BR_HCI_OP_VENDOR_BRC6, 0x11u, NULL, 0u);
		break;
	}
}

bool br_engine_hci_from_host(br_engine_t *e, const uint8_t *h4, uint16_t len)
{
	if (!e || !h4 || len < 1u) {
		return false;
	}

	/* ACL H4 packet (0x02): intercept ONLY if handle == BR_ACL_HANDLE_BASE (0x0B00)! */
	if (h4[0] == BR_H4_ACL) {
		if (len < 5u) {
			return false;
		}
		uint16_t raw_h  = (uint16_t)((uint16_t)h4[1] | ((uint16_t)h4[2] << 8));
		uint16_t handle = (uint16_t)(raw_h & 0x0FFFu);
		if (handle != BR_ACL_HANDLE_BASE) {
			return false; /* Pass BLE ACL handles straight through to C6 BLE controller! */
		}
		uint16_t dlen = (uint16_t)((uint16_t)h4[3] | ((uint16_t)h4[4] << 8));
		if (e->state != BR_STATE_CONNECTED || (uint32_t)(5u + dlen) > len ||
		    dlen == 0u || dlen > BR_ACL_SDU_MAX) {
			return true;
		}
		if (e->acl_count >= BR_ACL_TX_CREDITS) {
			/* Return credit defensively if host overflowed so host never wedges */
			send_num_completed_pkts(e, 1u);
			return true;
		}
		acl_sdu_slot_t *slot = &e->acl_q[e->acl_tail];
		slot->in_use = true;
		slot->len    = dlen;
		slot->offset = 0u;
		memcpy(slot->data, &h4[5], dlen);
		e->acl_tail = (uint8_t)((e->acl_tail + 1u) % BR_ACL_TX_CREDITS);
		e->acl_count++;
		schedule_next_step(e);
		return true;
	}

	if (h4[0] != BR_H4_CMD || len < 4u) {
		return false;
	}

	uint16_t opcode = (uint16_t)((uint16_t)h4[1] | ((uint16_t)h4[2] << 8));
	uint8_t plen    = h4[3];
	if ((uint16_t)(4u + plen) > len) {
		return false;
	}
	const uint8_t *param = &h4[4];

	/* HCI_Reset (0x0C03): reset Soft-BR AND return false so stock BLE + CIS also reset! */
	if (opcode == BR_HCI_OP_RESET) {
		br_engine_reset(e);
		return false;
	}

	/* HCI_Disconnect (0x0406): consume ONLY if handle == BR_ACL_HANDLE_BASE! */
	if (opcode == BR_HCI_OP_DISCONNECT) {
		if (plen < 3u) {
			return false;
		}
		uint16_t handle = (uint16_t)((uint16_t)param[0] | ((uint16_t)param[1] << 8));
		if ((handle & 0x0FFFu) != BR_ACL_HANDLE_BASE) {
			return false; /* Let stock BLE / CIS handle BLE/CIS disconnects! */
		}
		send_cmd_status(e, opcode, 0x00u);
		if (e->state == BR_STATE_CONNECTED) {
			teardown_link_to_idle(e, 0x16u, true); /* Connection Terminated by Local Host */
		} else {
			send_disconn_complete(e, 0x02u);
		}
		return true;
	}

	/* Vendor Soft-BR opcode (0xFC31 'BRC6') */
	if (opcode == BR_HCI_OP_VENDOR_BRC6) {
		if (plen < 5u || param[0] != BR_VENDOR_MAGIC_0 || param[1] != BR_VENDOR_MAGIC_1 ||
		    param[2] != BR_VENDOR_MAGIC_2 || param[3] != BR_VENDOR_MAGIC_3) {
			return false;
		}
		handle_vendor_brc6(e, param, plen);
		return true;
	}

	switch (opcode) {
	case BR_HCI_OP_INQUIRY: {
		/* Params: LAP[3], Inquiry_Length (1.28s units, 1..0x30), Num_Responses */
		if (plen < 5u) {
			send_cmd_status(e, opcode, 0x12u);
			return true;
		}
		if (e->state != BR_STATE_IDLE) {
			send_cmd_status(e, opcode, 0x0Cu);
			return true;
		}
		uint32_t lap = (uint32_t)param[0] | ((uint32_t)param[1] << 8) | ((uint32_t)param[2] << 16);
		uint8_t inq_len = param[3];
		if (inq_len == 0u) {
			inq_len = 4u;
		}
		uint32_t now = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : e->clk_ref_us;
		sync_clk_to_now(e, now);

		e->inq_lap                = lap;
		e->inq_ulap               = br_ulap(lap, BR_DCI_UAP);
		e->inq_sw                 = br_syncword_from_lap(lap);
		e->inq_end_us             = now + (uint32_t)inq_len * 1280000u;
		e->inq_max_rsp            = param[4];
		e->inq_rsp_cnt            = 0u;
		e->inq_subtrain           = 0u;
		e->inq_idx8               = 0u;
		e->inq_subtrain_switch_us = now + 640000u;
		e->next_sched_clk         = 0u;
		memset(e->inq_seen, 0, sizeof(e->inq_seen));

		e->state = BR_STATE_INQUIRY;
		if (e->ops.set_gauss_bt05) {
			e->ops.set_gauss_bt05(e->ops.ctx, e->knobs.gauss_bt05);
		}
		send_cmd_status(e, opcode, 0x00u);
		schedule_next_step(e);
		return true;
	}
	case BR_HCI_OP_INQUIRY_CANCEL: {
		if (e->state == BR_STATE_INQUIRY) {
			teardown_link_to_idle(e, 0u, false);
		}
		send_cmd_complete(e, opcode, 0x00u, NULL, 0u);
		return true;
	}
	case BR_HCI_OP_CREATE_CONN: {
		/* Params: BD_ADDR[6], Packet_Type[2], Page_Scan_Rep_Mode[1], Reserved[1], Clock_Offset[2], Allow_Role_Switch[1] */
		if (plen < 13u) {
			send_cmd_status(e, opcode, 0x12u);
			return true;
		}
		if (e->state != BR_STATE_IDLE) {
			send_cmd_status(e, opcode, 0x0Cu);
			return true;
		}
		uint32_t now = e->ops.now_us ? e->ops.now_us(e->ops.ctx) : e->clk_ref_us;
		sync_clk_to_now(e, now);

		memcpy(e->peer_bdaddr, &param[0], 6);
		br_bdaddr_to_parts(e->peer_bdaddr, &e->peer_lap, &e->peer_uap, &e->peer_nap);
		e->peer_ulap               = br_ulap(e->peer_lap, e->peer_uap);
		e->peer_dac_sw             = br_syncword_from_lap(e->peer_lap);
		e->peer_clk_off            = (uint16_t)((uint16_t)param[10] | ((uint16_t)param[11] << 8));
		e->lt_addr                 = 1u;
		e->page_deadline_us        = now + 5500000u; /* 5.5 s Page Timeout covers all 4 subtrains */
		e->page_subtrain           = 0u;
		e->page_idx8               = 0u;
		e->page_subtrain_switch_us = now + 1280000u;
		e->name_req_only           = false;
		e->next_sched_clk          = 0u;

		e->state = BR_STATE_PAGE;
		if (e->ops.set_gauss_bt05) {
			e->ops.set_gauss_bt05(e->ops.ctx, e->knobs.gauss_bt05);
		}
		send_cmd_status(e, opcode, 0x00u);
		schedule_next_step(e);
		return true;
	}
	case BR_HCI_OP_CREATE_CONN_CANCEL: {
		if (e->state == BR_STATE_PAGE || e->state == BR_STATE_PAGE_MASTER_RSP ||
		    e->state == BR_STATE_NEW_CONN_POLL) {
			uint8_t peer[6];
			memcpy(peer, e->peer_bdaddr, 6);
			teardown_link_to_idle(e, 0u, false);
			send_cmd_complete(e, opcode, 0x00u, peer, 6u);
			memcpy(e->peer_bdaddr, peer, 6);
			send_conn_complete(e, 0x02u); /* Unknown Connection Identifier / Cancelled */
		} else {
			uint8_t dummy[6] = {0};
			send_cmd_complete(e, opcode, 0x02u, dummy, 6u);
		}
		return true;
	}
	case BR_HCI_OP_WRITE_SCAN_ENABLE: {
		/* We operate strictly as Central/Master Initiator; acknowledge cleanly */
		send_cmd_complete(e, opcode, 0x00u, NULL, 0u);
		return true;
	}
	default:
		return false;
	}
}

br_state_t br_engine_get_state(const br_engine_t *e)
{
	return e ? e->state : BR_STATE_IDLE;
}

void br_engine_get_bdaddr(const br_engine_t *e, uint8_t out_bdaddr[6])
{
	if (e && out_bdaddr) {
		memcpy(out_bdaddr, e->local_bdaddr, 6);
	}
}

uint32_t br_engine_get_clk(const br_engine_t *e)
{
	return e ? e->clk_ref : 0u;
}

void br_engine_get_link_diag(const br_engine_t *e, br_link_diag_t *out)
{
	if (e && out) {
		out->tx_max_slots   = e->tx_max_slots;
		out->tx_size_level  = e->tx_size_level;
		out->tx_flushes     = e->tx_flushes;
		out->size_strikes   = e->size_strikes_total;
		out->probes         = e->probes;
		out->pairs_refused  = e->pairs_refused;
		out->silent_run_max = e->silent_run_max;
	}
}

uint8_t br_engine_take_gaps(br_engine_t *e, br_gap_t out[BR_GAP_LOG], uint16_t *missed)
{
	if (!e || !out) {
		return 0u;
	}
	const uint8_t n = e->gap_count;
	memcpy(out, e->gaps, (size_t)n * sizeof(e->gaps[0]));
	if (missed) {
		*missed = e->gap_missed;
	}
	e->gap_count  = 0u;
	e->gap_missed = 0u;
	return n;
}

void br_engine_get_chan_stats(const br_engine_t *e, uint8_t tried[BR_NUM_CHANNELS], uint8_t heard[BR_NUM_CHANNELS])
{
	if (e && tried && heard) {
		memcpy(tried, e->chan_tried, BR_NUM_CHANNELS);
		memcpy(heard, e->chan_heard, BR_NUM_CHANNELS);
	}
}

void br_engine_get_build_times(const br_engine_t *e, br_build_times_t *out)
{
	if (e != NULL && out != NULL) {
		*out = e->build_times;
	}
}

void br_engine_get_page_progress(const br_engine_t *e, br_page_progress_t *out)
{
	if (e != NULL && out != NULL) {
		*out = e->page_progress;
	}
}

void br_engine_get_stats(const br_engine_t *e, br_diag_stats_t *out)
{
	if (e && out) {
		*out = e->stats;
	}
}
