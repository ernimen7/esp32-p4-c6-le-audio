/*
 * Cyberdeck Soft-BR: ESP32-C6 Mode-0 Raw 1M GFSK Radio Adapter for Bluetooth Classic (br_ll/).
 *
 * All offsets, bitmasks, and calling conventions verified directly against ESP-IDF 5.5.5
 * libble_app.a (dtm_hal.c.o, ble_lll_mmgmt.c.o, ble_lll_sched.c.o, ble_lll.c.o).
 * Zero binary symbol hooks required; zero BLE connection/buffer pool blocks consumed.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "esp_attr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"

#include "br_c6.h"

static const char *TAG = "br_c6_radio";

/* ---- Verified controller symbols from libble_app.a ---- */
extern void *r_ble_lll_mmgmt_global_block_malloc(uint16_t size);
extern int r_ble_lll_sched_insert(void *sch, void *conflict_cb, void *cb_arg);
extern void r_ble_lll_sched_delete_by_sm_num_and_type(uint16_t sm_num, uint8_t sched_type, uint16_t *out_cnt);
extern uint32_t r_ble_lll_timer_current_tick_get(void);
extern void r_ble_phy_disable(void);

extern uint8_t *ble_lll_mmgmt_env_p;
extern uint32_t *ble_lll_module_env_p;
extern const uint8_t *ble_lll_sched_env_p;

/* ---- Verified HP-SRAM descriptor & buffer offsets ---- */
#define DESC_DATA         8u
#define TXD_HDR           16u
#define TXD_LEN           17u
#define TXD_PAYLOAD       18u

/* Third hardware run, 2026-11-10: the baseband rewrites the status word at the end of every RX window, packet or
 * not (6494 of 6494 windows, the bytes from +28 untouched, the same RSSI byte in all of them). So the status word
 * does not show a reception. The bytes after the access address do: they are cleared before each window. */
#define RXD_STATUS        12u /* u32, rewritten at the end of every window */
#define RXD_RSSI          15u /* s8: hardware RSSI in dBm (dtm_hal_rxProcess+0x1a) */
#define RXD_STAMP         16u /* u32: reception time stamp (ble_lll_scan.c.o reads it as one) */
#define RXD_CLEARED_BYTES 20u /* +16 .. +35, cleared before each window */
#define RXD_HDR           28u /* first byte after the access address */
#define RXD_LEN           29u
#define RXD_PAYLOAD       30u
#define RX_STATUS_EMPTY   0x00FFFFFFu

#define BR_SCHED_TYPE     5u
#define BR_SM_NUM_BASE    0x00F0u
#define BR_SLOT_COUNT     8u

/* Baseband registers, read only. Second hardware run, 2026-11-10: after a raw RX item the state register has bit 31
 * clear and its low 20 bits still point at the item. */
#define BR_HW_SCH_CUR     0x600A18FCu /* schedule item handed to the baseband (dtm_hal_schedEvent+0x16e) */
#define BR_HW_SCH_STATE   0x600A1900u /* bit 31: an item is active (r_ble_phy_isr+0x108) */

/* Raw RX items do not come back by themselves: the baseband runs and ends them, but the stock radio interrupt does
 * not report the end of a type-5 item, so the recycle callback is never called (docs/bt-classic-soft-br.md,
 * section 5). br_c6_radio_service collects every RX slot once its scheduled end has passed. */
/* Fourth hardware run, 2026-11-10: BR_RX_RECIPE_STOCK with a 112 us search for the access address heard nothing in
 * five 60 ms windows; searching for the whole window it received a packet in 48 of 48. Nobody has measured yet when
 * a Classic answer arrives relative to its slot, so every RX slot opens this early and searches until its end. To
 * be narrowed once trace 0xBF has shown the arrival times. */
#define BR_RX_EARLY_US    100u
/* Shortest RX slot, from the slot boundary. The engine queues the next pair when a slot is reported, so with its
 * 220 us slots for ID answers a page sent a pair every 1.25 ms and the next TX item started about 0.2 ms after the
 * RX item ended. Runs 8 to 13: 190 pages of a speaker that a computer reached in under 2 s got no answer, while
 * inquiries, whose 500 us slots give a pair every 2.5 ms, found it every time. A public project built on this
 * firmware measured that the modem silently drops a TX set up too soon after an RX window. With this floor a page
 * runs at the pace of an inquiry; the real minimum gap has not been measured. */
#define BR_RX_MIN_US      500u
/* Longest packet the baseband takes in a slot that waits for an ID packet. The byte it reads as the length comes
 * from the sync word (bits 40..47) and can ask for 255 bytes of noise after the 68 bits of the ID, which would
 * still be on the air when the answer to that ID is due. A public project built on this firmware measured that
 * the baseband gives up at once when the length is over this limit and that the bytes after the access address
 * are in the buffer all the same; 4 is the value it used. Not seen on our hardware yet. */
#define BR_RX_ID_MAX_LEN  4u
#define BR_RX_SETTLE_US   40u  /* after the scheduled end, before the RX buffer is read */
/* An item goes to the controller's scheduler only while its start is at least this far ahead. The engine hands
 * pairs over earlier than that (br_engine.c, pair_built_in_time); this is the last check before a closed-source
 * scheduler that hangs in its queue walk when it is given an item whose start has passed (second sound trial,
 * 2026-11-10; reproduced on purpose in hardware run 20: a 3-slot TX item 1000 us late, a hang within seconds). */
#define BR_INSERT_MIN_US  40u
#define BR_RX_LINKED_US   500u /* the controller still has the item in its queue: look again this much later */
#define BR_QUEUE_MAX      24u  /* more items than this in the controller's queue: taken for a damaged queue */
#define BR_RX_RECHECK_US  100u /* the baseband still holds the item: look again this much later */
#define BR_RX_OVERRUN_US  600u /* still held this long after the end: stop the radio, report the slot as skipped */
/* The same for a slot that waits for an ID packet: the length byte comes from the sync word and can ask for 255
 * bytes (2040 us) after the ID. Sixth hardware run: five page attempts with the short length limit below saw no
 * answer at all, not even a time stamp, so the other way is kept for comparison: no limit, wait for the end. */
#define BR_RX_ID_OVERRUN_US 2300u

typedef struct {
	bool     allocated;
	bool     busy;
	bool     cancelled;
	bool     is_tx;
	bool     probe;     /* bench probe (self-test image): completion is counted, the engine is not told */
	bool     held;      /* RX: the baseband still ran the item when br_c6_radio_service took it back */
	bool     id_only;   /* RX: the slot waits for an ID packet */
	bool     parked;    /* the executed item waits at the head of the controller's queue: its recycle pass was
	                     * told not to take it yet (r_ble_lll_sched_pop_executed_sch below) */
	uint8_t  probe_no;
	uint8_t  recipe;    /* RX: br_c6_rx_recipe_t the item was built with */
	uint8_t  idx;
	uint8_t  chan;
	uint16_t sm_num;
	uint32_t slot_tag;
	uint32_t end_tick;  /* scheduled end (sch+48) */
	uint32_t anchor_tick; /* RX: the slot boundary the engine asked for */
	uint32_t due_tick;  /* RX: when br_c6_radio_service looks at the slot */

	uint32_t *ls;       /* 120 B Link State in 0x408xxxxx */
	uint32_t *sch;      /*  72 B Schedule Item in 0x408xxxxx */
	uint8_t  *user_blk; /*  36 B standalone user block (user_blk[20] = 0x02) */
	uint8_t  *tx_hdr;   /*  16 B TX buffer header */
	uint8_t  *tx_buf;   /* 288 B TX payload buffer */
	uint8_t  *rx_hdr;   /*  16 B RX buffer header */
	uint8_t  *rx_buf;   /* 304 B RX payload buffer */
	uint8_t  *dummy_hdr;/*  16 B dummy header at ls+108 */
} br_hw_slot_t;

static br_hw_slot_t s_slots[BR_SLOT_COUNT];
static bool s_slots_ready;
static uint8_t s_next_slot;
static br_c6_radio_stats_t s_rstats;
static uint8_t s_rx_recipe = BR_RX_RECIPE_STOCK; /* what the engine's RX slots are built with */
/* ID-only slots take packets of BR_RX_ID_MAX_LEN bytes at most. Off: with the limit the modem delivers one byte
 * of the answer, which the engine does not accept as a match yet (run 15), without it the whole sync word tail. */
static bool s_id_rx_limit = false;

/* What the LL task was doing when the chip was last reset, kept across the reset: the third hardware run stopped
 * answering the host at the same point of the second inquiry twice and left nothing behind. */
#define BR_LAST_MAGIC 0x42524C53u /* 'BRLS' */
static RTC_NOINIT_ATTR br_c6_last_t s_rtc_last;
static br_c6_last_t s_prev_last; /* the previous run's record, read once at start */

static void last_mark(uint8_t where)
{
	s_rtc_last.where = where;
}

#if CONFIG_CYBERDECK_BR_SELFTEST
#define BR_PROBE_RING 8u
static br_c6_probe_t s_probes[BR_PROBE_RING];
static uint8_t s_probe_w;
static uint8_t s_probe_r;
#endif

/* Saved factory 1M Gaussian filter coefficients at 0x600A20E0..0x600A20EC.
 * br_c6_set_gauss_bt05 scales them by 0.64 on the assumption that this turns LE's modulation index (about 0.5) into
 * Classic's (0.28 to 0.35, Core Spec Vol 2 Part A 3.1). Hardware run 22 (2026-11-11): with the scale on, a paged
 * computer gave no ID answer in 12 rounds; without it, 10 connections in 11 rounds. Whether the scaled values spoil
 * the transmitter or the receiver (which may share them) is not known. The knob stays off. */
#define BB_GAUSS_1M_BASE 0x600A20E0u
static bool s_gauss_saved;
static bool s_gauss_scaled;
static uint32_t s_gauss_orig[4];

static void br_c6_recycle_cb(void *sch_ptr, void *ls_ptr, uint8_t sm_num);
static void rearm_rx_timer(void);

static uint32_t sched_lead_us(void)
{
	if (ble_lll_sched_env_p != NULL) {
		uint32_t lead = (uint32_t)(*ble_lll_sched_env_p);
		if (lead >= 80u && lead <= 400u) {
			return lead;
		}
	}
	return 192u;
}

/* True while the controller can still reach the slot's schedule item: it is the item handed to the baseband, or it
 * is in the controller's queue (head at the scheduler environment + 4, word 0 of each item holds the offset of the
 * next one; r_ble_lll_sched_check_remaining_entries walks it that way from the radio interrupt).
 * Fifth hardware run, 2026-11-10: the chip was reset by the interrupt watchdog inside that walk, three times at the
 * same point of an inquiry. The walk has no end when an item is in the queue twice, and the adapter put one there
 * whenever it built a new item in a slot the controller had not let go of: an ended RX slot is taken back by
 * time, not by a report from the controller. A slot is therefore not reused while this is true. */
static bool controller_links(const br_hw_slot_t *s)
{
	const uint32_t off = (uint32_t)(uintptr_t)s->sch & 0x000FFFFFu;
	if ((*(volatile uint32_t *)(uintptr_t)BR_HW_SCH_CUR & 0x000FFFFFu) == off) {
		return true;
	}
	if (ble_lll_sched_env_p == NULL) {
		return false;
	}
	bool linked = false;
	const UBaseType_t key = portSET_INTERRUPT_MASK_FROM_ISR(); /* the radio interrupt takes items off the queue */
	uint32_t item  = *(const uint32_t *)(ble_lll_sched_env_p + 4u) & 0x000FFFFFu;
	uint32_t steps = 0u;
	while (item != 0u && !linked) {
		if (item == off || ++steps > BR_QUEUE_MAX) {
			linked = true;
		} else {
			item = *(const uint32_t *)(uintptr_t)(0x40800000u | item) & 0x000FFFFFu;
		}
	}
	portCLEAR_INTERRUPT_MASK_FROM_ISR(key);
	return linked;
}

static bool alloc_one_slot(uint8_t idx)
{
	br_hw_slot_t *s = &s_slots[idx];
	memset(s, 0, sizeof(*s));
	s->idx    = idx;
	s->sm_num = (uint16_t)(BR_SM_NUM_BASE + idx);

	s->user_blk  = (uint8_t *)r_ble_lll_mmgmt_global_block_malloc(36u);
	s->ls        = (uint32_t *)r_ble_lll_mmgmt_global_block_malloc(120u);
	s->sch       = (uint32_t *)r_ble_lll_mmgmt_global_block_malloc(72u);
	s->tx_hdr    = (uint8_t *)r_ble_lll_mmgmt_global_block_malloc(16u);
	s->tx_buf    = (uint8_t *)r_ble_lll_mmgmt_global_block_malloc(288u);
	s->rx_hdr    = (uint8_t *)r_ble_lll_mmgmt_global_block_malloc(16u);
	s->rx_buf    = (uint8_t *)r_ble_lll_mmgmt_global_block_malloc(304u);
	s->dummy_hdr = (uint8_t *)r_ble_lll_mmgmt_global_block_malloc(16u);

	if (!s->user_blk || !s->ls || !s->sch || !s->tx_hdr ||
	    !s->tx_buf || !s->rx_hdr || !s->rx_buf || !s->dummy_hdr) {
		return false;
	}

	memset(s->user_blk, 0, 36u);
	memset(s->ls, 0, 120u);
	memset(s->sch, 0, 72u);
	memset(s->tx_hdr, 0, 16u);
	memset(s->tx_buf, 0, 288u);
	memset(s->rx_hdr, 0, 16u);
	memset(s->rx_buf, 0, 304u);
	memset(s->dummy_hdr, 0, 16u);

	/* Standalone user_blk: bit 1 (0x02) at +20 = rxbuffer_reuse_unapply so precheck is a no-op */
	s->user_blk[20] = 0x02u;

	/* Link TX and RX descriptors to their HP-SRAM buffers */
	*(uint16_t *)s->tx_hdr = (uint16_t)(255u << 3);
	*(uint32_t *)(s->tx_hdr + DESC_DATA) = (uint32_t)((uintptr_t)s->tx_buf & 0x000FFFFFu);
	*(uint32_t *)(s->rx_hdr + DESC_DATA) = (uint32_t)((uintptr_t)s->rx_buf & 0x000FFFFFu);

	/* Initialize Link State (ls) exactly as r_ble_lll_mmgmt_alloc_link_state + dtm_hal_allocMemory */
	uint8_t *lsb = (uint8_t *)s->ls;
	if (ble_lll_mmgmt_env_p != NULL) {
		uint32_t env_off = (uint32_t)(((uintptr_t)ble_lll_mmgmt_env_p + 20u) & 0x000FFFFFu);
		*(uint32_t *)(lsb + 76u) = (*(uint32_t *)(lsb + 76u) & 0xFFF00000u) | env_off;
	}
	*(void **)(lsb + 88u)  = s->sch;
	*(void **)(lsb + 92u)  = s->rx_hdr;
	*(void **)(lsb + 100u) = s->rx_hdr;
	*(void **)(lsb + 96u)  = s->tx_hdr;
	*(void **)(lsb + 104u) = s->tx_hdr;
	*(void **)(lsb + 108u) = s->dummy_hdr;
	*(void **)(lsb + 112u) = s->user_blk;

	/* Initialize Schedule Item (sch) exactly as r_ble_lll_mmgmt_alloc_sch + dtm_hal_allocMemory */
	uint8_t *schb = (uint8_t *)s->sch;
	schb[2] |= 0x30u;
	schb[20] = 0u;
	uint32_t mod_timing = (ble_lll_module_env_p != NULL) ? (ble_lll_module_env_p[5] & 0xFFDF7FFFu) : 0u;
	s->sch[6] = mod_timing | 0x18000000u;
	s->sch[0] = (s->sch[0] & 0xFFF00000u) | 0x00100000u;
	s->sch[1] = (s->sch[1] & 0xFF000000u) | ((uint32_t)((uintptr_t)s->ls & 0x000FFFFFu));
	*(uint16_t *)(schb + 32u) = s->sm_num;
	schb[53] = BR_SCHED_TYPE;
	*(void **)(schb + 64u) = (void *)br_c6_recycle_cb;
	*(uint32_t *)(schb + 68u) = 0u;

	s->allocated = true;
	return true;
}

int br_c6_radio_init(void)
{
	if (s_slots_ready) {
		return 0;
	}
	for (uint8_t i = 0; i < BR_SLOT_COUNT; i++) {
		if (!alloc_one_slot(i)) {
			ESP_LOGE(TAG, "Failed to allocate HP-SRAM slot %u for Soft-BR", i);
			return -1;
		}
	}
	s_prev_last = s_rtc_last;
	memset(&s_rtc_last, 0, sizeof(s_rtc_last));
	s_rtc_last.magic = BR_LAST_MAGIC;
	s_slots_ready = true;
	return 0;
}

bool br_c6_radio_prev_last(br_c6_last_t *out)
{
	if (out == NULL || s_prev_last.magic != BR_LAST_MAGIC) {
		return false;
	}
	*out = s_prev_last;
	return true;
}

bool br_c6_radio_kept_last(br_c6_last_t *out)
{
	if (out == NULL || s_rtc_last.magic != BR_LAST_MAGIC) {
		return false;
	}
	*out = s_rtc_last;
	return true;
}

void br_c6_radio_set_id_rx_limit(bool limit)
{
	s_id_rx_limit = limit;
}

void br_c6_radio_set_rx_recipe(uint8_t recipe)
{
	if (recipe < BR_RX_RECIPE_COUNT) {
		s_rx_recipe = recipe;
	}
}

void br_c6_radio_reset(void)
{
	if (!s_slots_ready) {
		return;
	}
	br_c6_cancel_all(NULL);
	br_c6_set_gauss_bt05(NULL, false);
}

static br_hw_slot_t *acquire_free_slot(void)
{
	if (!s_slots_ready) {
		return NULL;
	}
	/* In turn, not first-free: a slot the adapter has just collected or freed is used again last, so a report the
	 * controller still sends for its previous item finds it idle and is ignored. */
	for (uint8_t n = 0; n < BR_SLOT_COUNT; n++) {
		br_hw_slot_t *s = &s_slots[(uint8_t)((s_next_slot + n) % BR_SLOT_COUNT)];
		if (s->allocated && !s->busy) {
			if (controller_links(s)) {
				s_rstats.slot_linked++;
				continue;
			}
			s->busy      = true;
			s->cancelled = false;
			s->probe     = false;
			s->parked    = false;
			s_next_slot  = (uint8_t)((s->idx + 1u) % BR_SLOT_COUNT);
			return s;
		}
	}
	return NULL;
}

static void prep_common_ls(br_hw_slot_t *s, uint32_t access_addr, bool is_tx, uint8_t rx_max_len)
{
	uint32_t *ls = s->ls;
	/* ls[0]: bit 31 = active, bits 27:20 = 0xFF, bit 28 = 0 (hardware BLE whitening OFF!) */
	ls[0] = 0x8FF00000u | ((uint32_t)(((uintptr_t)s->tx_hdr + 4u) & 0x000FFFFFu));
	/* ls[1]: TX power index 11 (~+9 dBm) */
	ls[1] = (ls[1] & 0xF00FFFFFu) | (11u << 20);
	/* ls[2]: RX descriptor + 4, longest packet taken in bits 27:20 */
	ls[2] = ((uint32_t)rx_max_len << 20) | ((uint32_t)(((uintptr_t)s->rx_hdr + 4u) & 0x000FFFFFu));
	/* ls[5]: bit 27 always set, bit 26 set for TX ready */
	ls[5] = is_tx ? ((ls[5] & 0xF3FFFFFFu) | 0x0C000000u)
		      : ((ls[5] & 0xF3FFFFFFu) | 0x08000000u);
	/* ls[9]: dummy 24-bit BLE CRC init */
	ls[9] = (ls[9] & 0xFF000000u) | 0x00555555u;
	/* ls[10]: coexistence PTI = 15 (highest priority over Wi-Fi) */
	ls[10] = (ls[10] & 0xFFFF0000u) | 0x000000FFu;
	ls[11] = 0u;
	ls[12] = access_addr;
	s->user_blk[20] = 0x02u;
}

static bool starts_too_soon(uint32_t start_tick)
{
	return (int32_t)(start_tick - r_ble_lll_timer_current_tick_get()) < (int32_t)BR_INSERT_MIN_US;
}

static int insert_tx_slot(br_hw_slot_t *s, const br_radio_tx_req_t *req, uint32_t *out_end_us)
{
	s->is_tx    = true;
	s->slot_tag = req->slot_tag;
	s->chan     = req->chan_1mhz;

	prep_common_ls(s, req->access_addr, true, 0xFFu);
	if (req->crc_preset_set) {
		s->ls[9] = (s->ls[9] & 0xFF000000u) | (req->crc_preset & 0x00FFFFFFu);
	}

	s->tx_buf[TXD_HDR] = req->tx_hdr;
	s->tx_buf[TXD_LEN] = req->tx_len;
	if (req->tx_len > 0u) {
		memcpy(&s->tx_buf[TXD_PAYLOAD], req->tx_payload, req->tx_len);
	}
	*(uint16_t *)s->tx_hdr = (uint16_t)((uint16_t)req->tx_len << 3);

	uint32_t lead         = sched_lead_us();
	uint32_t air_start_us = req->anchor_us - (uint32_t)req->lead_us;
	uint32_t start_tick   = air_start_us - lead;
	/* Exact 1 Msps BLE frame duration: 1B preamble + 4B AA + 2B HDR/LEN + tx_len + 3B CRC24 */
	uint32_t air_dur_us   = (uint32_t)(10u + (uint32_t)req->tx_len) * 8u;
	uint32_t end_tick     = air_start_us + air_dur_us;
	s->end_tick           = end_tick;

	uint32_t *sch = s->sch;
	uint8_t *schb = (uint8_t *)sch;

	sch[0]  = 0x00100000u;
	schb[2] = (uint8_t)((schb[2] & ~0x50u) | 0x10u); /* Single TX */
	sch[1]  = (sch[1] & 0xFF000000u) | ((uint32_t)((uintptr_t)s->ls & 0x000FFFFFu));
	sch[4]  = 0x00100000u; /* PHY 1M = rate 0 in bits 31:28 */
	sch[5]  = (sch[5] & 0xFFFF8000u) | (((uint32_t)(req->chan_1mhz & 0x7Fu)) << 8) | 0x7Fu;
	sch[7]  = 0x000F0001u;
	sch[10] = 0u;
	sch[11] = start_tick;
	sch[2]  = start_tick;
	sch[12] = end_tick;
	*(uint16_t *)(schb + 32u) = s->sm_num;
	schb[52] = 0u;
	schb[53] = BR_SCHED_TYPE;
	schb[54] = 0u;
	schb[55] = 0u;
	sch[15]  = 0u;
	*(void **)(schb + 64u) = (void *)br_c6_recycle_cb;
	*(uint32_t *)(schb + 68u) = 0u;

	if (starts_too_soon(start_tick)) {
		s_rstats.insert_late++;
		s->busy = false;
		return -1;
	}
	last_mark(BR_AT_SCHED_INSERT);
	const int rc = r_ble_lll_sched_insert(sch, NULL, NULL);
	last_mark(BR_AT_ADAPTER);
	if (rc != 0) {
		s_rstats.insert_fail++;
		s->busy = false;
		return -1;
	}
	s_rstats.insert_ok++;
	if (out_end_us) {
		*out_end_us = end_tick;
	}
	return 0;
}

static int insert_rx_slot(br_hw_slot_t *s, const br_radio_rx_req_t *req, uint32_t min_start_tick, uint8_t recipe)
{
	s->is_tx    = false;
	s->held     = false;
	s->id_only  = req->id_only;
	s->recipe   = recipe;
	s->slot_tag = req->slot_tag;
	s->chan     = req->chan_1mhz;

	prep_common_ls(s, req->access_addr, false, (req->id_only && s_id_rx_limit) ? BR_RX_ID_MAX_LEN : 0xFFu);

	*(uint32_t *)(s->rx_buf + RXD_STATUS) = RX_STATUS_EMPTY;
	memset(s->rx_buf + RXD_STAMP, 0, RXD_CLEARED_BYTES);

	uint32_t lead = sched_lead_us();
	/* Open the correlator before the nominal slot boundary, clamped cleanly after the preceding TX end */
	uint32_t air_start = req->anchor_us - BR_RX_EARLY_US;
	uint32_t start_tick = air_start - lead;
	if (min_start_tick != 0u && (int32_t)(start_tick - min_start_tick) < 0) {
		start_tick = min_start_tick;
		air_start  = start_tick + lead;
	}
	uint32_t max_dur  = (req->max_duration_us > BR_RX_MIN_US) ? req->max_duration_us : BR_RX_MIN_US;
	uint32_t end_tick = req->anchor_us + max_dur;
	/* Item word 7, low half: how long the baseband looks for the access address, in us, counted from the item's
	 * start, which is the scheduler's lead before the radio is on the air. The whole slot. Runs eight and nine
	 * counted it from the air start: the 500 us inquiry slots still reached past the answer (it is found 43 us
	 * after the slot boundary), the 220 us slots that wait for an ID answer to a page ended a lead earlier and
	 * heard none of 44 pages, while a computer connected to the same speaker in 2 s. */
	uint32_t search   = (end_tick - start_tick) + 32u;
	uint16_t sync_win = (search > 0xFFFFu) ? 0xFFFFu : (uint16_t)search;
	s->end_tick       = end_tick;
	s->anchor_tick    = req->anchor_us;
	s->due_tick       = end_tick + BR_RX_SETTLE_US;

	uint32_t *sch = s->sch;
	uint8_t *schb = (uint8_t *)sch;

	sch[0]  = 0x00100000u;
	schb[2] = (uint8_t)((schb[2] & ~0x50u) | 0x40u); /* Single RX */
	sch[1]  = (sch[1] & 0xFF000000u) | ((uint32_t)((uintptr_t)s->ls & 0x000FFFFFu));
	sch[4]  = 0x00100000u; /* PHY 1M = rate 0 */
	sch[5]  = (sch[5] & 0xFFFF8000u) | (((uint32_t)(req->chan_1mhz & 0x7Fu)) << 8) | 0x7Fu;
	/* Three fields decide how the baseband runs an RX item. BR_RX_RECIPE_STOCK is what this adapter always wrote;
	 * no packet has been received with it on hardware. The others take the values a public project built on this
	 * firmware measured receiving Classic packets inside a vendor test (DTM) session: the link state's RX window
	 * in us from the item start (0 = listen until a packet), 255 in item word 7, and the item's end one tick
	 * after its start. Which of them matter for an item the stock scheduler runs is what the bench probes ask. */
	const bool win = (recipe == BR_RX_RECIPE_WINDOW || recipe == BR_RX_RECIPE_WINDOW_SHORT_ITEM);
	s->ls[11] = win ? (end_tick - start_tick) : 0u;
	sch[7]  = (recipe == BR_RX_RECIPE_STOCK) ? ((0x000Fu << 16) | (uint32_t)sync_win) : 255u;
	sch[10] = 0u;
	sch[11] = start_tick;
	sch[2]  = start_tick;
	sch[12] = (recipe == BR_RX_RECIPE_WINDOW_SHORT_ITEM) ? start_tick + 1u : end_tick;
	*(uint16_t *)(schb + 32u) = s->sm_num;
	schb[52] = 0u;
	schb[53] = BR_SCHED_TYPE;
	schb[54] = 0u;
	schb[55] = 0u;
	sch[15]  = 0u;
	*(void **)(schb + 64u) = (void *)br_c6_recycle_cb;
	*(uint32_t *)(schb + 68u) = 0u;

	(void)air_start;
	if (starts_too_soon(start_tick)) {
		s_rstats.insert_late++;
		s->busy = false;
		return -1;
	}
	last_mark(BR_AT_SCHED_INSERT);
	const int rc = r_ble_lll_sched_insert(sch, NULL, NULL);
	last_mark(BR_AT_ADAPTER);
	if (rc != 0) {
		s_rstats.insert_fail++;
		s->busy = false;
		return -1;
	}
	s_rstats.insert_ok++;
	rearm_rx_timer();
	return 0;
}

/* Recycle callback invoked by r_ble_lll_process_dequeued_sch in the LL task */
static void IRAM_ATTR br_c6_recycle_cb(void *sch_ptr, void *ls_ptr, uint8_t sm_num)
{
	(void)ls_ptr;
	if (sm_num < (uint8_t)BR_SM_NUM_BASE || sm_num >= (uint8_t)(BR_SM_NUM_BASE + BR_SLOT_COUNT)) {
		return;
	}
	br_hw_slot_t *s = &s_slots[sm_num - (uint8_t)BR_SM_NUM_BASE];
	if (s->sch != (uint32_t *)sch_ptr || !s->busy) {
		return;
	}

	const bool was_cancelled = s->cancelled;
	const bool is_tx         = s->is_tx;
	const uint32_t tag       = s->slot_tag;
	const uint8_t *schb      = (const uint8_t *)s->sch;
	const bool skipped       = (schb[55] & 0x02u) != 0u;

	br_radio_rx_ind_t rx_ind;
	uint8_t rx_copy[256];
	if (!was_cancelled && !is_tx) {
		memset(&rx_ind, 0, sizeof(rx_ind));
		rx_ind.skipped = skipped;
		if (!skipped && *(const uint32_t *)(s->rx_buf + RXD_HDR) != 0u) {
			rx_ind.sync_matched = true;
			rx_ind.rssi_dbm     = *(const int8_t *)(s->rx_buf + RXD_RSSI);
			rx_ind.rx_hdr       = s->rx_buf[RXD_HDR];
			rx_ind.rx_len       = s->rx_buf[RXD_LEN];
			uint16_t cap_len    = rx_ind.rx_len;
			if (cap_len > sizeof(rx_copy)) {
				cap_len = sizeof(rx_copy);
			}
			if (cap_len > 0u) {
				memcpy(rx_copy, &s->rx_buf[RXD_PAYLOAD], cap_len);
			}
			rx_ind.raw_payload = rx_copy;
			rx_ind.raw_len     = cap_len;
			s_rstats.rx_captured++;
			s_rstats.cap_seq++;
			s_rstats.cap_rssi = rx_ind.rssi_dbm;
			s_rstats.cap_len  = rx_ind.rx_len;
			s_rstats.cap_hdr  = rx_ind.rx_hdr;
			s_rstats.cap_chan = s->chan;
			s_rstats.cap_late_us = (int32_t)(*(const uint32_t *)(s->rx_buf + RXD_STAMP) - s->anchor_tick);
			memset(s_rstats.cap_raw, 0, sizeof(s_rstats.cap_raw));
			memcpy(s_rstats.cap_raw, rx_copy, cap_len < sizeof(s_rstats.cap_raw) ? cap_len : sizeof(s_rstats.cap_raw));
		}
	}
	if (!was_cancelled && !is_tx && !skipped && *(const uint32_t *)(s->rx_buf + RXD_HDR) == 0u &&
	    *(const uint32_t *)(s->rx_buf + RXD_STAMP) != 0u) {
		s_rstats.rx_stamp_only++;
	}
	if (!was_cancelled) {
		if (skipped) {
			s_rstats.skipped++;
		} else if (is_tx) {
			s_rstats.tx_done++;
		} else {
			s_rstats.rx_done++;
		}
	}

	const bool was_probe = s->probe;
#if CONFIG_CYBERDECK_BR_SELFTEST
	if (was_probe && !was_cancelled) {
		br_c6_probe_t *r = &s_probes[s_probe_w % BR_PROBE_RING];
		r->probe   = s->probe_no;
		r->recipe  = s->recipe;
		r->held    = s->held;
		r->skipped = skipped;
		r->status  = *(const uint32_t *)(s->rx_buf + RXD_STATUS);
		r->stamp   = *(const uint32_t *)(s->rx_buf + RXD_STAMP);
		memcpy(r->data, s->rx_buf + RXD_HDR, sizeof(r->data));
		s_probe_w++;
	}
#endif
	s->busy      = false;
	s->cancelled = false;

	if (was_cancelled || was_probe) {
		return;
	}
	br_engine_t *eng = br_c6_engine_ll();
	if (eng == NULL) {
		return;
	}
	last_mark(BR_AT_ENGINE);
	if (is_tx) {
		br_engine_on_tx_done(eng, tag, skipped);
	} else {
		br_engine_on_rx_done(eng, tag, &rx_ind);
	}
	last_mark(BR_AT_ADAPTER);
	br_c6_live_mark(br_engine_get_state(eng) != BR_STATE_IDLE);
}

/* Hook (cmake/ble_hooks.txt). The controller takes executed schedule items back in the LL task
 * (r_ble_lll_recycle_sch_in_task) by popping them off the head of its queue. When the baseband's state register
 * still points at the item - nothing has been handed to the baseband after it - the memory cannot be given back,
 * so the controller copies the 72 bytes into a spare block of its own, returns the copy and keeps the original as
 * its next spare (r_ble_lll_sched_pop_executed_sch + 0x128). A Soft-BR item must not go that way: the adapter's
 * blocks are of another kind than the spare (the word before the block says 5, the spare's says 0) and the copy
 * refuses that with an assertion - "BLE assert: line 912 in function r_ble_lll_mmgmt_block_copy, param: 0x0, 0x5",
 * read from the black box on 2026-11-12 after a connection attempt restarted the tablet; the spare is not one of
 * the adapter's blocks after LE work of the host, e.g. an LE connection attempt - and a copy that goes through
 * leaves the controller owning the block the adapter builds its next item in.
 * It is no rare case: an ended RX item stays the baseband's item until the next TX starts. This hook counted
 * about 120 such passes a second during pages (1.5.3, trace 0xCD); up to 1.5.2 each of them took the swap.
 * So such an item is not popped: the pass is told there is nothing to take, the item waits at the head, and the
 * next pass after the baseband has moved on takes it the ordinary way. The slot is marked parked: its item has
 * run, so br_c6_radio_service takes an RX slot back at once instead of waiting for the controller to let go of it
 * (1.5.3 waited, and the answer to a page reached the engine too late: no connection), and the slot is not used
 * again while the item is in the queue (acquire_free_slot). The controller's report for it then finds it idle. */
extern void *orig_r_ble_lll_sched_pop_executed_sch(void);
static uint32_t s_pop_held;

void *r_ble_lll_sched_pop_executed_sch(void)
{
	if (s_slots_ready && ble_lll_sched_env_p != NULL) {
		const uint32_t *env = (const uint32_t *)(const void *)ble_lll_sched_env_p;
		const uint32_t head = env[1]; /* the item the pass would take; env[2], env[3]: the controller's own two
		                               * reasons not to take it that way */
		const uint32_t hw   = *(volatile uint32_t *)(uintptr_t)BR_HW_SCH_STATE & 0x000FFFFFu;
		if (head != 0u && head != env[2] && head != env[3] && hw != 0u && (head & 0x000FFFFFu) == hw) {
			for (uint8_t i = 0; i < BR_SLOT_COUNT; i++) {
				if ((uint32_t)(uintptr_t)s_slots[i].sch == head) {
					s_slots[i].parked = true;
					s_pop_held++;
					return NULL;
				}
			}
		}
	}
	return orig_r_ble_lll_sched_pop_executed_sch();
}

uint32_t br_c6_radio_pop_held(void)
{
	return s_pop_held;
}

static bool baseband_holds(const br_hw_slot_t *s)
{
	const uint32_t state = *(volatile uint32_t *)(uintptr_t)BR_HW_SCH_STATE;
	return (state & 0x80000000u) != 0u && (state & 0x000FFFFFu) == ((uint32_t)(uintptr_t)s->sch & 0x000FFFFFu);
}

/* Wakes the LL task for the RX slot whose look is due first. */
static void rearm_rx_timer(void)
{
	const uint32_t now = r_ble_lll_timer_current_tick_get();
	bool pending       = false;
	int32_t soonest    = 0;
	for (uint8_t i = 0; i < BR_SLOT_COUNT; i++) {
		const br_hw_slot_t *s = &s_slots[i];
		if (!s->busy || s->is_tx) {
			continue;
		}
		const int32_t wait = (int32_t)(s->due_tick - now);
		if (!pending || wait < soonest) {
			soonest = wait;
			pending = true;
		}
	}
	if (pending) {
		s_rstats.rx_timer_arms++;
		br_c6_rx_timer_arm(soonest > 0 ? (uint32_t)soonest : 0u);
	}
}

static void collect_rx_slot(br_hw_slot_t *s, bool held)
{
	if (held) {
		/* Past its end and still on the air: the length byte comes from the air and can ask for 255 bytes. Stop the
		 * radio the way the vendor test mode does before each of its items (dtm_hal_schedEvent+0x15a). */
		last_mark(BR_AT_PHY_DISABLE);
		r_ble_phy_disable();
		s_rstats.rx_overrun++;
	}
	s->held = held;
	/* An item the scheduler never started is still in its queue and has to leave it before the slot is used again;
	 * one the baseband has run is not there any more (second hardware run: 0 deleted). */
	uint16_t deleted = 0u;
	if (!s->parked) { /* a parked item has run: deleting it would unlink it and report the reception as skipped */
		last_mark(BR_AT_SCHED_DELETE);
		r_ble_lll_sched_delete_by_sm_num_and_type(s->sm_num, BR_SCHED_TYPE, &deleted);
		last_mark(BR_AT_ADAPTER);
	}
	if (held || deleted > 0u) {
		((uint8_t *)s->sch)[55] |= 0x02u; /* reported as skipped: the buffer does not hold a whole packet */
	}
	if (held && baseband_holds(s)) {
		s->allocated = false; /* the baseband still points at it: never used again */
		s_rstats.retired++;
	}
	s_rstats.rx_collected++;
	br_c6_recycle_cb(s->sch, s->ls, (uint8_t)s->sm_num);
}

void br_c6_radio_service(void)
{
	if (!s_slots_ready) {
		return;
	}
	s_rstats.service_runs++;
	s_rtc_last.ll_tick      = r_ble_lll_timer_current_tick_get();
	s_rtc_last.esp_us       = (uint32_t)esp_timer_get_time();
	s_rtc_last.service_runs = s_rstats.service_runs;
	s_rtc_last.tx_done      = s_rstats.tx_done;
	last_mark(BR_AT_ADAPTER);
	for (uint8_t i = 0; i < BR_SLOT_COUNT; i++) {
		br_hw_slot_t *s = &s_slots[i];
		if (!s->busy || s->is_tx) {
			continue;
		}
		const uint32_t now = r_ble_lll_timer_current_tick_get();
		if ((int32_t)(now - s->due_tick) < 0) {
			s_rstats.rx_not_due++;
			continue;
		}
		const bool held = baseband_holds(s);
		if (held && (int32_t)(now - s->end_tick) < (int32_t)(s->id_only ? BR_RX_ID_OVERRUN_US : BR_RX_OVERRUN_US)) {
			s->due_tick = now + BR_RX_RECHECK_US;
			s_rstats.rx_not_due++;
			continue;
		}
		if (!held && !s->parked && controller_links(s)) {
			/* Not run yet, or run and not let go of: its buffer is not final and the slot cannot be reused. A
			 * parked slot has run and the controller holds its item only because the adapter asked it to. */
			s->due_tick = now + BR_RX_LINKED_US;
			s_rstats.rx_linked++;
			continue;
		}
		collect_rx_slot(s, held); /* may queue the next pair from inside the engine */
	}
	rearm_rx_timer();
	last_mark(BR_AT_IDLE);
}

/* Takes an item out of the scheduler. One still in its queue is freed here: nothing will report it. One the
 * baseband already has comes back through the recycle callback (TX) or br_c6_radio_service (RX) and is dropped
 * there. Only for an item queued a moment ago, whose start is still a scheduling lead away (the TX half of a pair
 * whose RX half the scheduler refused): deleting items that are about to start hung the controller, see
 * br_c6_cancel_all. */
static void cancel_slot(br_hw_slot_t *s)
{
	s->cancelled = true;
	uint16_t deleted = 0u;
	r_ble_lll_sched_delete_by_sm_num_and_type(s->sm_num, BR_SCHED_TYPE, &deleted);
	if (deleted > 0u && s->busy) {
		s->busy      = false;
		s->cancelled = false;
	}
}

int br_c6_schedule_tx(void *ctx, const br_radio_tx_req_t *req)
{
	(void)ctx;
	if (!req) {
		return -1;
	}
	br_hw_slot_t *s = acquire_free_slot();
	if (!s) {
		return -1;
	}
	return insert_tx_slot(s, req, NULL);
}

int br_c6_schedule_rx(void *ctx, const br_radio_rx_req_t *req)
{
	(void)ctx;
	if (!req) {
		return -1;
	}
	br_hw_slot_t *s = acquire_free_slot();
	if (!s) {
		return -1;
	}
	return insert_rx_slot(s, req, 0u, s_rx_recipe);
}

int br_c6_schedule_tx_rx(void *ctx, const br_radio_tx_req_t *tx_req, const br_radio_rx_req_t *rx_req)
{
	(void)ctx;
	if (!tx_req || !rx_req) {
		return -1;
	}
	br_hw_slot_t *tx_s = acquire_free_slot();
	if (!tx_s) {
		return -1;
	}
	br_hw_slot_t *rx_s = acquire_free_slot();
	if (!rx_s) {
		tx_s->busy = false;
		return -1;
	}

	uint32_t tx_end_us = 0u;
	if (insert_tx_slot(tx_s, tx_req, &tx_end_us) != 0) {
		rx_s->busy = false;
		return -1;
	}
	if (insert_rx_slot(rx_s, rx_req, tx_end_us + 8u, s_rx_recipe) != 0) {
		/* Roll back queued TX slot cleanly so TX never fires orphaned without RX */
		cancel_slot(tx_s);
		return -1;
	}
	return 0;
}

/* Gives up everything the engine has in flight. The items stay in the controller's scheduler and run out within a
 * few slot pairs; what comes back for them (the recycle callback for TX, br_c6_radio_service for RX) is dropped
 * because the slot is marked cancelled, and only then is the slot used again.
 * Up to 1.5.2 every item was deleted from the controller's queue here (cancel_slot). 2026-11-12, regular image on
 * the Tab5: the link layer task did not come back from that deletion - it looped in the queue walk of
 * r_ble_lll_sched_delete_by_sm_num_and_type until the task watchdog ended it (hang record 0xFC30/0x09: cancel_slot
 * <- br_c6_cancel_all <- teardown_link_to_idle <- a host command). It takes an engine stopped in mid-flight, with
 * its pairs queued one after the other and the next one about to start: a host that gives a page up half way (its
 * name requests after an inquiry do, 1.8 s into the page), or a page whose handshake fails. A page or inquiry
 * that nobody answers ends by the engine's own timeout and went through here 78 times that afternoon without
 * harm. What breaks inside the closed controller is not known; leaving its queue alone avoids it. The test image
 * option BR_ST_ABORT_TEST stops a page half way every two seconds. */
void br_c6_cancel_all(void *ctx)
{
	(void)ctx;
	if (!s_slots_ready) {
		return;
	}
	for (uint8_t i = 0; i < BR_SLOT_COUNT; i++) {
		if (s_slots[i].busy) {
			s_slots[i].cancelled = true;
		}
	}
	rearm_rx_timer();
}

void br_c6_radio_caps(void *ctx, br_radio_caps_t *out)
{
	(void)ctx;
	if (!out) {
		return;
	}
	out->sched_lead_us        = sched_lead_us() + 80u;
	out->max_pipelined_slots  = BR_SLOT_COUNT;
	out->supports_gauss_scale = true;
}

void br_c6_set_gauss_bt05(void *ctx, bool enable)
{
	(void)ctx;
	volatile uint32_t *regs = (volatile uint32_t *)(uintptr_t)BB_GAUSS_1M_BASE;
	if (!s_gauss_saved) {
		for (int i = 0; i < 4; i++) {
			s_gauss_orig[i] = regs[i];
		}
		s_gauss_saved = true;
	}
	if (enable && !s_gauss_scaled) {
		for (int i = 0; i < 4; i++) {
			uint32_t w = s_gauss_orig[i];
			uint32_t out = 0u;
			for (int b = 0; b < 4; b++) {
				uint32_t c = (w >> (b * 8)) & 0xFFu;
				uint32_t sc = (c * 164u + 128u) >> 8; /* 0.64x deviation scale (h=0.50 -> h=0.32) */
				out |= (sc & 0xFFu) << (b * 8);
			}
			regs[i] = out;
		}
		s_gauss_scaled = true;
	} else if (!enable && s_gauss_scaled) {
		for (int i = 0; i < 4; i++) {
			regs[i] = s_gauss_orig[i];
		}
		s_gauss_scaled = false;
	}
}

uint32_t br_c6_now_us(void *ctx)
{
	(void)ctx;
	return r_ble_lll_timer_current_tick_get();
}

void br_c6_radio_get_stats(br_c6_radio_stats_t *out)
{
	if (out != NULL) {
		*out = s_rstats;
	}
}

#if CONFIG_CYBERDECK_BR_SELFTEST
/*
 * Bench probes (self-test image only, LL task). First hardware run, 2026-11-10: the TX item came back through the
 * recycle callback, the RX item never did. RX slots are now collected by br_c6_radio_service; these probes show
 * where a slot it missed stands and try the two ways of getting it back.
 */
#define BR_ST_LATE_US    20000u      /* a slot this far past its end was missed by br_c6_radio_service */
#define BR_ST_RX_LEAD_US 3000u       /* a lone probe RX starts this long after the call */

bool br_c6_st_stuck(br_c6_stuck_t *out)
{
	if (!s_slots_ready || out == NULL) {
		return false;
	}
	const uint32_t now = r_ble_lll_timer_current_tick_get();
	for (uint8_t i = 0; i < BR_SLOT_COUNT; i++) {
		const br_hw_slot_t *s = &s_slots[i];
		if (!s->allocated || !s->busy || (int32_t)(now - s->end_tick) < (int32_t)BR_ST_LATE_US) {
			continue;
		}
		out->idx        = i;
		out->is_tx      = s->is_tx;
		out->probe      = s->probe;
		out->late_us    = now - s->end_tick;
		out->sch0       = s->sch[0];
		out->sch_flags  = s->sch[13];
		out->hw_cur     = *(volatile uint32_t *)(uintptr_t)BR_HW_SCH_CUR;
		out->hw_state   = *(volatile uint32_t *)(uintptr_t)BR_HW_SCH_STATE;
		out->sch_off    = (uint32_t)(uintptr_t)s->sch & 0x000FFFFFu;
		out->hw_current = (out->hw_state & 0x000FFFFFu) == out->sch_off;
		return true;
	}
	return false;
}

/* Hands a stuck slot back to its owner the way a skipped slot comes back. */
static void st_return_slot(br_hw_slot_t *s)
{
	((uint8_t *)s->sch)[55] |= 0x02u;
	br_c6_recycle_cb(s->sch, s->ls, (uint8_t)s->sm_num);
}

bool br_c6_st_force(uint8_t idx, uint8_t step, uint16_t *deleted)
{
	if (!s_slots_ready || idx >= BR_SLOT_COUNT || deleted == NULL) {
		return false;
	}
	br_hw_slot_t *s = &s_slots[idx];
	*deleted = 0u;
	if (!s->busy) {
		return true;
	}
	if (step == 1u) {
		const uint32_t state = *(volatile uint32_t *)(uintptr_t)BR_HW_SCH_STATE;
		if ((state & 0x80000000u) == 0u) {
			/* Second hardware run, 2026-11-10: the baseband had finished the RX item (active bit clear), the
			 * scheduler held nothing to delete and no interrupt recycled it. Collect the result here, the way the
			 * recycle callback would have. */
			br_c6_recycle_cb(s->sch, s->ls, (uint8_t)s->sm_num);
			return true; /* not !s->busy: the engine may have queued the slot again from inside the callback */
		}
		/* Still running: ask the scheduler to drop it. If it did and no recycle followed, nothing references the
		 * item any more. */
		r_ble_lll_sched_delete_by_sm_num_and_type(s->sm_num, BR_SCHED_TYPE, deleted);
		if (*deleted > 0u && s->busy) {
			st_return_slot(s);
			return true;
		}
		return !s->busy;
	}
	/* Stop the radio the way the vendor test mode does before each of its items (dtm_hal_schedEvent+0x15a).
	 * The scheduler may still reference the item, so the slot is retired instead of reused. */
	r_ble_phy_disable();
	s->allocated = false;
	st_return_slot(s);
	return true;
}

int br_c6_st_lone_rx(uint8_t probe_no, uint8_t recipe, uint8_t chan_1mhz, uint32_t access_addr, uint16_t dur_us,
		uint32_t start_in_us, bool id_only)
{
	if (recipe >= BR_RX_RECIPE_COUNT) {
		return -1;
	}
	br_hw_slot_t *s = acquire_free_slot();
	if (s == NULL) {
		return -1;
	}
	s->probe    = true;
	s->probe_no = probe_no;
	const br_radio_rx_req_t req = {
		.anchor_us       = r_ble_lll_timer_current_tick_get() + BR_ST_RX_LEAD_US + start_in_us,
		.max_duration_us = dur_us,
		.chan_1mhz       = chan_1mhz,
		.access_addr     = access_addr,
		.id_only         = id_only,
	};
	return insert_rx_slot(s, &req, 0u, recipe);
}

bool br_c6_st_probe_pop(br_c6_probe_t *out)
{
	if (out == NULL || s_probe_r == s_probe_w) {
		return false;
	}
	if ((uint8_t)(s_probe_w - s_probe_r) > BR_PROBE_RING) {
		s_probe_r = (uint8_t)(s_probe_w - BR_PROBE_RING); /* older results were overwritten */
	}
	*out = s_probes[s_probe_r % BR_PROBE_RING];
	s_probe_r++;
	return true;
}
#endif /* CONFIG_CYBERDECK_BR_SELFTEST */
