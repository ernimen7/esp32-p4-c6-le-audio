/*
 * ESP32-P4 Bluetooth Classic host runtime: HCI over the esp_hosted SDIO transport to the ESP32-C6 (Soft-BR in
 * c6_firmware), LMP, L2CAP, SDP, AVDTP and AVRCP, and the SBC stream.
 *  - HCI goes out through esp_hosted_cyberdeck_hci_tx and comes in through a receive callback of esp_hosted, which
 *    the LE Audio host (p4_le_audio) shares: each host takes its own packets and ignores the rest;
 *  - the samples go through a ring that is read once it holds kPcmTargetFrames; a writer that does not wait is
 *    kept there by a small change of the resampling ratio, a writer that waits keeps itself there;
 *  - the controller's counters are kept for bt_classic_get_diag;
 *  - nothing large is static: the runtime, the queues and the task stacks are in PSRAM.
 * Trial records: docs/bt-classic-soft-br.md.
 */
#include "bt_classic.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

#include "br_engine.h"
#include "br_proto.h"
#include "btc_bonds.h"
#include "btc_l2cap_avdtp.h"
#include "btc_lmp.h"
#include "btc_media_queue.h"
#include "btc_rate.h"
#include "sbc_enc.h"

#ifdef ESP_PLATFORM
#include "esp_heap_caps.h"
#include "esp_hosted.h"
#include "esp_hosted_cyberdeck.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

namespace {

constexpr const char *kTag     = "bt_classic";
constexpr const char *kBondKey = "bt.classic_bond";

struct RxQueueItem {
    uint16_t len;
    uint8_t  data[1036];
};

constexpr size_t kRxQueueDepth   = 24u;
constexpr size_t kPcmRingFrames  = 8192u; /* ~185 ms stereo PCM @ 44.1 kHz */
/* What the ring holds before it is read, and what the resampler steers it back to: 50 ms at 44.1 kHz. The writer
 * brings 10 ms at a time on the codec's clock, the reader takes 15 to 23 ms at a time on the system timer's. */
constexpr size_t kPcmTargetFrames = 2205u;
constexpr int    kMaxScanDevices = 24;
constexpr int    kMaxFlightCreds = 8;     /* Leaves 4 credits in C6 Soft-BR (12 total) for signaling */
constexpr uint8_t kReqStart   = 1u << 0; /* BtcRuntime::upper_req */
constexpr uint8_t kReqSuspend = 1u << 1;
constexpr uint8_t kReqVolume  = 1u << 2;

struct BtcRuntime {
    std::mutex           api_mtx;
    std::mutex           state_mtx;
    std::mutex           pcm_mtx;
    portMUX_TYPE         rx_spin = portMUX_INITIALIZER_UNLOCKED;

    SemaphoreHandle_t    rx_sem       = nullptr;
    SemaphoreHandle_t    cmd_sem      = nullptr;
    SemaphoreHandle_t    inq_sem      = nullptr;
    SemaphoreHandle_t    conn_sem     = nullptr;
    SemaphoreHandle_t    setup_sem    = nullptr;
    TaskHandle_t         evt_task     = nullptr;
    TaskHandle_t         stream_task  = nullptr;

    bt_classic_config_t  cfg          = BT_CLASSIC_CONFIG_DEFAULT();
    char                 dev_name[64] = "Tab5 Classic";
    char                 pin_str[16]  = "0000";

    bool                 initialized      = false;
    bool                 c6_ready         = false;
    uint8_t              local_bdaddr[6]  = {0x36, 0x10, 0x22, 0x33, 0x44, 0x55};

    /* Synchronous HCI Command wait */
    std::atomic<uint16_t> wait_opcode{0};
    uint8_t              cmd_status       = 0xFFu;
    uint8_t              cmd_ret[252]     = {};
    uint8_t              cmd_ret_len      = 0u;

    /* Inquiry & Page wait */
    bool                 scanning_active  = false;
    bt_classic_device_t  scan_devs[kMaxScanDevices] = {};
    int                  scan_count       = 0;

    uint8_t              conn_status      = 0xFFu;
    bool                 acl_up           = false;
    bool                 setup_ok         = false;
    uint8_t              setup_err        = 0u;
    /* Where the traces are copied to before they are printed: here, in PSRAM with the rest, and neither on the
     * caller's stack nor in the internal RAM. */
    btc_lmp_rec_t        lmp_trace_copy[BTC_LMP_TRACE]     = {};
    btc_upper_rec_t      l2cap_trace_copy[BTC_UPPER_TRACE] = {};
    bool                 avdtp_ready_flag = false;

    /* ACL TX flow-control credits for handle 0x0B00 */
    std::atomic<int>     acl_credits{kMaxFlightCreds};
    std::atomic<int64_t> last_credit_us{0};

    /* The remembered devices, most recently used first (btc_bonds.h); under state_mtx */
    btc_bonds_t          bonds            = {};

    /* Live status & media command */
    bt_classic_status_t  status           = {};
    std::atomic<int>     media_cmd{BTC_MEDIA_CMD_NONE};
    std::atomic<uint8_t> volume{200}; /* 0..255 (~78%) */
    /* What other tasks want from the upper layer (kReq*): the event task, which runs everything else in that
     * layer, does it. */
    std::atomic<uint8_t> upper_req{0};

    /* Protocol engines */
    btc_lmp_t            lmp              = {};
    btc_upper_t          upper            = {};
    sbc_enc_t            sbc              = {};
    sbc_params_t         sbc_cfg          = {};

    /* RX Queue from SDIO thread -> evt_task */
    RxQueueItem          rx_q[kRxQueueDepth] = {};
    size_t               rx_head          = 0u;
    size_t               rx_tail          = 0u;
    size_t               rx_count         = 0u;

    /* Stereo PCM Ring Buffer + Fractional Linear Resampler */
    int16_t              pcm_ring[kPcmRingFrames * 2u] = {};
    size_t               pcm_r            = 0u;
    size_t               pcm_w            = 0u;
    size_t               pcm_avail        = 0u;
    uint32_t             resamp_phase_q16 = 0u;
    int16_t              resamp_prev_l    = 0;
    int16_t              resamp_prev_r    = 0;
    bool                 resamp_has_prev  = false;
    bool                 pcm_primed       = false; /* the ring reached its target and is being read */
    int64_t              pcm_last_write_us = 0;

    /* Media packets waiting for room in the controller (btc_media_queue.h): the stream task's alone. */
    btc_media_queue_t    media_q          = {};

    /* The controller's counters as it last reported them (bt_classic_get_diag); written in the receive thread. */
    portMUX_TYPE         diag_spin        = portMUX_INITIALIZER_UNLOCKED;
    bt_classic_diag_t    c6               = {};
};

BtcRuntime *g_rt = nullptr;

static void format_cod_fallback_name(const uint8_t bd[6], uint32_t cod, char *out, size_t cap)
{
    uint8_t major = (uint8_t)((cod >> 8) & 0x1Fu);
    uint8_t minor = (uint8_t)((cod >> 2) & 0x3Fu);
    const char *prefix = "Urządzenie BT";
    if (major == 0x04u) {
        if (minor == 0x01u || minor == 0x02u || minor == 0x06u) {
            prefix = "Słuchawki BT";
        } else if (minor == 0x05u || minor == 0x04u || minor == 0x08u || minor == 0x0Au) {
            prefix = "Głośnik BT";
        } else {
            prefix = "Audio BT";
        }
    } else if ((cod & 0x040000u) != 0u) {
        prefix = "Audio BT";
    }
    std::snprintf(out, cap, "%s (%02X:%02X:%02X)", prefix, bd[2], bd[1], bd[0]);
}

static bool is_cod_audio_sink(uint32_t cod)
{
    uint8_t major = (uint8_t)((cod >> 8) & 0x1Fu);
    return (major == 0x04u) || ((cod & 0x040000u) != 0u);
}

/* A name from one field of the runtime to another. A record found by its address and the destination are different
 * objects, but the compiler cannot see that, and snprintf's arguments must not overlap: through a buffer. */
static void copy_name(char *dst, size_t cap, const char *src)
{
    char tmp[64];
    std::snprintf(tmp, sizeof(tmp), "%s", src);
    std::snprintf(dst, cap, "%s", tmp);
}

/* The record of a remembered device, nullptr when it is not remembered. Under state_mtx. */
static btc_bond_t *bond_of(BtcRuntime *rt, const uint8_t addr[6])
{
    const int at = btc_bonds_find(&rt->bonds, addr);
    return at >= 0 ? &rt->bonds.items[at] : nullptr;
}

static void save_bonds_locked(BtcRuntime *rt)
{
    rt->status.bonded = rt->bonds.count > 0u;
    if (rt->bonds.count == 0u) {
        if (rt->cfg.kv.erase) {
            rt->cfg.kv.erase(rt->cfg.kv.ctx, kBondKey);
        }
        return;
    }
    uint8_t buf[BTC_BONDS_STORE_MAX];
    const size_t n = btc_bonds_store(&rt->bonds, buf, sizeof(buf));
    if (n > 0u && rt->cfg.kv.set) {
        rt->cfg.kv.set(rt->cfg.kv.ctx, kBondKey, buf, n);
    }
}

static void load_bonds_locked(BtcRuntime *rt)
{
    rt->bonds = {};
    if (!rt->cfg.kv.get) {
        return;
    }
    uint8_t buf[BTC_BONDS_STORE_MAX];
    size_t got = 0u;
    if (rt->cfg.kv.get(rt->cfg.kv.ctx, kBondKey, buf, sizeof(buf), &got) == 0 &&
        btc_bonds_load(&rt->bonds, buf, got) && rt->bonds.count > 0u) {
        const btc_bond_t &last = rt->bonds.items[0];
        rt->status.bonded = true;
        memcpy(rt->status.peer_addr, last.addr, 6u);
        std::snprintf(rt->status.peer_name, sizeof(rt->status.peer_name), "%s", last.name);
        ESP_LOGI(kTag, "Classic: %u remembered device(s), last used '%s'", (unsigned)rt->bonds.count,
                 last.name);
    }
}

/* ---- Raw HCI TX Helpers ---- */
static bool send_hci_cmd_sync(BtcRuntime *rt, uint16_t opcode, const uint8_t *params, uint8_t plen,
                              uint32_t timeout_ms, uint8_t *out_status = nullptr,
                              uint8_t *out_ret = nullptr, uint8_t *out_ret_len = nullptr)
{
    uint8_t h4[260];
    h4[0] = BR_H4_CMD;
    h4[1] = (uint8_t)(opcode & 0xFFu);
    h4[2] = (uint8_t)((opcode >> 8) & 0xFFu);
    h4[3] = plen;
    if (plen > 0u && params != nullptr) {
        memcpy(&h4[4], params, plen);
    }

    xSemaphoreTake(rt->cmd_sem, 0); /* Drain stale signal */
    rt->cmd_status  = 0xFFu;
    rt->cmd_ret_len = 0u;
    rt->wait_opcode.store(opcode, std::memory_order_release);

    if (esp_hosted_cyberdeck_hci_tx(h4, (uint16_t)(4u + plen)) != 0) {
        rt->wait_opcode.store(0u, std::memory_order_release);
        return false;
    }

    if (xSemaphoreTake(rt->cmd_sem, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
        rt->wait_opcode.store(0u, std::memory_order_release);
        return false;
    }

    if (out_status) *out_status = rt->cmd_status;
    if (out_ret && out_ret_len) {
        *out_ret_len = rt->cmd_ret_len;
        if (rt->cmd_ret_len > 0u) {
            memcpy(out_ret, rt->cmd_ret, rt->cmd_ret_len);
        }
    }
    return rt->cmd_status == 0x00u;
}

static void send_hci_cmd_fire_and_forget(uint16_t opcode, const uint8_t *params, uint8_t plen)
{
    uint8_t h4[64];
    if (4u + plen > sizeof(h4)) {
        return;
    }
    h4[0] = BR_H4_CMD;
    h4[1] = (uint8_t)(opcode & 0xFFu);
    h4[2] = (uint8_t)((opcode >> 8) & 0xFFu);
    h4[3] = plen;
    if (plen > 0u && params != nullptr) {
        memcpy(&h4[4], params, plen);
    }
    (void)esp_hosted_cyberdeck_hci_tx(h4, (uint16_t)(4u + plen));
}

/* What the stream task and the receive thread tell bt_classic_get_diag and each other. */
static std::atomic<uint16_t> s_media_waiting{0};
static std::atomic<uint16_t> s_media_most{0}; /* most waiting at once since the last bt_classic_get_diag */
static std::atomic<uint32_t> s_media_lost{0};
static std::atomic<uint16_t> s_media_mtu{0};  /* the speaker's MTU on the media channel */
static std::atomic<uint8_t>  s_busy_pct{0};   /* the link's load in the last rate window */
static std::atomic<uint32_t> s_rate_windows{0};
static std::atomic<uint32_t> s_bitpool_up{0};
static std::atomic<uint32_t> s_bitpool_down{0};
static std::atomic<uint32_t> s_l2cap_rx{0};
static std::atomic<uint32_t> s_pcm_underruns{0};
static std::atomic<uint32_t> s_pcm_dropped{0};
static std::atomic<uint16_t> s_soft_gain_q15{32767}; /* for a speaker that does not set the level itself */
static std::atomic<uint8_t>  s_rate_up_pct{BTC_RATE_UP_PCT};   /* bt_classic_set_link_limits */
static std::atomic<uint8_t>  s_rate_down_pct{BTC_RATE_DOWN_PCT};

/* The link's load for btc_rate.h: the time in which the controller held data that had not gone out yet. It
 * starts when a frame is handed over while nothing was on its way, and ends when the controller has given every
 * credit back; s_link_busy_us collects it for the stream task's window. */
static std::atomic<int64_t>  s_link_busy_since_us{0};
static std::atomic<uint32_t> s_link_busy_us{0};

/* The controller's counters for the link, as BR_VS_GET_DIAG returns them: what goes out, what comes back and how
 * the peer answers. Receive thread. */
static void keep_c6_diag(BtcRuntime *rt, const uint8_t *ret, size_t len)
{
    br_diag_stats_t d;
    memcpy(&d, ret, sizeof(d));
    const uint8_t *b = ret + sizeof(d);
    portENTER_CRITICAL(&rt->diag_spin);
    bt_classic_diag_t &o = rt->c6;
    o.slots_tx = d.slots_tx;
    o.slots_rx = d.slots_rx;
    o.slots_skipped = d.slots_skipped;
    o.pairs_lost = d.pairs_lost;
    o.rx_sync_ok = d.rx_sync_ok;
    o.rx_hec_ok = d.rx_hec_ok;
    o.rx_hec_err = d.rx_hec_err;
    o.rx_crc_ok = d.rx_crc_ok;
    o.rx_crc_err = d.rx_crc_err;
    o.tx_acks = d.tx_acks;
    o.tx_naks = d.tx_naks;
    o.tx_retrans = d.tx_retrans;
    o.acl_sdu_tx = d.acl_sdu_tx;
    o.lmp_tx = d.lmp_tx_cnt;
    o.lmp_rx = d.lmp_rx_cnt;
    if (len >= sizeof(d) + 9u) {
        o.pairs_late         = (uint16_t)(b[0] | (b[1] << 8));
        o.build_longest_us   = (uint16_t)(b[2] | (b[3] << 8));
        o.build_allowance_us = (uint16_t)(b[4] | (b[5] << 8));
        o.tx_max_slots       = b[6];
        o.tx_size_level      = b[7];
        o.tx_flushes         = b[8];
    }
    if (len >= sizeof(d) + 16u) {
        o.size_strikes  = b[9];
        o.probes        = (uint16_t)(b[10] | (b[11] << 8));
        o.pairs_refused = (uint16_t)(b[12] | (b[13] << 8));
        /* The controller starts this one again with every answer: keep the longest since the link came up. */
        o.silent_run_max = std::max<uint16_t>(o.silent_run_max, (uint16_t)(b[14] | (b[15] << 8)));
    }
    o.c6_reports++;
    portEXIT_CRITICAL(&rt->diag_spin);
}

/* The gaps in the speaker's answers, as BR_VS_GET_GAPS returns (and forgets) them: summed up. Receive thread. */
static void keep_c6_gaps(BtcRuntime *rt, const uint8_t *ret, size_t len)
{
    const unsigned n      = ret[0];
    const unsigned missed = (unsigned)ret[1] | ((unsigned)ret[2] << 8);
    if (len < 3u + 8u * n) {
        return;
    }
    portENTER_CRITICAL(&rt->diag_spin);
    bt_classic_diag_t &o = rt->c6;
    o.gaps_unrecorded += missed;
    for (unsigned i = 0; i < n; i++) {
        const uint8_t *g = &ret[3u + 8u * i];
        const unsigned len_100us = (unsigned)g[4] | ((unsigned)g[5] << 8);
        const unsigned pairs     = (unsigned)g[6] | ((unsigned)g[7] << 8);
        o.gaps++;
        o.gap_pairs += pairs;
        o.gap_total_100us += len_100us;
        o.gap_longest_100us = std::max<uint16_t>(o.gap_longest_100us, (uint16_t)len_100us);
    }
    portEXIT_CRITICAL(&rt->diag_spin);
}

/* Pairs answered per RF channel, as BR_VS_GET_CHAN_STATS returns them: one character per channel 0..78, '0'..'9'
 * for the tenth of its pairs that got an answer, '-' for a channel with fewer than four pairs. Receive thread. */
static void keep_c6_chan(BtcRuntime *rt, const uint8_t *tried, const uint8_t *heard)
{
    char row[BR_NUM_CHANNELS + 1u];
    for (size_t ch = 0; ch < BR_NUM_CHANNELS; ch++) {
        const unsigned tenth = tried[ch] ? (unsigned)heard[ch] * 10u / tried[ch] : 0u;
        row[ch] = (tried[ch] < 4u) ? '-' : (char)('0' + (tenth > 9u ? 9u : tenth));
    }
    row[BR_NUM_CHANNELS] = '\0';
    portENTER_CRITICAL(&rt->diag_spin);
    memcpy(rt->c6.chan_row, row, sizeof(row));
    portEXIT_CRITICAL(&rt->diag_spin);
}

/* ---- LMP & Upper Layer Callbacks (invoked on evt_task / stream_task) ---- */
static void cb_send_lmp(void *ctx, const uint8_t *pdu, uint8_t len)
{
    (void)ctx;
    if (!pdu || len == 0u || len > BR_MAX_DM1_BYTES) {
        return;
    }
    uint8_t p[8 + BR_MAX_DM1_BYTES];
    p[0] = BR_VENDOR_MAGIC_0;
    p[1] = BR_VENDOR_MAGIC_1;
    p[2] = BR_VENDOR_MAGIC_2;
    p[3] = BR_VENDOR_MAGIC_3;
    p[4] = BR_VS_SEND_LMP;
    p[5] = (uint8_t)(BR_ACL_HANDLE_BASE & 0xFFu);
    p[6] = (uint8_t)((BR_ACL_HANDLE_BASE >> 8) & 0xFFu);
    p[7] = len;
    memcpy(&p[8], pdu, len);
    send_hci_cmd_fire_and_forget(BR_HCI_OP_VENDOR_BRC6, p, (uint8_t)(8u + len));
}

/* The peer's word on multi-slot packets goes to the controller, which sends 1-slot packets until then. */
static void cb_on_peer_max_slots(void *ctx, uint8_t slots, uint8_t why, uint8_t err)
{
    (void)ctx;
    static const char *const kWhy[] = { "the speaker sent LMP_max_slot", "the speaker accepted our LMP_max_slot_req",
                                        "the speaker refused our LMP_max_slot_req" };
    ESP_LOGD(kTag, "ACL packets to the speaker: up to %u slot(s) (%s%s%02X)", (unsigned)slots,
             why < 3u ? kWhy[why] : "?", why == 2u ? ", reason 0x" : ", ", (unsigned)err);
    const uint8_t p[6] = { BR_VENDOR_MAGIC_0, BR_VENDOR_MAGIC_1, BR_VENDOR_MAGIC_2, BR_VENDOR_MAGIC_3,
                           BR_VS_SET_TX_SLOTS, slots };
    send_hci_cmd_fire_and_forget(BR_HCI_OP_VENDOR_BRC6, p, sizeof(p));
}

static void cb_start_encryption(void *ctx, const uint8_t en_rand[16], const uint8_t kc_prime[16])
{
    BtcRuntime *rt = static_cast<BtcRuntime *>(ctx);
    {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        rt->status.phase = BTC_PHASE_ENCRYPTING;
    }
    uint8_t p[39];
    p[0] = BR_VENDOR_MAGIC_0;
    p[1] = BR_VENDOR_MAGIC_1;
    p[2] = BR_VENDOR_MAGIC_2;
    p[3] = BR_VENDOR_MAGIC_3;
    p[4] = BR_VS_START_ENC;
    p[5] = (uint8_t)(BR_ACL_HANDLE_BASE & 0xFFu);
    p[6] = (uint8_t)((BR_ACL_HANDLE_BASE >> 8) & 0xFFu);
    memcpy(&p[7], en_rand, 16u);
    memcpy(&p[23], kc_prime, 16u);
    send_hci_cmd_fire_and_forget(BR_HCI_OP_VENDOR_BRC6, p, sizeof(p));
}

static void cb_random_bytes(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    esp_fill_random(out, len);
}

static void cb_on_remote_name(void *ctx, const char *name_utf8)
{
    BtcRuntime *rt = static_cast<BtcRuntime *>(ctx);
    if (!name_utf8 || !name_utf8[0]) {
        return;
    }
    std::lock_guard<std::mutex> sl(rt->state_mtx);
    std::snprintf(rt->status.peer_name, sizeof(rt->status.peer_name), "%s", name_utf8);
    if (btc_bond_t *bond = bond_of(rt, rt->status.peer_addr)) {
        std::snprintf(bond->name, sizeof(bond->name), "%s", name_utf8);
        save_bonds_locked(rt);
    }
}

static void cb_on_link_key(void *ctx, const uint8_t peer_bdaddr[6], const uint8_t link_key[16])
{
    BtcRuntime *rt = static_cast<BtcRuntime *>(ctx);
    std::lock_guard<std::mutex> sl(rt->state_mtx);
    /* A new device goes to the front of the list; with the list full the one used longest ago is forgotten. */
    btc_bond_t *bond = btc_bonds_touch(&rt->bonds, peer_bdaddr);
    memcpy(bond->link_key, link_key, 16u);
    if (rt->status.peer_name[0] != '\0') {
        copy_name(bond->name, sizeof(bond->name), rt->status.peer_name);
    } else if (bond->name[0] == '\0') {
        format_cod_fallback_name(peer_bdaddr, 0x240404u, bond->name, sizeof(bond->name));
    }
    save_bonds_locked(rt);
    ESP_LOGI(kTag, "Classic: pairing key saved for '%s'", bond->name);
}

static void cb_on_setup_done(void *ctx, bool ok, uint8_t err_reason)
{
    BtcRuntime *rt = static_cast<BtcRuntime *>(ctx);
    {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        rt->setup_ok  = ok;
        rt->setup_err = err_reason;
        if (ok && rt->lmp.goal == BTC_LMP_GOAL_CONNECT) {
            rt->status.encrypted = rt->lmp.encrypted;
            rt->status.state     = BT_CLASSIC_CONFIGURING;
            rt->status.phase     = BTC_PHASE_SDP;
        }
    }
    if (ok && rt->lmp.goal == BTC_LMP_GOAL_CONNECT) {
        btc_upper_start_initiator(&rt->upper);
    }
    xSemaphoreGive(rt->setup_sem);
}

static bool cb_send_l2cap_pdu(void *ctx, const uint8_t *l2cap_sdu, uint16_t sdu_len)
{
    BtcRuntime *rt = static_cast<BtcRuntime *>(ctx);
    if (!rt->acl_up || !l2cap_sdu || sdu_len == 0u || sdu_len > BR_ACL_SDU_MAX) {
        return false;
    }

    /* Check/consume ACL credit (with 600 ms stall-recovery guard) */
    int creds = rt->acl_credits.load(std::memory_order_acquire);
    if (creds <= 0) {
        int64_t now_us = esp_timer_get_time();
        int64_t prev_us = rt->last_credit_us.load(std::memory_order_acquire);
        if (now_us - prev_us > 600000) {
            rt->acl_credits.store(2, std::memory_order_release);
            rt->last_credit_us.store(now_us, std::memory_order_release);
        } else {
            return false;
        }
    }
    if (rt->acl_credits.fetch_sub(1, std::memory_order_acq_rel) >= kMaxFlightCreds) {
        s_link_busy_since_us.store(esp_timer_get_time(), std::memory_order_relaxed);
    }
    rt->last_credit_us.store(esp_timer_get_time(), std::memory_order_release);

    uint8_t h4[5 + BR_ACL_SDU_MAX];
    uint16_t hdr = (uint16_t)(BR_ACL_HANDLE_BASE | (0x02u << 12)); /* PB = 10 (first auto-flush) */
    h4[0] = BR_H4_ACL;
    h4[1] = (uint8_t)(hdr & 0xFFu);
    h4[2] = (uint8_t)((hdr >> 8) & 0xFFu);
    h4[3] = (uint8_t)(sdu_len & 0xFFu);
    h4[4] = (uint8_t)((sdu_len >> 8) & 0xFFu);
    memcpy(&h4[5], l2cap_sdu, sdu_len);

    if (esp_hosted_cyberdeck_hci_tx(h4, (uint16_t)(5u + sdu_len)) != 0) {
        rt->acl_credits.fetch_add(1, std::memory_order_acq_rel);
        return false;
    }
    return true;
}

static void cb_on_avdtp_ready(void *ctx, const sbc_params_t *negotiated_sbc, uint16_t media_mtu)
{
    BtcRuntime *rt = static_cast<BtcRuntime *>(ctx);
    s_media_mtu.store(media_mtu, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        rt->sbc_cfg = *negotiated_sbc;
        sbc_enc_init(&rt->sbc, &rt->sbc_cfg);
        rt->status.sample_rate     = sbc_sample_rate_hz(rt->sbc_cfg.freq);
        rt->status.sbc_bitpool     = rt->sbc_cfg.bitpool;
        rt->status.sbc_frame_bytes = sbc_frame_length(&rt->sbc_cfg);
        rt->status.state           = BT_CLASSIC_READY;
        rt->status.phase           = BTC_PHASE_AVDTP_OPEN;
        rt->avdtp_ready_flag       = true;
    }
    ESP_LOGI(kTag, "Classic: stream ready, %lu Hz, mode %u, bitpool %u (%u B a frame)",
             (unsigned long)rt->status.sample_rate, (unsigned)rt->sbc_cfg.mode,
             (unsigned)rt->status.sbc_bitpool, (unsigned)rt->status.sbc_frame_bytes);
    xSemaphoreGive(rt->setup_sem);
}

static void cb_on_stream_state(void *ctx, bool streaming)
{
    BtcRuntime *rt = static_cast<BtcRuntime *>(ctx);
    {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        if (streaming) {
            rt->status.state = BT_CLASSIC_STREAMING;
            rt->status.phase = BTC_PHASE_STREAMING;
        } else if (rt->acl_up) {
            rt->status.state = rt->avdtp_ready_flag ? BT_CLASSIC_READY : BT_CLASSIC_CONFIGURING;
            rt->status.phase = rt->avdtp_ready_flag ? BTC_PHASE_AVDTP_OPEN : BTC_PHASE_AVDTP_CFG;
        }
    }
    xSemaphoreGive(rt->setup_sem);
}

static void cb_on_avrcp_state(void *ctx, bool connected)
{
    BtcRuntime *rt = static_cast<BtcRuntime *>(ctx);
    {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        rt->status.avrcp_connected = connected;
    }
    if (connected) {
        btc_upper_set_volume(&rt->upper, rt->volume.load());
    }
}

static void cb_on_media_cmd(void *ctx, bt_classic_media_cmd_t cmd)
{
    BtcRuntime *rt = static_cast<BtcRuntime *>(ctx);
    rt->media_cmd.store((int)cmd, std::memory_order_release);
}

static void cb_on_peer_volume(void *ctx, uint8_t vol_0_255)
{
    BtcRuntime *rt = static_cast<BtcRuntime *>(ctx);
    rt->volume.store(vol_0_255, std::memory_order_release);
}

/* Commands only Classic sends: their Command Complete and Command Status are not shown to the LE host. */
static bool classic_only_opcode(uint16_t op)
{
    return op == BR_HCI_OP_VENDOR_BRC6 || op == BR_HCI_OP_INQUIRY || op == BR_HCI_OP_INQUIRY_CANCEL ||
           op == BR_HCI_OP_CREATE_CONN || op == BR_HCI_OP_CREATE_CONN_CANCEL || op == BR_HCI_OP_REMOTE_NAME_REQ;
}

/* ---- HCI receive: every packet from the controller, in the transport's receive thread (4 kB stack). True: the
 * packet is Classic's (its ACL handle, its events, the answers to its commands). The LE host gets the same packets
 * through its own callback and ignores these. Short: counters are copied here, everything else is queued for the
 * event task. ---- */
static bool on_hci_rx(const uint8_t *data, uint32_t len)
{
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized || !data || len < 3u) {
        return false;
    }

    if (data[0] == BR_H4_ACL) {
        if (len < 5u) return false;
        uint16_t h = (uint16_t)(((uint16_t)data[1] | ((uint16_t)data[2] << 8)) & 0x0FFFu);
        if (h != BR_ACL_HANDLE_BASE) return false;
    } else if (data[0] == BR_H4_EVT) {
        uint8_t evt = data[1];
        uint8_t plen = data[2];
        if (3u + plen > len) return false;
        const uint8_t *p = &data[3];

        /* Synchronous Command_Complete / Command_Status wakeup */
        uint16_t wop = rt->wait_opcode.load(std::memory_order_acquire);
        if (evt == BR_HCI_EVT_CMD_COMPLETE && plen >= 4u) {
            uint16_t op = (uint16_t)((uint16_t)p[1] | ((uint16_t)p[2] << 8));
            if (op == BR_HCI_OP_VENDOR_BRC6 && plen >= 4u + 5u + sizeof(br_diag_stats_t) && p[8] == BR_VS_GET_DIAG) {
                keep_c6_diag(rt, &p[9], (size_t)plen - 9u);
                return true; /* asked for by the stream task once a second: nobody waits for it */
            }
            if (op == BR_HCI_OP_VENDOR_BRC6 && plen >= 4u + 5u + 3u && p[8] == BR_VS_GET_GAPS) {
                keep_c6_gaps(rt, &p[9], (size_t)plen - 9u);
                return true; /* the same */
            }
            if (op == BR_HCI_OP_VENDOR_BRC6 && plen >= 4u + 5u + 2u * BR_NUM_CHANNELS && p[8] == BR_VS_GET_CHAN_STATS) {
                keep_c6_chan(rt, &p[9], &p[9 + BR_NUM_CHANNELS]);
                return true; /* the same, every ten seconds */
            }
            if (wop != 0u && op == wop) {
                rt->cmd_status  = p[3];
                rt->cmd_ret_len = (uint8_t)std::min<size_t>(plen - 4u, sizeof(rt->cmd_ret));
                if (rt->cmd_ret_len > 0u) {
                    memcpy(rt->cmd_ret, &p[4], rt->cmd_ret_len);
                }
                rt->wait_opcode.store(0u, std::memory_order_release);
                xSemaphoreGive(rt->cmd_sem);
            }
            /* HCI_Disconnect is sent by both hosts and its answer names no handle: the LE host looks at it too. */
            return classic_only_opcode(op);
        }
        if (evt == BR_HCI_EVT_CMD_STATUS && plen >= 4u) {
            uint16_t op = (uint16_t)((uint16_t)p[2] | ((uint16_t)p[3] << 8));
            if (wop != 0u && op == wop) {
                rt->cmd_status  = p[0];
                rt->cmd_ret_len = 0u;
                rt->wait_opcode.store(0u, std::memory_order_release);
                xSemaphoreGive(rt->cmd_sem);
            }
            return classic_only_opcode(op);
        }
        if (evt == BR_HCI_EVT_NUM_COMP_PKTS && plen >= 5u) {
            uint16_t h = (uint16_t)(((uint16_t)p[1] | ((uint16_t)p[2] << 8)) & 0x0FFFu);
            if (h != BR_ACL_HANDLE_BASE) {
                return false;
            }
            uint16_t cnt = (uint16_t)((uint16_t)p[3] | ((uint16_t)p[4] << 8));
            int cur = rt->acl_credits.fetch_add((int)cnt, std::memory_order_acq_rel) + (int)cnt;
            if (cur > kMaxFlightCreds) {
                rt->acl_credits.store(kMaxFlightCreds, std::memory_order_release);
            }
            if (cur >= kMaxFlightCreds) {
                const int64_t since = s_link_busy_since_us.exchange(0, std::memory_order_relaxed);
                if (since != 0) {
                    s_link_busy_us.fetch_add((uint32_t)(esp_timer_get_time() - since), std::memory_order_relaxed);
                }
            }
            rt->last_credit_us.store(esp_timer_get_time(), std::memory_order_release);
            return true;
        }
        if (evt == BR_HCI_EVT_DISCONN_COMPLETE && plen >= 4u) {
            uint16_t h = (uint16_t)(((uint16_t)p[1] | ((uint16_t)p[2] << 8)) & 0x0FFFu);
            if (h != BR_ACL_HANDLE_BASE) return false;
        } else if (evt == BR_HCI_EVT_VENDOR) {
            if (plen < 5u || p[0] != BR_VENDOR_MAGIC_0 || p[1] != BR_VENDOR_MAGIC_1 ||
                p[2] != BR_VENDOR_MAGIC_2 || p[3] != BR_VENDOR_MAGIC_3) {
                return false;
            }
        } else if (evt != BR_HCI_EVT_INQUIRY_COMPLETE &&
                   evt != BR_HCI_EVT_INQUIRY_RESULT_RSSI &&
                   evt != BR_HCI_EVT_CONN_COMPLETE) {
            return false;
        }
    } else {
        return false;
    }

    if (len > sizeof(RxQueueItem::data)) {
        return true;
    }

    bool queued = false;
    portENTER_CRITICAL(&rt->rx_spin);
    if (rt->rx_count < kRxQueueDepth) {
        RxQueueItem &slot = rt->rx_q[rt->rx_tail];
        slot.len = (uint16_t)len;
        memcpy(slot.data, data, len);
        rt->rx_tail = (rt->rx_tail + 1u) % kRxQueueDepth;
        rt->rx_count++;
        queued = true;
    }
    portEXIT_CRITICAL(&rt->rx_spin);

    if (queued) {
        xSemaphoreGive(rt->rx_sem);
    }
    return true;
}

/* ---- Protocol Event Worker Task (12 KB PSRAM stack) ---- */
static void evt_worker_task(void *arg)
{
    BtcRuntime *rt = static_cast<BtcRuntime *>(arg);
    RxQueueItem item;
    int64_t last_lmp_tick_us = 0;

    for (;;) {
        xSemaphoreTake(rt->rx_sem, pdMS_TO_TICKS(100));
        const uint8_t req = rt->upper_req.exchange(0u, std::memory_order_acq_rel);
        if (rt->acl_up) {
            if (req & kReqVolume) {
                btc_upper_set_volume(&rt->upper, rt->volume.load(std::memory_order_acquire));
            }
            if (req & kReqSuspend) {
                btc_upper_request_suspend(&rt->upper);
            }
            if (req & kReqStart) {
                btc_upper_request_start(&rt->upper);
            }
        }
        if (rt->acl_up && esp_timer_get_time() - last_lmp_tick_us >= 500000) {
            last_lmp_tick_us = esp_timer_get_time();
            btc_lmp_on_tick(&rt->lmp);
            btc_upper_on_tick(&rt->upper);
        }

        for (;;) {
            bool got = false;
            portENTER_CRITICAL(&rt->rx_spin);
            if (rt->rx_count > 0u) {
                item = rt->rx_q[rt->rx_head];
                rt->rx_head = (rt->rx_head + 1u) % kRxQueueDepth;
                rt->rx_count--;
                got = true;
            }
            portEXIT_CRITICAL(&rt->rx_spin);

            if (!got) {
                break;
            }

            if (item.data[0] == BR_H4_ACL && item.len >= 5u) {
                uint16_t dlen = (uint16_t)((uint16_t)item.data[3] | ((uint16_t)item.data[4] << 8));
                if (5u + dlen <= item.len) {
                    s_l2cap_rx.fetch_add(1u, std::memory_order_relaxed);
                    btc_upper_on_l2cap_pdu(&rt->upper, &item.data[5], dlen);
                }
                continue;
            }

            if (item.data[0] != BR_H4_EVT || item.len < 3u) {
                continue;
            }
            uint8_t evt = item.data[1];
            uint8_t plen = item.data[2];
            const uint8_t *p = &item.data[3];

            if (evt == BR_HCI_EVT_INQUIRY_RESULT_RSSI && plen >= 15u) {
                std::lock_guard<std::mutex> sl(rt->state_mtx);
                if (!rt->scanning_active) continue;
                const uint8_t *bd = &p[1];
                uint8_t sr = p[7];
                uint32_t cod = (uint32_t)p[9] | ((uint32_t)p[10] << 8) | ((uint32_t)p[11] << 16);
                uint16_t clk_off = (uint16_t)((uint16_t)p[12] | ((uint16_t)p[13] << 8));
                int8_t rssi = (int8_t)p[14];

                int idx = -1;
                for (int i = 0; i < rt->scan_count; i++) {
                    if (memcmp(rt->scan_devs[i].addr, bd, 6u) == 0) {
                        idx = i;
                        break;
                    }
                }
                if (idx < 0 && rt->scan_count < kMaxScanDevices) {
                    idx = rt->scan_count++;
                    memset(&rt->scan_devs[idx], 0, sizeof(bt_classic_device_t));
                    memcpy(rt->scan_devs[idx].addr, bd, 6u);
                }
                if (idx >= 0) {
                    bt_classic_device_t &d = rt->scan_devs[idx];
                    d.class_of_device = cod;
                    d.clock_offset    = clk_off;
                    d.page_scan_rep   = sr;
                    d.rssi            = rssi;
                    d.is_audio_sink   = is_cod_audio_sink(cod);
                    const btc_bond_t *bond = bond_of(rt, bd);
                    if (bond != nullptr && bond->name[0] != '\0') {
                        copy_name(d.name, sizeof(d.name), bond->name);
                    } else if (d.name[0] == '\0') {
                        format_cod_fallback_name(bd, cod, d.name, sizeof(d.name));
                    }
                }
            } else if (evt == BR_HCI_EVT_INQUIRY_COMPLETE) {
                {
                    std::lock_guard<std::mutex> sl(rt->state_mtx);
                    rt->scanning_active = false;
                }
                xSemaphoreGive(rt->inq_sem);
            } else if (evt == BR_HCI_EVT_CONN_COMPLETE && plen >= 11u) {
                uint8_t st = p[0];
                {
                    std::lock_guard<std::mutex> sl(rt->state_mtx);
                    rt->conn_status = st;
                    rt->acl_up      = (st == 0x00u);
                    rt->acl_credits.store(kMaxFlightCreds, std::memory_order_release);
                    rt->last_credit_us.store(esp_timer_get_time(), std::memory_order_release);
                }
                xSemaphoreGive(rt->conn_sem);
            } else if (evt == BR_HCI_EVT_DISCONN_COMPLETE && plen >= 4u) {
                uint8_t reason = p[3];
                ESP_LOGI(kTag, "Classic: connection ended (reason 0x%02X)", reason);
                {
                    std::lock_guard<std::mutex> sl(rt->state_mtx);
                    rt->acl_up                   = false;
                    rt->avdtp_ready_flag         = false;
                    rt->status.encrypted         = false;
                    rt->status.avrcp_connected   = false;
                    rt->status.last_disconnect_reason = reason;
                    if (rt->status.state != BT_CLASSIC_SCANNING) {
                        rt->status.state = BT_CLASSIC_IDLE;
                        rt->status.phase = BTC_PHASE_NONE;
                    }
                }
                btc_upper_reset(&rt->upper);
                xSemaphoreGive(rt->conn_sem);
                xSemaphoreGive(rt->setup_sem);
            } else if (evt == BR_HCI_EVT_VENDOR && plen >= 8u) {
                uint8_t sub = p[4];
                if (sub == BR_VSEVT_LMP_RX && plen >= 8u + p[7]) {
                    btc_lmp_on_pdu(&rt->lmp, &p[8], p[7]);
                } else if (sub == BR_VSEVT_ENC_STATE && plen >= 9u) {
                    btc_lmp_on_encryption_state(&rt->lmp, p[7], p[8] != 0u);
                }
            }
        }
    }
}

/* Hands the waiting media packets on for as long as there is room for them. */
static void send_waiting_media(BtcRuntime *rt, uint16_t spf)
{
    for (const btc_media_pkt_t *p = btc_media_queue_front(&rt->media_q); p != nullptr;
         p = btc_media_queue_front(&rt->media_q)) {
        if (!btc_upper_send_media_packet(&rt->upper, p->data, p->len, p->frames, spf)) {
            break;
        }
        rt->status.tx_frames++;
        btc_media_queue_pop(&rt->media_q);
    }
    s_media_waiting.store(rt->media_q.count, std::memory_order_relaxed);
}

static uint16_t rate_frame_bytes(void *ctx, uint8_t bitpool)
{
    sbc_params_t p = *static_cast<const sbc_params_t *>(ctx);
    p.bitpool = bitpool;
    return sbc_frame_length(&p);
}

/* The share of the last window, in percent, in which the controller held data; starts the next window. */
static uint32_t take_link_busy_pct(int64_t window_start_us, int64_t now_us)
{
    uint32_t busy_us = s_link_busy_us.exchange(0u, std::memory_order_relaxed);
    int64_t since = s_link_busy_since_us.load(std::memory_order_relaxed);
    /* Still busy: count up to now and let the rest fall into the next window (unless it has just ended). */
    if (since != 0 && s_link_busy_since_us.compare_exchange_strong(since, now_us, std::memory_order_relaxed)) {
        busy_us += (uint32_t)(now_us - since);
    }
    const int64_t window_us = now_us - window_start_us;
    if (window_us <= 0) {
        return 0u;
    }
    const uint64_t pct = (uint64_t)busy_us * 100u / (uint64_t)window_us;
    return pct > 100u ? 100u : (uint32_t)pct;
}

/* ---- Real-Time A2DP RTP+SBC Streamer Task (12 KB PSRAM stack) ---- */
static void stream_worker_task(void *arg)
{
    BtcRuntime *rt = static_cast<BtcRuntime *>(arg);
    int64_t next_deadline_us = 0;
    uint32_t frac_rem_ns     = 0u;
    int16_t  frame_pcm[128 * 2];
    uint8_t  sbc_pkt[BTC_MEDIA_PKT_MAX];
    /* The bitpool follows the link (btc_rate.h): judged every kRateWindowUs while the stream runs. */
    static constexpr int64_t kRateWindowUs = 2000000;
    btc_rate_t rate           = {};
    bool       rate_running   = false;
    int64_t    rate_window_us = 0;
    uint32_t   rate_lost_seen = 0;

    int64_t last_diag_us = 0;
    int64_t last_chan_us = 0;
    bool    was_streaming = false;
    for (;;) {
        if (rt->acl_up && esp_timer_get_time() - last_diag_us >= 1000000) {
            last_diag_us = esp_timer_get_time();
            const uint8_t ask[5] = { BR_VENDOR_MAGIC_0, BR_VENDOR_MAGIC_1, BR_VENDOR_MAGIC_2, BR_VENDOR_MAGIC_3,
                                     BR_VS_GET_DIAG };
            send_hci_cmd_fire_and_forget(BR_HCI_OP_VENDOR_BRC6, ask, sizeof(ask));
            const uint8_t ask_gaps[5] = { BR_VENDOR_MAGIC_0, BR_VENDOR_MAGIC_1, BR_VENDOR_MAGIC_2,
                                          BR_VENDOR_MAGIC_3, BR_VS_GET_GAPS };
            send_hci_cmd_fire_and_forget(BR_HCI_OP_VENDOR_BRC6, ask_gaps, sizeof(ask_gaps));
        }
        if (rt->acl_up && esp_timer_get_time() - last_chan_us >= 10000000) {
            last_chan_us = esp_timer_get_time();
            const uint8_t ask[5] = { BR_VENDOR_MAGIC_0, BR_VENDOR_MAGIC_1, BR_VENDOR_MAGIC_2, BR_VENDOR_MAGIC_3,
                                     BR_VS_GET_CHAN_STATS };
            send_hci_cmd_fire_and_forget(BR_HCI_OP_VENDOR_BRC6, ask, sizeof(ask));
        }
        if (!rt->acl_up || !btc_upper_can_send_media(&rt->upper)) {
            next_deadline_us = 0;
            frac_rem_ns = 0u;
            rate_running = false;
            was_streaming = false;
            btc_media_queue_reset(&rt->media_q);
            s_media_waiting.store(0u, std::memory_order_relaxed);
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }

        if (!was_streaming) {
            /* What was written while the stream was being started is old by now: the newest target's worth
             * stays, so that the sound is not later than it has to be. */
            was_streaming = true;
            std::lock_guard<std::mutex> pl(rt->pcm_mtx);
            if (rt->pcm_avail > kPcmTargetFrames) {
                rt->pcm_r = (rt->pcm_r + (rt->pcm_avail - kPcmTargetFrames)) % kPcmRingFrames;
                rt->pcm_avail = kPcmTargetFrames;
            }
            rt->pcm_primed = false;
        }

        uint32_t srate  = rt->status.sample_rate ? rt->status.sample_rate : 44100u;
        uint16_t spf    = sbc_pcm_samples_per_frame(&rt->sbc_cfg);
        if (rt->status.sbc_frame_bytes == 0u || spf == 0u) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }

        uint16_t mtu = s_media_mtu.load(std::memory_order_relaxed);
        if (mtu == 0u || mtu > BTC_L2CAP_LOCAL_MTU) {
            mtu = BTC_L2CAP_LOCAL_MTU;
        }
        if (!rate_running) {
            /* A new stream starts where the configuration says, and may go as low and as high as the speaker
             * allows. */
            uint8_t bp_min = 0, bp_max = 0;
            btc_upper_bitpool_range(&rt->upper, &bp_min, &bp_max);
            btc_rate_init(&rate, rt->cfg.sbc_bitpool, bp_min < 10u ? 10u : bp_min, bp_max, BR_DEFAULT_DH3_CAP, mtu,
                          rate_frame_bytes, &rt->sbc_cfg);
            rate_running   = true;
            rate_window_us = esp_timer_get_time();
            rate_lost_seen = s_media_lost.load(std::memory_order_relaxed);
            (void)take_link_busy_pct(rate_window_us, rate_window_us);
        } else if (esp_timer_get_time() - rate_window_us >= kRateWindowUs) {
            btc_rate_set_limits(&rate, s_rate_up_pct.load(std::memory_order_relaxed),
                                s_rate_down_pct.load(std::memory_order_relaxed));
            const int64_t  now      = esp_timer_get_time();
            const uint32_t busy_pct = take_link_busy_pct(rate_window_us, now);
            const uint32_t lost_now = s_media_lost.load(std::memory_order_relaxed);
            (void)btc_rate_end_window(&rate, busy_pct, lost_now - rate_lost_seen);
            s_busy_pct.store((uint8_t)busy_pct, std::memory_order_relaxed);
            s_rate_windows.fetch_add(1u, std::memory_order_relaxed);
            rate_window_us = now;
            rate_lost_seen = lost_now;
        }
        if (rate.bitpool != rt->sbc_cfg.bitpool) {
            std::lock_guard<std::mutex> sl(rt->state_mtx);
            (rate.bitpool > rt->sbc_cfg.bitpool ? s_bitpool_up : s_bitpool_down)
                .fetch_add(1u, std::memory_order_relaxed);
            rt->sbc_cfg.bitpool        = rate.bitpool;
            rt->sbc.params.bitpool     = rate.bitpool;
            rt->status.sbc_bitpool     = rate.bitpool;
            rt->status.sbc_frame_bytes = sbc_frame_length(&rt->sbc_cfg);
        }

        /* As many frames to a media packet as fill its 3-slot packets best (btc_rate.h). */
        const uint16_t fbytes = rt->status.sbc_frame_bytes;
        uint8_t frames_per_pkt = 1u, dh3_per_pkt = 1u;
        if (!btc_rate_packing(fbytes, BR_DEFAULT_DH3_CAP, mtu, &frames_per_pkt, &dh3_per_pkt)) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        size_t needed_pcm_frames = (size_t)frames_per_pkt * (size_t)spf;

        send_waiting_media(rt, spf);

        int64_t now_us = esp_timer_get_time();
        if (next_deadline_us == 0 || now_us - next_deadline_us > 60000) {
            next_deadline_us = now_us;
            frac_rem_ns = 0u;
        } else if (now_us < next_deadline_us) {
            int64_t sleep_us = next_deadline_us - now_us;
            /* With packets waiting the controller is asked again every 2 ms: after a gap the link takes them
             * faster than the stream makes them. */
            if (rt->media_q.count > 0u && sleep_us > 2000) {
                sleep_us = 2000;
            }
            /* Always a real sleep: at this priority a loop that only looks at the clock would keep core 1 from
             * everything below it. Up to 1 ms late is nothing to a deadline counted from the one before. */
            vTaskDelay(pdMS_TO_TICKS(sleep_us >= 1000 ? (uint32_t)(sleep_us / 1000) : 1u));
            continue;
        }

        /* Advance exact fractional deadline (zero cumulative drift at 44100 Hz!) */
        uint64_t total_ns = (uint64_t)needed_pcm_frames * 1000000000ULL + (uint64_t)frac_rem_ns;
        uint64_t step_ns  = total_ns / (uint64_t)srate;
        frac_rem_ns       = (uint32_t)(total_ns % (uint64_t)srate);
        next_deadline_us += (int64_t)(step_ns / 1000ULL);
        if (frac_rem_ns + (uint32_t)(step_ns % 1000ULL) * srate >= 1000u * srate) {
            /* Sub-microsecond residual is < 0.01% */
        }

        uint16_t sbc_total_bytes = 0u;
        /* A speaker that took SetAbsoluteVolume sets the level itself and gets the samples at full scale; for any
         * other the samples are scaled here. */
        const int32_t gain_q15 = btc_upper_peer_sets_volume(&rt->upper)
                                     ? 32767 : (int32_t)s_soft_gain_q15.load(std::memory_order_relaxed);

        /* The ring is read only once it holds its target. A packet it cannot fill goes out as silence and the
         * ring fills up again first; what is left when the writer has stopped goes out followed by silence. */
        size_t take = 0u;
        {
            std::lock_guard<std::mutex> pl(rt->pcm_mtx);
            const bool writer_gone = now_us - rt->pcm_last_write_us > 60000;
            if (rt->pcm_avail >= needed_pcm_frames && (rt->pcm_primed || rt->pcm_avail >= kPcmTargetFrames)) {
                rt->pcm_primed = true;
                take = needed_pcm_frames;
            } else {
                if (rt->pcm_primed && !writer_gone) {
                    s_pcm_underruns.fetch_add(1u, std::memory_order_relaxed);
                }
                rt->pcm_primed = false;
                take = writer_gone ? std::min(rt->pcm_avail, needed_pcm_frames) : 0u;
            }
        }

        for (uint8_t f = 0u; f < frames_per_pkt; f++) {
            {
                std::lock_guard<std::mutex> pl(rt->pcm_mtx);
                for (uint16_t s = 0u; s < spf; s++) {
                    if (take > 0u && rt->pcm_avail > 0u) {
                        take--;
                        int32_t l = rt->pcm_ring[rt->pcm_r * 2u];
                        int32_t r = rt->pcm_ring[rt->pcm_r * 2u + 1u];
                        rt->pcm_r = (rt->pcm_r + 1u) % kPcmRingFrames;
                        rt->pcm_avail--;
                        if (gain_q15 < 32767) {
                            l = (l * gain_q15) >> 15;
                            r = (r * gain_q15) >> 15;
                        }
                        frame_pcm[s * 2u]     = (int16_t)l;
                        frame_pcm[s * 2u + 1u] = (int16_t)r;
                    } else {
                        frame_pcm[s * 2u]     = 0;
                        frame_pcm[s * 2u + 1u] = 0;
                    }
                }
            }

            size_t enc_b = sbc_encode_frame(&rt->sbc, frame_pcm, 2,
                                            &sbc_pkt[sbc_total_bytes], sizeof(sbc_pkt) - sbc_total_bytes);
            sbc_total_bytes = (uint16_t)(sbc_total_bytes + enc_b);
        }

        if (sbc_total_bytes > 0u) {
            /* The packet waits for its turn; one is lost only when the queue is full (then the oldest) or when it
             * does not fit a queue slot at all. The receiver is shown the loss. */
            const uint32_t lost_before = rt->media_q.dropped;
            const bool taken = btc_media_queue_push(&rt->media_q, sbc_pkt, sbc_total_bytes, frames_per_pkt);
            if (!taken || rt->media_q.dropped != lost_before) {
                rt->status.tx_drops++;
                s_media_lost.fetch_add(1u, std::memory_order_relaxed);
                btc_upper_skip_media_packet(&rt->upper, frames_per_pkt, spf);
            }
            if (rt->media_q.count > s_media_most.load(std::memory_order_relaxed)) {
                s_media_most.store(rt->media_q.count, std::memory_order_relaxed);
            }
            send_waiting_media(rt, spf);
        }
    }
}

static bool probe_c6_soft_br(BtcRuntime *rt)
{
    if (!esp_hosted_cyberdeck_transport_up()) {
        if (esp_hosted_cyberdeck_connect(12000) != ESP_OK) {
            ESP_LOGW(kTag, "ESP-Hosted SDIO transport not up yet");
            return false;
        }
    }

    uint8_t ping[5] = {
        BR_VENDOR_MAGIC_0, BR_VENDOR_MAGIC_1, BR_VENDOR_MAGIC_2, BR_VENDOR_MAGIC_3, BR_VS_PING
    };
    uint8_t st = 0xFFu;
    uint8_t ret[32] = {};
    uint8_t rlen = 0u;

    if (send_hci_cmd_sync(rt, BR_HCI_OP_VENDOR_BRC6, ping, sizeof(ping), 800u, &st, ret, &rlen) &&
        rlen >= 12u && ret[0] == 'B' && ret[1] == 'R' && ret[2] == 'C' && ret[3] == '6') {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        memcpy(rt->local_bdaddr, &ret[6], 6u);
        memcpy(rt->lmp.local_bdaddr, &ret[6], 6u);
        rt->c6_ready = true;
        rt->status.c6_soft_br_ready = true;
        ESP_LOGI(kTag, "Classic: the C6 coprocessor has Soft-BR");
        return true;
    }

    std::lock_guard<std::mutex> sl(rt->state_mtx);
    rt->c6_ready = false;
    rt->status.c6_soft_br_ready = false;
    ESP_LOGW(kTag, "Classic: the C6 coprocessor has no Soft-BR (status 0x%02X) - it needs firmware 1.5.x", st);
    return false;
}

static void abort_and_disconnect_sync(BtcRuntime *rt)
{
    if (rt->acl_up) {
        uint8_t disc[3] = {
            (uint8_t)(BR_ACL_HANDLE_BASE & 0xFFu),
            (uint8_t)((BR_ACL_HANDLE_BASE >> 8) & 0xFFu),
            0x13u /* Remote User Terminated Connection */
        };
        xSemaphoreTake(rt->conn_sem, 0);
        send_hci_cmd_sync(rt, BR_HCI_OP_DISCONNECT, disc, sizeof(disc), 500u);
        xSemaphoreTake(rt->conn_sem, pdMS_TO_TICKS(600));
    }
    uint8_t ab[5] = { BR_VENDOR_MAGIC_0, BR_VENDOR_MAGIC_1, BR_VENDOR_MAGIC_2, BR_VENDOR_MAGIC_3, BR_VS_ABORT_ALL };
    send_hci_cmd_sync(rt, BR_HCI_OP_VENDOR_BRC6, ab, sizeof(ab), 500u);

    std::lock_guard<std::mutex> sl(rt->state_mtx);
    rt->acl_up = false;
    rt->avdtp_ready_flag = false;
    rt->status.encrypted = false;
    rt->status.avrcp_connected = false;
    rt->status.state = BT_CLASSIC_IDLE;
    rt->status.phase = BTC_PHASE_NONE;
    btc_upper_reset(&rt->upper);
}

static esp_err_t connect_internal(BtcRuntime *rt, const uint8_t addr[6], uint16_t clk_off,
                                  uint8_t sr, const char *known_name)
{
    std::lock_guard<std::mutex> al(rt->api_mtx);
    if (!rt->c6_ready && !probe_c6_soft_br(rt)) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    abort_and_disconnect_sync(rt);

    {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        rt->status.state = BT_CLASSIC_CONNECTING;
        rt->status.phase = BTC_PHASE_PAGING;
        memcpy(rt->status.peer_addr, addr, 6u);
        if (known_name && known_name[0] != '\0') {
            std::snprintf(rt->status.peer_name, sizeof(rt->status.peer_name), "%s", known_name);
        } else if (bond_of(rt, addr) != nullptr && bond_of(rt, addr)->name[0] != '\0') {
            copy_name(rt->status.peer_name, sizeof(rt->status.peer_name), bond_of(rt, addr)->name);
        } else {
            format_cod_fallback_name(addr, 0x240404u, rt->status.peer_name, sizeof(rt->status.peer_name));
        }

        if (btc_bond_t *bond = bond_of(rt, addr)) {
            btc_lmp_set_link_key(&rt->lmp, bond->link_key);
            if (clk_off == 0u) {
                /* Called by address alone (a remembered device picked from the list): what the last page of it
                 * needed is the best guess for this one. */
                clk_off = bond->clock_offset;
                sr      = bond->page_scan_rep;
            } else {
                bond->clock_offset  = clk_off;
                bond->page_scan_rep = sr;
            }
        } else {
            btc_lmp_clear_link_key(&rt->lmp);
        }
    }

    /* 1. Baseband Page (HCI_Create_Connection) */
    uint8_t cc[13];
    memcpy(&cc[0], addr, 6u);
    cc[6]  = 0x18u; /* DM1 | DH1 | DM3 | DH3 */
    cc[7]  = 0xCCu;
    cc[8]  = (sr <= 2u) ? sr : 1u;
    cc[9]  = 0x00u;
    uint16_t coff_valid = (clk_off != 0u) ? (uint16_t)(clk_off | 0x8000u) : 0x0000u;
    cc[10] = (uint8_t)(coff_valid & 0xFFu);
    cc[11] = (uint8_t)((coff_valid >> 8) & 0xFFu);
    cc[12] = 0x00u; /* Allow_Role_Switch = 0 (we remain Master) */

    /* One page lasts 5.5 s and meets a speaker that scans every 1.28 s about four times; with a third of the
     * exchanges lost on this radio that is not always enough (sound trial 9: two timeouts in a row). */
    static constexpr unsigned kPageAttempts = 3u;
    for (unsigned attempt = 1u;; attempt++) {
        xSemaphoreTake(rt->conn_sem, 0);
        xSemaphoreTake(rt->setup_sem, 0);

        if (!send_hci_cmd_sync(rt, BR_HCI_OP_CREATE_CONN, cc, sizeof(cc), 1000u)) {
            abort_and_disconnect_sync(rt);
            return ESP_FAIL;
        }
        if (xSemaphoreTake(rt->conn_sem, pdMS_TO_TICKS(6500)) == pdTRUE && rt->acl_up) {
            break;
        }
        ESP_LOGW(kTag, "Classic: page %u of %u unanswered (status 0x%02X)", attempt, kPageAttempts,
                 rt->conn_status);
        abort_and_disconnect_sync(rt);
        if (attempt == kPageAttempts) {
            return ESP_ERR_TIMEOUT;
        }
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        rt->status.state = BT_CLASSIC_CONNECTING;
        rt->status.phase = BTC_PHASE_PAGING;
    }

    portENTER_CRITICAL(&rt->diag_spin);
    rt->c6 = {};
    portEXIT_CRITICAL(&rt->diag_spin);
    s_media_lost.store(0u, std::memory_order_relaxed);
    s_media_most.store(0u, std::memory_order_relaxed);
    s_rate_windows.store(0u, std::memory_order_relaxed);
    s_bitpool_up.store(0u, std::memory_order_relaxed);
    s_bitpool_down.store(0u, std::memory_order_relaxed);
    s_l2cap_rx.store(0u, std::memory_order_relaxed);
    s_pcm_underruns.store(0u, std::memory_order_relaxed);
    s_pcm_dropped.store(0u, std::memory_order_relaxed);

    /* 2. LMP Setup + Authentication/Pairing + E0 Encryption + SDP + AVDTP OPEN */
    {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        rt->status.tx_frames = 0u;
        rt->status.tx_drops  = 0u;
        rt->setup_ok = false;
        rt->avdtp_ready_flag = false;
        rt->status.state = rt->lmp.has_link_key ? BT_CLASSIC_CONNECTING : BT_CLASSIC_PAIRING;
        rt->status.phase = BTC_PHASE_LMP_SETUP;
    }
    btc_upper_reset(&rt->upper);
    btc_upper_trace_clear(&rt->upper);
    btc_lmp_start(&rt->lmp, addr, BTC_LMP_GOAL_CONNECT);

    /* Wait up to 12 seconds for LMP + SSP/PIN + E0 + SDP + AVDTP OPEN */
    int64_t deadline = esp_timer_get_time() + 12000000LL;
    while (esp_timer_get_time() < deadline) {
        if (!rt->acl_up) {
            return ESP_FAIL;
        }
        if (rt->avdtp_ready_flag) {
            /* Enable AFH avoiding common Wi-Fi ch 1 / 6 center if peer supports AFH */
            if (rt->lmp.peer_afh_slave) {
                uint8_t afh[18];
                afh[0] = BR_VENDOR_MAGIC_0; afh[1] = BR_VENDOR_MAGIC_1;
                afh[2] = BR_VENDOR_MAGIC_2; afh[3] = BR_VENDOR_MAGIC_3;
                afh[4] = BR_VS_SET_AFH;
                afh[5] = (uint8_t)(BR_ACL_HANDLE_BASE & 0xFFu);
                afh[6] = (uint8_t)((BR_ACL_HANDLE_BASE >> 8) & 0xFFu);
                afh[7] = 1u;
                memset(&afh[8], 0xFF, 10u);
                afh[17] = 0x7Fu; /* 79 channels valid */
                send_hci_cmd_fire_and_forget(BR_HCI_OP_VENDOR_BRC6, afh, sizeof(afh));
            }
            {
                std::lock_guard<std::mutex> sl(rt->state_mtx);
                if (btc_bonds_find(&rt->bonds, addr) > 0) {
                    (void)btc_bonds_touch(&rt->bonds, addr); /* now the most recently used */
                    save_bonds_locked(rt);
                }
            }
            return ESP_OK;
        }
        if (rt->lmp.setup_finished && !rt->setup_ok) {
            ESP_LOGW(kTag, "Classic: pairing or authentication failed (code 0x%02X)", rt->setup_err);
            abort_and_disconnect_sync(rt);
            return ESP_FAIL;
        }
        xSemaphoreTake(rt->setup_sem, pdMS_TO_TICKS(250));
    }

    /* Read next to the event task that writes it: one 16-bit value, and the link is about to be closed anyway. */
    const uint16_t refusal = btc_upper_audio_refusal(&rt->upper);
    if (refusal != 0u) {
        ESP_LOGW(kTag, "Classic: the device refused the audio channel (L2CAP result 0x%04X)", (unsigned)refusal);
        abort_and_disconnect_sync(rt);
        return ESP_ERR_NOT_ALLOWED;
    }
    ESP_LOGW(kTag, "Classic: the device did not open the audio channel within 12 s");
    abort_and_disconnect_sync(rt);
    return ESP_ERR_TIMEOUT;
}

/* esp_hosted hands every HCI packet to every registered callback; what on_hci_rx says about ownership is for a
 * transport with one receiver and is not needed here. */
static void on_hci_rx_cb(const uint8_t *data, uint32_t len)
{
    (void)on_hci_rx(data, len);
}

} /* namespace */

/* =========================================================================
 * Public C API (`bt_classic.h`)
 * ========================================================================= */
extern "C" esp_err_t bt_classic_init(const bt_classic_config_t *cfg)
{
    if (g_rt && g_rt->initialized) {
        return ESP_OK;
    }

    if (!g_rt) {
        void *mem = heap_caps_calloc(1, sizeof(BtcRuntime), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!mem) {
            mem = std::calloc(1, sizeof(BtcRuntime));
        }
        if (!mem) {
            return ESP_ERR_NO_MEM;
        }
        g_rt = new (mem) BtcRuntime();
    }

    BtcRuntime *rt = g_rt;
    if (cfg) {
        rt->cfg = *cfg;
    }
    if (rt->cfg.device_name && rt->cfg.device_name[0]) {
        std::snprintf(rt->dev_name, sizeof(rt->dev_name), "%s", rt->cfg.device_name);
    }
    if (rt->cfg.legacy_pin && rt->cfg.legacy_pin[0]) {
        std::snprintf(rt->pin_str, sizeof(rt->pin_str), "%s", rt->cfg.legacy_pin);
    }
    if (rt->cfg.sbc_bitpool < 18u || rt->cfg.sbc_bitpool > 53u) {
        rt->cfg.sbc_bitpool = 35u;
    }

    rt->rx_sem    = xSemaphoreCreateBinary();
    rt->cmd_sem   = xSemaphoreCreateBinary();
    rt->inq_sem   = xSemaphoreCreateBinary();
    rt->conn_sem  = xSemaphoreCreateBinary();
    rt->setup_sem = xSemaphoreCreateBinary();

    btc_lmp_ops_t lmp_ops = {
        .ctx              = rt,
        .send_lmp         = cb_send_lmp,
        .start_encryption = cb_start_encryption,
        .random_bytes     = cb_random_bytes,
        .on_remote_name   = cb_on_remote_name,
        .on_link_key      = cb_on_link_key,
        .on_setup_done    = cb_on_setup_done,
        .on_peer_max_slots = cb_on_peer_max_slots,
    };
    btc_lmp_init(&rt->lmp, &lmp_ops, rt->local_bdaddr, rt->dev_name, rt->pin_str);

    btc_upper_ops_t up_ops = {
        .ctx            = rt,
        .send_l2cap_pdu = cb_send_l2cap_pdu,
        .on_avdtp_ready = cb_on_avdtp_ready,
        .on_stream_state = cb_on_stream_state,
        .on_avrcp_state = cb_on_avrcp_state,
        .on_media_cmd   = cb_on_media_cmd,
        .on_peer_volume = cb_on_peer_volume,
    };
    btc_upper_init(&rt->upper, &up_ops, rt->cfg.sbc_bitpool, rt->cfg.prefer_44k1);
    sbc_enc_init(&rt->sbc, nullptr);

    {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        load_bonds_locked(rt);
    }

    /* The stream task has a packet to hand over every 15 to 23 ms: the priority and the core of the LE Audio
     * stream thread (19, core 1; le_stream.cpp), above whatever produces the samples. The event task answers the
     * peer's LMP and signalling, where tenths of a second do not matter but seconds do. */
    xTaskCreatePinnedToCoreWithCaps(evt_worker_task, "btc_evt", 12288, rt, 10,
                                    &rt->evt_task, tskNO_AFFINITY, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    xTaskCreatePinnedToCoreWithCaps(stream_worker_task, "btc_sbc", 12288, rt, 19,
                                    &rt->stream_task, 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

    esp_hosted_cyberdeck_add_hci_rx_cb(on_hci_rx_cb);
    rt->initialized = true;

    probe_c6_soft_br(rt);
    return ESP_OK;
}

extern "C" bool bt_classic_c6_supported(void)
{
    if (!g_rt || !g_rt->initialized) {
        return false;
    }
    if (g_rt->c6_ready) {
        return true;
    }
    return probe_c6_soft_br(g_rt);
}

extern "C" int bt_classic_scan(bt_classic_device_t *out, int max_out, uint32_t duration_ms, bool resolve_names)
{
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized || !out || max_out <= 0) {
        return -1;
    }
    std::lock_guard<std::mutex> al(rt->api_mtx);
    if (!rt->c6_ready && !probe_c6_soft_br(rt)) {
        return -1;
    }

    abort_and_disconnect_sync(rt);

    uint32_t units = (duration_ms + 640u) / 1280u;
    if (units < 2u) units = 2u;
    if (units > 12u) units = 12u;

    {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        rt->scan_count      = 0;
        rt->scanning_active = true;
        rt->status.state    = BT_CLASSIC_SCANNING;
        rt->status.phase    = BTC_PHASE_INQUIRY;
    }

    xSemaphoreTake(rt->inq_sem, 0);
    uint8_t inq[5] = { 0x33u, 0x8Bu, 0x9Eu /* GIAC 0x9E8B33 */, (uint8_t)units, 0u };
    if (!send_hci_cmd_sync(rt, BR_HCI_OP_INQUIRY, inq, sizeof(inq), 1000u)) {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        rt->scanning_active = false;
        rt->status.state    = BT_CLASSIC_IDLE;
        rt->status.phase    = BTC_PHASE_NONE;
        return -1;
    }

    xSemaphoreTake(rt->inq_sem, pdMS_TO_TICKS(units * 1280u + 1500u));
    if (rt->scanning_active) {
        send_hci_cmd_sync(rt, BR_HCI_OP_INQUIRY_CANCEL, nullptr, 0u, 500u);
    }

    /* Sort Audio Sinks first, then strongest RSSI */
    int count = 0;
    {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        rt->scanning_active = false;
        std::sort(rt->scan_devs, rt->scan_devs + rt->scan_count,
                  [](const bt_classic_device_t &a, const bt_classic_device_t &b) {
                      if (a.is_audio_sink != b.is_audio_sink) return a.is_audio_sink > b.is_audio_sink;
                      return a.rssi > b.rssi;
                  });
        count = rt->scan_count;
    }

    /* Optional fast Page + LMP_name_req for top Audio Sink candidates without cached names */
    if (resolve_names && count > 0) {
        {
            std::lock_guard<std::mutex> sl(rt->state_mtx);
            rt->status.phase = BTC_PHASE_NAME_RESOLVE;
        }
        int resolved = 0;
        for (int i = 0; i < count && resolved < 4; i++) {
            bt_classic_device_t dev = rt->scan_devs[i];
            if (!dev.is_audio_sink) continue;
            {
                std::lock_guard<std::mutex> sl(rt->state_mtx);
                const btc_bond_t *bond = bond_of(rt, dev.addr);
                if (bond != nullptr && bond->name[0] != '\0') continue;
            }

            uint8_t cc[13];
            memcpy(&cc[0], dev.addr, 6u);
            cc[6] = 0x18u; cc[7] = 0xCCu;
            cc[8] = (dev.page_scan_rep <= 2u) ? dev.page_scan_rep : 1u;
            cc[9] = 0u;
            uint16_t coff = (uint16_t)(dev.clock_offset | 0x8000u);
            cc[10] = (uint8_t)(coff & 0xFFu);
            cc[11] = (uint8_t)((coff >> 8) & 0xFFu);
            cc[12] = 0u;

            xSemaphoreTake(rt->conn_sem, 0);
            xSemaphoreTake(rt->setup_sem, 0);
            if (send_hci_cmd_sync(rt, BR_HCI_OP_CREATE_CONN, cc, sizeof(cc), 600u) &&
                xSemaphoreTake(rt->conn_sem, pdMS_TO_TICKS(1800)) == pdTRUE && rt->acl_up) {
                btc_lmp_start(&rt->lmp, dev.addr, BTC_LMP_GOAL_NAME_ONLY);
                xSemaphoreTake(rt->setup_sem, pdMS_TO_TICKS(900));
                if (rt->lmp.remote_name[0] != '\0') {
                    std::lock_guard<std::mutex> sl(rt->state_mtx);
                    std::snprintf(rt->scan_devs[i].name, sizeof(rt->scan_devs[i].name), "%.63s", rt->lmp.remote_name);
                }
            }
            abort_and_disconnect_sync(rt);
            resolved++;
        }
    }

    int n = std::min(count, max_out);
    {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        for (int i = 0; i < n; i++) {
            out[i] = rt->scan_devs[i];
        }
        rt->status.state = BT_CLASSIC_IDLE;
        rt->status.phase = BTC_PHASE_NONE;
    }
    return n;
}

extern "C" esp_err_t bt_classic_connect_device(const bt_classic_device_t *dev)
{
    if (!g_rt || !g_rt->initialized || !dev) {
        return ESP_ERR_INVALID_ARG;
    }
    return connect_internal(g_rt, dev->addr, dev->clock_offset, dev->page_scan_rep, dev->name);
}

extern "C" esp_err_t bt_classic_connect_addr(const uint8_t addr[6], uint16_t clock_offset, uint8_t page_scan_rep)
{
    if (!g_rt || !g_rt->initialized || !addr) {
        return ESP_ERR_INVALID_ARG;
    }
    return connect_internal(g_rt, addr, clock_offset, page_scan_rep, nullptr);
}

extern "C" esp_err_t bt_classic_connect_bonded(void)
{
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    btc_bond_t rec;
    {
        std::lock_guard<std::mutex> sl(rt->state_mtx);
        if (rt->bonds.count == 0u) {
            return ESP_ERR_NOT_FOUND;
        }
        rec = rt->bonds.items[0];
    }
    return connect_internal(rt, rec.addr, rec.clock_offset, rec.page_scan_rep, rec.name);
}

extern "C" esp_err_t bt_classic_start(void)
{
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized || !rt->acl_up || !rt->avdtp_ready_flag) {
        return ESP_ERR_INVALID_STATE;
    }
    if (rt->status.state == BT_CLASSIC_STREAMING) {
        return ESP_OK;
    }
    xSemaphoreTake(rt->setup_sem, 0);
    rt->upper_req.fetch_or(kReqStart, std::memory_order_acq_rel);
    xSemaphoreGive(rt->rx_sem);
    int64_t deadline = esp_timer_get_time() + 3000000LL;
    while (esp_timer_get_time() < deadline) {
        if (rt->status.state == BT_CLASSIC_STREAMING) {
            return ESP_OK;
        }
        if (!rt->acl_up) {
            return ESP_FAIL;
        }
        xSemaphoreTake(rt->setup_sem, pdMS_TO_TICKS(100));
    }
    return (rt->status.state == BT_CLASSIC_STREAMING) ? ESP_OK : ESP_ERR_TIMEOUT;
}

extern "C" esp_err_t bt_classic_stop(void)
{
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    {
        std::lock_guard<std::mutex> pl(rt->pcm_mtx);
        rt->pcm_r = rt->pcm_w = rt->pcm_avail = 0u;
        rt->resamp_has_prev = false;
        rt->pcm_primed = false;
    }
    if (rt->acl_up && rt->status.state == BT_CLASSIC_STREAMING) {
        rt->upper_req.fetch_or(kReqSuspend, std::memory_order_acq_rel);
        xSemaphoreGive(rt->rx_sem);
    }
    return ESP_OK;
}

extern "C" esp_err_t bt_classic_disconnect(void)
{
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    std::lock_guard<std::mutex> al(rt->api_mtx);
    abort_and_disconnect_sync(rt);
    return ESP_OK;
}

extern "C" esp_err_t bt_classic_forget_bonds(void)
{
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    std::lock_guard<std::mutex> sl(rt->state_mtx);
    rt->bonds = {};
    btc_lmp_clear_link_key(&rt->lmp);
    save_bonds_locked(rt);
    return ESP_OK;
}

extern "C" esp_err_t bt_classic_forget(const uint8_t addr[6])
{
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized || !addr) {
        return ESP_ERR_INVALID_STATE;
    }
    std::lock_guard<std::mutex> sl(rt->state_mtx);
    if (!btc_bonds_remove(&rt->bonds, addr)) {
        return ESP_ERR_NOT_FOUND;
    }
    if (memcmp(rt->status.peer_addr, addr, 6u) == 0) {
        btc_lmp_clear_link_key(&rt->lmp);
    }
    save_bonds_locked(rt);
    return ESP_OK;
}

extern "C" int bt_classic_saved(bt_classic_saved_t *out, int max_out)
{
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized || !out || max_out <= 0) {
        return 0;
    }
    std::lock_guard<std::mutex> sl(rt->state_mtx);
    int n = 0;
    for (; n < (int)rt->bonds.count && n < max_out; n++) {
        memcpy(out[n].addr, rt->bonds.items[n].addr, 6u);
        std::snprintf(out[n].name, sizeof(out[n].name), "%s", rt->bonds.items[n].name);
    }
    return n;
}

extern "C" bool bt_classic_ready(void)
{
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized) {
        return false;
    }
    return rt->acl_up && (rt->status.state == BT_CLASSIC_READY || rt->status.state == BT_CLASSIC_STREAMING);
}

extern "C" size_t bt_classic_write_pcm(const int16_t *pcm, size_t frames, uint32_t input_sample_rate, int channels,
                                       int timeout_ms)
{
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized || !pcm || frames == 0u || channels < 1) {
        return 0u;
    }
    uint32_t out_rate = rt->status.sample_rate ? rt->status.sample_rate : 44100u;
    if (input_sample_rate == 0u) {
        input_sample_rate = out_rate;
    }

    /* A producer that can run ahead waits here until the stream task has read the ring down to its working level:
     * the ring then stays where the reader wants it and nothing is dropped. Only while a stream is reading. */
    if (timeout_ms > 0) {
        const int64_t wait_until = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
        while (esp_timer_get_time() < wait_until) {
            {
                std::lock_guard<std::mutex> wl(rt->pcm_mtx);
                if (rt->pcm_avail <= kPcmTargetFrames) {
                    break;
                }
            }
            if (!rt->acl_up || rt->status.state != BT_CLASSIC_STREAMING) {
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(2));
        }
    }

    std::lock_guard<std::mutex> pl(rt->pcm_mtx);
    rt->pcm_last_write_us = esp_timer_get_time();
    if (input_sample_rate == out_rate) {
        size_t i = 0u;
        for (; i < frames && rt->pcm_avail < kPcmRingFrames; i++) {
            int16_t l = (channels == 1) ? pcm[i] : pcm[i * 2u];
            int16_t r = (channels == 1) ? pcm[i] : pcm[i * 2u + 1u];
            rt->pcm_ring[rt->pcm_w * 2u]     = l;
            rt->pcm_ring[rt->pcm_w * 2u + 1u] = r;
            rt->pcm_w = (rt->pcm_w + 1u) % kPcmRingFrames;
            rt->pcm_avail++;
        }
        s_pcm_dropped.fetch_add((uint32_t)(frames - i), std::memory_order_relaxed);
        return i;
    }

    /* Stateful Q16.16 fractional linear resampler (e.g. 48000 Hz -> 44100 Hz) */
    /* The writer runs on the codec's clock and the reader on the system timer's. While the ring is being read
     * it is steered to its target by reading the input up to 0.1 % faster or slower: far below what can be heard,
     * far above what two clocks differ by. */
    uint32_t step_q16 = (uint32_t)(((uint64_t)input_sample_rate << 16) / (uint64_t)out_rate);
    if (rt->pcm_primed) {
        const int32_t off = ((int32_t)rt->pcm_avail - (int32_t)kPcmTargetFrames) / 64;
        const int32_t lim = (int32_t)(step_q16 / 1000u);
        step_q16 = (uint32_t)((int32_t)step_q16 + std::clamp(off, -lim, lim));
    }
    size_t in_idx = 0u;

    if (!rt->resamp_has_prev) {
        rt->resamp_prev_l = (channels == 1) ? pcm[0] : pcm[0];
        rt->resamp_prev_r = (channels == 1) ? pcm[0] : pcm[1];
        rt->resamp_has_prev = true;
        rt->resamp_phase_q16 = 0u;
    }

    while (in_idx < frames && rt->pcm_avail < kPcmRingFrames) {
        int16_t cur_l = (channels == 1) ? pcm[in_idx] : pcm[in_idx * 2u];
        int16_t cur_r = (channels == 1) ? pcm[in_idx] : pcm[in_idx * 2u + 1u];

        while (rt->resamp_phase_q16 < 65536u && rt->pcm_avail < kPcmRingFrames) {
            int32_t frac = (int32_t)(rt->resamp_phase_q16 & 0xFFFFu);
            int32_t out_l = rt->resamp_prev_l + (((int32_t)(cur_l - rt->resamp_prev_l) * frac) >> 16);
            int32_t out_r = rt->resamp_prev_r + (((int32_t)(cur_r - rt->resamp_prev_r) * frac) >> 16);
            rt->pcm_ring[rt->pcm_w * 2u]     = (int16_t)out_l;
            rt->pcm_ring[rt->pcm_w * 2u + 1u] = (int16_t)out_r;
            rt->pcm_w = (rt->pcm_w + 1u) % kPcmRingFrames;
            rt->pcm_avail++;
            rt->resamp_phase_q16 += step_q16;
        }

        while (rt->resamp_phase_q16 >= 65536u && in_idx < frames) {
            rt->resamp_prev_l = (channels == 1) ? pcm[in_idx] : pcm[in_idx * 2u];
            rt->resamp_prev_r = (channels == 1) ? pcm[in_idx] : pcm[in_idx * 2u + 1u];
            rt->resamp_phase_q16 -= 65536u;
            in_idx++;
        }
    }
    s_pcm_dropped.fetch_add((uint32_t)(frames - in_idx), std::memory_order_relaxed);
    return in_idx;
}

extern "C" esp_err_t bt_classic_set_volume(uint8_t volume)
{
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    rt->volume.store(volume, std::memory_order_release);
    /* 40 dB over the range, silence at 0. */
    const float pct = (float)volume * 100.0f / 255.0f;
    const float gain = volume == 0u ? 0.0f : std::pow(10.0f, (pct - 100.0f) * 0.4f / 20.0f);
    s_soft_gain_q15.store((uint16_t)std::lround(gain * 32767.0f), std::memory_order_relaxed);
    if (rt->acl_up && rt->status.avrcp_connected) {
        rt->upper_req.fetch_or(kReqVolume, std::memory_order_acq_rel);
        xSemaphoreGive(rt->rx_sem);
    }
    return ESP_OK;
}

extern "C" uint8_t bt_classic_get_volume(void)
{
    return g_rt ? g_rt->volume.load(std::memory_order_acquire) : 200u;
}

extern "C" void bt_classic_get_status(bt_classic_status_t *out)
{
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized) {
        return;
    }
    std::lock_guard<std::mutex> sl(rt->state_mtx);
    *out = rt->status;
    if (rt->bonds.count > 0u) {
        std::snprintf(out->bond_name, sizeof(out->bond_name), "%s", rt->bonds.items[0].name);
    }
}

extern "C" bt_classic_media_cmd_t bt_classic_take_media_command(void)
{
    if (!g_rt) {
        return BTC_MEDIA_CMD_NONE;
    }
    return (bt_classic_media_cmd_t)g_rt->media_cmd.exchange((int)BTC_MEDIA_CMD_NONE, std::memory_order_acq_rel);
}

extern "C" size_t bt_classic_lmp_trace_text(char *out, size_t size)
{
    BtcRuntime *rt = g_rt;
    if (!out || size == 0u) {
        return 0u;
    }
    out[0] = '\0';
    if (!rt || !rt->initialized) {
        return 0u;
    }
    /* Read while the event task may be writing: a record can come out half new. Good enough for a diagnosis, and
     * a lock here would be held across the peer's messages. */
    btc_lmp_rec_t *rec = rt->lmp_trace_copy;
    const uint8_t  n   = btc_lmp_trace_read(&rt->lmp, rec, BTC_LMP_TRACE);
    size_t at = 0u;
    for (uint8_t i = 0; i < n && at + 20u < size; i++) {
        at += (size_t)std::snprintf(out + at, size - at, "%c%u:%02x%02x%02x%02x%02x/%u ", rec[i].dir ? 'R' : 'S',
                                    (unsigned)rec[i].tick, rec[i].d[0], rec[i].d[1], rec[i].d[2], rec[i].d[3],
                                    rec[i].d[4], (unsigned)rec[i].len);
    }
    return at;
}

extern "C" size_t bt_classic_l2cap_trace_text(char *out, size_t size)
{
    BtcRuntime *rt = g_rt;
    if (!out || size == 0u) {
        return 0u;
    }
    out[0] = '\0';
    if (!rt || !rt->initialized) {
        return 0u;
    }
    /* Read while the event task may be writing, as in bt_classic_lmp_trace_text. */
    btc_upper_rec_t *rec = rt->l2cap_trace_copy;
    const uint8_t    n   = btc_upper_trace_read(&rt->upper, rec, BTC_UPPER_TRACE);
    size_t at = 0u;
    for (uint8_t i = 0; i < n && at + 72u < size; i++) { /* an item is 65 characters at most */
        const btc_upper_rec_t &r = rec[i];
        at += (size_t)std::snprintf(out + at, size - at, "%c%u:%04x:", r.dir == 0u ? 'S' : (r.dir == 1u ? 'R' : 'X'),
                                    (unsigned)r.tick, (unsigned)r.cid);
        const size_t shown = r.len < sizeof(r.d) ? r.len : sizeof(r.d);
        for (size_t b = 0; b < shown; b++) {
            at += (size_t)std::snprintf(out + at, size - at, "%02x", r.d[b]);
        }
        at += (size_t)std::snprintf(out + at, size - at, "/%u ", (unsigned)r.len);
    }
    return at;
}

extern "C" void bt_classic_get_diag(bt_classic_diag_t *out)
{
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));
    BtcRuntime *rt = g_rt;
    if (!rt || !rt->initialized) {
        return;
    }
    portENTER_CRITICAL(&rt->diag_spin);
    *out = rt->c6;
    portEXIT_CRITICAL(&rt->diag_spin);
    out->media_sent    = rt->status.tx_frames;
    out->media_lost    = s_media_lost.load(std::memory_order_relaxed);
    out->media_waiting = s_media_waiting.load(std::memory_order_relaxed);
    out->media_most    = s_media_most.exchange(0u, std::memory_order_relaxed);
    out->link_busy_pct = s_busy_pct.load(std::memory_order_relaxed);
    out->bitpool       = rt->status.sbc_bitpool;
    out->rate_windows  = s_rate_windows.load(std::memory_order_relaxed);
    out->bitpool_up    = s_bitpool_up.load(std::memory_order_relaxed);
    out->bitpool_down  = s_bitpool_down.load(std::memory_order_relaxed);
    out->l2cap_rx      = s_l2cap_rx.load(std::memory_order_relaxed);
    out->pcm_underruns = s_pcm_underruns.load(std::memory_order_relaxed);
    out->pcm_dropped_frames = s_pcm_dropped.load(std::memory_order_relaxed);
    out->peer_sets_volume   = btc_upper_peer_sets_volume(&rt->upper);
    out->rate_up_pct        = s_rate_up_pct.load(std::memory_order_relaxed);
    out->rate_down_pct      = s_rate_down_pct.load(std::memory_order_relaxed);
    std::lock_guard<std::mutex> pl(rt->pcm_mtx);
    out->pcm_fill_frames = (uint16_t)rt->pcm_avail;
}

extern "C" void bt_classic_set_link_limits(uint8_t up_pct, uint8_t down_pct)
{
    btc_rate_t r = {};
    btc_rate_set_limits(&r, up_pct, down_pct); /* brings them into range */
    s_rate_up_pct.store(r.up_pct, std::memory_order_relaxed);
    s_rate_down_pct.store(r.down_pct, std::memory_order_relaxed);
}

#endif /* ESP_PLATFORM */
