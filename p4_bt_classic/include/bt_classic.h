/*
 * Bluetooth Classic Audio Source (A2DP SBC + AVRCP) for ESP32-P4 + ESP32-C6 (Soft-BR).
 *
 * Drives the Soft-BR 1 Msps GFSK baseband engine (`br_ll`) on ESP32-C6 over ESP-Hosted HCI H4,
 * running LMP (Link Key auth, SSP P-192 ECDH Just Works, Legacy PIN, E0 encryption, AFH),
 * L2CAP, SDP, AVDTP 1.3 Source (SBC stereo/joint-stereo), and AVRCP on ESP32-P4.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef ESP_PLATFORM
#include "esp_err.h"
#else
typedef int esp_err_t;
#ifndef ESP_OK
#define ESP_OK                  0
#define ESP_FAIL                (-1)
#define ESP_ERR_INVALID_ARG     0x102
#define ESP_ERR_INVALID_STATE   0x103
#define ESP_ERR_NO_MEM          0x101
#define ESP_ERR_NOT_FOUND       0x105
#define ESP_ERR_NOT_SUPPORTED   0x106
#define ESP_ERR_TIMEOUT         0x107
#define ESP_ERR_NOT_ALLOWED     0x10D
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Optional persistent key-value callbacks for Classic Link Key bond storage.
 * NOTE (ESP32-P4 PSRAM stack safety): these callbacks may be invoked from PSRAM-stacked
 * worker threads, so implementations MUST read/write a RAM cache and flush NVS on an
 * internal-SRAM task (never call `nvs_*` directly inside these callbacks). */
typedef struct {
    int (*get)(void *ctx, const char *key, uint8_t *buf, size_t buf_size, size_t *out_len);
    int (*set)(void *ctx, const char *key, const uint8_t *val, size_t len);
    int (*erase)(void *ctx, const char *key);
    void *ctx;
} bt_classic_kv_t;

typedef struct {
    const char *device_name;    /* Local Classic friendly name (UTF-8), NULL -> "Tab5 Classic" */
    const char *legacy_pin;     /* Fallback PIN for BT 2.0 devices without SSP, NULL -> "0000" */
    uint8_t sbc_bitpool;        /* Preferred SBC bitpool (18..53), 0 -> 35 (~229 kbps @ 44.1 kHz JS) */
    bool prefer_44k1;           /* Prefer 44.1 kHz over 48 kHz when Sink supports both */
    bt_classic_kv_t kv;         /* Optional bond storage callbacks (all-NULL = RAM-only) */
} bt_classic_config_t;

#define BT_CLASSIC_CONFIG_DEFAULT() { \
    .device_name = "Tab5 Classic",    \
    .legacy_pin  = "0000",            \
    .sbc_bitpool = 35,                \
    .prefer_44k1 = true,              \
    .kv          = { NULL, NULL, NULL, NULL }, \
}

typedef enum {
    BT_CLASSIC_IDLE = 0,
    BT_CLASSIC_SCANNING,
    BT_CLASSIC_CONNECTING,
    BT_CLASSIC_PAIRING,
    BT_CLASSIC_CONFIGURING,
    BT_CLASSIC_READY,       /* AVDTP OPEN + Media L2CAP channel ready */
    BT_CLASSIC_STREAMING,   /* AVDTP START active, RTP+SBC packets flowing */
} bt_classic_link_state_t;

typedef enum {
    BTC_PHASE_NONE = 0,
    BTC_PHASE_INQUIRY,
    BTC_PHASE_NAME_RESOLVE,
    BTC_PHASE_PAGING,
    BTC_PHASE_LMP_SETUP,
    BTC_PHASE_AUTH_PAIRING,
    BTC_PHASE_ENCRYPTING,
    BTC_PHASE_SDP,
    BTC_PHASE_AVDTP_CFG,
    BTC_PHASE_AVDTP_OPEN,
    BTC_PHASE_STREAMING,
} bt_classic_stream_phase_t;

typedef struct {
    uint8_t addr[6];            /* Little-endian BD_ADDR (addr[5] = NAP MSB, addr[0] = LAP LSB) */
    uint32_t class_of_device;   /* 24-bit CoD from Inquiry FHS */
    uint16_t clock_offset;      /* 15-bit clock offset from Inquiry FHS */
    uint8_t page_scan_rep;      /* SR mode (R0=0, R1=1, R2=2) */
    int8_t rssi;                /* RSSI in dBm */
    bool is_audio_sink;         /* True if CoD Major=Audio/Video (0x04) or Rendering bit (0x040000) */
    char name[64];              /* Remote friendly name (UTF-8) or formatted CoD/BD_ADDR fallback */
} bt_classic_device_t;

typedef struct {
    bt_classic_link_state_t state;
    bt_classic_stream_phase_t phase;
    bool c6_soft_br_ready;      /* True if C6 answered BR_VS_PING ('BRC6' v1.5.0+) */
    bool bonded;
    bool encrypted;
    bool avrcp_connected;
    uint32_t sample_rate;       /* Negotiated A2DP SBC sample rate (44100 or 48000) */
    uint8_t sbc_bitpool;        /* Negotiated SBC bitpool */
    uint16_t sbc_frame_bytes;   /* Encoded bytes per 128-sample SBC frame */
    uint8_t peer_addr[6];
    char peer_name[64];
    char bond_name[64];         /* Name of the saved (paired) device; empty when there is none */
    uint32_t tx_frames;         /* Total RTP+SBC media packets transmitted */
    uint32_t tx_drops;          /* Media packets dropped due to RF backpressure */
    uint8_t last_disconnect_reason;
} bt_classic_status_t;

typedef enum {
    BTC_MEDIA_CMD_NONE = 0,
    BTC_MEDIA_CMD_PLAY,
    BTC_MEDIA_CMD_PAUSE,
    BTC_MEDIA_CMD_STOP,
    BTC_MEDIA_CMD_NEXT,
    BTC_MEDIA_CMD_PREV,
    BTC_MEDIA_CMD_VOL_UP,
    BTC_MEDIA_CMD_VOL_DOWN,
} bt_classic_media_cmd_t;

esp_err_t bt_classic_init(const bt_classic_config_t *cfg);

/* Probes/returns whether the ESP32-C6 coprocessor runs Soft-BR firmware (>= 1.5.0). */
bool bt_classic_c6_supported(void);

/* Runs GIAC Inquiry for `duration_ms` (e.g. 5120..7680 ms).
 * If `resolve_names` is true, briefly pages discovered Audio Sink devices to fetch `LMP_name_req`.
 * Returns number of discovered devices written to `out[0..max_out-1]`, or < 0 on error. */
int bt_classic_scan(bt_classic_device_t *out, int max_out, uint32_t duration_ms, bool resolve_names);

/* Connects to a user-selected Classic speaker/headphones from `bt_classic_scan()`; returns when the audio channel
 * is open or the attempt has failed (up to about 30 s). ESP_ERR_TIMEOUT: no answer to the page, or the setup did
 * not finish in its 12 s. ESP_ERR_NOT_ALLOWED: the device answered and refused the audio channel - headphones do
 * that while another phone or computer holds them. ESP_FAIL: pairing or authentication failed, or the link was
 * lost. ESP_ERR_NOT_SUPPORTED: the C6 firmware has no Soft-BR. After a failure bt_classic_lmp_trace_text and
 * bt_classic_l2cap_trace_text show how far the setup got. */
esp_err_t bt_classic_connect_device(const bt_classic_device_t *dev);
esp_err_t bt_classic_connect_addr(const uint8_t addr[6], uint16_t clock_offset, uint8_t page_scan_rep);

/* Connects the remembered device that was used last (ESP_ERR_NOT_FOUND if none is remembered). */
esp_err_t bt_classic_connect_bonded(void);

/* The remembered (paired) devices, most recently used first; up to four are kept, a fifth pushes out the one used
 * longest ago. Returns how many were written to `out`. */
typedef struct {
    uint8_t addr[6];
    char    name[64];
} bt_classic_saved_t;
int bt_classic_saved(bt_classic_saved_t *out, int max_out);

/* Forgets one remembered device (its pairing key). ESP_ERR_NOT_FOUND: it was not remembered. */
esp_err_t bt_classic_forget(const uint8_t addr[6]);

esp_err_t bt_classic_start(void);
esp_err_t bt_classic_stop(void);
esp_err_t bt_classic_disconnect(void);
esp_err_t bt_classic_forget_bonds(void);

bool bt_classic_ready(void);

/* Feeds 16-bit signed PCM (`channels` = 1 or 2) at `input_sample_rate` (e.g. 48000 or 44100 Hz); it is resampled
 * to the negotiated A2DP sample rate (44.1/48 kHz). The stream task is the clock.
 *  - timeout_ms > 0, for a producer that can run ahead (a file decoder): waits up to that long until the buffer
 *    is down to its working level (about 50 ms of sound), so writing in a loop paces the producer, as
 *    le_audio_write_pcm does;
 *  - timeout_ms <= 0, for a producer with a clock of its own (an audio output task): never waits.
 * Returns the input frames taken; the rest found the buffer full and is counted in
 * bt_classic_diag_t.pcm_dropped_frames. */
size_t bt_classic_write_pcm(const int16_t *pcm, size_t frames, uint32_t input_sample_rate, int channels,
                            int timeout_ms);

/* Volume 0..255 (matching le_audio_set_volume scale for seamless UI sharing). */
esp_err_t bt_classic_set_volume(uint8_t volume);
uint8_t bt_classic_get_volume(void);

void bt_classic_get_status(bt_classic_status_t *out);
bt_classic_media_cmd_t bt_classic_take_media_command(void);

/* Counters of the link and of the stream since the link came up, for diagnostics. */
typedef struct {
    /* The controller's, as BR_VS_GET_DIAG reports them once a second while the link is up. */
    uint32_t slots_tx, slots_rx, slots_skipped, pairs_lost;
    uint32_t rx_sync_ok, rx_hec_ok, rx_hec_err, rx_crc_ok, rx_crc_err;
    uint32_t tx_acks, tx_naks, tx_retrans, acl_sdu_tx, lmp_tx, lmp_rx;
    uint16_t pairs_late, build_longest_us, build_allowance_us, probes, pairs_refused, silent_run_max;
    uint8_t  tx_max_slots, tx_size_level, tx_flushes, size_strikes;
    uint32_t c6_reports;         /* reports so far: 0 = the numbers above have not arrived yet */
    /* Stretches in which the peer answered nothing (BR_VS_GET_GAPS). */
    uint32_t gaps, gaps_unrecorded, gap_pairs, gap_total_100us;
    uint16_t gap_longest_100us;
    /* Answers per RF channel 0..78 over the last ten seconds: '0'..'9' for the tenth of the pairs that were
     * answered, '-' for a channel with fewer than four pairs. Empty until the first report. */
    char     chan_row[80];
    /* The host's. */
    uint32_t media_sent, media_lost;
    uint16_t media_waiting, media_most; /* most: since the previous bt_classic_get_diag */
    uint8_t  link_busy_pct;             /* share of the last 2 s in which the controller held data */
    uint8_t  bitpool;
    uint32_t rate_windows, bitpool_up, bitpool_down;
    uint32_t l2cap_rx;                  /* L2CAP frames from the peer */
    uint32_t pcm_underruns;             /* times the ring ran dry while samples were being written */
    uint32_t pcm_dropped_frames;        /* frames that found the ring full */
    uint16_t pcm_fill_frames;
    bool     peer_sets_volume;          /* the peer accepted AVRCP SetAbsoluteVolume */
    uint8_t  rate_up_pct, rate_down_pct; /* bt_classic_set_link_limits */
} bt_classic_diag_t;
void bt_classic_get_diag(bt_classic_diag_t *out);

/* The LMP messages of the current or the last link, oldest first, as text for a log or a diagnostic page (about
 * 1.4 kB when full): one item per
 * message, "S" sent or "R" received, the tick of its moment (about two a second), the first five bytes in hex
 * (opcode << 1 | TID first) and the length, e.g. "S0:4e01020304/9 R1:0b..". For a device whose connection setup
 * stops: the counters do not say at which message. Returns the characters written (without the final zero). */
size_t bt_classic_lmp_trace_text(char *out, size_t size);

/* The same for the L2CAP frames of the link (signalling, SDP, AVDTP, AVRCP; media packets left out): one item per
 * frame, "S" sent, "R" received or "X" received but cut short and dropped, the tick, the channel the frame was
 * addressed to, up to 24 payload bytes in hex and the payload length, e.g. "S0:0001:0201040001004000/8" (about
 * 4.2 kB when full). Neither trace holds a device address; the first characters of the device's name can show
 * in them. */
size_t bt_classic_l2cap_trace_text(char *out, size_t size);

/* How much of the link the stream may fill: the bitpool goes up a step while the load it would bring stays under
 * `up_pct` and down a step above `down_pct` (defaults 85 and 95, btc_rate.h). Lower limits leave the radio time
 * for Wi-Fi, which shares it. */
void bt_classic_set_link_limits(uint8_t up_pct, uint8_t down_pct);

#ifdef __cplusplus
}
#endif
