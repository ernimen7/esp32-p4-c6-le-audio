/*
 * Bluetooth Classic L2CAP + SDP + AVDTP 1.3 Source + AVRCP 1.5 Engine.
 *
 * Host-testable C++17 protocol layer operating over complete L2CAP PDUs on ACL handle 0x0B00.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bt_classic.h"
#include "sbc_enc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BTC_L2CAP_PSM_SDP   0x0001u
#define BTC_L2CAP_PSM_AVCTP 0x0017u
#define BTC_L2CAP_PSM_AVDTP 0x0019u

#define BTC_L2CAP_MAX_CHANS 8u
#define BTC_L2CAP_LOCAL_MTU 668u /* Fits inside BR_ACL_SDU_MAX (672 B = 4 B L2CAP hdr + 668 B payload) */

typedef enum {
    BTC_CHAN_CLOSED = 0,
    BTC_CHAN_WAIT_CONN_RSP,
    BTC_CHAN_CONFIG,
    BTC_CHAN_OPEN,
    BTC_CHAN_WAIT_DISCONN_RSP,
} btc_chan_state_t;

typedef enum {
    BTC_CHAN_ROLE_NONE = 0,
    BTC_CHAN_ROLE_SDP_CLIENT,
    BTC_CHAN_ROLE_SDP_SERVER,
    BTC_CHAN_ROLE_AVDTP_SIG,
    BTC_CHAN_ROLE_AVDTP_MEDIA,
    BTC_CHAN_ROLE_AVCTP,
} btc_chan_role_t;

typedef struct {
    btc_chan_state_t state;
    btc_chan_role_t  role;
    uint16_t         psm;
    uint16_t         local_cid;
    uint16_t         remote_cid;
    uint16_t         remote_mtu;
    bool             local_cfg_sent;
    bool             local_cfg_acked;
    bool             remote_cfg_rcvd;
} btc_l2cap_chan_t;

typedef struct {
    void *ctx;
    /* Sends a complete L2CAP SDU (`[len_lo, len_hi, cid_lo, cid_hi, payload...]`) over ACL 0x0B00. */
    bool (*send_l2cap_pdu)(void *ctx, const uint8_t *l2cap_sdu, uint16_t sdu_len);
    void (*on_avdtp_ready)(void *ctx, const sbc_params_t *negotiated_sbc, uint16_t media_mtu);
    void (*on_stream_state)(void *ctx, bool streaming);
    void (*on_avrcp_state)(void *ctx, bool connected);
    void (*on_media_cmd)(void *ctx, bt_classic_media_cmd_t cmd);
    void (*on_peer_volume)(void *ctx, uint8_t vol_0_255);
} btc_upper_ops_t;

/* A sink that answers the request for the audio signalling channel with "no resources" is asked again after
 * BTC_UPPER_AUDIO_RETRY_TICKS calls of btc_upper_on_tick, at most BTC_UPPER_AUDIO_RETRIES times. */
#define BTC_UPPER_AUDIO_RETRY_TICKS 2u
#define BTC_UPPER_AUDIO_RETRIES     4u

/* One L2CAP frame of the link, kept for a diagnosis (btc_upper_trace_read). */
#define BTC_UPPER_TRACE 64u
typedef struct {
    uint8_t  dir;   /* 0 sent, 1 received, 2 received but shorter than its header says (dropped) */
    uint8_t  tick;  /* btc_upper_on_tick calls since btc_upper_trace_clear, about two a second; stops at 255 */
    uint16_t cid;   /* the channel the frame is addressed to: the peer's for a sent frame, ours for a received one */
    uint16_t len;   /* payload length from the frame's header */
    uint8_t  d[24]; /* first payload bytes: enough for an SDP request or a set of AVDTP capabilities */
} btc_upper_rec_t;

typedef struct btc_upper {
    btc_upper_ops_t  ops;
    uint8_t          preferred_bitpool;
    bool             prefer_44k1;

    uint8_t          next_sig_id;
    btc_l2cap_chan_t chans[BTC_L2CAP_MAX_CHANS];

    /* SDP discovery state */
    bool             sdp_done;
    uint16_t         sdp_tx_id;

    /* AVDTP Source state */
    uint8_t          avdtp_tx_label;
    uint8_t          sep_list[8];
    uint8_t          sep_count;
    uint8_t          sep_probe_idx;
    uint8_t          chosen_acp_seid;
    bool             chosen_has_delay_report;
    sbc_params_t     negotiated_sbc;
    /* The bitpools the configuration allows: the stream starts at negotiated_sbc.bitpool and may use any of them
     * (btc_rate.h). */
    uint8_t          negotiated_bitpool_min;
    uint8_t          negotiated_bitpool_max;
    bool             avdtp_configured;
    bool             avdtp_opened;
    bool             avdtp_streaming;
    bool             start_requested;
    bool             avrcp_opened_once;

    /* RTP state */
    uint16_t         rtp_seq;
    uint32_t         rtp_timestamp;
    uint32_t         rtp_ssrc;

    /* AVRCP state */
    uint8_t          avctp_tx_label;
    bool             vol_notify_pending;
    uint8_t          vol_notify_label;
    uint8_t          current_vol_7bit; /* 0x00..0x7F */
    bool             peer_abs_volume;  /* the peer accepted SetAbsoluteVolume (btc_upper_peer_sets_volume) */

    /* The peer's refusal of the audio signalling channel: its L2CAP result (btc_upper_audio_refusal), the ticks
     * until the request goes out again and how many times it has. */
    uint16_t         audio_refusal;
    uint8_t          audio_retry_in;
    uint8_t          audio_retries;

    /* The frames of the current or the last link, media packets left out. Kept last in the struct: btc_upper_reset
     * clears everything before them. */
    btc_upper_rec_t  trace[BTC_UPPER_TRACE];
    uint16_t         trace_n;
    uint8_t          trace_tick;
} btc_upper_t;

void btc_upper_init(btc_upper_t *u, const btc_upper_ops_t *ops, uint8_t preferred_bitpool, bool prefer_44k1);
void btc_upper_reset(btc_upper_t *u);

/* The layer's clock, to be called about twice a second while the link is up: it times the request for the audio
 * channel that is sent again and the records of the trace. */
void btc_upper_on_tick(btc_upper_t *u);

/* The L2CAP result with which the peer refused the audio signalling channel (0x0004 "no resources": it is busy,
 * as headphones that play from another device are), or 0 when it has not refused or the channel is open since. */
uint16_t btc_upper_audio_refusal(const btc_upper_t *u);

/* The trace of L2CAP frames: emptied where a new link begins and read oldest first (returns the number of records
 * copied, at most `max_out`). With a device whose setup stops after pairing the counters do not say at which frame
 * of SDP or AVDTP. */
void    btc_upper_trace_clear(btc_upper_t *u);
uint8_t btc_upper_trace_read(const btc_upper_t *u, btc_upper_rec_t *out, uint8_t max_out);

/* Begins outgoing SDP -> AVDTP -> AVRCP connection sequence once LMP + E0 encryption finish. */
void btc_upper_start_initiator(btc_upper_t *u);

/* Feeds a complete reassembled L2CAP PDU (`[len_lo, len_hi, cid_lo, cid_hi, payload...]`). */
void btc_upper_on_l2cap_pdu(btc_upper_t *u, const uint8_t *sdu, uint16_t sdu_len);

/* AVDTP stream control */
bool btc_upper_request_start(btc_upper_t *u);
bool btc_upper_request_suspend(btc_upper_t *u);
bool btc_upper_can_send_media(const btc_upper_t *u);

/* Packs `num_frames` encoded SBC frames into an RTP + A2DP SBC Media L2CAP SDU and transmits it. False: the
 * packet did not go out (no room below, stream not open) and may be offered again; the sequence number and the
 * timestamp move on only with a packet that went out. */
bool btc_upper_send_media_packet(btc_upper_t *u, const uint8_t *sbc_frames, uint16_t sbc_bytes,
                                 uint8_t num_frames, uint16_t pcm_samples_per_frame);

/* The lowest and highest bitpool the stream may use under the configuration set with the peer. */
void btc_upper_bitpool_range(const btc_upper_t *u, uint8_t *min_bitpool, uint8_t *max_bitpool);

/* A media packet that was given up without being sent: its sequence number and its samples are counted, so that
 * the receiver sees one packet missing. */
void btc_upper_skip_media_packet(btc_upper_t *u, uint8_t num_frames, uint16_t pcm_samples_per_frame);

/* Sends AVRCP SetAbsoluteVolume (and/or CHANGED notification response) for volume 0..255. */
void btc_upper_set_volume(btc_upper_t *u, uint8_t vol_0_255);

/* True once the peer has accepted SetAbsoluteVolume on this connection: it sets the level itself and the samples
 * go out at full scale. False (no AVRCP, no answer yet, command rejected): the source has to scale them. */
bool btc_upper_peer_sets_volume(const btc_upper_t *u);

#ifdef __cplusplus
}
#endif
