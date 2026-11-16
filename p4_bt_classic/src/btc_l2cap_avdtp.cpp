/*
 * Bluetooth Classic L2CAP + SDP + AVDTP 1.3 Source + AVRCP 1.5 Engine.
 */
#include "btc_l2cap_avdtp.h"

#include <stddef.h>
#include <string.h>

namespace {

/* L2CAP Signaling CID & Command Codes */
enum {
    L2CAP_CID_SIGNALING = 0x0001u,

    L2CAP_CMD_REJECT       = 0x01u,
    L2CAP_CONN_REQ         = 0x02u,
    L2CAP_CONN_RSP         = 0x03u,
    L2CAP_CONF_REQ         = 0x04u,
    L2CAP_CONF_RSP         = 0x05u,
    L2CAP_DISCONN_REQ      = 0x06u,
    L2CAP_DISCONN_RSP      = 0x07u,
    L2CAP_ECHO_REQ         = 0x08u,
    L2CAP_ECHO_RSP         = 0x09u,
    L2CAP_INFO_REQ         = 0x0Au,
    L2CAP_INFO_RSP         = 0x0Bu,
};

/* Result of an L2CAP connection response: "Connection refused - no resources available" (Core Spec Vol 3 Part A
 * 4.3). */
enum {
    L2CAP_CONN_NO_RESOURCES = 0x0004u,
};

/* SDP PDU IDs */
enum {
    SDP_ERROR_RSP                      = 0x01u,
    SDP_SERVICE_SEARCH_REQ             = 0x02u,
    SDP_SERVICE_SEARCH_RSP             = 0x03u,
    SDP_SERVICE_ATTR_REQ               = 0x04u,
    SDP_SERVICE_ATTR_RSP               = 0x05u,
    SDP_SERVICE_SEARCH_ATTR_REQ        = 0x06u,
    SDP_SERVICE_SEARCH_ATTR_RSP        = 0x07u,
};

/* SDP error codes (Core Spec Vol 3 Part B, SDP_ErrorResponse) */
enum {
    SDP_ERR_INVALID_HANDLE       = 0x0002u,
    SDP_ERR_INVALID_SYNTAX       = 0x0003u,
    SDP_ERR_INVALID_CONTINUATION = 0x0005u,
};

/* AVDTP Signal IDs & Message Types */
enum {
    AVDTP_MSG_COMMAND        = 0x00u,
    AVDTP_MSG_GENERAL_REJECT = 0x01u,
    AVDTP_MSG_RESPONSE_ACCEPT = 0x02u,
    AVDTP_MSG_RESPONSE_REJECT = 0x03u,

    AVDTP_DISCOVER             = 0x01u,
    AVDTP_GET_CAPABILITIES     = 0x02u,
    AVDTP_SET_CONFIGURATION    = 0x03u,
    AVDTP_GET_CONFIGURATION    = 0x04u,
    AVDTP_RECONFIGURE          = 0x05u,
    AVDTP_OPEN                 = 0x06u,
    AVDTP_START                = 0x07u,
    AVDTP_CLOSE                = 0x08u,
    AVDTP_SUSPEND              = 0x09u,
    AVDTP_ABORT                = 0x0Au,
    AVDTP_GET_ALL_CAPABILITIES = 0x0Cu,
    AVDTP_DELAYREPORT          = 0x0Du,

    AVDTP_CAT_MEDIA_TRANSPORT  = 0x01u,
    AVDTP_CAT_MEDIA_CODEC      = 0x07u,
    AVDTP_CAT_DELAY_REPORTING  = 0x08u,

    AVDTP_LOCAL_SRC_SEID       = 0x01u,
};

static uint16_t rd_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static void wr_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static uint16_t rd_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static void wr_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xFFu);
    p[1] = (uint8_t)(v & 0xFFu);
}

static void wr_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFFu);
    p[1] = (uint8_t)((v >> 16) & 0xFFu);
    p[2] = (uint8_t)((v >> 8) & 0xFFu);
    p[3] = (uint8_t)(v & 0xFFu);
}

static uint8_t next_sig_ident(btc_upper_t *u)
{
    u->next_sig_id++;
    if (u->next_sig_id == 0u) {
        u->next_sig_id = 1u;
    }
    return u->next_sig_id;
}

static void trace_put(btc_upper_t *u, uint8_t dir, uint16_t cid, uint16_t len, const uint8_t *payload, uint16_t have)
{
    btc_upper_rec_t *r = &u->trace[u->trace_n % BTC_UPPER_TRACE];
    memset(r, 0, sizeof(*r));
    r->dir  = dir;
    r->tick = u->trace_tick;
    r->cid  = cid;
    r->len  = len;
    if (have > 0u && payload != nullptr) {
        memcpy(r->d, payload, have < sizeof(r->d) ? have : sizeof(r->d));
    }
    if (u->trace_n < 0xFFFFu - BTC_UPPER_TRACE) {
        u->trace_n++;
    } else {
        u->trace_n = (uint16_t)(u->trace_n - BTC_UPPER_TRACE + 1u); /* same ring position, no wrap of the count */
    }
}

/* Media packets go out through this one, past the trace: fifty a second would leave nothing else in it. */
static bool send_l2cap_untraced(btc_upper_t *u, uint16_t remote_cid, const uint8_t *payload, uint16_t plen)
{
    if (!u->ops.send_l2cap_pdu || (uint32_t)plen + 4u > 672u) {
        return false;
    }
    uint8_t sdu[672];
    wr_le16(&sdu[0], plen);
    wr_le16(&sdu[2], remote_cid);
    if (plen > 0u && payload != nullptr) {
        memcpy(&sdu[4], payload, plen);
    }
    return u->ops.send_l2cap_pdu(u->ops.ctx, sdu, (uint16_t)(4u + plen));
}

static bool send_l2cap_frame(btc_upper_t *u, uint16_t remote_cid, const uint8_t *payload, uint16_t plen)
{
    trace_put(u, 0u, remote_cid, plen, payload, plen);
    return send_l2cap_untraced(u, remote_cid, payload, plen);
}

static void send_l2cap_sig(btc_upper_t *u, uint8_t code, uint8_t ident, const uint8_t *data, uint16_t dlen)
{
    uint8_t buf[128];
    if (4u + dlen > sizeof(buf)) {
        return;
    }
    buf[0] = code;
    buf[1] = ident;
    wr_le16(&buf[2], dlen);
    if (dlen > 0u && data != nullptr) {
        memcpy(&buf[4], data, dlen);
    }
    send_l2cap_frame(u, L2CAP_CID_SIGNALING, buf, (uint16_t)(4u + dlen));
}

static btc_l2cap_chan_t *find_chan_by_local_cid(btc_upper_t *u, uint16_t lcid)
{
    for (size_t i = 0; i < BTC_L2CAP_MAX_CHANS; i++) {
        if (u->chans[i].state != BTC_CHAN_CLOSED && u->chans[i].local_cid == lcid) {
            return &u->chans[i];
        }
    }
    return nullptr;
}

static btc_l2cap_chan_t *find_chan_by_role(btc_upper_t *u, btc_chan_role_t role)
{
    for (size_t i = 0; i < BTC_L2CAP_MAX_CHANS; i++) {
        if (u->chans[i].state != BTC_CHAN_CLOSED && u->chans[i].role == role) {
            return &u->chans[i];
        }
    }
    return nullptr;
}

static const btc_l2cap_chan_t *find_chan_by_role_const(const btc_upper_t *u, btc_chan_role_t role)
{
    for (size_t i = 0; i < BTC_L2CAP_MAX_CHANS; i++) {
        if (u->chans[i].state != BTC_CHAN_CLOSED && u->chans[i].role == role) {
            return &u->chans[i];
        }
    }
    return nullptr;
}

static btc_l2cap_chan_t *alloc_chan(btc_upper_t *u, uint16_t psm, btc_chan_role_t role)
{
    for (size_t i = 0; i < BTC_L2CAP_MAX_CHANS; i++) {
        if (u->chans[i].state == BTC_CHAN_CLOSED) {
            btc_l2cap_chan_t *c = &u->chans[i];
            memset(c, 0, sizeof(*c));
            c->psm        = psm;
            c->role       = role;
            c->local_cid  = (uint16_t)(0x0040u + i);
            c->remote_mtu = 672u;
            return c;
        }
    }
    return nullptr;
}

static void send_chan_config_req(btc_upper_t *u, btc_l2cap_chan_t *c)
{
    if (c->local_cfg_sent) {
        return;
    }
    c->local_cfg_sent = true;
    uint8_t req[8];
    wr_le16(&req[0], c->remote_cid);
    wr_le16(&req[2], 0x0000u); /* flags = 0 */
    req[4] = 0x01u;            /* Option: MTU */
    req[5] = 0x02u;            /* Length: 2 */
    wr_le16(&req[6], BTC_L2CAP_LOCAL_MTU);
    send_l2cap_sig(u, L2CAP_CONF_REQ, next_sig_ident(u), req, sizeof(req));
}

static btc_l2cap_chan_t *open_outgoing_chan(btc_upper_t *u, uint16_t psm, btc_chan_role_t role)
{
    btc_l2cap_chan_t *existing = find_chan_by_role(u, role);
    if (existing) {
        return existing;
    }
    btc_l2cap_chan_t *c = alloc_chan(u, psm, role);
    if (!c) {
        return nullptr;
    }
    c->state = BTC_CHAN_WAIT_CONN_RSP;
    uint8_t req[4];
    wr_le16(&req[0], psm);
    wr_le16(&req[2], c->local_cid);
    send_l2cap_sig(u, L2CAP_CONN_REQ, next_sig_ident(u), req, sizeof(req));
    return c;
}

static void close_chan(btc_upper_t *u, btc_l2cap_chan_t *c)
{
    if (!c || c->state == BTC_CHAN_CLOSED) {
        return;
    }
    uint8_t req[4];
    wr_le16(&req[0], c->remote_cid);
    wr_le16(&req[2], c->local_cid);
    c->state = BTC_CHAN_WAIT_DISCONN_RSP;
    send_l2cap_sig(u, L2CAP_DISCONN_REQ, next_sig_ident(u), req, sizeof(req));
}

/* Forward declarations */
static void on_channel_opened(btc_upper_t *u, btc_l2cap_chan_t *c);
static void on_channel_closed(btc_upper_t *u, btc_chan_role_t old_role);
static void handle_sdp_pdu(btc_upper_t *u, btc_l2cap_chan_t *c, const uint8_t *p, uint16_t len);
static void handle_avdtp_sig_pdu(btc_upper_t *u, btc_l2cap_chan_t *c, const uint8_t *p, uint16_t len);
static void handle_avctp_pdu(btc_upper_t *u, btc_l2cap_chan_t *c, const uint8_t *p, uint16_t len);

static void check_chan_open_transition(btc_upper_t *u, btc_l2cap_chan_t *c)
{
    if (c->state == BTC_CHAN_CONFIG && c->local_cfg_acked && c->remote_cfg_rcvd) {
        c->state = BTC_CHAN_OPEN;
        on_channel_opened(u, c);
    }
}

/* ==== AVDTP Signaling Helpers ==== */
static void send_avdtp_cmd(btc_upper_t *u, uint8_t sig_id, const uint8_t *params, uint16_t plen)
{
    btc_l2cap_chan_t *c = find_chan_by_role(u, BTC_CHAN_ROLE_AVDTP_SIG);
    if (!c || c->state != BTC_CHAN_OPEN) {
        return;
    }
    uint8_t label = (uint8_t)(u->avdtp_tx_label & 0x0Fu);
    u->avdtp_tx_label = (uint8_t)((u->avdtp_tx_label + 1u) & 0x0Fu);

    uint8_t buf[64];
    if (2u + plen > sizeof(buf)) {
        return;
    }
    buf[0] = (uint8_t)((label << 4) | AVDTP_MSG_COMMAND);
    buf[1] = (uint8_t)(sig_id & 0x3Fu);
    if (plen > 0u && params != nullptr) {
        memcpy(&buf[2], params, plen);
    }
    send_l2cap_frame(u, c->remote_cid, buf, (uint16_t)(2u + plen));
}

static void send_avdtp_rsp(btc_upper_t *u, btc_l2cap_chan_t *c, uint8_t rx_label,
                           uint8_t msg_type, uint8_t sig_id, const uint8_t *params, uint16_t plen)
{
    uint8_t buf[64];
    if (2u + plen > sizeof(buf)) {
        return;
    }
    buf[0] = (uint8_t)(((rx_label & 0x0Fu) << 4) | (msg_type & 0x03u));
    buf[1] = (uint8_t)(sig_id & 0x3Fu);
    if (plen > 0u && params != nullptr) {
        memcpy(&buf[2], params, plen);
    }
    send_l2cap_frame(u, c->remote_cid, buf, (uint16_t)(2u + plen));
}

static void avdtp_probe_next_sep(btc_upper_t *u)
{
    if (u->sep_probe_idx >= u->sep_count) {
        return;
    }
    uint8_t seid = u->sep_list[u->sep_probe_idx];
    uint8_t p[1] = { (uint8_t)(seid << 2) };
    send_avdtp_cmd(u, AVDTP_GET_CAPABILITIES, p, 1u);
}

static bool select_sbc_from_caps(btc_upper_t *u, const uint8_t *caps, uint16_t caps_len,
                                 uint8_t out_codec_ie[4], bool *out_has_delay)
{
    *out_has_delay = false;
    bool found_sbc = false;
    uint8_t sbc_ie[4] = {0};

    uint16_t pos = 0u;
    while (pos + 2u <= caps_len) {
        uint8_t cat  = caps[pos];
        uint8_t clen = caps[pos + 1u];
        if (pos + 2u + clen > caps_len) {
            break;
        }
        const uint8_t *body = &caps[pos + 2u];
        if (cat == AVDTP_CAT_DELAY_REPORTING) {
            *out_has_delay = true;
        } else if (cat == AVDTP_CAT_MEDIA_CODEC && clen >= 6u &&
                   (body[0] >> 4) == 0x00u /* Audio */ && body[1] == 0x00u /* SBC */) {
            memcpy(sbc_ie, &body[2], 4u);
            found_sbc = true;
        }
        pos = (uint16_t)(pos + 2u + clen);
    }

    if (!found_sbc) {
        return false;
    }

    /* Octet 0: [16k(7) | 32k(6) | 44.1k(5) | 48k(4) | Mono(3) | Dual(2) | Stereo(1) | JointStereo(0)] */
    uint8_t freq_mask = (uint8_t)(sbc_ie[0] & 0xF0u);
    uint8_t mode_mask = (uint8_t)(sbc_ie[0] & 0x0Fu);
    uint8_t sel_freq_bit = 0x20u;
    sbc_freq_t sel_freq  = SBC_FREQ_44100;

    if (u->prefer_44k1 && (freq_mask & 0x20u)) {
        sel_freq_bit = 0x20u; sel_freq = SBC_FREQ_44100;
    } else if (freq_mask & 0x10u) {
        sel_freq_bit = 0x10u; sel_freq = SBC_FREQ_48000;
    } else if (freq_mask & 0x20u) {
        sel_freq_bit = 0x20u; sel_freq = SBC_FREQ_44100;
    } else if (freq_mask & 0x40u) {
        sel_freq_bit = 0x40u; sel_freq = SBC_FREQ_32000;
    } else if (freq_mask & 0x80u) {
        sel_freq_bit = 0x80u; sel_freq = SBC_FREQ_16000;
    } else {
        return false;
    }

    uint8_t sel_mode_bit = 0x01u;
    sbc_mode_t sel_mode  = SBC_MODE_JOINT_STEREO;
    if (mode_mask & 0x01u) {
        sel_mode_bit = 0x01u; sel_mode = SBC_MODE_JOINT_STEREO;
    } else if (mode_mask & 0x02u) {
        sel_mode_bit = 0x02u; sel_mode = SBC_MODE_STEREO;
    } else if (mode_mask & 0x04u) {
        sel_mode_bit = 0x04u; sel_mode = SBC_MODE_DUAL_CHANNEL;
    } else if (mode_mask & 0x08u) {
        sel_mode_bit = 0x08u; sel_mode = SBC_MODE_MONO;
    } else {
        return false;
    }

    /* Octet 1: [blk4(7) | blk8(6) | blk12(5) | blk16(4) | sb4(3) | sb8(2) | SNR(1) | Loudness(0)] */
    uint8_t blk_mask = (uint8_t)(sbc_ie[1] & 0xF0u);
    uint8_t sb_mask  = (uint8_t)(sbc_ie[1] & 0x0Cu);
    uint8_t al_mask  = (uint8_t)(sbc_ie[1] & 0x03u);

    if ((sb_mask & 0x04u) == 0u) {
        return false; /* 8 subbands is mandatory for A2DP Sink */
    }
    uint8_t sel_blk_bit = 0x10u;
    uint8_t sel_blocks  = 16u;
    if (blk_mask & 0x10u)      { sel_blk_bit = 0x10u; sel_blocks = 16u; }
    else if (blk_mask & 0x20u) { sel_blk_bit = 0x20u; sel_blocks = 12u; }
    else if (blk_mask & 0x40u) { sel_blk_bit = 0x40u; sel_blocks = 8u;  }
    else if (blk_mask & 0x80u) { sel_blk_bit = 0x80u; sel_blocks = 4u;  }
    else return false;

    uint8_t sel_al_bit   = (al_mask & 0x01u) ? 0x01u : 0x02u;
    sbc_alloc_t sel_alloc = (sel_al_bit == 0x01u) ? SBC_ALLOC_LOUDNESS : SBC_ALLOC_SNR;

    uint8_t min_bp = sbc_ie[2] < 2u ? 2u : sbc_ie[2];
    uint8_t max_bp = sbc_ie[3] > 53u ? 53u : sbc_ie[3];
    if (max_bp < min_bp) {
        max_bp = min_bp;
    }
    uint8_t target_bp = u->preferred_bitpool;
    if (target_bp < min_bp) target_bp = min_bp;
    if (target_bp > max_bp) target_bp = max_bp;

    u->negotiated_sbc.freq     = sel_freq;
    u->negotiated_sbc.blocks   = sel_blocks;
    u->negotiated_sbc.mode     = sel_mode;
    u->negotiated_sbc.alloc    = sel_alloc;
    u->negotiated_sbc.subbands = 8u;
    u->negotiated_sbc.bitpool  = target_bp;
    u->negotiated_bitpool_min  = min_bp;
    u->negotiated_bitpool_max  = max_bp;

    /* The configuration names the range of bitpools the stream may use, not the one it starts with: the stream
     * raises its bitpool when the link has room (btc_rate.h), and every frame carries its own bitpool. */
    out_codec_ie[0] = (uint8_t)(sel_freq_bit | sel_mode_bit);
    out_codec_ie[1] = (uint8_t)(sel_blk_bit | 0x04u | sel_al_bit);
    out_codec_ie[2] = min_bp;
    out_codec_ie[3] = max_bp;
    return true;
}

static void on_channel_opened(btc_upper_t *u, btc_l2cap_chan_t *c)
{
    switch (c->role) {
    case BTC_CHAN_ROLE_SDP_CLIENT: {
        /* Send SDP_ServiceSearchAttributeRequest (0x06) for UUID16 AudioSink (0x110B), all attrs 0x0000..0xFFFF */
        u->sdp_tx_id = 0x0001u;
        static const uint8_t kSdpQueryAudioSink[] = {
            0x35, 0x03, 0x19, 0x11, 0x0B, /* ServiceSearchPattern:Seq(3B) { UUID16(0x110B) } */
            0x00, 0xFF,                   /* MaximumAttributeByteCount = 255 */
            0x35, 0x05, 0x0A, 0x00, 0x00, 0xFF, 0xFF, /* AttributeIDList: Seq(5B) { Range 0x0000..0xFFFF } */
            0x00                          /* ContinuationState = 0 */
        };
        uint8_t pdu[5 + sizeof(kSdpQueryAudioSink)];
        pdu[0] = SDP_SERVICE_SEARCH_ATTR_REQ;
        wr_be16(&pdu[1], u->sdp_tx_id);
        wr_be16(&pdu[3], (uint16_t)sizeof(kSdpQueryAudioSink));
        memcpy(&pdu[5], kSdpQueryAudioSink, sizeof(kSdpQueryAudioSink));
        send_l2cap_frame(u, c->remote_cid, pdu, sizeof(pdu));
        break;
    }

    case BTC_CHAN_ROLE_AVDTP_SIG: {
        /* Ours or the one the peer opened after refusing ours: either way the refusal is over. */
        u->audio_refusal  = 0u;
        u->audio_retry_in = 0u;
        if (!u->avdtp_configured) {
            send_avdtp_cmd(u, AVDTP_DISCOVER, nullptr, 0u);
        }
        break;
    }

    case BTC_CHAN_ROLE_AVDTP_MEDIA: {
        if (u->ops.on_avdtp_ready) {
            u->ops.on_avdtp_ready(u->ops.ctx, &u->negotiated_sbc, c->remote_mtu);
        }
        /* Open AVRCP (PSM 0x0017) in the background if speaker hasn't already opened it */
        if (!u->avrcp_opened_once && !find_chan_by_role(u, BTC_CHAN_ROLE_AVCTP)) {
            u->avrcp_opened_once = true;
            open_outgoing_chan(u, BTC_L2CAP_PSM_AVCTP, BTC_CHAN_ROLE_AVCTP);
        }
        if (u->start_requested && !u->avdtp_streaming) {
            uint8_t p[1] = { (uint8_t)(u->chosen_acp_seid << 2) };
            send_avdtp_cmd(u, AVDTP_START, p, 1u);
        }
        break;
    }

    case BTC_CHAN_ROLE_AVCTP: {
        if (u->ops.on_avrcp_state) {
            u->ops.on_avrcp_state(u->ops.ctx, true);
        }
        break;
    }

    default:
        break;
    }
}

static void on_channel_closed(btc_upper_t *u, btc_chan_role_t old_role)
{
    if (old_role == BTC_CHAN_ROLE_SDP_CLIENT) {
        u->sdp_done = true;
        if (!find_chan_by_role(u, BTC_CHAN_ROLE_AVDTP_SIG)) {
            open_outgoing_chan(u, BTC_L2CAP_PSM_AVDTP, BTC_CHAN_ROLE_AVDTP_SIG);
        }
    } else if (old_role == BTC_CHAN_ROLE_AVDTP_MEDIA) {
        if (u->avdtp_streaming) {
            u->avdtp_streaming = false;
            if (u->ops.on_stream_state) {
                u->ops.on_stream_state(u->ops.ctx, false);
            }
        }
    } else if (old_role == BTC_CHAN_ROLE_AVCTP) {
        if (u->ops.on_avrcp_state) {
            u->ops.on_avrcp_state(u->ops.ctx, false);
        }
    }
}

/* ==== L2CAP Signaling Handler (`CID 0x0001`) ==== */
static void handle_l2cap_signaling(btc_upper_t *u, const uint8_t *p, uint16_t len)
{
    uint16_t pos = 0u;
    while (pos + 4u <= len) {
        uint8_t  code  = p[pos];
        uint8_t  ident = p[pos + 1u];
        uint16_t clen  = rd_le16(&p[pos + 2u]);
        if (pos + 4u + clen > len) {
            break;
        }
        const uint8_t *d = &p[pos + 4u];

        switch (code) {
        case L2CAP_CONN_REQ: {
            if (clen < 4u) break;
            uint16_t psm  = rd_le16(&d[0]);
            uint16_t scid = rd_le16(&d[2]);
            btc_chan_role_t role = BTC_CHAN_ROLE_NONE;

            if (psm == BTC_L2CAP_PSM_SDP) {
                role = BTC_CHAN_ROLE_SDP_SERVER;
            } else if (psm == BTC_L2CAP_PSM_AVCTP) {
                role = BTC_CHAN_ROLE_AVCTP;
            } else if (psm == BTC_L2CAP_PSM_AVDTP) {
                if (!find_chan_by_role(u, BTC_CHAN_ROLE_AVDTP_SIG)) {
                    role = BTC_CHAN_ROLE_AVDTP_SIG;
                } else if (!find_chan_by_role(u, BTC_CHAN_ROLE_AVDTP_MEDIA)) {
                    role = BTC_CHAN_ROLE_AVDTP_MEDIA;
                }
            }

            btc_l2cap_chan_t *c = (role != BTC_CHAN_ROLE_NONE) ? alloc_chan(u, psm, role) : nullptr;
            uint8_t rsp[8];
            if (c) {
                c->remote_cid = scid;
                c->state      = BTC_CHAN_CONFIG;
                wr_le16(&rsp[0], c->local_cid);
                wr_le16(&rsp[2], scid);
                wr_le16(&rsp[4], 0x0000u); /* Connection Successful */
                wr_le16(&rsp[6], 0x0000u);
                send_l2cap_sig(u, L2CAP_CONN_RSP, ident, rsp, sizeof(rsp));
                send_chan_config_req(u, c);
            } else {
                wr_le16(&rsp[0], 0u);
                wr_le16(&rsp[2], scid);
                wr_le16(&rsp[4], (role == BTC_CHAN_ROLE_NONE) ? 0x0002u : 0x0004u);
                wr_le16(&rsp[6], 0x0000u);
                send_l2cap_sig(u, L2CAP_CONN_RSP, ident, rsp, sizeof(rsp));
            }
            break;
        }

        case L2CAP_CONN_RSP: {
            if (clen < 8u) break;
            uint16_t dcid   = rd_le16(&d[0]);
            uint16_t scid   = rd_le16(&d[2]);
            uint16_t result = rd_le16(&d[4]);
            btc_l2cap_chan_t *c = find_chan_by_local_cid(u, scid);
            if (!c) break;

            if (result == 0x0001u) {
                /* Connection Pending (e.g. speaker finishing internal check): keep waiting */
                c->remote_cid = dcid;
                break;
            }
            if (result == 0x0000u) {
                c->remote_cid = dcid;
                c->state      = BTC_CHAN_CONFIG;
                send_chan_config_req(u, c);
            } else {
                btc_chan_role_t old_role = c->role;
                c->state = BTC_CHAN_CLOSED;
                if (old_role == BTC_CHAN_ROLE_AVDTP_SIG) {
                    /* "No resources" passes: headphones give it while they are busy with their own start or with
                     * another device (Sony WH-1000XM3, 2026-11-15, after "pending"). The other results do not. */
                    u->audio_refusal = result;
                    if (result == L2CAP_CONN_NO_RESOURCES && u->audio_retries < BTC_UPPER_AUDIO_RETRIES) {
                        u->audio_retries++;
                        u->audio_retry_in = BTC_UPPER_AUDIO_RETRY_TICKS;
                    }
                }
                on_channel_closed(u, old_role);
            }
            break;
        }

        case L2CAP_CONF_REQ: {
            if (clen < 4u) break;
            uint16_t dcid  = rd_le16(&d[0]);
            uint16_t flags = rd_le16(&d[2]);
            btc_l2cap_chan_t *c = find_chan_by_local_cid(u, dcid);
            if (!c) {
                uint8_t rej[6] = {0x02, 0x00, d[0], d[1], 0x00, 0x00};
                send_l2cap_sig(u, L2CAP_CMD_REJECT, ident, rej, 6u);
                break;
            }

            uint16_t opt_pos = 4u;
            bool unacceptable_rfc = false;
            uint8_t rfc_fallback[11] = {0x04u, 0x09u, 0x00u, 0,0,0,0,0,0,0,0};

            while (opt_pos + 2u <= clen) {
                uint8_t otype = d[opt_pos];
                uint8_t olen  = d[opt_pos + 1u];
                if (opt_pos + 2u + olen > clen) break;
                const uint8_t *oval = &d[opt_pos + 2u];
                if ((otype & 0x7Fu) == 0x01u && olen >= 2u) {
                    uint16_t mtu = rd_le16(oval);
                    c->remote_mtu = (mtu < 48u) ? 48u : mtu;
                } else if ((otype & 0x7Fu) == 0x04u && olen >= 1u && oval[0] != 0x00u) {
                    /* Reject ERTM/Streaming mode -> negotiate Basic L2CAP mode (0x00) */
                    unacceptable_rfc = true;
                }
                opt_pos = (uint16_t)(opt_pos + 2u + olen);
            }

            if (unacceptable_rfc) {
                uint8_t rsp[6 + sizeof(rfc_fallback)];
                wr_le16(&rsp[0], c->remote_cid);
                wr_le16(&rsp[2], flags & 0x0001u);
                wr_le16(&rsp[4], 0x0001u); /* Unacceptable Parameters */
                memcpy(&rsp[6], rfc_fallback, sizeof(rfc_fallback));
                send_l2cap_sig(u, L2CAP_CONF_RSP, ident, rsp, sizeof(rsp));
                break;
            }

            uint8_t rsp[6];
            wr_le16(&rsp[0], c->remote_cid);
            wr_le16(&rsp[2], flags & 0x0001u);
            wr_le16(&rsp[4], 0x0000u); /* Success */
            send_l2cap_sig(u, L2CAP_CONF_RSP, ident, rsp, sizeof(rsp));

            if ((flags & 0x0001u) == 0u) {
                c->remote_cfg_rcvd = true;
                send_chan_config_req(u, c);
                check_chan_open_transition(u, c);
            }
            break;
        }

        case L2CAP_CONF_RSP: {
            if (clen < 6u) break;
            uint16_t scid   = rd_le16(&d[0]);
            uint16_t flags  = rd_le16(&d[2]);
            uint16_t result = rd_le16(&d[4]);
            btc_l2cap_chan_t *c = find_chan_by_local_cid(u, scid);
            if (!c) break;

            if (result == 0x0000u && (flags & 0x0001u) == 0u) {
                c->local_cfg_acked = true;
                check_chan_open_transition(u, c);
            } else if (result == 0x0001u) {
                /* Retry config with peer's suggested MTU or default 672 */
                c->local_cfg_sent = false;
                uint8_t req[4];
                wr_le16(&req[0], c->remote_cid);
                wr_le16(&req[2], 0x0000u);
                send_l2cap_sig(u, L2CAP_CONF_REQ, next_sig_ident(u), req, sizeof(req));
                c->local_cfg_sent = true;
            }
            break;
        }

        case L2CAP_DISCONN_REQ: {
            if (clen < 4u) break;
            uint16_t dcid = rd_le16(&d[0]);
            uint16_t scid = rd_le16(&d[2]);
            uint8_t rsp[4];
            wr_le16(&rsp[0], dcid);
            wr_le16(&rsp[2], scid);
            send_l2cap_sig(u, L2CAP_DISCONN_RSP, ident, rsp, sizeof(rsp));

            btc_l2cap_chan_t *c = find_chan_by_local_cid(u, dcid);
            if (c) {
                btc_chan_role_t old_role = c->role;
                c->state = BTC_CHAN_CLOSED;
                on_channel_closed(u, old_role);
            }
            break;
        }

        case L2CAP_DISCONN_RSP: {
            if (clen < 4u) break;
            uint16_t scid = rd_le16(&d[2]);
            btc_l2cap_chan_t *c = find_chan_by_local_cid(u, scid);
            if (c) {
                btc_chan_role_t old_role = c->role;
                c->state = BTC_CHAN_CLOSED;
                on_channel_closed(u, old_role);
            }
            break;
        }

        case L2CAP_ECHO_REQ:
            send_l2cap_sig(u, L2CAP_ECHO_RSP, ident, d, clen);
            break;

        case L2CAP_INFO_REQ: {
            if (clen < 2u) break;
            uint16_t itype = rd_le16(&d[0]);
            if (itype == 0x0002u) {
                /* Extended Features Mask = 0x00000000 (Basic Mode) */
                uint8_t rsp[8] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                send_l2cap_sig(u, L2CAP_INFO_RSP, ident, rsp, sizeof(rsp));
            } else if (itype == 0x0003u) {
                /* Fixed Channels Supported: bit 1 = L2CAP Signaling (0x0001) */
                uint8_t rsp[12] = { 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0,0,0,0,0,0 };
                send_l2cap_sig(u, L2CAP_INFO_RSP, ident, rsp, sizeof(rsp));
            } else {
                uint8_t rsp[4] = { d[0], d[1], 0x01, 0x00 /* Not Supported */ };
                send_l2cap_sig(u, L2CAP_INFO_RSP, ident, rsp, sizeof(rsp));
            }
            break;
        }

        default:
            break;
        }

        pos = (uint16_t)(pos + 4u + clen);
    }
}

/* ==== SDP (`PSM 0x0001`): a client for one question, a server for two records (Core Spec Vol 3 Part B) ==== */

/* One attribute of a service record: its ID and its value, a data element. */
struct SdpAttr {
    uint16_t       id;
    const uint8_t *value;
    uint8_t        len;
};

struct SdpRecord {
    uint32_t        handle;
    const SdpAttr  *attrs;   /* in ascending order of ID, the order they are returned in */
    uint8_t         n_attrs;
    const uint16_t *uuids;   /* every UUID in the values: what a service search pattern is matched against */
    uint8_t         n_uuids;
};

/* AudioSource, A2DP 1.3 */
static const uint8_t kA2dpHandle[]   = { 0x0A, 0x00, 0x01, 0x00, 0x01 };
static const uint8_t kA2dpClasses[]  = { 0x35, 0x03, 0x19, 0x11, 0x0A };
static const uint8_t kA2dpProtocol[] = { 0x35, 0x10,
                                         0x35, 0x06, 0x19, 0x01, 0x00, 0x09, 0x00, 0x19,   /* L2CAP, PSM 0x0019 */
                                         0x35, 0x06, 0x19, 0x00, 0x19, 0x09, 0x01, 0x03 }; /* AVDTP 1.3 */
static const uint8_t kA2dpProfile[]  = { 0x35, 0x08, 0x35, 0x06, 0x19, 0x11, 0x0D, 0x09, 0x01, 0x03 };
static const uint8_t kA2dpFeatures[] = { 0x09, 0x00, 0x01 }; /* Player */
static const SdpAttr kA2dpAttrs[] = {
    { 0x0000u, kA2dpHandle, sizeof(kA2dpHandle) },     /* ServiceRecordHandle */
    { 0x0001u, kA2dpClasses, sizeof(kA2dpClasses) },   /* ServiceClassIDList */
    { 0x0004u, kA2dpProtocol, sizeof(kA2dpProtocol) }, /* ProtocolDescriptorList */
    { 0x0009u, kA2dpProfile, sizeof(kA2dpProfile) },   /* BluetoothProfileDescriptorList */
    { 0x0311u, kA2dpFeatures, sizeof(kA2dpFeatures) }, /* SupportedFeatures */
};
static const uint16_t kA2dpUuids[] = { 0x110Au, 0x0100u, 0x0019u, 0x110Du };

/* AVRCP 1.5: A/V Remote Control and its Target */
static const uint8_t kAvrcpHandle[]   = { 0x0A, 0x00, 0x01, 0x00, 0x02 };
static const uint8_t kAvrcpClasses[]  = { 0x35, 0x06, 0x19, 0x11, 0x0E, 0x19, 0x11, 0x0C };
static const uint8_t kAvrcpProtocol[] = { 0x35, 0x10,
                                          0x35, 0x06, 0x19, 0x01, 0x00, 0x09, 0x00, 0x17,   /* L2CAP, PSM 0x0017 */
                                          0x35, 0x06, 0x19, 0x00, 0x17, 0x09, 0x01, 0x04 }; /* AVCTP 1.4 */
static const uint8_t kAvrcpProfile[]  = { 0x35, 0x08, 0x35, 0x06, 0x19, 0x11, 0x0E, 0x09, 0x01, 0x05 };
static const SdpAttr kAvrcpAttrs[] = {
    { 0x0000u, kAvrcpHandle, sizeof(kAvrcpHandle) },
    { 0x0001u, kAvrcpClasses, sizeof(kAvrcpClasses) },
    { 0x0004u, kAvrcpProtocol, sizeof(kAvrcpProtocol) },
    { 0x0009u, kAvrcpProfile, sizeof(kAvrcpProfile) },
};
static const uint16_t kAvrcpUuids[] = { 0x110Eu, 0x110Cu, 0x0100u, 0x0017u };

static const SdpRecord kSdpRecords[] = {
    { 0x00010001u, kA2dpAttrs, (uint8_t)(sizeof(kA2dpAttrs) / sizeof(kA2dpAttrs[0])), kA2dpUuids,
      (uint8_t)(sizeof(kA2dpUuids) / sizeof(kA2dpUuids[0])) },
    { 0x00010002u, kAvrcpAttrs, (uint8_t)(sizeof(kAvrcpAttrs) / sizeof(kAvrcpAttrs[0])), kAvrcpUuids,
      (uint8_t)(sizeof(kAvrcpUuids) / sizeof(kAvrcpUuids[0])) },
};
#define SDP_RECORD_COUNT (sizeof(kSdpRecords) / sizeof(kSdpRecords[0]))

/* The longest answer: a sequence of both records with every attribute (per attribute three bytes of ID, per
 * sequence two of header). */
#define SDP_ANSWER_MAX 128u
static_assert(2u + (2u + 5u * 3u + sizeof(kA2dpHandle) + sizeof(kA2dpClasses) + sizeof(kA2dpProtocol) +
                    sizeof(kA2dpProfile) + sizeof(kA2dpFeatures)) +
                      (2u + 4u * 3u + sizeof(kAvrcpHandle) + sizeof(kAvrcpClasses) + sizeof(kAvrcpProtocol) +
                       sizeof(kAvrcpProfile)) <= SDP_ANSWER_MAX,
              "both records fit in an answer");

static uint32_t rd_be32(const uint8_t *p)
{
    return ((uint32_t)rd_be16(&p[0]) << 16) | rd_be16(&p[2]);
}

/* The data element sequence that starts at `p`: its contents, and in `used` the length of the whole element. False
 * when there is no sequence there or it is longer than the `len` bytes that are left. */
static bool sdp_sequence(const uint8_t *p, uint16_t len, const uint8_t **body, uint16_t *body_len, uint16_t *used)
{
    uint32_t n   = 0u;
    uint16_t hdr = 0u;
    if (len >= 2u && p[0] == 0x35u) {
        n   = p[1];
        hdr = 2u;
    } else if (len >= 3u && p[0] == 0x36u) {
        n   = rd_be16(&p[1]);
        hdr = 3u;
    } else if (len >= 5u && p[0] == 0x37u) {
        n   = rd_be32(&p[1]);
        hdr = 5u;
    } else {
        return false;
    }
    if (n > (uint32_t)(len - hdr)) {
        return false;
    }
    *body     = &p[hdr];
    *body_len = (uint16_t)n;
    *used     = (uint16_t)(hdr + n);
    return true;
}

/* The UUID element at `p` (16, 32 or 128 bits): its length, 0 when there is none, and its value as the short form
 * of the Bluetooth base UUID; a 128-bit UUID that is not built on the base gets a value no record holds. */
static uint16_t sdp_uuid(const uint8_t *p, uint16_t len, uint32_t *value)
{
    static const uint8_t kBaseTail[12] = { 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB };
    if (len >= 3u && p[0] == 0x19u) {
        *value = rd_be16(&p[1]);
        return 3u;
    }
    if (len >= 5u && p[0] == 0x1Au) {
        *value = rd_be32(&p[1]);
        return 5u;
    }
    if (len >= 17u && p[0] == 0x1Cu) {
        *value = (memcmp(&p[5], kBaseTail, sizeof(kBaseTail)) == 0) ? rd_be32(&p[1]) : 0xFFFFFFFFu;
        return 17u;
    }
    return 0u;
}

/* A service search pattern is a list of UUIDs, at least one. */
static bool sdp_pattern_valid(const uint8_t *pattern, uint16_t len)
{
    uint16_t pos = 0u;
    while (pos < len) {
        uint32_t value = 0u;
        const uint16_t used = sdp_uuid(&pattern[pos], (uint16_t)(len - pos), &value);
        if (used == 0u) {
            return false;
        }
        pos = (uint16_t)(pos + used);
    }
    return len > 0u;
}

/* A pattern matches a record that holds every one of its UUIDs, in any attribute and any order (Core Spec Vol 3
 * Part B, Service Search Patterns). The pattern has passed sdp_pattern_valid. */
static bool sdp_record_matches(const SdpRecord &r, const uint8_t *pattern, uint16_t len)
{
    uint16_t pos = 0u;
    while (pos < len) {
        uint32_t value = 0u;
        pos = (uint16_t)(pos + sdp_uuid(&pattern[pos], (uint16_t)(len - pos), &value));
        bool held = false;
        for (uint8_t i = 0; i < r.n_uuids; i++) {
            held = held || (r.uuids[i] == value);
        }
        if (!held) {
            return false;
        }
    }
    return true;
}

/* The element of an attribute ID list at `p`: a 16-bit ID, or a 32-bit range with the first ID in its high half and
 * the last in its low half. Returns the element's length, 0 when it is neither. */
static uint16_t sdp_id_range(const uint8_t *p, uint16_t len, uint16_t *first, uint16_t *last)
{
    if (len >= 3u && p[0] == 0x09u) {
        *first = rd_be16(&p[1]);
        *last  = *first;
        return 3u;
    }
    if (len >= 5u && p[0] == 0x0Au) {
        *first = rd_be16(&p[1]);
        *last  = rd_be16(&p[3]);
        return 5u;
    }
    return 0u;
}

static bool sdp_id_list_valid(const uint8_t *ids, uint16_t len)
{
    uint16_t pos = 0u;
    while (pos < len) {
        uint16_t first = 0u, last = 0u;
        const uint16_t used = sdp_id_range(&ids[pos], (uint16_t)(len - pos), &first, &last);
        if (used == 0u) {
            return false;
        }
        pos = (uint16_t)(pos + used);
    }
    return len > 0u;
}

/* The list has passed sdp_id_list_valid. */
static bool sdp_id_wanted(const uint8_t *ids, uint16_t len, uint16_t id)
{
    uint16_t pos = 0u;
    while (pos < len) {
        uint16_t first = 0u, last = 0u;
        pos = (uint16_t)(pos + sdp_id_range(&ids[pos], (uint16_t)(len - pos), &first, &last));
        if (id >= first && id <= last) {
            return true;
        }
    }
    return false;
}

/* The attribute list of one record, with the attributes the request names: a sequence of IDs and values. Returns
 * its length; SDP_ANSWER_MAX is room for all of it. */
static uint16_t sdp_put_record(const SdpRecord &r, const uint8_t *ids, uint16_t ids_len, uint8_t *out)
{
    uint16_t at = 2u;
    for (uint8_t i = 0; i < r.n_attrs; i++) {
        const SdpAttr &a = r.attrs[i];
        if (!sdp_id_wanted(ids, ids_len, a.id)) {
            continue;
        }
        out[at] = 0x09u;
        wr_be16(&out[at + 1u], a.id);
        memcpy(&out[at + 3u], a.value, a.len);
        at = (uint16_t)(at + 3u + a.len);
    }
    out[0] = 0x35u;
    out[1] = (uint8_t)(at - 2u);
    return at;
}

static void sdp_send_error(btc_upper_t *u, const btc_l2cap_chan_t *c, uint16_t tx_id, uint16_t code)
{
    uint8_t err[7] = { SDP_ERROR_RSP, 0, 0, 0x00, 0x02, 0, 0 };
    wr_be16(&err[1], tx_id);
    wr_be16(&err[5], code);
    send_l2cap_frame(u, c->remote_cid, err, sizeof(err));
}

/* One part of an attribute answer. The request's MaximumAttributeByteCount limits the attribute bytes of one
 * response (Core Spec Vol 3 Part B, SDP_ServiceAttributeRequest and SDP_ServiceSearchAttributeRequest: 7 is its
 * smallest value), and the PDU has to fit the MTU the peer gave for the channel; what is left
 * follows when the peer repeats its request with the continuation state of this part, which is the offset of the
 * next one. Headphones ask in small steps: Sony WH-1000XM3 allows 32 bytes on a channel with an MTU of 48, and an
 * answer that ignored both was dropped there (2026-11-15). `state` is the request's continuation state, its
 * length byte first. */
static void sdp_send_attr_part(btc_upper_t *u, const btc_l2cap_chan_t *c, uint8_t pdu_id, uint16_t tx_id,
                               const uint8_t *answer, uint16_t total, uint16_t max_bytes, const uint8_t *state,
                               uint16_t state_len)
{
    if (max_bytes < 7u || state_len < 1u || state_len != (uint16_t)(1u + state[0])) {
        sdp_send_error(u, c, tx_id, SDP_ERR_INVALID_SYNTAX);
        return;
    }
    uint16_t offset = 0u;
    if (state[0] != 0u) {
        offset = (state[0] == 2u) ? rd_be16(&state[1]) : 0u;
        if (offset == 0u || offset >= total) {
            sdp_send_error(u, c, tx_id, SDP_ERR_INVALID_CONTINUATION);
            return;
        }
    }
    /* Next to the attribute bytes: PDU header 5, byte count 2, continuation state up to 3. The MTU is 48 or more. */
    const uint16_t room = (uint16_t)(c->remote_mtu - 10u);
    uint16_t part = (uint16_t)(total - offset);
    if (part > max_bytes) {
        part = max_bytes;
    }
    if (part > room) {
        part = room;
    }
    uint8_t rsp[10u + SDP_ANSWER_MAX];
    rsp[0] = pdu_id;
    wr_be16(&rsp[1], tx_id);
    wr_be16(&rsp[5], part);
    memcpy(&rsp[7], &answer[offset], part);
    uint16_t at = (uint16_t)(7u + part);
    if ((uint16_t)(offset + part) < total) {
        rsp[at] = 0x02u;
        wr_be16(&rsp[at + 1u], (uint16_t)(offset + part));
        at = (uint16_t)(at + 3u);
    } else {
        rsp[at++] = 0x00u;
    }
    wr_be16(&rsp[3], (uint16_t)(at - 5u));
    send_l2cap_frame(u, c->remote_cid, rsp, at);
}

static void handle_sdp_pdu(btc_upper_t *u, btc_l2cap_chan_t *c, const uint8_t *p, uint16_t len)
{
    if (len < 5u) {
        return;
    }
    uint8_t  pdu_id = p[0];
    uint16_t tx_id  = rd_be16(&p[1]);
    uint16_t plen   = rd_be16(&p[3]);
    if (5u + plen > len) {
        return;
    }
    const uint8_t *body = &p[5];

    if (c->role == BTC_CHAN_ROLE_SDP_CLIENT) {
        /* Any valid SDP response completes discovery -> disconnect SDP and open AVDTP! */
        if (pdu_id == SDP_SERVICE_SEARCH_ATTR_RSP || pdu_id == SDP_SERVICE_SEARCH_RSP || pdu_id == SDP_ERROR_RSP) {
            close_chan(u, c);
        }
        return;
    }

    /* SDP server for the peer's questions about the source. Each request: parameters, then a continuation state. */
    const uint8_t *pattern = nullptr, *ids = nullptr;
    uint16_t pattern_len = 0u, ids_len = 0u, used = 0u;

    if (pdu_id == SDP_SERVICE_SEARCH_REQ) {
        /* ServiceSearchPattern, MaximumServiceRecordCount, ContinuationState (none: the handles fit one answer) */
        if (!sdp_sequence(body, plen, &pattern, &pattern_len, &used) || !sdp_pattern_valid(pattern, pattern_len) ||
            plen != (uint16_t)(used + 3u) || body[used + 2u] != 0u) {
            sdp_send_error(u, c, tx_id, SDP_ERR_INVALID_SYNTAX);
            return;
        }
        const uint16_t max_count = rd_be16(&body[used]);
        uint8_t  rsp[5u + 4u + 4u * SDP_RECORD_COUNT + 1u];
        uint16_t count = 0u;
        for (size_t i = 0; i < SDP_RECORD_COUNT && count < max_count; i++) {
            if (sdp_record_matches(kSdpRecords[i], pattern, pattern_len)) {
                wr_be32(&rsp[9u + 4u * count], kSdpRecords[i].handle);
                count++;
            }
        }
        const uint16_t at = (uint16_t)(9u + 4u * count);
        rsp[0] = SDP_SERVICE_SEARCH_RSP;
        wr_be16(&rsp[1], tx_id);
        wr_be16(&rsp[3], (uint16_t)(at + 1u - 5u));
        wr_be16(&rsp[5], count); /* TotalServiceRecordCount */
        wr_be16(&rsp[7], count); /* CurrentServiceRecordCount */
        rsp[at] = 0x00u;         /* ContinuationState: none */
        send_l2cap_frame(u, c->remote_cid, rsp, (uint16_t)(at + 1u));
    } else if (pdu_id == SDP_SERVICE_ATTR_REQ) {
        /* ServiceRecordHandle, MaximumAttributeByteCount, AttributeIDList, ContinuationState */
        if (plen < 6u || !sdp_sequence(&body[6], (uint16_t)(plen - 6u), &ids, &ids_len, &used) ||
            !sdp_id_list_valid(ids, ids_len)) {
            sdp_send_error(u, c, tx_id, SDP_ERR_INVALID_SYNTAX);
            return;
        }
        const uint32_t handle = rd_be32(&body[0]);
        const SdpRecord *rec  = nullptr;
        for (size_t i = 0; i < SDP_RECORD_COUNT; i++) {
            if (kSdpRecords[i].handle == handle) {
                rec = &kSdpRecords[i];
            }
        }
        if (rec == nullptr) {
            sdp_send_error(u, c, tx_id, SDP_ERR_INVALID_HANDLE);
            return;
        }
        uint8_t answer[SDP_ANSWER_MAX];
        const uint16_t total = sdp_put_record(*rec, ids, ids_len, answer);
        sdp_send_attr_part(u, c, SDP_SERVICE_ATTR_RSP, tx_id, answer, total, rd_be16(&body[4]), &body[6u + used],
                           (uint16_t)(plen - 6u - used));
    } else if (pdu_id == SDP_SERVICE_SEARCH_ATTR_REQ) {
        /* ServiceSearchPattern, MaximumAttributeByteCount, AttributeIDList, ContinuationState */
        uint16_t ids_used = 0u;
        if (!sdp_sequence(body, plen, &pattern, &pattern_len, &used) || !sdp_pattern_valid(pattern, pattern_len) ||
            plen < (uint16_t)(used + 2u) ||
            !sdp_sequence(&body[used + 2u], (uint16_t)(plen - used - 2u), &ids, &ids_len, &ids_used) ||
            !sdp_id_list_valid(ids, ids_len)) {
            sdp_send_error(u, c, tx_id, SDP_ERR_INVALID_SYNTAX);
            return;
        }
        /* One attribute list per matching record, in a sequence; none match: an empty sequence. */
        uint8_t  answer[SDP_ANSWER_MAX];
        uint16_t total = 2u;
        for (size_t i = 0; i < SDP_RECORD_COUNT; i++) {
            if (sdp_record_matches(kSdpRecords[i], pattern, pattern_len)) {
                total = (uint16_t)(total + sdp_put_record(kSdpRecords[i], ids, ids_len, &answer[total]));
            }
        }
        answer[0] = 0x35u;
        answer[1] = (uint8_t)(total - 2u);
        const uint16_t state_at = (uint16_t)(used + 2u + ids_used);
        sdp_send_attr_part(u, c, SDP_SERVICE_SEARCH_ATTR_RSP, tx_id, answer, total, rd_be16(&body[used]),
                           &body[state_at], (uint16_t)(plen - state_at));
    } else {
        sdp_send_error(u, c, tx_id, SDP_ERR_INVALID_SYNTAX);
    }
}

/* ==== AVDTP 1.3 Signaling Handler (`PSM 0x0019`) ==== */
static void handle_avdtp_sig_pdu(btc_upper_t *u, btc_l2cap_chan_t *c, const uint8_t *p, uint16_t len)
{
    if (len < 2u) {
        return;
    }
    uint8_t rx_label = (uint8_t)((p[0] >> 4) & 0x0Fu);
    uint8_t pkt_type = (uint8_t)((p[0] >> 2) & 0x03u);
    uint8_t msg_type = (uint8_t)(p[0] & 0x03u);
    uint8_t sig_id   = (uint8_t)(p[1] & 0x3Fu);
    if (pkt_type != 0u) {
        return; /* Single-packet signaling covers all SBC SEPs */
    }
    const uint8_t *body = &p[2];
    uint16_t blen = (uint16_t)(len - 2u);

    /* ---- Incoming AVDTP Commands from Sink (Responder path) ---- */
    if (msg_type == AVDTP_MSG_COMMAND) {
        switch (sig_id) {
        case AVDTP_DISCOVER: {
            /* Expose Local SEP #1: Audio (0), Source (tsep=0) */
            uint8_t sep_info[2] = {
                (uint8_t)((AVDTP_LOCAL_SRC_SEID << 2) | (u->avdtp_configured ? 0x02u : 0x00u)),
                0x00u /* media_type=Audio(0), tsep=SRC(0) */
            };
            send_avdtp_rsp(u, c, rx_label, AVDTP_MSG_RESPONSE_ACCEPT, sig_id, sep_info, 2u);
            break;
        }
        case AVDTP_GET_CAPABILITIES:
        case AVDTP_GET_ALL_CAPABILITIES: {
            static const uint8_t kLocalSrcCaps[] = {
                AVDTP_CAT_MEDIA_TRANSPORT, 0x00u,
                AVDTP_CAT_MEDIA_CODEC, 0x06u, 0x00u, 0x00u, 0x3Fu /* 44.1/48k, all modes */, 0x15u /* 16blk, 8sb, Loudness */, 2u, 53u
            };
            send_avdtp_rsp(u, c, rx_label, AVDTP_MSG_RESPONSE_ACCEPT, sig_id, kLocalSrcCaps, sizeof(kLocalSrcCaps));
            break;
        }
        case AVDTP_SET_CONFIGURATION: {
            if (blen >= 2u) {
                u->chosen_acp_seid = (uint8_t)((body[1] >> 2) & 0x3Fu);
                bool has_delay = false;
                uint8_t dummy[4];
                select_sbc_from_caps(u, &body[2], (uint16_t)(blen - 2u), dummy, &has_delay);
                u->avdtp_configured = true;
            }
            send_avdtp_rsp(u, c, rx_label, AVDTP_MSG_RESPONSE_ACCEPT, sig_id, nullptr, 0u);
            break;
        }
        case AVDTP_OPEN:
            u->avdtp_opened = true;
            send_avdtp_rsp(u, c, rx_label, AVDTP_MSG_RESPONSE_ACCEPT, sig_id, nullptr, 0u);
            break;
        case AVDTP_START:
            u->avdtp_streaming = true;
            send_avdtp_rsp(u, c, rx_label, AVDTP_MSG_RESPONSE_ACCEPT, sig_id, nullptr, 0u);
            if (u->ops.on_stream_state) u->ops.on_stream_state(u->ops.ctx, true);
            break;
        case AVDTP_SUSPEND:
            u->avdtp_streaming = false;
            send_avdtp_rsp(u, c, rx_label, AVDTP_MSG_RESPONSE_ACCEPT, sig_id, nullptr, 0u);
            if (u->ops.on_stream_state) u->ops.on_stream_state(u->ops.ctx, false);
            break;
        case AVDTP_CLOSE:
        case AVDTP_ABORT:
            u->avdtp_streaming = false;
            u->avdtp_opened = false;
            u->avdtp_configured = false;
            send_avdtp_rsp(u, c, rx_label, AVDTP_MSG_RESPONSE_ACCEPT, sig_id, nullptr, 0u);
            if (u->ops.on_stream_state) u->ops.on_stream_state(u->ops.ctx, false);
            break;
        case AVDTP_DELAYREPORT:
            send_avdtp_rsp(u, c, rx_label, AVDTP_MSG_RESPONSE_ACCEPT, sig_id, nullptr, 0u);
            break;
        default: {
            uint8_t err[1] = { 0x11u /* Bad Header / Not Supported */ };
            send_avdtp_rsp(u, c, rx_label, AVDTP_MSG_GENERAL_REJECT, sig_id, err, 0u);
            break;
        }
        }
        return;
    }

    /* ---- AVDTP Responses to our Initiator Commands ---- */
    if (msg_type == AVDTP_MSG_RESPONSE_ACCEPT) {
        switch (sig_id) {
        case AVDTP_DISCOVER: {
            u->sep_count = 0u;
            u->sep_probe_idx = 0u;
            for (uint16_t i = 0u; i + 1u < blen && u->sep_count < sizeof(u->sep_list); i += 2u) {
                uint8_t seid       = (uint8_t)((body[i] >> 2) & 0x3Fu);
                bool    in_use     = (body[i] & 0x02u) != 0u;
                uint8_t media_type = (uint8_t)((body[i + 1u] >> 4) & 0x0Fu);
                uint8_t tsep       = (uint8_t)((body[i + 1u] >> 3) & 0x01u);
                if (!in_use && media_type == 0x00u /* Audio */ && tsep == 0x01u /* SNK */ && seid != 0u) {
                    u->sep_list[u->sep_count++] = seid;
                }
            }
            avdtp_probe_next_sep(u);
            break;
        }

        case AVDTP_GET_CAPABILITIES:
        case AVDTP_GET_ALL_CAPABILITIES: {
            uint8_t codec_ie[4];
            bool has_delay = false;
            if (select_sbc_from_caps(u, body, blen, codec_ie, &has_delay)) {
                u->chosen_acp_seid = u->sep_list[u->sep_probe_idx];
                u->chosen_has_delay_report = has_delay;

                uint8_t cfg[14];
                uint16_t clen = 0u;
                cfg[clen++] = (uint8_t)(u->chosen_acp_seid << 2);
                cfg[clen++] = (uint8_t)(AVDTP_LOCAL_SRC_SEID << 2);
                cfg[clen++] = AVDTP_CAT_MEDIA_TRANSPORT;
                cfg[clen++] = 0x00u;
                cfg[clen++] = AVDTP_CAT_MEDIA_CODEC;
                cfg[clen++] = 0x06u;
                cfg[clen++] = 0x00u; /* Media Type: Audio */
                cfg[clen++] = 0x00u; /* Codec: SBC */
                memcpy(&cfg[clen], codec_ie, 4u);
                clen = (uint16_t)(clen + 4u);

                send_avdtp_cmd(u, AVDTP_SET_CONFIGURATION, cfg, clen);
            } else {
                u->sep_probe_idx++;
                avdtp_probe_next_sep(u);
            }
            break;
        }

        case AVDTP_SET_CONFIGURATION: {
            u->avdtp_configured = true;
            uint8_t op[1] = { (uint8_t)(u->chosen_acp_seid << 2) };
            send_avdtp_cmd(u, AVDTP_OPEN, op, 1u);
            break;
        }

        case AVDTP_OPEN: {
            u->avdtp_opened = true;
            open_outgoing_chan(u, BTC_L2CAP_PSM_AVDTP, BTC_CHAN_ROLE_AVDTP_MEDIA);
            break;
        }

        case AVDTP_START: {
            u->avdtp_streaming = true;
            if (u->ops.on_stream_state) {
                u->ops.on_stream_state(u->ops.ctx, true);
            }
            break;
        }

        case AVDTP_SUSPEND: {
            u->avdtp_streaming = false;
            if (u->ops.on_stream_state) {
                u->ops.on_stream_state(u->ops.ctx, false);
            }
            break;
        }

        default:
            break;
        }
    } else if (msg_type == AVDTP_MSG_RESPONSE_REJECT) {
        if (sig_id == AVDTP_GET_CAPABILITIES || sig_id == AVDTP_SET_CONFIGURATION) {
            u->sep_probe_idx++;
            avdtp_probe_next_sep(u);
        }
    }
}

/* ==== AVRCP 1.5 over AVCTP (`PSM 0x0017`) ==== */
static void handle_avctp_pdu(btc_upper_t *u, btc_l2cap_chan_t *c, const uint8_t *p, uint16_t len)
{
    if (len < 6u) {
        return;
    }
    uint8_t avctp_hdr = p[0];
    uint8_t label     = (uint8_t)((avctp_hdr >> 4) & 0x0Fu);
    uint8_t cr        = (uint8_t)((avctp_hdr >> 1) & 0x01u); /* 0 = Command, 1 = Response */
    uint16_t pid      = rd_be16(&p[1]);
    if (pid != 0x110Eu) {
        if (cr == 0u) {
            uint8_t ipid_rsp[3] = { (uint8_t)((label << 4) | 0x03u /* Response + IPID=1 */), p[1], p[2] };
            send_l2cap_frame(u, c->remote_cid, ipid_rsp, 3u);
        }
        return;
    }
    if (cr == 1u) {
        /* Response from speaker (e.g. SetAbsoluteVolume acknowledgement or volume notification) */
        if (len >= 11u && p[5] == 0x00u && p[9] == 0x31u /* RegisterNotification */ &&
            (p[3] == 0x0Du /* CHANGED */ || p[3] == 0x0Fu /* INTERIM */) && len >= 15u && p[13] == 0x0Du) {
            uint8_t v7 = p[14] & 0x7Fu;
            u->current_vol_7bit = v7;
            if (u->ops.on_peer_volume) {
                u->ops.on_peer_volume(u->ops.ctx, (uint8_t)(((uint16_t)v7 * 255u) / 127u));
            }
        }
        /* The answer to our SetAbsoluteVolume: ACCEPTED (0x9) from a speaker that sets the level itself, anything
         * else (NOT_IMPLEMENTED, REJECTED) from one that leaves it to the source. */
        if (len >= 10u && p[5] == 0x00u && p[9] == 0x50u /* SetAbsoluteVolume */) {
            u->peer_abs_volume = ((p[3] & 0x0Fu) == 0x09u);
        }
        return;
    }

    uint8_t ctype  = (uint8_t)(p[3] & 0x0Fu);
    uint8_t sub    = p[4];
    uint8_t opcode = p[5];

    if (opcode == 0x30u /* UNIT INFO */) {
        uint8_t rsp[11] = {
            (uint8_t)((label << 4) | 0x02u), 0x11, 0x0E,
            0x0Cu /* Implemented/Stable */, 0xFFu, 0x30u,
            0x07u, 0x48u /* Panel */, 0x00u, 0x19u, 0x58u /* BT SIG */
        };
        send_l2cap_frame(u, c->remote_cid, rsp, sizeof(rsp));
    } else if (opcode == 0x31u /* SUBUNIT INFO */) {
        uint8_t rsp[11] = {
            (uint8_t)((label << 4) | 0x02u), 0x11, 0x0E,
            0x0Cu, 0xFFu, 0x31u,
            0x07u, 0x48u, 0xFFu, 0xFFu, 0xFFu
        };
        send_l2cap_frame(u, c->remote_cid, rsp, sizeof(rsp));
    } else if (opcode == 0x7Cu /* PASSTHROUGH */ && len >= 8u) {
        uint8_t op_id   = (uint8_t)(p[6] & 0x7Fu);
        bool    pressed = (p[6] & 0x80u) == 0u;

        /* Reply Accepted (0x09) echoing exact command payload */
        uint8_t rsp[16];
        uint16_t rlen = (len > sizeof(rsp)) ? (uint16_t)sizeof(rsp) : len;
        memcpy(rsp, p, rlen);
        rsp[0] = (uint8_t)((label << 4) | 0x02u);
        rsp[3] = 0x09u; /* Accepted */
        send_l2cap_frame(u, c->remote_cid, rsp, rlen);

        if (pressed && ctype == 0x00u && u->ops.on_media_cmd) {
            bt_classic_media_cmd_t cmd = BTC_MEDIA_CMD_NONE;
            switch (op_id) {
            case 0x44u: cmd = BTC_MEDIA_CMD_PLAY;     break;
            case 0x46u: cmd = BTC_MEDIA_CMD_PAUSE;    break;
            case 0x45u: cmd = BTC_MEDIA_CMD_STOP;     break;
            case 0x4Bu: cmd = BTC_MEDIA_CMD_NEXT;     break;
            case 0x4Cu: cmd = BTC_MEDIA_CMD_PREV;     break;
            case 0x41u: cmd = BTC_MEDIA_CMD_VOL_UP;   break;
            case 0x42u: cmd = BTC_MEDIA_CMD_VOL_DOWN; break;
            default: break;
            }
            if (cmd != BTC_MEDIA_CMD_NONE) {
                u->ops.on_media_cmd(u->ops.ctx, cmd);
            }
        }
    } else if (opcode == 0x00u /* VENDOR DEPENDENT */ && len >= 13u &&
               p[6] == 0x00u && p[7] == 0x19u && p[8] == 0x58u) {
        uint8_t pdu_id = p[9];
        if (pdu_id == 0x10u /* GetCapabilities */ && len >= 14u && p[13] == 0x03u /* Events */) {
            uint8_t rsp[17] = {
                (uint8_t)((label << 4) | 0x02u), 0x11, 0x0E,
                0x0Cu /* Stable */, sub, 0x00u, 0x00, 0x19, 0x58,
                0x10u, 0x00u, 0x00, 0x04,
                0x03u, 0x02u, 0x01u /* PLAYBACK_STATUS */, 0x0Du /* VOLUME_CHANGED */
            };
            send_l2cap_frame(u, c->remote_cid, rsp, sizeof(rsp));
        } else if (pdu_id == 0x31u /* RegisterNotification */ && len >= 14u && p[13] == 0x01u /* PLAYBACK_STATUS */) {
            /* GetCapabilities above lists this event, so its registration is answered and not rejected: INTERIM
             * with the present status (0x01 playing, 0x02 paused). No CHANGED follows: the stream's own state
             * (AVDTP START and SUSPEND) tells the speaker the same. */
            uint8_t rsp[15] = {
                (uint8_t)((label << 4) | 0x02u), 0x11, 0x0E,
                0x0Fu /* INTERIM */, sub, 0x00u, 0x00, 0x19, 0x58,
                0x31u, 0x00u, 0x00, 0x02,
                0x01u, (uint8_t)(u->avdtp_streaming ? 0x01u : 0x02u)
            };
            send_l2cap_frame(u, c->remote_cid, rsp, sizeof(rsp));
        } else if (pdu_id == 0x31u /* RegisterNotification */ && len >= 14u && p[13] == 0x0Du /* VOLUME_CHANGED */) {
            u->vol_notify_pending = true;
            u->vol_notify_label   = label;
            uint8_t rsp[15] = {
                (uint8_t)((label << 4) | 0x02u), 0x11, 0x0E,
                0x0Fu /* INTERIM */, sub, 0x00u, 0x00, 0x19, 0x58,
                0x31u, 0x00u, 0x00, 0x02,
                0x0Du, u->current_vol_7bit
            };
            send_l2cap_frame(u, c->remote_cid, rsp, sizeof(rsp));
        } else if (pdu_id == 0x50u /* SetAbsoluteVolume */ && len >= 14u) {
            uint8_t v7 = p[13] & 0x7Fu;
            u->current_vol_7bit = v7;
            uint8_t rsp[14] = {
                (uint8_t)((label << 4) | 0x02u), 0x11, 0x0E,
                0x09u /* Accepted */, sub, 0x00u, 0x00, 0x19, 0x58,
                0x50u, 0x00u, 0x00, 0x01, v7
            };
            send_l2cap_frame(u, c->remote_cid, rsp, sizeof(rsp));
            if (u->ops.on_peer_volume) {
                u->ops.on_peer_volume(u->ops.ctx, (uint8_t)(((uint16_t)v7 * 255u) / 127u));
            }
        } else {
            uint8_t rej[14] = {
                (uint8_t)((label << 4) | 0x02u), 0x11, 0x0E,
                0x0Au /* Rejected */, sub, 0x00u, 0x00, 0x19, 0x58,
                pdu_id, 0x00u, 0x00, 0x01, 0x00u /* Invalid Command */
            };
            send_l2cap_frame(u, c->remote_cid, rej, sizeof(rej));
        }
    }
}

} /* namespace */

extern "C" void btc_upper_init(btc_upper_t *u, const btc_upper_ops_t *ops, uint8_t preferred_bitpool, bool prefer_44k1)
{
    if (!u) {
        return;
    }
    memset(u, 0, sizeof(*u));
    if (ops) {
        u->ops = *ops;
    }
    u->preferred_bitpool = (preferred_bitpool >= 18u && preferred_bitpool <= 53u) ? preferred_bitpool : 35u;
    u->prefer_44k1       = prefer_44k1;
    u->rtp_ssrc          = 0x43594252u;
    u->current_vol_7bit  = 0x64u;
}

extern "C" void btc_upper_reset(btc_upper_t *u)
{
    if (!u) {
        return;
    }
    btc_upper_ops_t saved_ops = u->ops;
    uint8_t bp = u->preferred_bitpool;
    bool p44   = u->prefer_44k1;
    uint8_t v7 = u->current_vol_7bit;
    /* Everything but the trace, which is read after the link has ended and is the struct's tail. */
    memset(u, 0, offsetof(btc_upper_t, trace));
    u->ops               = saved_ops;
    u->preferred_bitpool = bp;
    u->prefer_44k1       = p44;
    u->rtp_ssrc          = 0x43594252u;
    u->current_vol_7bit  = v7;
}

extern "C" void btc_upper_trace_clear(btc_upper_t *u)
{
    if (!u) {
        return;
    }
    memset(u->trace, 0, sizeof(u->trace));
    u->trace_n    = 0u;
    u->trace_tick = 0u;
}

extern "C" void btc_upper_on_tick(btc_upper_t *u)
{
    if (!u) {
        return;
    }
    if (u->trace_tick < 0xFFu) {
        u->trace_tick++;
    }
    if (u->audio_retry_in != 0u && --u->audio_retry_in == 0u && !find_chan_by_role(u, BTC_CHAN_ROLE_AVDTP_SIG)) {
        open_outgoing_chan(u, BTC_L2CAP_PSM_AVDTP, BTC_CHAN_ROLE_AVDTP_SIG);
    }
}

extern "C" uint16_t btc_upper_audio_refusal(const btc_upper_t *u)
{
    return u ? u->audio_refusal : 0u;
}

extern "C" uint8_t btc_upper_trace_read(const btc_upper_t *u, btc_upper_rec_t *out, uint8_t max_out)
{
    if (!u || !out) {
        return 0u;
    }
    const uint16_t kept  = u->trace_n < BTC_UPPER_TRACE ? u->trace_n : (uint16_t)BTC_UPPER_TRACE;
    const uint16_t first = (uint16_t)(u->trace_n - kept);
    const uint8_t  n     = kept < max_out ? (uint8_t)kept : max_out;
    for (uint8_t i = 0; i < n; i++) {
        out[i] = u->trace[(first + i) % BTC_UPPER_TRACE];
    }
    return n;
}

extern "C" void btc_upper_start_initiator(btc_upper_t *u)
{
    if (!u) {
        return;
    }
    if (!find_chan_by_role(u, BTC_CHAN_ROLE_AVDTP_SIG) && !find_chan_by_role(u, BTC_CHAN_ROLE_SDP_CLIENT)) {
        open_outgoing_chan(u, BTC_L2CAP_PSM_SDP, BTC_CHAN_ROLE_SDP_CLIENT);
    }
}

extern "C" void btc_upper_on_l2cap_pdu(btc_upper_t *u, const uint8_t *sdu, uint16_t sdu_len)
{
    if (!u || !sdu || sdu_len < 4u) {
        return;
    }
    uint16_t plen = rd_le16(&sdu[0]);
    uint16_t lcid = rd_le16(&sdu[2]);
    if (4u + plen > sdu_len) {
        trace_put(u, 2u, lcid, plen, &sdu[4], (uint16_t)(sdu_len - 4u));
        return;
    }
    const uint8_t *payload = &sdu[4];
    trace_put(u, 1u, lcid, plen, payload, plen);

    if (lcid == L2CAP_CID_SIGNALING) {
        handle_l2cap_signaling(u, payload, plen);
        return;
    }

    btc_l2cap_chan_t *c = find_chan_by_local_cid(u, lcid);
    if (!c || c->state != BTC_CHAN_OPEN) {
        return;
    }

    switch (c->role) {
    case BTC_CHAN_ROLE_SDP_CLIENT:
    case BTC_CHAN_ROLE_SDP_SERVER:
        handle_sdp_pdu(u, c, payload, plen);
        break;
    case BTC_CHAN_ROLE_AVDTP_SIG:
        handle_avdtp_sig_pdu(u, c, payload, plen);
        break;
    case BTC_CHAN_ROLE_AVCTP:
        handle_avctp_pdu(u, c, payload, plen);
        break;
    default:
        break;
    }
}

extern "C" bool btc_upper_request_start(btc_upper_t *u)
{
    if (!u) {
        return false;
    }
    u->start_requested = true;
    if (u->avdtp_streaming) {
        return true;
    }
    btc_l2cap_chan_t *med = find_chan_by_role(u, BTC_CHAN_ROLE_AVDTP_MEDIA);
    if (u->avdtp_opened && med && med->state == BTC_CHAN_OPEN) {
        uint8_t p[1] = { (uint8_t)(u->chosen_acp_seid << 2) };
        send_avdtp_cmd(u, AVDTP_START, p, 1u);
        return true;
    }
    return false;
}

extern "C" bool btc_upper_request_suspend(btc_upper_t *u)
{
    if (!u) {
        return false;
    }
    u->start_requested = false;
    if (!u->avdtp_streaming) {
        return true;
    }
    uint8_t p[1] = { (uint8_t)(u->chosen_acp_seid << 2) };
    send_avdtp_cmd(u, AVDTP_SUSPEND, p, 1u);
    return true;
}

extern "C" bool btc_upper_can_send_media(const btc_upper_t *u)
{
    if (!u || !u->avdtp_streaming) {
        return false;
    }
    const btc_l2cap_chan_t *med = find_chan_by_role_const(u, BTC_CHAN_ROLE_AVDTP_MEDIA);
    return med && med->state == BTC_CHAN_OPEN;
}

extern "C" bool btc_upper_send_media_packet(btc_upper_t *u, const uint8_t *sbc_frames, uint16_t sbc_bytes,
                                            uint8_t num_frames, uint16_t pcm_samples_per_frame)
{
    if (!u || !sbc_frames || sbc_bytes == 0u || num_frames == 0u || num_frames > 15u) {
        return false;
    }
    btc_l2cap_chan_t *med = find_chan_by_role(u, BTC_CHAN_ROLE_AVDTP_MEDIA);
    if (!med || med->state != BTC_CHAN_OPEN || !u->avdtp_streaming) {
        return false;
    }

    uint16_t plen = (uint16_t)(12u + 1u + sbc_bytes);
    if (plen > med->remote_mtu || plen > BTC_L2CAP_LOCAL_MTU) {
        return false;
    }

    uint8_t pkt[BTC_L2CAP_LOCAL_MTU];
    pkt[0] = 0x80u; /* RTP v2 */
    pkt[1] = 0x60u; /* PT = 96 */
    wr_be16(&pkt[2], u->rtp_seq);
    wr_be32(&pkt[4], u->rtp_timestamp);
    wr_be32(&pkt[8], u->rtp_ssrc);
    pkt[12] = (uint8_t)(num_frames & 0x0Fu); /* A2DP SBC Media Payload Header */
    memcpy(&pkt[13], sbc_frames, sbc_bytes);

    /* The numbers move on only with a packet that went out: one that found no room is offered again
     * (btc_media_queue.h) and must not look like several lost packets to the receiver. */
    if (!send_l2cap_untraced(u, med->remote_cid, pkt, plen)) {
        return false;
    }
    u->rtp_seq++;
    u->rtp_timestamp += (uint32_t)num_frames * (uint32_t)pcm_samples_per_frame;
    return true;
}

extern "C" void btc_upper_bitpool_range(const btc_upper_t *u, uint8_t *min_bitpool, uint8_t *max_bitpool)
{
    if (!u || !min_bitpool || !max_bitpool) {
        return;
    }
    *min_bitpool = u->negotiated_bitpool_min;
    *max_bitpool = u->negotiated_bitpool_max;
}

extern "C" void btc_upper_skip_media_packet(btc_upper_t *u, uint8_t num_frames, uint16_t pcm_samples_per_frame)
{
    if (!u) {
        return;
    }
    u->rtp_seq++;
    u->rtp_timestamp += (uint32_t)num_frames * (uint32_t)pcm_samples_per_frame;
}

extern "C" void btc_upper_set_volume(btc_upper_t *u, uint8_t vol_0_255)
{
    if (!u) {
        return;
    }
    uint8_t v7 = (uint8_t)(((uint16_t)vol_0_255 * 127u + 127u) / 255u);
    if (v7 > 0x7Fu) v7 = 0x7Fu;
    u->current_vol_7bit = v7;

    btc_l2cap_chan_t *c = find_chan_by_role(u, BTC_CHAN_ROLE_AVCTP);
    if (!c || c->state != BTC_CHAN_OPEN) {
        return;
    }

    /* 1. If speaker registered for EVENT_VOLUME_CHANGED, complete CHANGED notification */
    if (u->vol_notify_pending) {
        u->vol_notify_pending = false;
        uint8_t chg[15] = {
            (uint8_t)((u->vol_notify_label << 4) | 0x02u), 0x11, 0x0E,
            0x0Du /* CHANGED */, 0x48u, 0x00u, 0x00, 0x19, 0x58,
            0x31u, 0x00u, 0x00, 0x02, 0x0Du, v7
        };
        send_l2cap_frame(u, c->remote_cid, chg, sizeof(chg));
    }

    /* 2. Also send AVRCP SetAbsoluteVolume command (0x50) for Absolute Volume sinks */
    uint8_t lbl = (uint8_t)(u->avctp_tx_label & 0x0Fu);
    u->avctp_tx_label = (uint8_t)((u->avctp_tx_label + 1u) & 0x0Fu);
    uint8_t cmd[14] = {
        (uint8_t)(lbl << 4), 0x11, 0x0E,
        0x00u /* Control */, 0x48u /* Panel */, 0x00u /* Vendor Dependent */,
        0x00, 0x19, 0x58,
        0x50u /* SetAbsoluteVolume */, 0x00u, 0x00, 0x01, v7
    };
    send_l2cap_frame(u, c->remote_cid, cmd, sizeof(cmd));
}

extern "C" bool btc_upper_peer_sets_volume(const btc_upper_t *u)
{
    return u != nullptr && u->peer_abs_volume;
}
