/*
 * Bluetooth Classic L2CAP + SDP + AVDTP 1.3 Source + AVRCP 1.5 Engine.
 */
#include "btc_l2cap_avdtp.h"

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

static bool send_l2cap_frame(btc_upper_t *u, uint16_t remote_cid, const uint8_t *payload, uint16_t plen)
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

/* ==== Minimalist SDP Server & Client (`PSM 0x0001`) ==== */
/* Complete pre-encoded SDP attribute list for AudioSource (0x110A) + A2DP v1.3 */
static const uint8_t kSdpAttrAudioSource[] = {
    0x35, 0x36, /* Sequence (54 bytes) */
        /* Attr 0x0000: ServiceRecordHandle = 0x00010001 */
        0x09, 0x00, 0x00,  0x0A, 0x00, 0x01, 0x00, 0x01,
        /* Attr 0x0001: ServiceClassIDList = { AudioSource (0x110A) } */
        0x09, 0x00, 0x01,  0x35, 0x03,  0x19, 0x11, 0x0A,
        /* Attr 0x0004: ProtocolDescriptorList = { {L2CAP, 0x0019}, {AVDTP, 0x0103} } */
        0x09, 0x00, 0x04,  0x35, 0x10,
            0x35, 0x06,  0x19, 0x01, 0x00,  0x09, 0x00, 0x19,
            0x35, 0x06,  0x19, 0x00, 0x19,  0x09, 0x01, 0x03,
        /* Attr 0x0009: BluetoothProfileDescriptorList = { {A2DP (0x110D), 0x0103} } */
        0x09, 0x00, 0x09,  0x35, 0x08,
            0x35, 0x06,  0x19, 0x11, 0x0D,  0x09, 0x01, 0x03,
        /* Attr 0x0311: SupportedFeatures = 0x0001 (Player) */
        0x09, 0x03, 0x11,  0x09, 0x00, 0x01,
};

/* Pre-encoded SDP attribute list for AVRCP Controller/Target (0x110E / 0x110C) */
static const uint8_t kSdpAttrAvrcp[] = {
    0x35, 0x33, /* Sequence (51 bytes) */
        0x09, 0x00, 0x00,  0x0A, 0x00, 0x01, 0x00, 0x02,
        0x09, 0x00, 0x01,  0x35, 0x06,  0x19, 0x11, 0x0E,  0x19, 0x11, 0x0C,
        0x09, 0x00, 0x04,  0x35, 0x10,
            0x35, 0x06,  0x19, 0x01, 0x00,  0x09, 0x00, 0x17,
            0x35, 0x06,  0x19, 0x00, 0x17,  0x09, 0x01, 0x04,
        0x09, 0x00, 0x09,  0x35, 0x08,
            0x35, 0x06,  0x19, 0x11, 0x0E,  0x09, 0x01, 0x05,
};

static bool buf_has_uuid16(const uint8_t *b, uint16_t len, uint16_t uuid)
{
    for (uint16_t i = 0; i + 2u < len; i++) {
        if (b[i] == 0x19u && rd_be16(&b[i + 1u]) == uuid) {
            return true;
        }
    }
    return false;
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

    /* SDP Server for incoming speaker queries */
    bool match_a2dp  = buf_has_uuid16(body, plen, 0x110Au) || buf_has_uuid16(body, plen, 0x110Du) ||
                       buf_has_uuid16(body, plen, 0x0100u);
    bool match_avrcp = buf_has_uuid16(body, plen, 0x110Cu) || buf_has_uuid16(body, plen, 0x110Eu) ||
                       buf_has_uuid16(body, plen, 0x0017u);

    if (pdu_id == SDP_SERVICE_SEARCH_REQ) {
        uint8_t rsp[32];
        uint16_t cnt = 0u;
        uint16_t dpos = 9u;
        if (match_a2dp)  { wr_be32(&rsp[dpos], 0x00010001u); dpos += 4u; cnt++; }
        if (match_avrcp) { wr_be32(&rsp[dpos], 0x00010002u); dpos += 4u; cnt++; }
        rsp[dpos++] = 0x00u; /* ContinuationState = 0 */
        rsp[0] = SDP_SERVICE_SEARCH_RSP;
        wr_be16(&rsp[1], tx_id);
        wr_be16(&rsp[3], (uint16_t)(dpos - 5u));
        wr_be16(&rsp[5], cnt);
        wr_be16(&rsp[7], cnt);
        send_l2cap_frame(u, c->remote_cid, rsp, dpos);
    } else if (pdu_id == SDP_SERVICE_SEARCH_ATTR_REQ) {
        uint8_t rsp[160];
        uint8_t list_buf[128];
        uint16_t lpos = 0u;
        if (match_a2dp) {
            memcpy(&list_buf[lpos], kSdpAttrAudioSource, sizeof(kSdpAttrAudioSource));
            lpos = (uint16_t)(lpos + sizeof(kSdpAttrAudioSource));
        }
        if (match_avrcp) {
            memcpy(&list_buf[lpos], kSdpAttrAvrcp, sizeof(kSdpAttrAvrcp));
            lpos = (uint16_t)(lpos + sizeof(kSdpAttrAvrcp));
        }
        uint16_t seq_total = (uint16_t)(2u + lpos);
        rsp[0] = SDP_SERVICE_SEARCH_ATTR_RSP;
        wr_be16(&rsp[1], tx_id);
        wr_be16(&rsp[3], (uint16_t)(2u + seq_total + 1u));
        wr_be16(&rsp[5], seq_total);
        rsp[7] = 0x35u;
        rsp[8] = (uint8_t)lpos;
        if (lpos > 0u) {
            memcpy(&rsp[9], list_buf, lpos);
        }
        rsp[9 + lpos] = 0x00u; /* ContinuationState = 0 */
        send_l2cap_frame(u, c->remote_cid, rsp, (uint16_t)(10u + lpos));
    } else if (pdu_id == SDP_SERVICE_ATTR_REQ && plen >= 4u) {
        uint32_t handle = ((uint32_t)rd_be16(&body[0]) << 16) | rd_be16(&body[2]);
        const uint8_t *rec = (handle == 0x00010002u) ? kSdpAttrAvrcp : kSdpAttrAudioSource;
        uint16_t rlen = (handle == 0x00010002u) ? (uint16_t)sizeof(kSdpAttrAvrcp) : (uint16_t)sizeof(kSdpAttrAudioSource);
        uint8_t rsp[96];
        rsp[0] = SDP_SERVICE_ATTR_RSP;
        wr_be16(&rsp[1], tx_id);
        wr_be16(&rsp[3], (uint16_t)(2u + rlen + 1u));
        wr_be16(&rsp[5], rlen);
        memcpy(&rsp[7], rec, rlen);
        rsp[7 + rlen] = 0x00u;
        send_l2cap_frame(u, c->remote_cid, rsp, (uint16_t)(8u + rlen));
    } else {
        uint8_t err[7] = { SDP_ERROR_RSP, p[1], p[2], 0x00, 0x02, 0x00, 0x03 };
        send_l2cap_frame(u, c->remote_cid, err, sizeof(err));
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
    memset(u, 0, sizeof(*u));
    u->ops               = saved_ops;
    u->preferred_bitpool = bp;
    u->prefer_44k1       = p44;
    u->rtp_ssrc          = 0x43594252u;
    u->current_vol_7bit  = v7;
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
        return;
    }
    const uint8_t *payload = &sdu[4];

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
    if (!send_l2cap_frame(u, med->remote_cid, pkt, plen)) {
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
