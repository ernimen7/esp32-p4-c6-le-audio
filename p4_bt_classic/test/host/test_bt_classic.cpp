/*
 * Host Unit & Protocol Integration Tests for `p4_bt_classic`:
 *  1. SBC Encoder/Decoder (A2DP Appendix B frame length, CRC-8, Joint Stereo & Stereo SNR > 30 dB)
 *  2. NIST P-192 ECDH key agreement & invalid-curve point rejection
 *  3. Full LMP SSP P-192 "Just Works" pairing + E1 auth + E3 Kc' derivation + multi-chunk remote name + role-switch guard
 *  4. LMP Saved Link Key fast reconnect, stale-key 0x06 fallback, and Legacy PIN ("0000") pairing
 *  5. L2CAP + SDP + AVDTP 1.3 (DISCOVER..START + RTP SBC media framing) + AVRCP (PASSTHROUGH & Absolute Volume)
 */
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <vector>

#include "br_crypto.h"
#include "br_proto.h"
#include "btc_bonds.h"
#include "btc_l2cap_avdtp.h"
#include "btc_lmp.h"
#include "btc_media_queue.h"
#include "btc_rate.h"
#include "sbc_enc.h"

#define CHECK(cond, msg)                                                              \
    do {                                                                              \
        if (!(cond)) {                                                                \
            std::fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg));    \
            return 1;                                                                 \
        }                                                                             \
    } while (0)

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* =========================================================================
 * 1. SBC Codec Test
 * ========================================================================= */
static int test_sbc_codec(void)
{
    sbc_params_t js = {
        .freq     = SBC_FREQ_44100,
        .blocks   = 16,
        .mode     = SBC_MODE_JOINT_STEREO,
        .alloc    = SBC_ALLOC_LOUDNESS,
        .subbands = 8,
        .bitpool  = 35,
    };
    CHECK(sbc_frame_length(&js) == 83u, "SBC 44.1k JS bitpool=35 frame length == 83");

    sbc_params_t js53 = js;
    js53.bitpool = 53;
    CHECK(sbc_frame_length(&js53) == 119u, "SBC 44.1k JS bitpool=53 frame length == 119");

    sbc_params_t st35 = js;
    st35.mode = SBC_MODE_STEREO;
    CHECK(sbc_frame_length(&st35) == 82u, "SBC 44.1k Stereo bitpool=35 frame length == 82");

    /* Encode & decode 32 frames (4096 stereo samples) of multi-tone audio at bitpool=50 */
    sbc_params_t p = js;
    p.bitpool = 50;
    sbc_enc_t enc;
    sbc_dec_t dec;
    sbc_enc_init(&enc, &p);
    sbc_dec_init(&dec);

    const size_t n_frames = 32;
    const size_t total_samples = n_frames * 128;
    std::vector<int16_t> in_pcm(total_samples * 2);
    std::vector<int16_t> out_pcm(total_samples * 2);

    for (size_t n = 0; n < total_samples; n++) {
        double t = (double)n / 44100.0;
        double l = 11000.0 * std::sin(2.0 * M_PI * 997.0 * t) + 4500.0 * std::cos(2.0 * M_PI * 3120.0 * t);
        double r = 10000.0 * std::sin(2.0 * M_PI * 1480.0 * t) - 4000.0 * std::sin(2.0 * M_PI * 997.0 * t);
        in_pcm[n * 2]     = (int16_t)std::lrint(l);
        in_pcm[n * 2 + 1] = (int16_t)std::lrint(r);
    }

    uint8_t sbc_buf[256];
    for (size_t f = 0; f < n_frames; f++) {
        size_t flen = sbc_encode_frame(&enc, &in_pcm[f * 128 * 2], 2, sbc_buf, sizeof(sbc_buf));
        CHECK(flen == sbc_frame_length(&p), "sbc_encode_frame exact length");
        CHECK(sbc_buf[0] == 0x9Cu, "SBC syncword 0x9C");

        sbc_params_t dec_p = {};
        size_t dlen = sbc_decode_frame(&dec, sbc_buf, flen, &out_pcm[f * 128 * 2], 128, &dec_p);
        CHECK(dlen == flen, "sbc_decode_frame accepted CRC-8 & length");
        CHECK(dec_p.bitpool == p.bitpool && dec_p.mode == p.mode, "decoded header matches");
    }

    /* Group delay of 80-tap 8-subband polyphase QMF is 73 samples */
    const size_t delay = 73;
    double sig_l = 0.0, err_l = 0.0, sig_r = 0.0, err_r = 0.0;
    for (size_t n = 256; n + delay < total_samples - 64; n++) {
        double dl = (double)out_pcm[(n + delay) * 2]     - (double)in_pcm[n * 2];
        double dr = (double)out_pcm[(n + delay) * 2 + 1] - (double)in_pcm[n * 2 + 1];
        sig_l += (double)in_pcm[n * 2] * (double)in_pcm[n * 2];
        sig_r += (double)in_pcm[n * 2 + 1] * (double)in_pcm[n * 2 + 1];
        err_l += dl * dl;
        err_r += dr * dr;
    }
    double snr_l = 10.0 * std::log10(sig_l / (err_l + 1e-9));
    double snr_r = 10.0 * std::log10(sig_r / (err_r + 1e-9));
    std::printf("  SBC Joint-Stereo SNR: L=%.2f dB, R=%.2f dB\n", snr_l, snr_r);
    CHECK(snr_l > 30.0 && snr_r > 30.0, "SBC stereo reconstruction SNR > 30 dB");
    return 0;
}

/* =========================================================================
 * 2. NIST P-192 ECDH Test
 * ========================================================================= */
static int test_p192_ecdh(void)
{
    uint8_t seed_a[24], seed_b[24];
    for (int i = 0; i < 24; i++) {
        seed_a[i] = (uint8_t)(0x11u + i * 7u);
        seed_b[i] = (uint8_t)(0xA3u ^ (i * 13u));
    }

    uint8_t priv_a[24], pub_a[48], priv_b[24], pub_b[48];
    btc_p192_gen_keypair(seed_a, priv_a, pub_a);
    btc_p192_gen_keypair(seed_b, priv_b, pub_b);

    uint8_t dh_ab[24], dh_ba[24];
    CHECK(btc_p192_compute_dhkey(priv_a, pub_b, dh_ab), "Alice computes P-192 DHKey");
    CHECK(btc_p192_compute_dhkey(priv_b, pub_a, dh_ba), "Bob computes P-192 DHKey");
    CHECK(std::memcmp(dh_ab, dh_ba, 24) == 0, "P-192 ECDH shared secret matches");

    /* Corrupt peer Y coordinate -> must reject off-curve point! */
    uint8_t bad_pub[48];
    std::memcpy(bad_pub, pub_b, 48);
    bad_pub[24] ^= 0x01u;
    uint8_t dummy[24];
    CHECK(!btc_p192_compute_dhkey(priv_a, bad_pub, dummy), "Off-curve P-192 public key rejected");
    return 0;
}

/* Bytes of a hex string that has the most significant byte on the left, stored least significant first. */
static void le_from_msb_hex(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned int v = 0;
        std::sscanf(&hex[2u * i], "%2x", &v);
        out[n - 1u - i] = (uint8_t)v;
    }
}

/* Official P-192 sample data of the Bluetooth Core Specification 5.4, Vol 2 Part G section 7.1.1 (sets 1 to 3):
 * the public key of a private key, and the DHKey of the other private key with that public key. */
static int test_p192_official_sample_data(void)
{
    static const struct {
        const char *priv_a, *priv_b, *pub_ax, *pub_ay, *dhkey;
    } sets[] = {
        { "07915f86918ddc27005df1d6cf0c142b625ed2eff4a518ff", "1e636ca790b50f68f15d8dbe86244e309211d635de00e16d",
          "15207009984421a6586f9fc3fe7e4329d2809ea51125f8ed", "b09d42b81bc5bd009f79e4b59dbbaa857fca856fb9f7ea25",
          "fb3ba2012c7e62466e486e229290175b4afebc13fdccee46" },
        { "52ec1ca6e0ec973c29065c3ca10be80057243002f09bb43e", "57231203533e9efe18cc622fd0e34c6a29c6e0fa3ab3bc53",
          "45571f027e0d690795d61560804da5de789a48f94ab4b07e", "0220016e8a6bce74b45ffec1e664aaa0273b7cbd907a8e2b",
          "a20a34b5497332aa7a76ab135cc0c168333be309d463c0c0" },
        { "00a0df08eaf51e6e7be519d67c6749ea3f4517cdd2e9e821", "2bf5e0d1699d50ca5025e8e2d9b13244b4d322a328be1821",
          "2ed35b430fa45f9d329186d754eeeb0495f0f653127f613d", "27e08db74e424395052ddae7e3d5a8fecb52a8039b735b73",
          "3b3986ba70790762f282a12a6d3bcae7a2ca01e25b87724e" },
    };
    for (size_t i = 0; i < sizeof(sets) / sizeof(sets[0]); i++) {
        uint8_t priv_a[24], priv_b[24], want_pub[48], want_dh[24];
        le_from_msb_hex(sets[i].priv_a, priv_a, 24u);
        le_from_msb_hex(sets[i].priv_b, priv_b, 24u);
        le_from_msb_hex(sets[i].pub_ax, &want_pub[0], 24u);
        le_from_msb_hex(sets[i].pub_ay, &want_pub[24], 24u);
        le_from_msb_hex(sets[i].dhkey, want_dh, 24u);

        uint8_t priv[24], pub[48], dh[24];
        btc_p192_gen_keypair(priv_a, priv, pub);
        CHECK(std::memcmp(priv, priv_a, 24) == 0, "a private key in range is used as it is");
        CHECK(std::memcmp(pub, want_pub, 48) == 0, "P-192 public key must match the specification's sample data");
        CHECK(btc_p192_compute_dhkey(priv_b, want_pub, dh), "DHKey of the sample data");
        CHECK(std::memcmp(dh, want_dh, 24) == 0, "P-192 DHKey must match the specification's sample data");
    }
    return 0;
}

/* =========================================================================
 * 3 & 4. LMP SSP, Saved Link Key, Stale Key Fallback & Legacy PIN Harness
 * ========================================================================= */
struct LmpPkt {
    bool                 from_master;
    std::vector<uint8_t> bytes;
};

struct LmpTestHarness {
    btc_lmp_t            master = {};
    btc_lmp_t            slave  = {};
    std::deque<LmpPkt>   wire;
    uint32_t             prng = 0xC0FFEE12u;
    char                 learned_name[64] = {};
    bool                 master_done = false;
    bool                 master_ok   = false;
    uint8_t              master_err  = 0;
    uint8_t              master_slots = 1;         /* what the peer allows, as the controller would be told */
    uint8_t              master_slots_why = 0xFF;
    uint8_t              master_slots_at_done = 0; /* the same at the moment the setup was reported done */
    bool                 lk_saved    = false;
    uint8_t              saved_lk[16] = {};
    std::vector<uint8_t> master_tx_log_ops;

    uint8_t next_byte()
    {
        prng ^= prng << 13;
        prng ^= prng >> 17;
        prng ^= prng << 5;
        return (uint8_t)(prng & 0xFFu);
    }
};

static void harness_send_master(void *ctx, const uint8_t *pdu, uint8_t len)
{
    auto *h = static_cast<LmpTestHarness *>(ctx);
    h->master_tx_log_ops.push_back((uint8_t)(pdu[0] >> 1));
    h->wire.push_back({true, std::vector<uint8_t>(pdu, pdu + len)});
}

static void harness_send_slave(void *ctx, const uint8_t *pdu, uint8_t len)
{
    auto *h = static_cast<LmpTestHarness *>(ctx);
    h->wire.push_back({false, std::vector<uint8_t>(pdu, pdu + len)});
}

static void harness_start_enc_master(void *ctx, const uint8_t en_rand[16], const uint8_t kc_prime[16])
{
    auto *h = static_cast<LmpTestHarness *>(ctx);
    (void)kc_prime;
    /* Mimic br_engine BR_VS_START_ENC: send LMP_start_encryption_req(17) to Slave */
    uint8_t p[17];
    p[0] = (uint8_t)((17u << 1) | 0u);
    std::memcpy(&p[1], en_rand, 16u);
    h->wire.push_back({true, std::vector<uint8_t>(p, p + 17)});
}

static void harness_rand(void *ctx, uint8_t *out, size_t len)
{
    auto *h = static_cast<LmpTestHarness *>(ctx);
    for (size_t i = 0; i < len; i++) out[i] = h->next_byte();
}

static void harness_on_name(void *ctx, const char *nm)
{
    auto *h = static_cast<LmpTestHarness *>(ctx);
    std::snprintf(h->learned_name, sizeof(h->learned_name), "%s", nm);
}

static void harness_on_lk(void *ctx, const uint8_t bd[6], const uint8_t lk[16])
{
    (void)bd;
    auto *h = static_cast<LmpTestHarness *>(ctx);
    h->lk_saved = true;
    std::memcpy(h->saved_lk, lk, 16u);
}

static void harness_on_done(void *ctx, bool ok, uint8_t err)
{
    auto *h = static_cast<LmpTestHarness *>(ctx);
    h->master_done = true;
    h->master_ok   = ok;
    h->master_err  = err;
    h->master_slots_at_done = h->master_slots;
}

static void harness_on_slots(void *ctx, uint8_t slots, uint8_t why, uint8_t err)
{
    (void)err;
    auto *h = static_cast<LmpTestHarness *>(ctx);
    h->master_slots     = slots;
    h->master_slots_why = why;
}

static void pump_lmp_wire(LmpTestHarness &h)
{
    int guard = 0;
    while (!h.wire.empty() && guard++ < 256) {
        LmpPkt pkt = std::move(h.wire.front());
        h.wire.pop_front();
        if (pkt.from_master) {
            btc_lmp_on_pdu(&h.slave, pkt.bytes.data(), (uint8_t)pkt.bytes.size());
        } else {
            /* Mimic br_engine intercepting Slave's LMP_accepted(17) to notify encryption state */
            if (pkt.bytes.size() >= 2 && (pkt.bytes[0] >> 1) == 3u && pkt.bytes[1] == 17u) {
                btc_lmp_on_encryption_state(&h.master, 0x00u, true);
            }
            btc_lmp_on_pdu(&h.master, pkt.bytes.data(), (uint8_t)pkt.bytes.size());
        }
    }
}

static int test_lmp_ssp_and_legacy(void)
{
    const uint8_t master_bd[6] = {0x36, 0x10, 0xAA, 0xBB, 0xCC, 0xDD};
    const uint8_t slave_bd[6]  = {0x99, 0x88, 0x77, 0x66, 0x55, 0x44};
    const char *spk_name       = "Marshall Stockwell II Vintage BT";

    LmpTestHarness h;
    btc_lmp_ops_t m_ops = { &h, harness_send_master, harness_start_enc_master, harness_rand,
                            harness_on_name, harness_on_lk, harness_on_done, harness_on_slots };
    btc_lmp_ops_t s_ops = { &h, harness_send_slave, nullptr, harness_rand,
                            nullptr, nullptr, nullptr, nullptr };

    btc_lmp_init(&h.master, &m_ops, master_bd, "Tab5 Classic", "0000");
    btc_lmp_init(&h.slave, &s_ops, slave_bd, spk_name, "0000");
    h.slave.is_slave_sim = true;

    /* A. Full SSP P-192 ECDH "Just Works" Pairing + E1 + E3 */
    btc_lmp_start(&h.slave, master_bd, BTC_LMP_GOAL_CONNECT);
    btc_lmp_start(&h.master, slave_bd, BTC_LMP_GOAL_CONNECT);

    /* Also inject a speaker Role-Switch attempt (LMP_switch_req = 19) mid-handshake to verify 0x21 rejection! */
    uint8_t sw_req[5] = { (uint8_t)((19u << 1) | 1u), 0x10, 0x00, 0x00, 0x00 };
    h.wire.push_back({false, std::vector<uint8_t>(sw_req, sw_req + 5)});

    pump_lmp_wire(h);

    CHECK(h.master_done && h.master_ok, "SSP P-192 Just Works setup completed");
    /* Core Spec Vol 2 Part C 4.1.10: one slot after a new connection; LMP_max_slot_req only once the setup is
     * complete; three slots only when the peer has accepted (third sound trial, 2026-11-11: the request went out
     * with the first PDUs and the controller used 3-slot packets whatever the answer). */
    CHECK(h.master_slots_at_done == 1u, "1-slot packets only while the connection is being set up");
    CHECK(h.master_slots == 3u && h.master_slots_why == 1u, "3-slot packets once the peer accepted LMP_max_slot_req");
    CHECK(h.lk_saved && h.slave.has_link_key, "Both sides derived SSP Link Key");
    CHECK(std::memcmp(h.master.link_key, h.slave.link_key, 16) == 0, "Master & Slave SSP Link Keys match");
    CHECK(h.master.encrypted && h.slave.encrypted, "Both sides enabled E0 encryption");
    CHECK(std::memcmp(h.master.last_kc_prime, h.slave.last_kc_prime, 16) == 0, "Master & Slave E3 Kc' match");
    CHECK(std::strcmp(h.learned_name, spk_name) == 0, "Multi-chunk 32-byte LMP_name_res reassembled");

    /* B. Fast Reconnect with Saved Link Key */
    h.master_done = false;
    h.master_ok   = false;
    h.lk_saved    = false;
    btc_lmp_start(&h.slave, master_bd, BTC_LMP_GOAL_CONNECT);
    btc_lmp_start(&h.master, slave_bd, BTC_LMP_GOAL_CONNECT);
    pump_lmp_wire(h);

    CHECK(h.master_done && h.master_ok && !h.lk_saved, "Saved Link Key fast reconnect succeeded without re-pairing");
    CHECK(std::memcmp(h.master.last_kc_prime, h.slave.last_kc_prime, 16) == 0, "Fast reconnect Kc' matches");

    /* C. Speaker Factory Reset (Slave lost key -> 0x06 PIN or Key Missing -> automatic SSP re-pair!) */
    btc_lmp_clear_link_key(&h.slave);
    h.master_done = false;
    h.master_ok   = false;
    btc_lmp_start(&h.slave, master_bd, BTC_LMP_GOAL_CONNECT);
    btc_lmp_start(&h.master, slave_bd, BTC_LMP_GOAL_CONNECT);
    pump_lmp_wire(h);
    CHECK(h.master_done && h.master_ok && h.lk_saved, "Stale bond (0x06) automatically recovered via fresh SSP");

    /* D. Legacy PIN "0000" Pairing (simulate BT 2.0 speaker without SSP) */
    btc_lmp_clear_link_key(&h.master);
    btc_lmp_clear_link_key(&h.slave);
    h.master_done = false;
    h.master_ok   = false;
    h.lk_saved    = false;
    btc_lmp_start(&h.slave, master_bd, BTC_LMP_GOAL_CONNECT);
    btc_lmp_start(&h.master, slave_bd, BTC_LMP_GOAL_CONNECT);
    /* Intercept Slave's LMP_features_res in wire to clear SSP & Extended Features bits (BT 2.0 speaker) */
    while (!h.wire.empty()) {
        LmpPkt pkt = std::move(h.wire.front());
        h.wire.pop_front();
        if (!pkt.from_master && (pkt.bytes[0] >> 1) == 40u && pkt.bytes.size() >= 9u) {
            pkt.bytes[7] = 0x00u; /* SSP Controller = 0 */
            pkt.bytes[8] = 0x00u; /* Extended features = 0 */
        }
        if (pkt.from_master) {
            btc_lmp_on_pdu(&h.slave, pkt.bytes.data(), (uint8_t)pkt.bytes.size());
        } else {
            if (pkt.bytes.size() >= 2 && (pkt.bytes[0] >> 1) == 3u && pkt.bytes[1] == 17u) {
                btc_lmp_on_encryption_state(&h.master, 0x00u, true);
            }
            btc_lmp_on_pdu(&h.master, pkt.bytes.data(), (uint8_t)pkt.bytes.size());
        }
    }
    CHECK(h.master_done && h.master_ok && h.lk_saved, "Legacy PIN '0000' pairing succeeded");
    CHECK(std::memcmp(h.master.link_key, h.slave.link_key, 16) == 0, "Legacy Combination Key matches");
    CHECK(std::memcmp(h.master.last_kc_prime, h.slave.last_kc_prime, 16) == 0, "Legacy E3 Kc' matches");
    return 0;
}

/* The speaker of the sound trials wants multi-slot packets, and the C6 takes 1-slot packets only.
 *  - Sound trial 8, 2026-11-11: every LMP_max_slot_req was answered at once with LMP_not_accepted and an
 *    LMP_max_slot 1, the speaker asked again at once, and the exchange ran about 50 times a second for the whole
 *    connection: 113 LMP PDUs a second going out, half of the link.
 *  - Sound trial 10: the request was refused with LMP_not_accepted alone ("Device requests a maximum number of
 *    slots. Remote Device rejects", Core Spec Vol 2 Part C 4.1.10, sequence 20). The loop was gone, and once the
 *    speaker had accepted our own LMP_max_slot_req its packets came in with a bad CRC, 50 a second, until the
 *    setup timed out: it had gone over to packets the C6 cannot take.
 * What worked in trial 8 is kept, at a pace that costs nothing: the speaker's request is answered on the next tick
 * with LMP_not_accepted and LMP_max_slot 1, and the answer to our own request is followed by LMP_max_slot 1 at
 * once, so that the last word the speaker has from us on its packets is always one slot. */
/* The LMP module keeps the last PDUs of the link, both ways: with a device nobody has tried the setup can stop
 * with silence on both sides (Sony WH-1000XM3, 2026-11-15) and the counters do not say at which PDU. */
static int test_lmp_keeps_a_trace_of_the_link(void)
{
    const uint8_t master_bd[6] = {0x36, 0x10, 0xAA, 0xBB, 0xCC, 0xDD};
    const uint8_t slave_bd[6]  = {0x99, 0x88, 0x77, 0x66, 0x55, 0x44};

    LmpTestHarness h;
    btc_lmp_ops_t m_ops = { &h, harness_send_master, harness_start_enc_master, harness_rand,
                            harness_on_name, harness_on_lk, harness_on_done, harness_on_slots };
    btc_lmp_ops_t s_ops = { &h, harness_send_slave, nullptr, harness_rand, nullptr, nullptr, nullptr, nullptr };
    btc_lmp_init(&h.master, &m_ops, master_bd, "Tab5 Classic", "0000");
    btc_lmp_init(&h.slave, &s_ops, slave_bd, "Speaker", "0000");
    h.slave.is_slave_sim = true;
    btc_lmp_start(&h.slave, master_bd, BTC_LMP_GOAL_CONNECT);
    btc_lmp_start(&h.master, slave_bd, BTC_LMP_GOAL_CONNECT);
    /* A role switch request of the peer (LMP_switch_req = 19, TID 1): received, then refused with not_accepted. */
    uint8_t sw_req[5] = { (uint8_t)((19u << 1) | 1u), 0x10, 0x00, 0x00, 0x00 };
    h.wire.push_back({false, std::vector<uint8_t>(sw_req, sw_req + 5)});
    pump_lmp_wire(h);
    CHECK(h.master_done && h.master_ok, "the setup of the traced link completed");

    btc_lmp_rec_t rec[BTC_LMP_TRACE];
    const uint8_t n = btc_lmp_trace_read(&h.master, rec, BTC_LMP_TRACE);
    CHECK(n > 10u && n <= BTC_LMP_TRACE, "the trace holds the PDUs of the setup");
    CHECK(rec[0].dir == 0u && rec[0].len >= 1u, "the first record is the first PDU the master sent");
    int got_switch = -1, refused_switch = -1;
    for (int i = 0; i < n; i++) {
        if (rec[i].dir == 1u && rec[i].d[0] == sw_req[0] && rec[i].len == 5u && rec[i].d[1] == 0x10u) got_switch = i;
        if (rec[i].dir == 0u && (rec[i].d[0] >> 1) == 4u && rec[i].d[1] == 19u) refused_switch = i;
    }
    CHECK(got_switch >= 0, "a received PDU is in the trace with its opcode, TID, length and first parameter");
    CHECK(refused_switch > got_switch, "the answer sent to it follows it in the trace");
    CHECK(btc_lmp_trace_read(&h.master, rec, 3u) == 3u && rec[2].dir <= 1u, "a short read gives the oldest records");

    /* The tick counter tells a stall from a quick exchange: two ticks, then one more PDU. */
    btc_lmp_on_tick(&h.master);
    btc_lmp_on_tick(&h.master);
    uint8_t auto_rate[2] = { (uint8_t)(35u << 1), 0xEEu };
    btc_lmp_on_pdu(&h.master, auto_rate, 2u);
    const uint8_t n2 = btc_lmp_trace_read(&h.master, rec, BTC_LMP_TRACE);
    CHECK(n2 == n + 1u && rec[n2 - 1u].tick == rec[n - 1u].tick + 2u && rec[n2 - 1u].d[1] == 0xEEu,
          "a record carries the tick count of its moment");

    /* More PDUs than the trace holds: the oldest go. */
    for (unsigned i = 0; i < BTC_LMP_TRACE + 6u; i++) {
        auto_rate[1] = (uint8_t)i;
        btc_lmp_on_pdu(&h.master, auto_rate, 2u);
    }
    CHECK(btc_lmp_trace_read(&h.master, rec, BTC_LMP_TRACE) == BTC_LMP_TRACE, "the trace is full, not longer");
    CHECK(rec[0].d[1] == 6u && rec[BTC_LMP_TRACE - 1u].d[1] == BTC_LMP_TRACE + 5u, "the oldest records were dropped");

    /* A new link starts with an empty trace. */
    h.wire.clear();
    btc_lmp_start(&h.master, slave_bd, BTC_LMP_GOAL_NAME_ONLY);
    const uint8_t n3 = btc_lmp_trace_read(&h.master, rec, BTC_LMP_TRACE);
    CHECK(n3 >= 1u && n3 < 8u && rec[0].dir == 0u && rec[0].tick == 0u, "a new link starts the trace again");
    return 0;
}

/* Sony WH-1000XM3, 2026-11-15 (LMP trace of the failed connection): the headphones accept the connection, then
 * answer the first LMP_io_capability_req with LMP_not_accepted_ext, error 0x24 "LMP PDU not allowed" - it reaches
 * them before they have asked for our features, which they do right after LMP_setup_complete. The module then
 * waited for ever and the host gave up after 12 s. */
static void feed_xm3_until_pairing_starts(LmpTestHarness &h)
{
    const uint8_t version_res[]  = { (uint8_t)(38u << 1), 0x07, 0x0A, 0x00, 0x07, 0x00 };
    const uint8_t features_res[] = { (uint8_t)(40u << 1), 0xFF, 0xFF, 0x8F, 0xFE, 0x9B, 0xFF, 0x59, 0x83 };
    const uint8_t ext_res[]      = { (uint8_t)(127u << 1), 4, 1, 2, 0x03, 0, 0, 0, 0, 0, 0, 0 };
    const uint8_t accepted[]     = { (uint8_t)(3u << 1), 51 };
    const uint8_t setup_done[]   = { (uint8_t)((49u << 1) | 1u) };
    btc_lmp_on_pdu(&h.master, version_res, sizeof(version_res));
    btc_lmp_on_pdu(&h.master, features_res, sizeof(features_res));
    btc_lmp_on_pdu(&h.master, ext_res, sizeof(ext_res));
    btc_lmp_on_pdu(&h.master, accepted, sizeof(accepted));
    btc_lmp_on_pdu(&h.master, setup_done, sizeof(setup_done));
}

static int count_io_capability_reqs(const LmpTestHarness &h)
{
    int n = 0;
    for (const auto &p : h.wire) {
        if (p.from_master && p.bytes.size() == 5u && (p.bytes[0] >> 1) == 127u && p.bytes[1] == 25u) n++;
    }
    return n;
}

static int test_lmp_pairing_request_refused_at_first_is_sent_again(void)
{
    const uint8_t master_bd[6] = {0x36, 0x10, 0xAA, 0xBB, 0xCC, 0xDD};
    const uint8_t peer_bd[6]   = {0x99, 0x88, 0x77, 0x66, 0x55, 0x44};
    const uint8_t not_allowed[]     = { (uint8_t)(127u << 1), 2, 127, 25, 0x24 };
    const uint8_t pairing_refused[] = { (uint8_t)(127u << 1), 2, 127, 25, 0x18 };

    LmpTestHarness h;
    btc_lmp_ops_t m_ops = { &h, harness_send_master, harness_start_enc_master, harness_rand,
                            harness_on_name, harness_on_lk, harness_on_done, harness_on_slots };
    btc_lmp_init(&h.master, &m_ops, master_bd, "Tab5 Classic", "0000");
    btc_lmp_start(&h.master, peer_bd, BTC_LMP_GOAL_CONNECT);
    feed_xm3_until_pairing_starts(h);
    CHECK(count_io_capability_reqs(h) == 1, "pairing starts with LMP_io_capability_req");

    btc_lmp_on_pdu(&h.master, not_allowed, sizeof(not_allowed));
    CHECK(!h.master_done, "'LMP PDU not allowed' is not the end of the setup");
    btc_lmp_on_tick(&h.master);
    CHECK(count_io_capability_reqs(h) == 1, "the request is not repeated at once");
    btc_lmp_on_tick(&h.master);
    CHECK(count_io_capability_reqs(h) == 2, "it is sent again about a second later");

    /* A peer that keeps refusing: three more tries, then the setup fails with the peer's reason. */
    for (int i = 0; i < 3; i++) {
        btc_lmp_on_pdu(&h.master, not_allowed, sizeof(not_allowed));
        btc_lmp_on_tick(&h.master);
        btc_lmp_on_tick(&h.master);
    }
    CHECK(count_io_capability_reqs(h) == 4 && h.master_done && !h.master_ok && h.master_err == 0x24u,
          "after three repeats the setup fails with the peer's reason");

    /* Any other refusal ends the setup at once: 0x18, the peer does not allow pairing (not in pairing mode). */
    LmpTestHarness h2;
    btc_lmp_ops_t m2_ops = { &h2, harness_send_master, harness_start_enc_master, harness_rand,
                             harness_on_name, harness_on_lk, harness_on_done, harness_on_slots };
    btc_lmp_init(&h2.master, &m2_ops, master_bd, "Tab5 Classic", "0000");
    btc_lmp_start(&h2.master, peer_bd, BTC_LMP_GOAL_CONNECT);
    feed_xm3_until_pairing_starts(h2);
    btc_lmp_on_pdu(&h2.master, pairing_refused, sizeof(pairing_refused));
    CHECK(h2.master_done && !h2.master_ok && h2.master_err == 0x18u, "'pairing not allowed' fails the setup at once");
    btc_lmp_on_tick(&h2.master);
    btc_lmp_on_tick(&h2.master);
    CHECK(count_io_capability_reqs(h2) == 1, "and nothing is sent again");
    return 0;
}

static int test_lmp_peer_stays_on_one_slot_without_a_loop(void)
{
    const uint8_t master_bd[6] = {0x36, 0x10, 0xAA, 0xBB, 0xCC, 0xDD};
    LmpTestHarness h;
    btc_lmp_ops_t m_ops = { &h, harness_send_master, harness_start_enc_master, harness_rand,
                            harness_on_name, harness_on_lk, harness_on_done, harness_on_slots };
    btc_lmp_init(&h.master, &m_ops, master_bd, "Tab5 Classic", "0000");

    const uint8_t tid_peer = 1u; /* the Peripheral started the transaction */
    const uint8_t max_slot_req[2] = { (uint8_t)((46u << 1) | tid_peer), 5u };
    btc_lmp_on_pdu(&h.master, max_slot_req, sizeof(max_slot_req));
    btc_lmp_on_pdu(&h.master, max_slot_req, sizeof(max_slot_req));
    CHECK(h.wire.empty(), "LMP_max_slot_req is not answered at once: that is what ran in a loop");
    btc_lmp_on_tick(&h.master);
    CHECK(h.wire.size() == 2u, "the tick answers the request once, with two PDUs");
    CHECK(h.wire[0].bytes.size() == 3u && h.wire[0].bytes[0] == (uint8_t)((4u << 1) | tid_peer) &&
          h.wire[0].bytes[1] == 46u, "LMP_max_slot_req for 5 slots is refused with LMP_not_accepted");
    CHECK(h.wire[1].bytes.size() == 2u && (h.wire[1].bytes[0] >> 1) == 45u && h.wire[1].bytes[1] == 1u,
          "and the speaker is told again that it has one slot");
    h.wire.clear();
    btc_lmp_on_tick(&h.master);
    CHECK(h.wire.empty(), "a tick with no request waiting sends nothing");

    const uint8_t accepted_ours[2] = { (uint8_t)((3u << 1) | 0u), 46u };
    btc_lmp_on_pdu(&h.master, accepted_ours, sizeof(accepted_ours));
    CHECK(h.master_slots == 3u, "our packets may take 3 slots once the speaker accepted LMP_max_slot_req");
    CHECK(h.wire.size() == 1u && (h.wire[0].bytes[0] >> 1) == 45u && h.wire[0].bytes[1] == 1u,
          "the speaker's own packets stay at one slot: LMP_max_slot 1 follows its LMP_accepted");
    h.wire.clear();

    const uint8_t incr_power[2] = { (uint8_t)((31u << 1) | tid_peer), 0u };
    btc_lmp_on_pdu(&h.master, incr_power, sizeof(incr_power));
    CHECK(h.wire.size() == 1u && (h.wire[0].bytes[0] >> 1) == 33u, "LMP_incr_power_req is answered with LMP_max_power");
    h.wire.clear();

    const uint8_t decr_power[2] = { (uint8_t)((32u << 1) | tid_peer), 0u };
    btc_lmp_on_pdu(&h.master, decr_power, sizeof(decr_power));
    CHECK(h.wire.size() == 1u && (h.wire[0].bytes[0] >> 1) == 34u, "LMP_decr_power_req is answered with LMP_min_power");
    h.wire.clear();

    const uint8_t auto_rate[1]      = { (uint8_t)((35u << 1) | tid_peer) };
    const uint8_t preferred_rate[2] = { (uint8_t)((36u << 1) | tid_peer), 0x01u };
    btc_lmp_on_pdu(&h.master, auto_rate, sizeof(auto_rate));
    btc_lmp_on_pdu(&h.master, preferred_rate, sizeof(preferred_rate));
    CHECK(h.wire.empty(), "LMP_auto_rate and LMP_preferred_rate ask for nothing and get no answer");
    return 0;
}

/* Sound trial 11, 2026-11-11: the stream lost 1.3 packets a second although the link carried 113 to 115 of the
 * 115 packets a second: it stops for 60 to 120 ms several times a second, and a packet that found the controller
 * full was thrown away. The packets wait in a queue instead; when that is full too, the oldest one goes. */
static int test_media_queue_bridges_a_gap(void)
{
    static btc_media_queue_t q;
    btc_media_queue_reset(&q);
    CHECK(btc_media_queue_front(&q) == nullptr, "an empty queue has no front");

    uint8_t pkt[BTC_MEDIA_PKT_MAX + 1u];
    /* A gap of 120 ms: fourteen packets of 8.7 ms arrive while nothing leaves. */
    for (uint8_t i = 0; i < 14u; i++) {
        std::memset(pkt, i, sizeof(pkt));
        CHECK(btc_media_queue_push(&q, pkt, 147u, 3u), "a packet of three 49-byte frames is taken");
    }
    CHECK(q.count == 14u && q.dropped == 0u && q.high_water == 14u, "nothing is lost in a 120 ms gap");
    for (uint8_t i = 0; i < 14u; i++) {
        const btc_media_pkt_t *p = btc_media_queue_front(&q);
        CHECK(p != nullptr && p->len == 147u && p->frames == 3u && p->data[0] == i && p->data[146] == i,
              "the packets leave in the order they came, unchanged");
        btc_media_queue_pop(&q);
    }
    CHECK(q.count == 0u && btc_media_queue_front(&q) == nullptr, "the queue is empty again");

    /* A gap longer than the queue: the oldest packets go, the newest stay. */
    for (uint16_t i = 0; i < BTC_MEDIA_QUEUE_DEPTH + 3u; i++) {
        std::memset(pkt, (int)(i & 0xFFu), sizeof(pkt));
        CHECK(btc_media_queue_push(&q, pkt, 147u, 3u), "a packet is taken even when the queue is full");
    }
    CHECK(q.count == BTC_MEDIA_QUEUE_DEPTH && q.dropped == 3u, "three packets too many: three lost");
    CHECK(btc_media_queue_front(&q)->data[0] == 3u, "the three oldest were the ones lost");

    CHECK(!btc_media_queue_push(&q, pkt, 0u, 3u), "an empty packet is not taken");
    CHECK(!btc_media_queue_push(&q, pkt, BTC_MEDIA_PKT_MAX + 1u, 3u), "a packet that is too long is not taken");
    CHECK(q.count == BTC_MEDIA_QUEUE_DEPTH && q.dropped == 3u, "and neither of them costs a waiting packet");
    return 0;
}

/* Sound trial 12, 2026-11-11: smooth at bitpool 18, and the owner hears what bitpool 18 sounds like. How much
 * more the link carries depends on the speaker and is found while playing (btc_rate.h). */
static uint16_t joint_stereo_frame_bytes(void *ctx, uint8_t bitpool)
{
    sbc_params_t p = *static_cast<const sbc_params_t *>(ctx);
    p.bitpool = bitpool;
    return sbc_frame_length(&p);
}

static int test_rate_follows_the_link(void)
{
    sbc_params_t sbc = { SBC_FREQ_44100, 16u, SBC_MODE_JOINT_STEREO, SBC_ALLOC_LOUDNESS, 8u, 18u };
    uint8_t k = 0, m = 0;

    /* Packing: the frames per media packet that need the fewest 3-slot packets of 168 bytes per frame. */
    CHECK(btc_rate_packing(49u, 168u, 668u, &k, &m) && k == 3u && m == 1u, "bitpool 18: three frames in one packet");
    CHECK(btc_rate_packing(63u, 168u, 668u, &k, &m) && k == 5u && m == 2u, "bitpool 25: five frames in two packets");
    CHECK(btc_rate_packing(69u, 168u, 668u, &k, &m) && k == 7u && m == 3u, "bitpool 28: seven frames in three");
    CHECK(btc_rate_packing(83u, 168u, 668u, &k, &m) && k == 5u && m == 3u, "bitpool 35: five frames in three");
    CHECK(btc_rate_packing(63u, 168u, 200u, &k, &m) && k == 2u && m == 1u, "a small MTU keeps to one packet");
    CHECK(!btc_rate_packing(600u, 168u, 668u, &k, &m), "a frame that fits no three packets is refused");

    btc_rate_t r;
    btc_rate_init(&r, 18u, 18u, 53u, 168u, 668u, joint_stereo_frame_bytes, &sbc);
    /* Six frames of 53 bytes fill two packets as three of 49 fill one: bitpool 20 costs what 18 costs. */
    CHECK(r.bitpool == 20u, "the start is the highest bitpool that costs no more than the one asked for");
    CHECK(btc_rate_load(&r, 18u) == btc_rate_load(&r, 20u) && btc_rate_load(&r, 21u) > btc_rate_load(&r, 20u),
          "bitpool 21 is the first that costs more");

    /* A link with room: 60 % busy. The next step costs 375 against 333 3-slot packets per 1000 frames, which
     * would make it 67 % busy: up, after three windows in a row. */
    CHECK(btc_rate_end_window(&r, 60u, 0u) == 20u && btc_rate_end_window(&r, 60u, 0u) == 20u, "not at once");
    CHECK(btc_rate_end_window(&r, 60u, 0u) == 23u, "up to the top of the next step after three good windows");
    /* 82 % busy now, and the step after (400 against 375) would be 87 %: no further. */
    for (int i = 0; i < 6; i++) {
        CHECK(btc_rate_end_window(&r, 82u, 0u) == 23u, "no step up that would leave too little room");
    }
    /* The link gets worse (the speaker starts to scan more, say): 97 % busy. Down at once, and no way back up
     * for ten windows however good they look. */
    CHECK(btc_rate_end_window(&r, 97u, 0u) == 20u, "down a step when the link is full");
    for (int i = 0; i < 10; i++) {
        CHECK(btc_rate_end_window(&r, 40u, 0u) == 20u, "held after a step down");
    }
    CHECK(btc_rate_end_window(&r, 40u, 0u) == 20u && btc_rate_end_window(&r, 40u, 0u) == 20u &&
          btc_rate_end_window(&r, 40u, 0u) == 23u, "and up again after the hold and three good windows");
    /* A lost packet takes it down whatever the load was. */
    CHECK(btc_rate_end_window(&r, 50u, 1u) == 20u, "down a step when a packet was lost");
    CHECK(btc_rate_end_window(&r, 99u, 0u) == 20u, "never below the lowest bitpool");

    /* A link with plenty of room climbs to the top and stays there. */
    btc_rate_init(&r, 18u, 18u, 35u, 168u, 668u, joint_stereo_frame_bytes, &sbc);
    uint8_t bp = r.bitpool;
    for (int i = 0; i < 60; i++) {
        const uint8_t next = btc_rate_end_window(&r, 10u, 0u);
        CHECK(next >= bp, "a quiet link never takes the bitpool down");
        bp = next;
    }
    CHECK(bp == 35u, "a quiet link reaches the highest bitpool the speaker allows");

    /* The limits can be set lower, to leave the radio time for something else (Wi-Fi shares it): the same loads
     * that let the bitpool climb above now hold it, and take it down. A new stream starts with the defaults. */
    btc_rate_init(&r, 18u, 18u, 53u, 168u, 668u, joint_stereo_frame_bytes, &sbc);
    btc_rate_set_limits(&r, 60u, 70u);
    for (int i = 0; i < 6; i++) {
        CHECK(btc_rate_end_window(&r, 55u, 0u) == 20u, "55 % busy would become 62 % a step up: over the limit of 60");
    }
    CHECK(btc_rate_end_window(&r, 50u, 0u) == 20u && btc_rate_end_window(&r, 50u, 0u) == 20u &&
          btc_rate_end_window(&r, 50u, 0u) == 23u, "50 % busy would become 56 %: a step up");
    CHECK(btc_rate_end_window(&r, 72u, 0u) == 20u, "72 % busy is over the limit of 70: a step down");
    btc_rate_init(&r, 18u, 18u, 53u, 168u, 668u, joint_stereo_frame_bytes, &sbc);
    CHECK(r.up_pct == BTC_RATE_UP_PCT && r.down_pct == BTC_RATE_DOWN_PCT, "a new stream starts with the defaults");
    btc_rate_set_limits(&r, 99u, 20u);
    CHECK(r.up_pct == 19u && r.down_pct == 20u, "the step-up limit stays under the step-down limit");
    btc_rate_set_limits(&r, 0u, 200u);
    CHECK(r.up_pct == 1u && r.down_pct == 100u, "limits out of range are brought into it");
    return 0;
}

/* =========================================================================
 * 5. L2CAP + SDP + AVDTP 1.3 + RTP SBC Media + AVRCP Test
 * ========================================================================= */
struct MockSink {
    btc_upper_t          src = {};
    std::deque<std::vector<uint8_t>> to_sink;
    std::deque<std::vector<uint8_t>> to_src;

    uint16_t sdp_src_cid   = 0;
    uint16_t sig_src_cid   = 0;
    uint16_t media_src_cid = 0;
    uint16_t avctp_src_cid = 0;

    bool     ready      = false;
    bool     streaming  = false;
    bool     avrcp_up   = false;
    int      media_pkts = 0;
    uint16_t last_media_len = 0;
    uint16_t last_media_seq = 0;  /* RTP sequence number and timestamp of the last media packet */
    uint32_t last_media_ts  = 0;
    bool     refuse_sends   = false; /* as a controller with no room: the stack's send hook returns false */
    int      refuse_audio   = 0;     /* so many requests for the AVDTP signalling channel get refuse_result */
    uint16_t refuse_result  = 0x0004u; /* Connection refused - no resources available */
    int      sig_conn_reqs  = 0;     /* requests for the AVDTP signalling channel seen */
    std::vector<uint8_t> last_avctp;  /* the last AVCTP frame the source sent */
    bt_classic_media_cmd_t last_cmd = BTC_MEDIA_CMD_NONE;
};

static bool mock_send_from_src(void *ctx, const uint8_t *sdu, uint16_t len)
{
    auto *m = static_cast<MockSink *>(ctx);
    if (m->refuse_sends) {
        return false;
    }
    m->to_sink.emplace_back(sdu, sdu + len);
    return true;
}

static void mock_send_to_src(MockSink *m, uint16_t dcid, const uint8_t *pay, uint16_t plen)
{
    std::vector<uint8_t> sdu(4u + plen);
    sdu[0] = (uint8_t)(plen & 0xFFu);
    sdu[1] = (uint8_t)((plen >> 8) & 0xFFu);
    sdu[2] = (uint8_t)(dcid & 0xFFu);
    sdu[3] = (uint8_t)((dcid >> 8) & 0xFFu);
    if (plen > 0u) std::memcpy(&sdu[4], pay, plen);
    m->to_src.push_back(std::move(sdu));
}

static void mock_sink_handle_pdu(MockSink *m, const uint8_t *sdu, uint16_t len)
{
    if (len < 4u) return;
    uint16_t plen = (uint16_t)(sdu[0] | (sdu[1] << 8));
    uint16_t cid  = (uint16_t)(sdu[2] | (sdu[3] << 8));
    const uint8_t *p = &sdu[4];

    if (cid == 0x0001u) {
        /* L2CAP Signaling */
        uint8_t code = p[0], id = p[1];
        if (code == 0x02u /* CONN_REQ */) {
            uint16_t psm  = (uint16_t)(p[4] | (p[5] << 8));
            uint16_t scid = (uint16_t)(p[6] | (p[7] << 8));
            uint16_t dcid = 0x0060u;
            if (psm == 0x0001u)      { dcid = 0x0061u; m->sdp_src_cid = scid; }
            else if (psm == 0x0019u) {
                if (m->sig_src_cid == 0) {
                    m->sig_conn_reqs++;
                    if (m->refuse_audio > 0) {
                        m->refuse_audio--;
                        uint8_t no[12] = { 0x03u, id, 8, 0, 0, 0, (uint8_t)scid, (uint8_t)(scid >> 8),
                                           (uint8_t)m->refuse_result, (uint8_t)(m->refuse_result >> 8), 0, 0 };
                        mock_send_to_src(m, 0x0001u, no, sizeof(no));
                        return;
                    }
                }
                if (m->sig_src_cid == 0) { dcid = 0x0062u; m->sig_src_cid = scid; }
                else                     { dcid = 0x0063u; m->media_src_cid = scid; }
            } else if (psm == 0x0017u) { dcid = 0x0064u; m->avctp_src_cid = scid; }

            uint8_t rsp[12] = { 0x03u, id, 8, 0,
                                (uint8_t)dcid, (uint8_t)(dcid >> 8),
                                (uint8_t)scid, (uint8_t)(scid >> 8),
                                0, 0, 0, 0 };
            mock_send_to_src(m, 0x0001u, rsp, sizeof(rsp));

            uint8_t creq[12] = { 0x04u, 0x21u, 8, 0,
                                 (uint8_t)scid, (uint8_t)(scid >> 8), 0, 0,
                                 0x01u, 0x02u, 0xA0u, 0x02u /* MTU 672 */ };
            mock_send_to_src(m, 0x0001u, creq, sizeof(creq));
        } else if (code == 0x04u /* CONF_REQ */) {
            uint16_t dcid = (uint16_t)(p[4] | (p[5] << 8));
            uint16_t scid = (dcid == 0x0061u) ? m->sdp_src_cid :
                            (dcid == 0x0062u) ? m->sig_src_cid :
                            (dcid == 0x0063u) ? m->media_src_cid : m->avctp_src_cid;
            uint8_t crsp[10] = { 0x05u, id, 6, 0,
                                 (uint8_t)scid, (uint8_t)(scid >> 8), 0, 0, 0, 0 };
            mock_send_to_src(m, 0x0001u, crsp, sizeof(crsp));
        } else if (code == 0x06u /* DISCONN_REQ */) {
            uint8_t drsp[8] = { 0x07u, id, 4, 0, p[4], p[5], p[6], p[7] };
            mock_send_to_src(m, 0x0001u, drsp, sizeof(drsp));
        }
        return;
    }

    if (cid == 0x0061u /* SDP */) {
        uint8_t rsp[9] = { 0x07u /* SearchAttrRsp */, p[1], p[2], 0x00, 0x04, 0x00, 0x01, 0x00, 0x00 };
        mock_send_to_src(m, m->sdp_src_cid, rsp, sizeof(rsp));
    } else if (cid == 0x0062u /* AVDTP Sig */) {
        uint8_t lbl = (uint8_t)(p[0] & 0xF0u);
        uint8_t sig = (uint8_t)(p[1] & 0x3Fu);
        if (sig == 0x01u /* DISCOVER */) {
            /* SEP #2: Audio Sink */
            uint8_t r[4] = { (uint8_t)(lbl | 0x02u), 0x01u, (uint8_t)(2u << 2), 0x08u /* Audio SNK */ };
            mock_send_to_src(m, m->sig_src_cid, r, sizeof(r));
        } else if (sig == 0x02u /* GET_CAPABILITIES */) {
            uint8_t r[12] = {
                (uint8_t)(lbl | 0x02u), 0x02u,
                0x01u, 0x00u, /* Media Transport */
                0x07u, 0x06u, 0x00u, 0x00u, 0x3Fu /* 44.1/48k, all modes */, 0x15u /* 16blk,8sb,Loud */, 2u, 53u
            };
            mock_send_to_src(m, m->sig_src_cid, r, sizeof(r));
        } else if (sig == 0x03u || sig == 0x06u || sig == 0x07u || sig == 0x09u) {
            uint8_t r[2] = { (uint8_t)(lbl | 0x02u), sig };
            mock_send_to_src(m, m->sig_src_cid, r, sizeof(r));
        }
    } else if (cid == 0x0064u /* AVCTP */) {
        m->last_avctp.assign(p, p + plen);
    } else if (cid == 0x0063u /* AVDTP Media */) {
        m->media_pkts++;
        m->last_media_len = plen;
        if (plen >= 12u) {
            m->last_media_seq = (uint16_t)((p[2] << 8) | p[3]);
            m->last_media_ts  = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 8) | p[7];
        }
    }
}

static void pump_upper(MockSink &m)
{
    int guard = 0;
    while ((!m.to_sink.empty() || !m.to_src.empty()) && guard++ < 256) {
        while (!m.to_sink.empty()) {
            auto pkt = std::move(m.to_sink.front());
            m.to_sink.pop_front();
            mock_sink_handle_pdu(&m, pkt.data(), (uint16_t)pkt.size());
        }
        while (!m.to_src.empty()) {
            auto pkt = std::move(m.to_src.front());
            m.to_src.pop_front();
            btc_upper_on_l2cap_pdu(&m.src, pkt.data(), (uint16_t)pkt.size());
        }
    }
}

static int test_l2cap_avdtp_avrcp(void)
{
    MockSink m;
    btc_upper_ops_t ops = {
        .ctx            = &m,
        .send_l2cap_pdu = mock_send_from_src,
        .on_avdtp_ready = [](void *c, const sbc_params_t *, uint16_t) { static_cast<MockSink *>(c)->ready = true; },
        .on_stream_state = [](void *c, bool s) { static_cast<MockSink *>(c)->streaming = s; },
        .on_avrcp_state = [](void *c, bool up) { static_cast<MockSink *>(c)->avrcp_up = up; },
        .on_media_cmd   = [](void *c, bt_classic_media_cmd_t cmd) { static_cast<MockSink *>(c)->last_cmd = cmd; },
        .on_peer_volume = nullptr,
    };

    btc_upper_init(&m.src, &ops, 35u, true);
    btc_upper_start_initiator(&m.src);
    pump_upper(m);

    CHECK(m.ready, "SDP -> AVDTP DISCOVER..OPEN -> Media L2CAP ready");
    CHECK(m.avrcp_up, "AVRCP AVCTP L2CAP channel opened");
    CHECK(m.src.negotiated_sbc.freq == SBC_FREQ_44100 && m.src.negotiated_sbc.bitpool == 35u,
          "Negotiated 44.1 kHz Joint-Stereo bitpool=35");

    {
        /* The configuration allows every bitpool the speaker takes, so that the stream can follow the link. */
        uint8_t bp_min = 0, bp_max = 0;
        btc_upper_bitpool_range(&m.src, &bp_min, &bp_max);
        CHECK(bp_min == 2u && bp_max == 53u, "the configured bitpool range is the speaker's, 2 to 53");
    }
    CHECK(btc_upper_request_start(&m.src), "AVDTP_START sent");
    pump_upper(m);
    CHECK(m.streaming && btc_upper_can_send_media(&m.src), "AVDTP streaming active");

    uint8_t dummy_sbc[83 * 3] = {};
    CHECK(btc_upper_send_media_packet(&m.src, dummy_sbc, sizeof(dummy_sbc), 3u, 128u), "Sent RTP+SBC media packet");
    pump_upper(m);
    CHECK(m.media_pkts == 1 && m.last_media_len == 12u + 1u + 83u * 3u, "Sink received exact 262-byte RTP+SBC PDU");

    /* A packet the controller has no room for waits and is offered again (btc_media_queue.h). The sequence number
     * and the timestamp belong to packets that went out: were they counted on every offer, the speaker would see
     * packets missing that it has in fact received. A packet that is given up is counted, so that the speaker
     * sees that one as missing. */
    const uint16_t seq1 = m.last_media_seq;
    const uint32_t ts1  = m.last_media_ts;
    m.refuse_sends = true;
    CHECK(!btc_upper_send_media_packet(&m.src, dummy_sbc, sizeof(dummy_sbc), 3u, 128u), "no room: the packet is not sent");
    CHECK(!btc_upper_send_media_packet(&m.src, dummy_sbc, sizeof(dummy_sbc), 3u, 128u), "nor on the second offer");
    m.refuse_sends = false;
    CHECK(btc_upper_send_media_packet(&m.src, dummy_sbc, sizeof(dummy_sbc), 3u, 128u), "room again: it goes out");
    pump_upper(m);
    CHECK(m.media_pkts == 2, "the packet that waited arrives");
    CHECK(m.last_media_seq == (uint16_t)(seq1 + 1u), "with the next sequence number, whatever the number of offers");
    CHECK(m.last_media_ts == ts1 + 3u * 128u, "and the timestamp of the samples that follow the first packet");
    btc_upper_skip_media_packet(&m.src, 3u, 128u);
    CHECK(btc_upper_send_media_packet(&m.src, dummy_sbc, sizeof(dummy_sbc), 3u, 128u), "the packet after a lost one");
    pump_upper(m);
    CHECK(m.last_media_seq == (uint16_t)(seq1 + 3u) && m.last_media_ts == ts1 + 3u * 3u * 128u,
          "a packet given up leaves its gap in the sequence numbers and the timestamps");

    /* Simulate speaker user pressing NEXT track button via AVRCP PASSTHROUGH (0x4B) */
    uint8_t pt_next[8] = { 0x10u /* label=1, cmd */, 0x11, 0x0E, 0x00u /* Control */, 0x48u, 0x7Cu, 0x4Bu, 0x00u };
    mock_send_to_src(&m, 0x0042u /* local AVCTP cid? find dynamically */, pt_next, sizeof(pt_next));
    for (size_t i = 0; i < BTC_L2CAP_MAX_CHANS; i++) {
        if (m.src.chans[i].state == BTC_CHAN_OPEN && m.src.chans[i].role == BTC_CHAN_ROLE_AVCTP) {
            m.to_src.clear();
            mock_send_to_src(&m, m.src.chans[i].local_cid, pt_next, sizeof(pt_next));
            break;
        }
    }
    pump_upper(m);
    CHECK(m.last_cmd == BTC_MEDIA_CMD_NEXT, "AVRCP PASSTHROUGH NEXT button decoded");

    /* The source lists EVENT_PLAYBACK_STATUS_CHANGED among its events (GetCapabilities), so a speaker that
     * registers for it gets INTERIM with the status, not a rejection it may answer by asking again. */
    uint8_t reg_status[18] = { 0x20u /* label=2, cmd */, 0x11, 0x0E, 0x03u /* Notify */, 0x48u, 0x00u,
                               0x00, 0x19, 0x58, 0x31u /* RegisterNotification */, 0x00u, 0x00, 0x05,
                               0x01u /* PLAYBACK_STATUS_CHANGED */, 0x00, 0x00, 0x00, 0x00 };
    m.last_avctp.clear();
    for (size_t i = 0; i < BTC_L2CAP_MAX_CHANS; i++) {
        if (m.src.chans[i].state == BTC_CHAN_OPEN && m.src.chans[i].role == BTC_CHAN_ROLE_AVCTP) {
            mock_send_to_src(&m, m.src.chans[i].local_cid, reg_status, sizeof(reg_status));
            break;
        }
    }
    pump_upper(m);
    CHECK(m.last_avctp.size() == 15u && m.last_avctp[0] == 0x22u /* label=2, response */ &&
          m.last_avctp[3] == 0x0Fu /* INTERIM */ && m.last_avctp[9] == 0x31u && m.last_avctp[13] == 0x01u &&
          m.last_avctp[14] == 0x01u /* playing */, "RegisterNotification for the playback status is answered INTERIM");

    /* The volume. A speaker that accepts SetAbsoluteVolume sets its own level and wants the samples at full
     * scale; one that rejects the command leaves the level to the source. Only its answer tells which. */
    uint16_t avctp_cid = 0;
    for (size_t i = 0; i < BTC_L2CAP_MAX_CHANS; i++) {
        if (m.src.chans[i].state == BTC_CHAN_OPEN && m.src.chans[i].role == BTC_CHAN_ROLE_AVCTP) {
            avctp_cid = m.src.chans[i].local_cid;
        }
    }
    CHECK(!btc_upper_peer_sets_volume(&m.src), "before the speaker has answered, the source scales the samples");
    m.last_avctp.clear();
    btc_upper_set_volume(&m.src, 128u);
    pump_upper(m);
    CHECK(m.last_avctp.size() == 14u && m.last_avctp[9] == 0x50u && m.last_avctp[13] == 64u,
          "SetAbsoluteVolume carries the level in 7 bits");
    const uint8_t label = (uint8_t)(m.last_avctp.empty() ? 0u : (m.last_avctp[0] & 0xF0u));
    uint8_t vol_rsp[14] = { (uint8_t)(label | 0x02u) /* response */, 0x11, 0x0E, 0x09u /* ACCEPTED */, 0x48u, 0x00u,
                            0x00, 0x19, 0x58, 0x50u /* SetAbsoluteVolume */, 0x00u, 0x00, 0x01, 64u };
    mock_send_to_src(&m, avctp_cid, vol_rsp, sizeof(vol_rsp));
    pump_upper(m);
    CHECK(btc_upper_peer_sets_volume(&m.src), "a speaker that accepted SetAbsoluteVolume sets the level itself");
    vol_rsp[3] = 0x0Au; /* REJECTED */
    mock_send_to_src(&m, avctp_cid, vol_rsp, sizeof(vol_rsp));
    pump_upper(m);
    CHECK(!btc_upper_peer_sets_volume(&m.src), "a speaker that rejected SetAbsoluteVolume leaves the level to us");
    vol_rsp[3] = 0x09u;
    mock_send_to_src(&m, avctp_cid, vol_rsp, sizeof(vol_rsp));
    pump_upper(m);
    btc_upper_reset(&m.src);
    CHECK(!btc_upper_peer_sets_volume(&m.src), "a new connection starts without that knowledge");
    return 0;
}

/* =========================================================================
 * 6. The remembered devices (btc_bonds.h)
 * ========================================================================= */
/* The L2CAP frames of a link are kept for a diagnosis: with a device whose setup stops after pairing the counters
 * do not say at which frame of SDP or AVDTP. */
static int test_upper_keeps_a_trace_of_the_l2cap_frames(void)
{
    MockSink m;
    btc_upper_ops_t ops = {
        .ctx            = &m,
        .send_l2cap_pdu = mock_send_from_src,
        .on_avdtp_ready = [](void *c, const sbc_params_t *, uint16_t) { static_cast<MockSink *>(c)->ready = true; },
        .on_stream_state = [](void *c, bool s) { static_cast<MockSink *>(c)->streaming = s; },
        .on_avrcp_state = nullptr,
        .on_media_cmd   = nullptr,
        .on_peer_volume = nullptr,
    };
    btc_upper_init(&m.src, &ops, 35u, true);
    btc_upper_rec_t rec[BTC_UPPER_TRACE];
    CHECK(btc_upper_trace_read(&m.src, rec, BTC_UPPER_TRACE) == 0u, "no frames yet: the trace is empty");

    btc_upper_start_initiator(&m.src);
    btc_upper_on_tick(&m.src);
    btc_upper_on_tick(&m.src);
    pump_upper(m);
    CHECK(m.ready, "the traced link reached the media channel");

    const uint8_t n = btc_upper_trace_read(&m.src, rec, BTC_UPPER_TRACE);
    CHECK(n > 12u && n <= BTC_UPPER_TRACE, "the trace holds the frames of the setup");
    /* L2CAP_ConnectionRequest on the signalling channel: code 0x02, identifier, length 4, PSM 0x0001 (SDP). */
    CHECK(rec[0].dir == 0u && rec[0].cid == 0x0001u && rec[0].len == 8u && rec[0].tick == 0u &&
              rec[0].d[0] == 0x02u && rec[0].d[4] == 0x01u && rec[0].d[5] == 0x00u,
          "the first record is the connection request for SDP, sent before any tick");
    CHECK(rec[1].dir == 1u && rec[1].cid == 0x0001u && rec[1].d[0] == 0x03u && rec[1].tick == 2u,
          "the peer's connection response follows, with the tick count of its moment");
    int sdp_req = -1, sdp_rsp = -1;
    for (int i = 0; i < n; i++) {
        if (rec[i].dir == 0u && rec[i].cid == 0x0061u && rec[i].d[0] == 0x06u) sdp_req = i;
        if (rec[i].dir == 1u && rec[i].cid >= 0x0040u && rec[i].d[0] == 0x07u && rec[i].len == 9u) sdp_rsp = i;
    }
    CHECK(sdp_req > 1 && sdp_rsp > sdp_req, "a data frame is there with its channel, length and first bytes");
    CHECK(btc_upper_trace_read(&m.src, rec, 2u) == 2u && rec[1].d[0] == 0x03u, "a short read gives the oldest records");

    /* A frame shorter than its header says is dropped; the trace shows that it came. */
    const uint8_t cut[6] = { 0x20, 0x00, 0x40, 0x00, 0x07, 0x00 };
    btc_upper_on_l2cap_pdu(&m.src, cut, sizeof(cut));
    const uint8_t n2 = btc_upper_trace_read(&m.src, rec, BTC_UPPER_TRACE);
    CHECK(n2 == n + 1u && rec[n2 - 1u].dir == 2u && rec[n2 - 1u].len == 0x20u && rec[n2 - 1u].d[0] == 0x07u,
          "a cut frame is marked as such");

    /* Media packets would push everything else out of the trace within a second. */
    CHECK(btc_upper_request_start(&m.src), "start requested");
    pump_upper(m);
    const uint8_t before_media = btc_upper_trace_read(&m.src, rec, BTC_UPPER_TRACE);
    uint8_t sbc[83 * 3] = {};
    CHECK(m.streaming && btc_upper_send_media_packet(&m.src, sbc, sizeof(sbc), 3u, 128u), "a media packet went out");
    CHECK(btc_upper_trace_read(&m.src, rec, BTC_UPPER_TRACE) == before_media, "media packets are not traced");

    /* The end of the link clears the layer's state, not the trace: it is read after the failure. */
    btc_upper_reset(&m.src);
    CHECK(btc_upper_trace_read(&m.src, rec, BTC_UPPER_TRACE) == before_media, "the trace outlives the link");
    btc_upper_trace_clear(&m.src);
    CHECK(btc_upper_trace_read(&m.src, rec, BTC_UPPER_TRACE) == 0u, "a new link starts with an empty trace");

    /* More frames than the trace holds: the oldest go. */
    for (unsigned i = 0; i < BTC_UPPER_TRACE + 5u; i++) {
        const uint8_t echo[9] = { 0x05, 0x00, 0x01, 0x00, 0x08 /* echo request */, (uint8_t)i, 0x01, 0x00, 0x5A };
        btc_upper_on_l2cap_pdu(&m.src, echo, sizeof(echo));
    }
    const uint8_t n3 = btc_upper_trace_read(&m.src, rec, BTC_UPPER_TRACE);
    CHECK(n3 == BTC_UPPER_TRACE && rec[n3 - 1u].dir == 0u && rec[n3 - 1u].d[0] == 0x09u &&
              rec[n3 - 1u].d[1] == (uint8_t)(BTC_UPPER_TRACE + 4u),
          "a full trace keeps the newest frames, the last one being the answer to the last request");
    return 0;
}

static btc_upper_ops_t plain_upper_ops(MockSink *m)
{
    btc_upper_ops_t ops = {
        .ctx            = m,
        .send_l2cap_pdu = mock_send_from_src,
        .on_avdtp_ready = [](void *c, const sbc_params_t *, uint16_t) { static_cast<MockSink *>(c)->ready = true; },
        .on_stream_state = [](void *c, bool s) { static_cast<MockSink *>(c)->streaming = s; },
        .on_avrcp_state = nullptr,
        .on_media_cmd   = nullptr,
        .on_peer_volume = nullptr,
    };
    return ops;
}

static void tick_upper(MockSink &m, int ticks)
{
    for (int i = 0; i < ticks; i++) {
        btc_upper_on_tick(&m.src);
        pump_upper(m);
    }
}

/* One frame from the peer, handled at once. */
static void feed_src(MockSink &m, uint16_t cid, const uint8_t *pay, uint16_t plen)
{
    mock_send_to_src(&m, cid, pay, plen);
    auto f = std::move(m.to_src.back());
    m.to_src.pop_back();
    btc_upper_on_l2cap_pdu(&m.src, f.data(), (uint16_t)f.size());
}

/* The peer opens an L2CAP channel to the source and both sides configure it. Returns the source's CID for it, or 0
 * when the source did not answer as it should. What the source sent after its configuration is left in to_sink. */
static uint16_t peer_opens_channel(MockSink &m, uint16_t psm, uint16_t their_cid, uint16_t their_mtu)
{
    m.to_sink.clear();
    const uint8_t conn_req[8] = { 0x02u, 0x31u, 4, 0, (uint8_t)psm, (uint8_t)(psm >> 8),
                                  (uint8_t)their_cid, (uint8_t)(their_cid >> 8) };
    feed_src(m, 0x0001u, conn_req, sizeof(conn_req));
    if (m.to_sink.size() != 2u) {
        return 0u;
    }
    const std::vector<uint8_t> rsp = m.to_sink[0], creq = m.to_sink[1];
    if (rsp[4] != 0x03u || rsp[10] != (uint8_t)their_cid || rsp[12] != 0u || rsp[13] != 0u || creq[4] != 0x04u ||
        creq[8] != (uint8_t)their_cid) {
        return 0u;
    }
    const uint16_t our_cid = (uint16_t)(rsp[8] | (rsp[9] << 8));
    m.to_sink.clear();
    const uint8_t their_cfg[12] = { 0x04u, 0x32u, 8, 0, (uint8_t)our_cid, (uint8_t)(our_cid >> 8), 0, 0,
                                    0x01u, 0x02u, (uint8_t)their_mtu, (uint8_t)(their_mtu >> 8) };
    const uint8_t our_cfg_ok[10] = { 0x05u, creq[5], 6, 0, (uint8_t)our_cid, (uint8_t)(our_cid >> 8), 0, 0, 0, 0 };
    feed_src(m, 0x0001u, their_cfg, sizeof(their_cfg));
    feed_src(m, 0x0001u, our_cfg_ok, sizeof(our_cfg_ok));
    return our_cid;
}

/* Sony WH-1000XM3, 2026-11-15: the request for the audio signalling channel came back "pending" and then "refused
 * - no resources", and the setup stood still until its time was up. The request goes out again a second later, a
 * few times, and what the peer said is kept for the message to the user. */
static int test_upper_refused_audio_channel_is_asked_for_again(void)
{
    {
        MockSink m;
        btc_upper_ops_t ops = plain_upper_ops(&m);
        m.refuse_audio = 2;
        btc_upper_init(&m.src, &ops, 35u, true);
        btc_upper_start_initiator(&m.src);
        pump_upper(m);
        CHECK(!m.ready && m.sig_conn_reqs == 1, "refused: nothing more goes out at once");
        CHECK(btc_upper_audio_refusal(&m.src) == 0x0004u, "the peer's result is kept");
        tick_upper(m, 1);
        CHECK(m.sig_conn_reqs == 1, "half a second later: still waiting");
        tick_upper(m, 1);
        CHECK(m.sig_conn_reqs == 2 && !m.ready, "a second later the request went out again, and was refused again");
        tick_upper(m, BTC_UPPER_AUDIO_RETRY_TICKS);
        CHECK(m.sig_conn_reqs == 3 && m.ready, "the third request is accepted and the setup reaches the media channel");
        CHECK(btc_upper_audio_refusal(&m.src) == 0u, "a refusal that was overcome is forgotten");
        tick_upper(m, 8);
        CHECK(m.sig_conn_reqs == 3, "no request after the channel is open");
    }
    {
        /* A sink that keeps refusing is not asked for ever. */
        MockSink m;
        btc_upper_ops_t ops = plain_upper_ops(&m);
        m.refuse_audio = 1000;
        btc_upper_init(&m.src, &ops, 35u, true);
        btc_upper_start_initiator(&m.src);
        pump_upper(m);
        tick_upper(m, 40);
        CHECK(m.sig_conn_reqs == 1 + (int)BTC_UPPER_AUDIO_RETRIES && !m.ready, "the number of requests is limited");
        CHECK(btc_upper_audio_refusal(&m.src) == 0x0004u, "and the refusal stays known");
    }
    {
        /* Other refusals do not pass with time: a security block is not asked again. */
        MockSink m;
        btc_upper_ops_t ops = plain_upper_ops(&m);
        m.refuse_audio  = 1000;
        m.refuse_result = 0x0003u;
        btc_upper_init(&m.src, &ops, 35u, true);
        btc_upper_start_initiator(&m.src);
        pump_upper(m);
        tick_upper(m, 10);
        CHECK(m.sig_conn_reqs == 1 && btc_upper_audio_refusal(&m.src) == 0x0003u, "a security refusal is final");
    }
    {
        /* The sink refuses and then opens the channel itself: that channel is used, and no request of ours goes
         * out next to it. */
        MockSink m;
        btc_upper_ops_t ops = plain_upper_ops(&m);
        m.refuse_audio = 1000;
        btc_upper_init(&m.src, &ops, 35u, true);
        btc_upper_start_initiator(&m.src);
        pump_upper(m);
        CHECK(m.sig_conn_reqs == 1 && m.to_sink.empty(), "refused, nothing in flight");

        CHECK(peer_opens_channel(m, 0x0019u, 0x0070u, 672u) != 0u, "the source accepts the channel the sink opens");
        bool discover = false;
        for (const auto &f : m.to_sink) {
            if (f.size() == 6u && f[2] == 0x70u && f[3] == 0x00u && (f[4] & 0x03u) == 0u && f[5] == 0x01u) discover = true;
        }
        CHECK(discover, "AVDTP discovery goes out on the channel the sink opened");
        CHECK(btc_upper_audio_refusal(&m.src) == 0u, "the refusal is forgotten with the channel open");
        m.to_sink.clear();
        for (int i = 0; i < 8; i++) {
            btc_upper_on_tick(&m.src);
        }
        CHECK(m.to_sink.empty(), "no connection request of ours follows");
    }
    return 0;
}

/* One SDP request of the peer on its channel; returns the source's answer, the SDP PDU without the L2CAP header
 * (empty when the answer is not exactly one frame on the peer's channel). */
static std::vector<uint8_t> sdp_ask(MockSink &m, uint16_t our_cid, uint16_t their_cid, uint8_t pdu,
                                    const std::vector<uint8_t> &params)
{
    std::vector<uint8_t> req = { pdu, 0x00u, 0x07u, (uint8_t)(params.size() >> 8), (uint8_t)params.size() };
    req.insert(req.end(), params.begin(), params.end());
    m.to_sink.clear();
    feed_src(m, our_cid, req.data(), (uint16_t)req.size());
    if (m.to_sink.size() != 1u) {
        return {};
    }
    const std::vector<uint8_t> &f = m.to_sink[0];
    if (f.size() < 9u || (uint16_t)(f[2] | (f[3] << 8)) != their_cid || f[5] != 0x00u || f[6] != 0x07u ||
        (size_t)((f[7] << 8) | f[8]) != f.size() - 9u) {
        return {};
    }
    return std::vector<uint8_t>(f.begin() + 4, f.end());
}

static std::vector<uint8_t> cat(std::initializer_list<std::vector<uint8_t>> parts)
{
    std::vector<uint8_t> out;
    for (const auto &part : parts) {
        out.insert(out.end(), part.begin(), part.end());
    }
    return out;
}

/* The source's SDP server, as Core Spec Vol 3 Part B asks: the attributes the request names, not more bytes than it
 * allows (nor than the channel's MTU), the rest on the continuation. Sony WH-1000XM3, 2026-11-15: its SDP channel
 * has an MTU of 48 and its request allows 32 bytes; the old answer of 68 bytes in one frame was dropped, and the
 * headphones never opened the audio channel. */
static int test_sdp_server_answers_within_the_limits_of_the_request(void)
{
    /* The two records, attribute by attribute (ID as a 16-bit unsigned integer, then the value). */
    const std::vector<uint8_t> a_handle   = { 0x09, 0x00, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01 };
    const std::vector<uint8_t> a_classes  = { 0x09, 0x00, 0x01, 0x35, 0x03, 0x19, 0x11, 0x0A };
    const std::vector<uint8_t> a_protocol = { 0x09, 0x00, 0x04, 0x35, 0x10, 0x35, 0x06, 0x19, 0x01, 0x00, 0x09, 0x00,
                                              0x19, 0x35, 0x06, 0x19, 0x00, 0x19, 0x09, 0x01, 0x03 };
    const std::vector<uint8_t> a_profile  = { 0x09, 0x00, 0x09, 0x35, 0x08, 0x35, 0x06, 0x19, 0x11, 0x0D, 0x09, 0x01,
                                              0x03 };
    const std::vector<uint8_t> a_features = { 0x09, 0x03, 0x11, 0x09, 0x00, 0x01 };
    const std::vector<uint8_t> a2dp_all =
        cat({ { 0x35, 56 }, a_handle, a_classes, a_protocol, a_profile, a_features }); /* 58 bytes */
    const std::vector<uint8_t> r_handle   = { 0x09, 0x00, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x02 };
    const std::vector<uint8_t> r_classes  = { 0x09, 0x00, 0x01, 0x35, 0x06, 0x19, 0x11, 0x0E, 0x19, 0x11, 0x0C };
    const std::vector<uint8_t> r_protocol = { 0x09, 0x00, 0x04, 0x35, 0x10, 0x35, 0x06, 0x19, 0x01, 0x00, 0x09, 0x00,
                                              0x17, 0x35, 0x06, 0x19, 0x00, 0x17, 0x09, 0x01, 0x04 };
    const std::vector<uint8_t> r_profile  = { 0x09, 0x00, 0x09, 0x35, 0x08, 0x35, 0x06, 0x19, 0x11, 0x0E, 0x09, 0x01,
                                              0x05 };
    const std::vector<uint8_t> avrcp_all = cat({ { 0x35, 53 }, r_handle, r_classes, r_protocol, r_profile });

    const std::vector<uint8_t> for_source  = { 0x35, 0x03, 0x19, 0x11, 0x0A }; /* search pattern: AudioSource */
    const std::vector<uint8_t> every_attr  = { 0x35, 0x05, 0x0A, 0x00, 0x00, 0xFF, 0xFF };
    const std::vector<uint8_t> profile_only = { 0x35, 0x03, 0x09, 0x00, 0x09 };
    const std::vector<uint8_t> no_more     = { 0x00 };

    {
        /* The headphones' channel and request: MTU 48, at most 32 bytes, the profile descriptor list only. */
        MockSink m;
        btc_upper_ops_t ops = plain_upper_ops(&m);
        btc_upper_init(&m.src, &ops, 35u, true);
        const uint16_t cid = peer_opens_channel(m, 0x0001u, 0x0070u, 48u);
        CHECK(cid != 0u, "the source accepts an SDP channel of the peer");

        std::vector<uint8_t> rsp =
            sdp_ask(m, cid, 0x0070u, 0x06u, cat({ for_source, { 0x00, 0x20 }, profile_only, no_more }));
        const std::vector<uint8_t> want_profile = cat({ { 0x35, 15, 0x35, 13 }, a_profile });
        CHECK(rsp.size() == 5u + 2u + 17u + 1u && rsp[0] == 0x07u && rsp[5] == 0x00u && rsp[6] == 17u &&
                  std::equal(want_profile.begin(), want_profile.end(), rsp.begin() + 7) && rsp.back() == 0x00u,
              "only the attribute that was asked for comes back, in one frame that fits the MTU");

        /* Everything, 32 bytes at a time: two answers, the first with a continuation state. */
        const std::vector<uint8_t> whole = cat({ { 0x35, 58 }, a2dp_all }); /* 60 bytes */
        rsp = sdp_ask(m, cid, 0x0070u, 0x06u, cat({ for_source, { 0x00, 0x20 }, every_attr, no_more }));
        CHECK(rsp.size() == 5u + 2u + 32u + 3u && rsp.size() <= 48u && rsp[6] == 32u, "the first part: 32 bytes");
        CHECK(std::equal(whole.begin(), whole.begin() + 32, rsp.begin() + 7), "they are the start of the answer");
        const std::vector<uint8_t> state(rsp.end() - 3, rsp.end());
        CHECK(state[0] == 0x02u, "followed by a continuation state of two bytes");
        rsp = sdp_ask(m, cid, 0x0070u, 0x06u, cat({ for_source, { 0x00, 0x20 }, every_attr, state }));
        CHECK(rsp.size() == 5u + 2u + 28u + 1u && rsp[6] == 28u && rsp.back() == 0x00u &&
                  std::equal(whole.begin() + 32, whole.end(), rsp.begin() + 7),
              "the request with that state brings the rest, and the answer ends there");

        /* A request that allows more than the channel carries is limited by the channel. */
        rsp = sdp_ask(m, cid, 0x0070u, 0x06u, cat({ for_source, { 0x00, 0xFF }, every_attr, no_more }));
        CHECK(rsp.size() == 48u && rsp[6] == 38u && rsp[rsp.size() - 3u] == 0x02u,
              "the MTU of the channel limits a part as well");

        /* A continuation state that points past the end. */
        rsp = sdp_ask(m, cid, 0x0070u, 0x06u, cat({ for_source, { 0x00, 0x20 }, every_attr, { 0x02, 0x01, 0x00 } }));
        CHECK(rsp == std::vector<uint8_t>({ 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x05 }),
              "a continuation state that is not ours: error 0x0005");
        rsp = sdp_ask(m, cid, 0x0070u, 0x06u, cat({ for_source, { 0x00, 0x06 }, every_attr, no_more }));
        CHECK(rsp == std::vector<uint8_t>({ 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x03 }),
              "fewer than seven bytes allowed: invalid request syntax");
    }
    {
        /* A roomy channel: whole answers, and the records are well-formed (each sequence as long as it says). */
        MockSink m;
        btc_upper_ops_t ops = plain_upper_ops(&m);
        btc_upper_init(&m.src, &ops, 35u, true);
        const uint16_t cid = peer_opens_channel(m, 0x0001u, 0x0070u, 672u);
        CHECK(cid != 0u, "SDP channel with the default MTU");

        std::vector<uint8_t> rsp =
            sdp_ask(m, cid, 0x0070u, 0x06u, cat({ for_source, { 0xFF, 0xFF }, every_attr, no_more }));
        CHECK(rsp == cat({ { 0x07, 0x00, 0x07, 0x00, 63, 0x00, 60, 0x35, 58 }, a2dp_all, no_more }),
              "the whole AudioSource record in one answer");

        /* AVRCP by a 128-bit UUID (0000110E-0000-1000-8000-00805F9B34FB) and two single attribute IDs. */
        const std::vector<uint8_t> for_avrcp128 = { 0x35, 0x11, 0x1C, 0x00, 0x00, 0x11, 0x0E, 0x00, 0x00, 0x10, 0x00,
                                                    0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB };
        rsp = sdp_ask(m, cid, 0x0070u, 0x06u,
                      cat({ for_avrcp128, { 0xFF, 0xFF }, { 0x35, 0x06, 0x09, 0x00, 0x01, 0x09, 0x00, 0x09 }, no_more }));
        CHECK(rsp == cat({ { 0x07, 0x00, 0x07, 0x00, 31, 0x00, 28, 0x35, 26, 0x35, 24 }, r_classes, r_profile, no_more }),
              "a 128-bit UUID finds the AVRCP record; two single IDs give two attributes");

        /* L2CAP (0x0100) is in both records. */
        rsp = sdp_ask(m, cid, 0x0070u, 0x06u,
                      cat({ { 0x35, 0x03, 0x19, 0x01, 0x00 }, { 0xFF, 0xFF }, { 0x35, 0x03, 0x09, 0x00, 0x00 }, no_more }));
        CHECK(rsp == cat({ { 0x07, 0x00, 0x07, 0x00, 25, 0x00, 22, 0x35, 20, 0x35, 8 }, a_handle, { 0x35, 8 },
                           r_handle, no_more }),
              "a pattern both records hold gives both, in the order of their handles");

        /* Serial Port (0x1101) is in none: an empty list, not an error. */
        rsp = sdp_ask(m, cid, 0x0070u, 0x06u, cat({ { 0x35, 0x03, 0x19, 0x11, 0x01 }, { 0xFF, 0xFF }, every_attr, no_more }));
        CHECK(rsp == std::vector<uint8_t>({ 0x07, 0x00, 0x07, 0x00, 0x05, 0x00, 0x02, 0x35, 0x00, 0x00 }),
              "no record matches: an empty list");
        /* A pattern asks for all of its UUIDs: AudioSource and Serial Port together match nothing. */
        rsp = sdp_ask(m, cid, 0x0070u, 0x06u,
                      cat({ { 0x35, 0x06, 0x19, 0x11, 0x0A, 0x19, 0x11, 0x01 }, { 0xFF, 0xFF }, every_attr, no_more }));
        CHECK(rsp == std::vector<uint8_t>({ 0x07, 0x00, 0x07, 0x00, 0x05, 0x00, 0x02, 0x35, 0x00, 0x00 }),
              "every UUID of the pattern has to be in the record");

        /* SDP_ServiceSearchRequest: handles; SDP_ServiceAttributeRequest: one record by its handle. */
        rsp = sdp_ask(m, cid, 0x0070u, 0x02u, cat({ for_source, { 0x00, 0x10 }, no_more }));
        CHECK(rsp == std::vector<uint8_t>({ 0x03, 0x00, 0x07, 0x00, 0x09, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
                                            0x01, 0x00 }),
              "the search alone gives the handle of the AudioSource record");
        rsp = sdp_ask(m, cid, 0x0070u, 0x02u, cat({ { 0x35, 0x03, 0x19, 0x01, 0x00 }, { 0x00, 0x01 }, no_more }));
        CHECK(rsp.size() == 14u && rsp[6] == 0x01u && rsp[8] == 0x01u && rsp[12] == 0x01u,
              "not more handles than the request allows");
        rsp = sdp_ask(m, cid, 0x0070u, 0x04u, cat({ { 0x00, 0x01, 0x00, 0x02 }, { 0xFF, 0xFF }, every_attr, no_more }));
        CHECK(rsp == cat({ { 0x05, 0x00, 0x07, 0x00, 58, 0x00, 55 }, avrcp_all, no_more }),
              "the attributes of the AVRCP record by its handle");
        rsp = sdp_ask(m, cid, 0x0070u, 0x04u, cat({ { 0x00, 0x01, 0x00, 0x01 }, { 0x00, 0x14 }, every_attr, no_more }));
        CHECK(rsp.size() == 5u + 2u + 20u + 3u && std::equal(a2dp_all.begin(), a2dp_all.begin() + 20, rsp.begin() + 7),
              "and in parts when the request allows only so many bytes");
        rsp = sdp_ask(m, cid, 0x0070u, 0x04u, cat({ { 0x00, 0x01, 0x00, 0x09 }, { 0xFF, 0xFF }, every_attr, no_more }));
        CHECK(rsp == std::vector<uint8_t>({ 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x02 }), "an unknown handle: error 0x0002");
        rsp = sdp_ask(m, cid, 0x0070u, 0x06u, { 0x35, 0x09, 0x19 });
        CHECK(rsp == std::vector<uint8_t>({ 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x03 }), "a cut request: error 0x0003");
    }
    return 0;
}

static int test_bonds_remember_several_devices(void)
{
    const uint8_t a[6] = {0xA0, 1, 2, 3, 4, 5}, b[6] = {0xB0, 1, 2, 3, 4, 5}, c[6] = {0xC0, 1, 2, 3, 4, 5};
    const uint8_t d[6] = {0xD0, 1, 2, 3, 4, 5}, e[6] = {0xE0, 1, 2, 3, 4, 5};
    btc_bonds_t l = {};
    CHECK(sizeof(btc_bond_t) == 96u, "the record keeps the layout of the first version (a stored speaker stays paired)");
    CHECK(btc_bonds_find(&l, a) == -1, "an empty list remembers nobody");

    btc_bond_t *ra = btc_bonds_touch(&l, a);
    CHECK(l.count == 1u && ra == &l.items[0] && memcmp(ra->addr, a, 6) == 0 && ra->magic == BTC_BOND_MAGIC,
          "a new device gets a record at the front");
    memset(ra->link_key, 0x11, 16);
    std::snprintf(ra->name, sizeof(ra->name), "Speaker A");
    btc_bond_t *rb = btc_bonds_touch(&l, b);
    memset(rb->link_key, 0x22, 16);
    std::snprintf(rb->name, sizeof(rb->name), "Headphones B");
    CHECK(l.count == 2u && btc_bonds_find(&l, b) == 0 && btc_bonds_find(&l, a) == 1, "the newest is first");

    ra = btc_bonds_touch(&l, a);
    CHECK(l.count == 2u && btc_bonds_find(&l, a) == 0 && btc_bonds_find(&l, b) == 1 && ra->link_key[0] == 0x11 &&
          strcmp(ra->name, "Speaker A") == 0, "using a remembered device moves it to the front with its key and name");

    (void)btc_bonds_touch(&l, c);
    (void)btc_bonds_touch(&l, d);
    CHECK(l.count == 4u, "four devices are remembered");
    (void)btc_bonds_touch(&l, e);
    CHECK(l.count == 4u && btc_bonds_find(&l, e) == 0 && btc_bonds_find(&l, b) == -1 && btc_bonds_find(&l, a) == 3,
          "a fifth pushes out the one used longest ago");

    uint8_t stored[BTC_BONDS_STORE_MAX + 4u];
    CHECK(btc_bonds_store(&l, stored, 16u) == 0u, "a buffer that is too small gets nothing");
    const size_t n = btc_bonds_store(&l, stored, sizeof(stored));
    CHECK(n == 8u + 4u * sizeof(btc_bond_t), "the stored form is a header and the records");
    btc_bonds_t back = {};
    CHECK(btc_bonds_load(&back, stored, n) && back.count == 4u && btc_bonds_find(&back, e) == 0 &&
          btc_bonds_find(&back, a) == 3 && back.items[3].link_key[5] == 0x11 &&
          strcmp(back.items[3].name, "Speaker A") == 0, "the list comes back as it was stored");

    CHECK(btc_bonds_remove(&l, d) && l.count == 3u && btc_bonds_find(&l, d) == -1 && btc_bonds_find(&l, e) == 0 &&
          btc_bonds_find(&l, c) == 1 && btc_bonds_find(&l, a) == 2, "forgetting one keeps the order of the others");
    CHECK(!btc_bonds_remove(&l, d), "forgetting a device that is not remembered changes nothing");

    /* What the first version stored: one record by itself. */
    btc_bond_t old = {};
    old.magic = BTC_BOND_MAGIC;
    memcpy(old.addr, a, 6);
    memset(old.link_key, 0x77, 16);
    std::snprintf(old.name, sizeof(old.name), "X8 Pro");
    CHECK(btc_bonds_load(&back, reinterpret_cast<const uint8_t *>(&old), sizeof(old)) && back.count == 1u &&
          btc_bonds_find(&back, a) == 0 && back.items[0].link_key[15] == 0x77 &&
          strcmp(back.items[0].name, "X8 Pro") == 0, "the single record of the first version is read as a list of one");

    /* Anything else is not ours. */
    stored[0] ^= 0xFFu;
    CHECK(!btc_bonds_load(&back, stored, n) && back.count == 0u, "a wrong magic leaves the list empty");
    stored[0] ^= 0xFFu;
    CHECK(!btc_bonds_load(&back, stored, n - 1u) && back.count == 0u, "a cut-off list is refused");
    stored[4] = 9u;
    CHECK(!btc_bonds_load(&back, stored, n) && back.count == 0u, "a count beyond the limit is refused");
    stored[4] = 4u;
    stored[8] ^= 0xFFu; /* the magic of the first record */
    CHECK(!btc_bonds_load(&back, stored, n) && back.count == 0u, "a record without its magic is refused");
    return 0;
}

int main(void)
{
    std::printf("=== p4_bt_classic host tests ===\n");
    if (test_sbc_codec() != 0)         return 1;
    if (test_p192_ecdh() != 0)         return 1;
    if (test_p192_official_sample_data() != 0) return 1;
    if (test_lmp_ssp_and_legacy() != 0) return 1;
    if (test_lmp_peer_stays_on_one_slot_without_a_loop() != 0) return 1;
    if (test_lmp_keeps_a_trace_of_the_link() != 0) return 1;
    if (test_lmp_pairing_request_refused_at_first_is_sent_again() != 0) return 1;
    if (test_media_queue_bridges_a_gap() != 0) return 1;
    if (test_rate_follows_the_link() != 0) return 1;
    if (test_l2cap_avdtp_avrcp() != 0) return 1;
    if (test_upper_keeps_a_trace_of_the_l2cap_frames() != 0) return 1;
    if (test_upper_refused_audio_channel_is_asked_for_again() != 0) return 1;
    if (test_sdp_server_answers_within_the_limits_of_the_request() != 0) return 1;
    if (test_bonds_remember_several_devices() != 0) return 1;
    std::printf("ALL PASS\n");
    return 0;
}
