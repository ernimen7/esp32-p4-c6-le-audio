/*
 * Bluetooth Classic Link Manager Protocol (LMP) & Security Engine (Core Spec v5.4 Vol 2 Part C & H).
 *
 * Implements:
 *  - Link setup (version, features/ext-features, remote name, host connection, supervision timeout)
 *  - Strict Soft-BR radio guards: role-switch disabled (0x21), EDR 2M/3M disabled, Slave->Master 1-slot (LMP_max_slot=1),
 *    Master->Slave 3-slot DH3 (LMP_max_slot_req=3)
 *  - Saved Link Key authentication (SAFER+ E1) with automatic fallback to pairing on 0x06 (Key Missing)
 *  - Secure Simple Pairing (SSP) P-192 ECDH "Just Works" / Numeric Comparison (Initiator & Responder)
 *  - Legacy PIN ("0000" / "1234") pairing (SAFER+ E22 + E21 Combination Key)
 *  - E0 Encryption negotiation & key derivation (SAFER+ E3 using latest E1 ACO + Kc' reduction)
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BTC_LMP_GOAL_CONNECT   = 0,
    BTC_LMP_GOAL_NAME_ONLY = 1,
} btc_lmp_goal_t;

typedef struct {
    void *ctx;
    void (*send_lmp)(void *ctx, const uint8_t *pdu, uint8_t len);
    void (*start_encryption)(void *ctx, const uint8_t en_rand[16], const uint8_t kc_prime[16]);
    void (*random_bytes)(void *ctx, uint8_t *out, size_t len);
    void (*on_remote_name)(void *ctx, const char *name_utf8);
    void (*on_link_key)(void *ctx, const uint8_t peer_bdaddr[6], const uint8_t link_key[16]);
    void (*on_setup_done)(void *ctx, bool ok, uint8_t err_reason);
    /* How many slots the peer lets our ACL packets take (Core Spec Vol 2 Part C 4.1.10: 1 after a new connection).
     * why: 0 the peer sent LMP_max_slot, 1 it accepted our LMP_max_slot_req, 2 it refused it (slots unchanged,
     * err = its reason). */
    void (*on_peer_max_slots)(void *ctx, uint8_t slots, uint8_t why, uint8_t err);
} btc_lmp_ops_t;

/* The last PDUs of the link, both ways. With a device nobody has tried the setup can stop with silence on both
 * sides (Sony WH-1000XM3, 2026-11-15: after about eleven PDUs each way) and the counters do not say at which. */
#define BTC_LMP_TRACE 64u
typedef struct {
    uint8_t dir;  /* 0 sent, 1 received */
    uint8_t len;  /* length of the PDU */
    uint8_t tick; /* btc_lmp_on_tick calls since btc_lmp_start, about two a second; stops at 255 */
    uint8_t d[5]; /* its first bytes: opcode << 1 | TID, then the extended opcode or the first parameters */
} btc_lmp_rec_t;

typedef struct btc_lmp {
    btc_lmp_ops_t  ops;
    btc_lmp_goal_t goal;
    bool           is_slave_sim; /* False in normal P4 Master operation; true only for simulated Slave in unit tests */

    uint8_t local_bdaddr[6];
    uint8_t peer_bdaddr[6];
    char    local_name[64];
    char    pin_code[16];
    uint8_t pin_len;

    bool    has_link_key;
    uint8_t link_key[16];
    bool    has_aco;
    uint8_t latest_aco[12];

    /* Peer capabilities */
    bool    peer_feat_rcvd;
    bool    peer_ext_feat_rcvd;
    bool    peer_ssp_ctrl;
    bool    peer_ssp_host;
    bool    peer_afh_slave;
    uint8_t peer_max_slots_allowed; /* 1 or 3 */
    /* The peer's LMP_max_slot_req for more than one slot waits for btc_lmp_on_tick (see there). */
    bool    peer_slot_req_waiting;
    uint8_t peer_slot_req_tid;

    /* Remote name assembly */
    char    remote_name[64];
    uint8_t remote_name_total;
    bool    remote_name_done;

    /* Connection & Auth state */
    bool    host_conn_sent;
    bool    host_conn_accepted;
    bool    host_conn_rejected_auth;
    bool    auth_started;
    bool    authenticated;
    bool    enc_started;
    bool    encrypted;
    bool    setup_finished;
    uint8_t enc_key_size;
    uint8_t pending_au_rand[16];
    uint8_t expected_sres[4];
    uint8_t pending_aco[12];
    bool    waiting_sres;
    bool    tried_fallback_pin;

    /* Legacy PIN pairing state */
    bool    legacy_active;
    bool    legacy_we_initiated;
    uint8_t k_init[16];
    uint8_t lk_rand_local[16];
    uint8_t comb_ka_local[16];
    bool    comb_sent;

    /* SSP P-192 ECDH state */
    bool    ssp_active;
    bool    ssp_we_initiated;
    uint8_t local_iocap[3]; /* [io_cap, oob, auth_req] in LMP wire order (LSO..MSO) */
    uint8_t peer_iocap[3];
    uint8_t priv_d_le[24];
    uint8_t local_pk_le[48]; /* X[24] || Y[24] in LMP little-endian */
    uint8_t peer_pk_le[48];
    uint8_t dhkey_le[24];
    bool    dhkey_ready;
    uint8_t tx_encap_idx;    /* 0..3 */
    bool    tx_encap_hdr_sent;
    bool    local_pk_sent;
    uint8_t rx_encap_bytes;
    bool    peer_pk_rcvd;

    uint8_t local_nonce_le[16];
    uint8_t peer_nonce_le[16];
    /* Our LMP_io_capability_req was refused with "LMP PDU not allowed": it goes out again when this reaches zero
     * (btc_lmp_on_tick), BTC_LMP_IOCAP_RETRIES times at most. */
    uint8_t iocap_retry_in;
    uint8_t iocap_retries;

    uint8_t peer_confirm_le[16];
    bool    peer_confirm_rcvd;
    bool    local_nonce_sent;
    bool    peer_nonce_rcvd;
    bool    dhkey_check_sent;

    /* Last derived Kc' for inspection/verification */
    uint8_t last_kc_prime[16];

    btc_lmp_rec_t trace[BTC_LMP_TRACE]; /* a ring: record i is trace[i % BTC_LMP_TRACE] */
    uint16_t      trace_n;              /* PDUs since btc_lmp_start */
    uint8_t       trace_tick;
} btc_lmp_t;

void btc_lmp_init(btc_lmp_t *lmp, const btc_lmp_ops_t *ops,
                  const uint8_t local_bdaddr[6], const char *local_name, const char *pin_code);

void btc_lmp_set_link_key(btc_lmp_t *lmp, const uint8_t link_key[16]);
void btc_lmp_clear_link_key(btc_lmp_t *lmp);

/* Starts LMP setup on a newly established ACL link (`0x0B00`). */
void btc_lmp_start(btc_lmp_t *lmp, const uint8_t peer_bdaddr[6], btc_lmp_goal_t goal);

/* Processes an incoming LMP PDU (`BR_VSEVT_LMP_RX`). */
void btc_lmp_on_pdu(btc_lmp_t *lmp, const uint8_t *pdu, uint8_t len);

/* Notifies LMP engine of controller atomic E0 encryption completion (`BR_VSEVT_ENC_STATE`). */
void btc_lmp_on_encryption_state(btc_lmp_t *lmp, uint8_t status, bool enc_on);

/* Called about twice a second while the link is up, from the context that calls btc_lmp_on_pdu: answers what
 * was left waiting so that it does not run as fast as the link allows. */
void btc_lmp_on_tick(btc_lmp_t *lmp);

/* The trace of the link since its btc_lmp_start, oldest record first; returns how many were written to `out`
 * (at most max_out and BTC_LMP_TRACE). */
uint8_t btc_lmp_trace_read(const btc_lmp_t *lmp, btc_lmp_rec_t *out, uint8_t max_out);

/* Portable NIST P-192 (secp192r1) ECDH primitives (exposed for deterministic vector tests).
 * Coordinates `pk_x_le`, `pk_y_le`, `priv_d_le`, `out_dhkey_x_le` are 24-byte Bluetooth little-endian. */
void btc_p192_gen_keypair(const uint8_t rand24_le[24], uint8_t out_priv_d_le[24], uint8_t out_pub_xy_le[48]);
bool btc_p192_compute_dhkey(const uint8_t priv_d_le[24], const uint8_t peer_pub_xy_le[48], uint8_t out_dhkey_x_le[24]);

#ifdef __cplusplus
}
#endif
