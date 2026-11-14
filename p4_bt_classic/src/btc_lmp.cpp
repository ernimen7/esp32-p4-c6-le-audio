/*
 * Bluetooth Classic Link Manager Protocol (LMP) & Security Engine.
 */
#include "btc_lmp.h"

#include <string.h>

#include "br_crypto.h"

/* =========================================================================
 * Self-contained NIST P-192 (secp192r1) ECDH in 6x32-bit limbs (little-endian).
 * Prime: p = 2^192 - 2^64 - 1 = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
 * Order: n = {0xB4D22831, 0x146BC9B1, 0x99DEF836, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
 * Curve: y^2 = x^3 - 3x + b (mod p)
 * ========================================================================= */
namespace {

struct u192 {
    uint32_t w[6];
};

static const u192 kP192_P = {{
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
}};
static const u192 kP192_B = {{
    0xC146B9B1u, 0xFEB8DEECu, 0x72243049u, 0x0FA7E9ABu, 0xE59C80E7u, 0x64210519u
}};
static const u192 kP192_GX = {{
    0x82FF1012u, 0xF4FF0AFDu, 0x43A18800u, 0x7CBF20EBu, 0xB03090F6u, 0x188DA80Eu
}};
static const u192 kP192_GY = {{
    0x1E794811u, 0x73F977A1u, 0x6B24CDD5u, 0x631011EDu, 0xFFC8DA78u, 0x07192B95u
}};
static const u192 kP192_N_MINUS_2 = {{
    0xB4D2282Fu, 0x146BC9B1u, 0x99DEF836u, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
}};

static void u192_from_le24(u192 *dst, const uint8_t b[24])
{
    for (int i = 0; i < 6; i++) {
        dst->w[i] = (uint32_t)b[i * 4 + 0] |
                    ((uint32_t)b[i * 4 + 1] << 8) |
                    ((uint32_t)b[i * 4 + 2] << 16) |
                    ((uint32_t)b[i * 4 + 3] << 24);
    }
}

static void u192_to_le24(const u192 *src, uint8_t b[24])
{
    for (int i = 0; i < 6; i++) {
        b[i * 4 + 0] = (uint8_t)(src->w[i] & 0xFFu);
        b[i * 4 + 1] = (uint8_t)((src->w[i] >> 8) & 0xFFu);
        b[i * 4 + 2] = (uint8_t)((src->w[i] >> 16) & 0xFFu);
        b[i * 4 + 3] = (uint8_t)((src->w[i] >> 24) & 0xFFu);
    }
}

static bool u192_is_zero(const u192 *a)
{
    return (a->w[0] | a->w[1] | a->w[2] | a->w[3] | a->w[4] | a->w[5]) == 0u;
}

static int u192_cmp(const u192 *a, const u192 *b)
{
    for (int i = 5; i >= 0; i--) {
        if (a->w[i] != b->w[i]) {
            return (a->w[i] > b->w[i]) ? 1 : -1;
        }
    }
    return 0;
}

static uint32_t u192_add_raw(u192 *out, const u192 *a, const u192 *b)
{
    uint64_t c = 0;
    for (int i = 0; i < 6; i++) {
        c += (uint64_t)a->w[i] + (uint64_t)b->w[i];
        out->w[i] = (uint32_t)c;
        c >>= 32;
    }
    return (uint32_t)c;
}

static uint32_t u192_sub_raw(u192 *out, const u192 *a, const u192 *b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < 6; i++) {
        uint64_t av = a->w[i];
        uint64_t bv = (uint64_t)b->w[i] + borrow;
        if (av >= bv) {
            out->w[i] = (uint32_t)(av - bv);
            borrow = 0;
        } else {
            out->w[i] = (uint32_t)((1ULL << 32) + av - bv);
            borrow = 1;
        }
    }
    return (uint32_t)borrow;
}

static void fp_add(u192 *out, const u192 *a, const u192 *b)
{
    u192 sum;
    uint32_t c = u192_add_raw(&sum, a, b);
    if (c || u192_cmp(&sum, &kP192_P) >= 0) {
        u192_sub_raw(out, &sum, &kP192_P);
    } else {
        *out = sum;
    }
}

static void fp_sub(u192 *out, const u192 *a, const u192 *b)
{
    u192 diff;
    if (u192_sub_raw(&diff, a, b)) {
        u192_add_raw(out, &diff, &kP192_P);
    } else {
        *out = diff;
    }
}

/* Fast NIST P-192 Solinas reduction from 384-bit product `t[0..11]` (FIPS 186-4 D.1.2.1):
 * Using 64-bit chunks B0..B5 (64 bits each):
 *   S1 = (B2, B1, B0)
 *   S2 = ( 0, B3, B3)
 *   S3 = (B4, B4,  0)
 *   S4 = (B5, B5, B5)
 *   result = S1 + S2 + S3 + S4 mod p! */
static void fp_mul(u192 *out, const u192 *a, const u192 *b)
{
    uint64_t prod[12] = {0};
    for (int i = 0; i < 6; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 6; j++) {
            uint64_t cur = prod[i + j] + (uint64_t)a->w[i] * (uint64_t)b->w[j] + carry;
            prod[i + j] = cur & 0xFFFFFFFFULL;
            carry = cur >> 32;
        }
        prod[i + 6] += carry;
    }

    /* Accumulate S1 + S2 + S3 + S4 in 32-bit limbs with carry:
     * B0 = (prod[1], prod[0]), B1 = (prod[3], prod[2]), B2 = (prod[5], prod[4])
     * B3 = (prod[7], prod[6]), B4 = (prod[9], prod[8]), B5 = (prod[11], prod[10]) */
    uint64_t acc[7] = {0};
    acc[0] = prod[0] + prod[6] + prod[10];
    acc[1] = prod[1] + prod[7] + prod[11];
    acc[2] = prod[2] + prod[6] + prod[8] + prod[10];
    acc[3] = prod[3] + prod[7] + prod[9] + prod[11];
    acc[4] = prod[4] + prod[8] + prod[10];
    acc[5] = prod[5] + prod[9] + prod[11];

    uint64_t c = 0;
    u192 r;
    for (int i = 0; i < 6; i++) {
        c += acc[i];
        r.w[i] = (uint32_t)c;
        c >>= 32;
    }
    /* Fold top carry c: 2^192 == 2^64 + 1 (mod p)! */
    while (c > 0) {
        uint64_t c0 = (uint64_t)r.w[0] + c;
        r.w[0] = (uint32_t)c0;
        uint64_t c1 = (uint64_t)r.w[1] + (c0 >> 32);
        r.w[1] = (uint32_t)c1;
        uint64_t c2 = (uint64_t)r.w[2] + (c1 >> 32) + c;
        r.w[2] = (uint32_t)c2;
        uint64_t c3 = (uint64_t)r.w[3] + (c2 >> 32);
        r.w[3] = (uint32_t)c3;
        uint64_t c4 = (uint64_t)r.w[4] + (c3 >> 32);
        r.w[4] = (uint32_t)c4;
        uint64_t c5 = (uint64_t)r.w[5] + (c4 >> 32);
        r.w[5] = (uint32_t)c5;
        c = c5 >> 32;
    }
    while (u192_cmp(&r, &kP192_P) >= 0) {
        u192_sub_raw(&r, &r, &kP192_P);
    }
    *out = r;
}

static void fp_sqr(u192 *out, const u192 *a)
{
    fp_mul(out, a, a);
}

/* Modular inverse via Fermat's Little Theorem: a^(p - 2) mod p */
static void fp_inv(u192 *out, const u192 *a)
{
    u192 p_minus_2 = kP192_P;
    p_minus_2.w[0] -= 2u; /* 0xFFFFFFFD */

    u192 res = {{1u, 0u, 0u, 0u, 0u, 0u}};
    u192 base = *a;
    for (int i = 0; i < 192; i++) {
        if ((p_minus_2.w[i >> 5] >> (i & 31)) & 1u) {
            fp_mul(&res, &res, &base);
        }
        fp_sqr(&base, &base);
    }
    *out = res;
}

struct jac_pt {
    u192 x;
    u192 y;
    u192 z;
    bool inf;
};

static void pt_double(jac_pt *r, const jac_pt *p)
{
    if (p->inf || u192_is_zero(&p->y)) {
        memset(r, 0, sizeof(*r));
        r->inf = true;
        return;
    }
    /* Jacobian doubling for a = -3:
     * delta = Z^2, gamma = Y^2, beta = X * gamma
     * alpha = 3 * (X - delta) * (X + delta)
     * X3 = alpha^2 - 8*beta
     * Z3 = (Y + Z)^2 - gamma - delta
     * Y3 = alpha * (4*beta - X3) - 8*gamma^2 */
    u192 delta, gamma, beta, t1, t2, alpha, x3, y3, z3;
    fp_sqr(&delta, &p->z);
    fp_sqr(&gamma, &p->y);
    fp_mul(&beta, &p->x, &gamma);

    fp_sub(&t1, &p->x, &delta);
    fp_add(&t2, &p->x, &delta);
    fp_mul(&alpha, &t1, &t2);
    fp_add(&t1, &alpha, &alpha);
    fp_add(&alpha, &t1, &alpha); /* 3 * (X - Z^2)(X + Z^2) */

    u192 beta4, beta8;
    fp_add(&beta4, &beta, &beta);
    fp_add(&beta4, &beta4, &beta4);
    fp_add(&beta8, &beta4, &beta4);

    fp_sqr(&x3, &alpha);
    fp_sub(&x3, &x3, &beta8);

    fp_add(&t1, &p->y, &p->z);
    fp_sqr(&z3, &t1);
    fp_sub(&z3, &z3, &gamma);
    fp_sub(&z3, &z3, &delta);

    fp_sub(&t1, &beta4, &x3);
    fp_mul(&y3, &alpha, &t1);
    fp_sqr(&t2, &gamma);
    fp_add(&t2, &t2, &t2);
    fp_add(&t2, &t2, &t2);
    fp_add(&t2, &t2, &t2); /* 8 * gamma^2 */
    fp_sub(&y3, &y3, &t2);

    r->x = x3;
    r->y = y3;
    r->z = z3;
    r->inf = false;
}

static void pt_add_affine(jac_pt *r, const jac_pt *p, const u192 *qx, const u192 *qy)
{
    if (p->inf) {
        r->x = *qx;
        r->y = *qy;
        memset(&r->z, 0, sizeof(r->z));
        r->z.w[0] = 1u;
        r->inf = false;
        return;
    }
    u192 z1z1, u2, z1z1z1, s2, h, r_slope;
    fp_sqr(&z1z1, &p->z);
    fp_mul(&u2, qx, &z1z1);
    fp_mul(&z1z1z1, &z1z1, &p->z);
    fp_mul(&s2, qy, &z1z1z1);

    fp_sub(&h, &u2, &p->x);
    fp_sub(&r_slope, &s2, &p->y);

    if (u192_is_zero(&h)) {
        if (u192_is_zero(&r_slope)) {
            pt_double(r, p);
        } else {
            memset(r, 0, sizeof(*r));
            r->inf = true;
        }
        return;
    }

    u192 hh, hhh, v, x3, y3, z3, t1;
    fp_sqr(&hh, &h);
    fp_mul(&hhh, &hh, &h);
    fp_mul(&v, &p->x, &hh);

    fp_sqr(&x3, &r_slope);
    fp_sub(&x3, &x3, &hhh);
    fp_sub(&x3, &x3, &v);
    fp_sub(&x3, &x3, &v);

    fp_sub(&t1, &v, &x3);
    fp_mul(&y3, &r_slope, &t1);
    fp_mul(&t1, &p->y, &hhh);
    fp_sub(&y3, &y3, &t1);

    fp_mul(&z3, &p->z, &h);

    r->x = x3;
    r->y = y3;
    r->z = z3;
    r->inf = false;
}

static bool pt_scalar_mul(const u192 *k, const u192 *px, const u192 *py, u192 *out_x, u192 *out_y)
{
    jac_pt acc;
    memset(&acc, 0, sizeof(acc));
    acc.inf = true;

    for (int i = 191; i >= 0; i--) {
        pt_double(&acc, &acc);
        if ((k->w[i >> 5] >> (i & 31)) & 1u) {
            pt_add_affine(&acc, &acc, px, py);
        }
    }
    if (acc.inf || u192_is_zero(&acc.z)) {
        return false;
    }
    u192 z_inv, z_inv2, z_inv3;
    fp_inv(&z_inv, &acc.z);
    fp_sqr(&z_inv2, &z_inv);
    fp_mul(&z_inv3, &z_inv2, &z_inv);
    if (out_x) fp_mul(out_x, &acc.x, &z_inv2);
    if (out_y) fp_mul(out_y, &acc.y, &z_inv3);
    return true;
}

static bool pt_is_on_curve(const u192 *x, const u192 *y)
{
    if (u192_cmp(x, &kP192_P) >= 0 || u192_cmp(y, &kP192_P) >= 0) {
        return false;
    }
    if (u192_is_zero(x) && u192_is_zero(y)) {
        return false;
    }
    /* Check y^2 == x^3 - 3x + b (mod p) */
    u192 lhs, x2, x3, x_times_3, rhs;
    fp_sqr(&lhs, y);
    fp_sqr(&x2, x);
    fp_mul(&x3, &x2, x);
    fp_add(&x_times_3, x, x);
    fp_add(&x_times_3, &x_times_3, x);
    fp_sub(&rhs, &x3, &x_times_3);
    fp_add(&rhs, &rhs, &kP192_B);
    return u192_cmp(&lhs, &rhs) == 0;
}

} /* namespace */

extern "C" void btc_p192_gen_keypair(const uint8_t rand24_le[24], uint8_t out_priv_d_le[24], uint8_t out_pub_xy_le[48])
{
    u192 d;
    u192_from_le24(&d, rand24_le);
    /* Clamp scalar d into [1, n - 2] */
    while (u192_cmp(&d, &kP192_N_MINUS_2) > 0) {
        d.w[5] >>= 1;
    }
    if (u192_is_zero(&d)) {
        d.w[0] = 1u;
    }
    u192_to_le24(&d, out_priv_d_le);

    u192 qx, qy;
    pt_scalar_mul(&d, &kP192_GX, &kP192_GY, &qx, &qy);
    u192_to_le24(&qx, &out_pub_xy_le[0]);
    u192_to_le24(&qy, &out_pub_xy_le[24]);
}

extern "C" bool btc_p192_compute_dhkey(const uint8_t priv_d_le[24], const uint8_t peer_pub_xy_le[48],
                                       uint8_t out_dhkey_x_le[24])
{
    u192 d, px, py;
    u192_from_le24(&d, priv_d_le);
    u192_from_le24(&px, &peer_pub_xy_le[0]);
    u192_from_le24(&py, &peer_pub_xy_le[24]);

    if (u192_is_zero(&d) || !pt_is_on_curve(&px, &py)) {
        return false;
    }
    u192 zx, zy;
    if (!pt_scalar_mul(&d, &px, &py, &zx, &zy)) {
        return false;
    }
    u192_to_le24(&zx, out_dhkey_x_le);
    return true;
}

/* =========================================================================
 * LMP Protocol Engine
 * ========================================================================= */
namespace {

enum {
    LMP_NAME_REQ                = 1,
    LMP_NAME_RES                = 2,
    LMP_ACCEPTED                = 3,
    LMP_NOT_ACCEPTED            = 4,
    LMP_CLKOFFSET_REQ           = 5,
    LMP_CLKOFFSET_RES           = 6,
    LMP_DETACH                  = 7,
    LMP_IN_RAND                 = 8,
    LMP_COMB_KEY                = 9,
    LMP_UNIT_KEY                = 10,
    LMP_AU_RAND                 = 11,
    LMP_SRES                    = 12,
    LMP_ENCRYPTION_MODE_REQ     = 15,
    LMP_ENCRYPTION_KEY_SIZE_REQ = 16,
    LMP_START_ENCRYPTION_REQ    = 17,
    LMP_STOP_ENCRYPTION_REQ     = 18,
    LMP_SWITCH_REQ              = 19,
    LMP_SNIFF_REQ               = 23,
    LMP_INCR_POWER_REQ          = 31,
    LMP_DECR_POWER_REQ          = 32,
    LMP_MAX_POWER               = 33,
    LMP_MIN_POWER               = 34,
    LMP_AUTO_RATE               = 35,
    LMP_PREFERRED_RATE          = 36,
    LMP_VERSION_REQ             = 37,
    LMP_VERSION_RES             = 38,
    LMP_FEATURES_REQ            = 39,
    LMP_FEATURES_RES            = 40,
    LMP_MAX_SLOT                = 45,
    LMP_MAX_SLOT_REQ            = 46,
    LMP_TIMING_ACCURACY_REQ     = 47,
    LMP_TIMING_ACCURACY_RES     = 48,
    LMP_SETUP_COMPLETE          = 49,
    LMP_HOST_CONNECTION_REQ     = 51,
    LMP_SLOT_OFFSET             = 52,
    LMP_PAGE_MODE_REQ           = 53,
    LMP_PAGE_SCAN_MODE_REQ      = 54,
    LMP_SUPERVISION_TIMEOUT     = 55,
    LMP_SET_AFH                 = 60,
    LMP_ENCAPSULATED_HEADER     = 61,
    LMP_ENCAPSULATED_PAYLOAD    = 62,
    LMP_SIMPLE_PAIRING_CONFIRM  = 63,
    LMP_SIMPLE_PAIRING_NUMBER   = 64,
    LMP_DHKEY_CHECK             = 65,
    LMP_ESCAPE_4                = 127,
};

enum {
    LMP_EXT_ACCEPTED                = 1,
    LMP_EXT_NOT_ACCEPTED            = 2,
    LMP_EXT_FEATURES_REQ            = 3,
    LMP_EXT_FEATURES_RES            = 4,
    LMP_EXT_PACKET_TYPE_TABLE_REQ   = 11,
    LMP_EXT_CHANNEL_CLASS_REQ       = 16,
    LMP_EXT_CHANNEL_CLASS           = 17,
    LMP_EXT_IO_CAPABILITY_REQ       = 25,
    LMP_EXT_IO_CAPABILITY_RES       = 26,
    LMP_EXT_NUMERIC_COMP_FAILED     = 27,
    LMP_EXT_POWER_CONTROL_REQ       = 31,
    LMP_EXT_POWER_CONTROL_RES       = 32,
};

/* Our Baseband LMP Features Page 0:
 *  - Byte 0 = 0x05: 3-slot packets (0x01) + Encryption (0x04). Bit 5 (role switch) = 0!
 *  - Byte 3 = 0x40: RSSI (0x40). Bits 1..2 (EDR 2M/3M) = 0!
 *  - Byte 4 = 0x08: AFH capable slave (0x08). EDR eSCO = 0!
 *  - Byte 5 = 0x18: AFH capable master (0x08) + AFH classification master (0x10). EDR 3/5-slot = 0!
 *  - Byte 6 = 0x18: SSP Controller Support (0x08) + Encapsulated PDU (0x10).
 *  - Byte 7 = 0x80: Extended features (0x80). */
static const uint8_t kLocalFeaturesPage0[8] = {
    0x05u, 0x00u, 0x00u, 0x40u, 0x08u, 0x18u, 0x18u, 0x80u
};
static const uint8_t kLocalFeaturesPage1[8] = {
    0x01u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u /* SSP Host Support = 1 */
};

static uint8_t my_init_tid(const btc_lmp_t *lmp)
{
    return lmp->is_slave_sim ? 1u : 0u;
}

static void tx_pdu(btc_lmp_t *lmp, const uint8_t *pdu, uint8_t len)
{
    if (lmp->ops.send_lmp) {
        lmp->ops.send_lmp(lmp->ops.ctx, pdu, len);
    }
}

static void tx_simple(btc_lmp_t *lmp, uint8_t opcode, uint8_t tid)
{
    uint8_t p[1] = { (uint8_t)((opcode << 1) | (tid & 1u)) };
    tx_pdu(lmp, p, 1u);
}

static void tx_accepted(btc_lmp_t *lmp, uint8_t accepted_op, uint8_t tid)
{
    uint8_t p[2] = { (uint8_t)((LMP_ACCEPTED << 1) | (tid & 1u)), accepted_op };
    tx_pdu(lmp, p, 2u);
}

static void tx_not_accepted(btc_lmp_t *lmp, uint8_t rejected_op, uint8_t err, uint8_t tid)
{
    uint8_t p[3] = { (uint8_t)((LMP_NOT_ACCEPTED << 1) | (tid & 1u)), rejected_op, err };
    tx_pdu(lmp, p, 3u);
}

static void tx_accepted_ext(btc_lmp_t *lmp, uint8_t esc_op, uint8_t ext_op, uint8_t tid)
{
    uint8_t p[4] = { (uint8_t)((LMP_ESCAPE_4 << 1) | (tid & 1u)), LMP_EXT_ACCEPTED, esc_op, ext_op };
    tx_pdu(lmp, p, 4u);
}

static void tx_not_accepted_ext(btc_lmp_t *lmp, uint8_t esc_op, uint8_t ext_op, uint8_t err, uint8_t tid)
{
    uint8_t p[5] = { (uint8_t)((LMP_ESCAPE_4 << 1) | (tid & 1u)), LMP_EXT_NOT_ACCEPTED, esc_op, ext_op, err };
    tx_pdu(lmp, p, 5u);
}

static void fill_rand(btc_lmp_t *lmp, uint8_t *buf, size_t len)
{
    if (lmp->ops.random_bytes) {
        lmp->ops.random_bytes(lmp->ops.ctx, buf, len);
    } else {
        for (size_t i = 0; i < len; i++) {
            buf[i] = (uint8_t)(0x5Au ^ (uint8_t)(i * 37u));
        }
    }
}

/* The peer's own packets stay at one slot: the C6 takes 1-slot packets only (46-byte capture). */
static void tx_max_slot_1(btc_lmp_t *lmp)
{
    uint8_t ms1[2] = { (uint8_t)((LMP_MAX_SLOT << 1) | my_init_tid(lmp)), 1u };
    tx_pdu(lmp, ms1, 2u);
}

static void peer_max_slots(btc_lmp_t *lmp, uint8_t slots, uint8_t why, uint8_t err)
{
    lmp->peer_max_slots_allowed = (slots >= 3u) ? 3u : 1u;
    if (lmp->ops.on_peer_max_slots) {
        lmp->ops.on_peer_max_slots(lmp->ops.ctx, lmp->peer_max_slots_allowed, why, err);
    }
}

static void finish_setup(btc_lmp_t *lmp, bool ok, uint8_t err_reason)
{
    if (lmp->setup_finished) {
        return;
    }
    lmp->setup_finished = true;
    if (ok && !lmp->is_slave_sim && lmp->goal == BTC_LMP_GOAL_CONNECT && lmp->peer_max_slots_allowed < 3u) {
        /* LMP_max_slot_req "can be sent at any time after connection setup is completed" (Core Spec Vol 2 Part C
         * 4.1.10): asking with the first PDUs of the setup, as this did until the third sound trial, is too early.
         * A peer that has already sent LMP_max_slot 3 or 5 needs no asking. */
        uint8_t msr3[2] = { (uint8_t)((LMP_MAX_SLOT_REQ << 1) | my_init_tid(lmp)), 3u };
        tx_pdu(lmp, msr3, 2u);
    }
    if (lmp->ops.on_setup_done) {
        lmp->ops.on_setup_done(lmp->ops.ctx, ok, err_reason);
    }
}

static void start_au_rand_challenge(btc_lmp_t *lmp)
{
    fill_rand(lmp, lmp->pending_au_rand, 16u);
    br_crypto_e1(lmp->link_key, lmp->pending_au_rand, lmp->peer_bdaddr,
                 lmp->expected_sres, lmp->pending_aco);
    lmp->waiting_sres = true;

    uint8_t p[17];
    p[0] = (uint8_t)((LMP_AU_RAND << 1) | my_init_tid(lmp));
    memcpy(&p[1], lmp->pending_au_rand, 16u);
    tx_pdu(lmp, p, 17u);
}

static void begin_encryption_flow(btc_lmp_t *lmp)
{
    if (lmp->enc_started || lmp->is_slave_sim) {
        return;
    }
    lmp->enc_started = true;
    uint8_t p[2] = { (uint8_t)((LMP_ENCRYPTION_MODE_REQ << 1) | my_init_tid(lmp)), 1u };
    tx_pdu(lmp, p, 2u);
}

static void send_start_enc_to_controller(btc_lmp_t *lmp)
{
    uint8_t en_rand[16];
    fill_rand(lmp, en_rand, 16u);

    uint8_t cof[12];
    if (lmp->has_aco) {
        memcpy(cof, lmp->latest_aco, 12u);
    } else {
        memcpy(&cof[0], lmp->peer_bdaddr, 6u);
        memcpy(&cof[6], lmp->peer_bdaddr, 6u);
    }

    uint8_t kc[16];
    br_crypto_e3(lmp->link_key, en_rand, cof, kc);
    br_crypto_kc_prime(kc, lmp->enc_key_size, lmp->last_kc_prime);

    if (lmp->ops.start_encryption) {
        lmp->ops.start_encryption(lmp->ops.ctx, en_rand, lmp->last_kc_prime);
    }
}

static void start_legacy_pin_pairing(btc_lmp_t *lmp)
{
    lmp->legacy_active = true;
    lmp->legacy_we_initiated = true;
    lmp->comb_sent = false;

    uint8_t in_rand[16];
    fill_rand(lmp, in_rand, 16u);
    /* Initiator sends LMP_in_rand -> E22 uses Responder's (peer's) BD_ADDR */
    br_crypto_e22((const uint8_t *)lmp->pin_code, lmp->pin_len, in_rand, lmp->peer_bdaddr, lmp->k_init);

    uint8_t p[17];
    p[0] = (uint8_t)((LMP_IN_RAND << 1) | my_init_tid(lmp));
    memcpy(&p[1], in_rand, 16u);
    tx_pdu(lmp, p, 17u);
}

static void start_ssp_pairing(btc_lmp_t *lmp)
{
    lmp->ssp_active = true;
    lmp->ssp_we_initiated = true;
    lmp->dhkey_ready = false;
    lmp->tx_encap_idx = 0u;
    lmp->tx_encap_hdr_sent = false;
    lmp->local_pk_sent = false;
    lmp->rx_encap_bytes = 0u;
    lmp->peer_pk_rcvd = false;
    lmp->peer_confirm_rcvd = false;
    lmp->local_nonce_sent = false;
    lmp->peer_nonce_rcvd = false;
    lmp->dhkey_check_sent = false;

    uint8_t seed[24];
    fill_rand(lmp, seed, 24u);
    btc_p192_gen_keypair(seed, lmp->priv_d_le, lmp->local_pk_le);
    fill_rand(lmp, lmp->local_nonce_le, 16u);

    uint8_t p[5] = {
        (uint8_t)((LMP_ESCAPE_4 << 1) | my_init_tid(lmp)),
        LMP_EXT_IO_CAPABILITY_REQ,
        lmp->local_iocap[0],
        lmp->local_iocap[1],
        lmp->local_iocap[2],
    };
    tx_pdu(lmp, p, 5u);
}

static void send_encap_pubkey_header(btc_lmp_t *lmp)
{
    lmp->tx_encap_hdr_sent = true;
    lmp->tx_encap_idx = 0u;
    uint8_t p[4] = {
        (uint8_t)((LMP_ENCAPSULATED_HEADER << 1) | my_init_tid(lmp)),
        1u, /* Major = 1 (P-192 Public Key) */
        1u, /* Minor = 1 */
        48u,
    };
    tx_pdu(lmp, p, 4u);
}

static void send_next_encap_pubkey_chunk(btc_lmp_t *lmp)
{
    if (lmp->tx_encap_idx >= 3u) {
        return;
    }
    uint8_t p[17];
    p[0] = (uint8_t)((LMP_ENCAPSULATED_PAYLOAD << 1) | my_init_tid(lmp));
    memcpy(&p[1], &lmp->local_pk_le[lmp->tx_encap_idx * 16u], 16u);
    lmp->tx_encap_idx++;
    tx_pdu(lmp, p, 17u);
}

static void derive_ssp_link_key(btc_lmp_t *lmp)
{
    const uint8_t *n1 = lmp->ssp_we_initiated ? lmp->local_nonce_le : lmp->peer_nonce_le;
    const uint8_t *n2 = lmp->ssp_we_initiated ? lmp->peer_nonce_le  : lmp->local_nonce_le;
    const uint8_t *a1 = lmp->ssp_we_initiated ? lmp->local_bdaddr   : lmp->peer_bdaddr;
    const uint8_t *a2 = lmp->ssp_we_initiated ? lmp->peer_bdaddr    : lmp->local_bdaddr;

    br_ssp_f2_btlk(lmp->dhkey_le, n1, n2, a1, a2, lmp->link_key);
    lmp->has_link_key = true;
    if (lmp->ops.on_link_key) {
        lmp->ops.on_link_key(lmp->ops.ctx, lmp->peer_bdaddr, lmp->link_key);
    }
}

static void start_auth_or_pairing_if_ready(btc_lmp_t *lmp)
{
    if (lmp->is_slave_sim || lmp->goal == BTC_LMP_GOAL_NAME_ONLY || lmp->auth_started) {
        return;
    }
    lmp->auth_started = true;
    if (lmp->has_link_key) {
        start_au_rand_challenge(lmp);
    } else if (lmp->peer_ssp_ctrl && lmp->peer_ssp_host) {
        start_ssp_pairing(lmp);
    } else {
        start_legacy_pin_pairing(lmp);
    }
}

static void send_comb_key(btc_lmp_t *lmp)
{
    if (lmp->comb_sent) {
        return;
    }
    lmp->comb_sent = true;
    fill_rand(lmp, lmp->lk_rand_local, 16u);
    br_crypto_e21(lmp->lk_rand_local, lmp->local_bdaddr, lmp->comb_ka_local);

    uint8_t p[17];
    p[0] = (uint8_t)((LMP_COMB_KEY << 1) | my_init_tid(lmp));
    for (int i = 0; i < 16; i++) {
        p[1 + i] = (uint8_t)(lmp->lk_rand_local[i] ^ lmp->k_init[i]);
    }
    tx_pdu(lmp, p, 17u);
}

} /* namespace */

extern "C" void btc_lmp_init(btc_lmp_t *lmp, const btc_lmp_ops_t *ops,
                             const uint8_t local_bdaddr[6], const char *local_name, const char *pin_code)
{
    if (!lmp) {
        return;
    }
    memset(lmp, 0, sizeof(*lmp));
    if (ops) {
        lmp->ops = *ops;
    }
    if (local_bdaddr) {
        memcpy(lmp->local_bdaddr, local_bdaddr, 6u);
    }
    const char *nm = (local_name && local_name[0]) ? local_name : "Tab5 Classic";
    strncpy(lmp->local_name, nm, sizeof(lmp->local_name) - 1u);

    const char *pin = (pin_code && pin_code[0]) ? pin_code : "0000";
    strncpy(lmp->pin_code, pin, sizeof(lmp->pin_code) - 1u);
    lmp->pin_len = (uint8_t)strlen(lmp->pin_code);

    lmp->enc_key_size = 16u;
    /* IO_Capability = 0x03 (NoInputNoOutput), OOB = 0x00, Auth_Req = 0x02 (Dedicated/General Bonding, no MITM) */
    lmp->local_iocap[0] = 0x03u;
    lmp->local_iocap[1] = 0x00u;
    lmp->local_iocap[2] = 0x02u;
}

extern "C" void btc_lmp_set_link_key(btc_lmp_t *lmp, const uint8_t link_key[16])
{
    if (!lmp || !link_key) {
        return;
    }
    memcpy(lmp->link_key, link_key, 16u);
    lmp->has_link_key = true;
}

extern "C" void btc_lmp_clear_link_key(btc_lmp_t *lmp)
{
    if (!lmp) {
        return;
    }
    memset(lmp->link_key, 0, sizeof(lmp->link_key));
    lmp->has_link_key = false;
}

extern "C" void btc_lmp_start(btc_lmp_t *lmp, const uint8_t peer_bdaddr[6], btc_lmp_goal_t goal)
{
    if (!lmp || !peer_bdaddr) {
        return;
    }
    /* Preserve configured identity, callbacks, and saved link_key across starts */
    btc_lmp_ops_t saved_ops = lmp->ops;
    uint8_t saved_local[6];
    memcpy(saved_local, lmp->local_bdaddr, 6u);
    char saved_name[64];
    memcpy(saved_name, lmp->local_name, sizeof(saved_name));
    char saved_pin[16];
    memcpy(saved_pin, lmp->pin_code, sizeof(saved_pin));
    uint8_t saved_pin_len = lmp->pin_len;
    bool had_lk = lmp->has_link_key;
    uint8_t saved_lk[16];
    memcpy(saved_lk, lmp->link_key, 16u);
    bool slave_sim = lmp->is_slave_sim;

    memset(lmp, 0, sizeof(*lmp));
    lmp->ops = saved_ops;
    memcpy(lmp->local_bdaddr, saved_local, 6u);
    memcpy(lmp->peer_bdaddr, peer_bdaddr, 6u);
    memcpy(lmp->local_name, saved_name, sizeof(saved_name));
    memcpy(lmp->pin_code, saved_pin, sizeof(saved_pin));
    lmp->pin_len = saved_pin_len;
    lmp->has_link_key = had_lk;
    memcpy(lmp->link_key, saved_lk, 16u);
    lmp->is_slave_sim = slave_sim;
    lmp->goal = goal;
    lmp->enc_key_size = 16u;
    lmp->peer_max_slots_allowed = 1u;
    lmp->local_iocap[0] = 0x03u;
    lmp->local_iocap[1] = 0x00u;
    lmp->local_iocap[2] = 0x02u;

    if (lmp->is_slave_sim) {
        return;
    }

    uint8_t tid = my_init_tid(lmp);
    if (goal == BTC_LMP_GOAL_NAME_ONLY) {
        uint8_t nr[2] = { (uint8_t)((LMP_NAME_REQ << 1) | tid), 0u };
        tx_pdu(lmp, nr, 2u);
        return;
    }

    /* 1. Force Slave->Master 1-slot max immediately so C6 single-slot capture never overflows */
    uint8_t ms1[2] = { (uint8_t)((LMP_MAX_SLOT << 1) | tid), 1u };
    tx_pdu(lmp, ms1, 2u);

    /* 2. Exchange LMP Version & Baseband Features */
    uint8_t ver[6] = { (uint8_t)((LMP_VERSION_REQ << 1) | tid), 0x09u, 0xE5u, 0x02u, 0x50u, 0x01u };
    tx_pdu(lmp, ver, 6u);

    uint8_t feat[9];
    feat[0] = (uint8_t)((LMP_FEATURES_REQ << 1) | tid);
    memcpy(&feat[1], kLocalFeaturesPage0, 8u);
    tx_pdu(lmp, feat, 9u);
}

extern "C" void btc_lmp_on_encryption_state(btc_lmp_t *lmp, uint8_t status, bool enc_on)
{
    if (!lmp) {
        return;
    }
    if (status == 0u && enc_on) {
        lmp->encrypted = true;
        if (!lmp->host_conn_accepted) {
            lmp->host_conn_sent = true;
            tx_simple(lmp, LMP_HOST_CONNECTION_REQ, my_init_tid(lmp));
        } else {
            finish_setup(lmp, true, 0u);
        }
    } else {
        finish_setup(lmp, false, status ? status : 0x1Fu);
    }
}

/* The speaker of the sound trials asks for multi-slot packets whenever it is told that it has one slot, and the
 * C6 takes 1-slot packets only (46-byte capture). Answered at once with LMP_not_accepted and LMP_max_slot 1, the
 * exchange ran about 50 times a second and took half of the link (sound trial 8). Answered with LMP_not_accepted
 * alone ("Device requests a maximum number of slots. Remote Device rejects", Core Spec Vol 2 Part C 4.1.10,
 * sequence 20), the speaker went over to packets the C6 cannot take (sound trial 10). So the answer of trial 8,
 * under which the speaker kept to 1-slot packets, goes out at the pace of this tick. */
extern "C" void btc_lmp_on_tick(btc_lmp_t *lmp)
{
    if (!lmp || !lmp->peer_slot_req_waiting) {
        return;
    }
    lmp->peer_slot_req_waiting = false;
    tx_not_accepted(lmp, LMP_MAX_SLOT_REQ, 0x20u, lmp->peer_slot_req_tid);
    tx_max_slot_1(lmp);
}

extern "C" void btc_lmp_on_pdu(btc_lmp_t *lmp, const uint8_t *pdu, uint8_t len)
{
    if (!lmp || !pdu || len == 0u) {
        return;
    }

    uint8_t tid = pdu[0] & 1u;
    uint8_t opcode = (uint8_t)(pdu[0] >> 1);

    /* ---- Extended Opcodes (Escape 4 = 127) ---- */
    if (opcode == LMP_ESCAPE_4) {
        if (len < 2u) {
            return;
        }
        uint8_t ext_op = pdu[1];
        switch (ext_op) {
        case LMP_EXT_FEATURES_REQ: {
            if (len < 12u) break;
            uint8_t page = pdu[2];
            if (page == 1u && (pdu[4] & 0x01u) != 0u) {
                lmp->peer_ssp_host = true;
            }
            uint8_t res[12];
            res[0] = (uint8_t)((LMP_ESCAPE_4 << 1) | tid);
            res[1] = LMP_EXT_FEATURES_RES;
            res[2] = page;
            res[3] = 1u;
            memset(&res[4], 0, 8u);
            if (page == 0u) {
                memcpy(&res[4], kLocalFeaturesPage0, 8u);
            } else if (page == 1u) {
                memcpy(&res[4], kLocalFeaturesPage1, 8u);
            }
            tx_pdu(lmp, res, 12u);
            break;
        }
        case LMP_EXT_FEATURES_RES: {
            if (len < 12u) break;
            uint8_t page = pdu[2];
            lmp->peer_ext_feat_rcvd = true;
            if (page == 1u) {
                lmp->peer_ssp_host = (pdu[4] & 0x01u) != 0u;
            }
            if (!lmp->is_slave_sim && lmp->goal == BTC_LMP_GOAL_CONNECT && !lmp->host_conn_sent) {
                lmp->host_conn_sent = true;
                uint8_t nr[2] = { (uint8_t)((LMP_NAME_REQ << 1) | my_init_tid(lmp)), 0u };
                tx_pdu(lmp, nr, 2u);
                tx_simple(lmp, LMP_HOST_CONNECTION_REQ, my_init_tid(lmp));
            }
            break;
        }
        case LMP_EXT_PACKET_TYPE_TABLE_REQ: {
            /* NEVER allow switching packet table to 2M/3M EDR (table == 1)! */
            uint8_t table = (len >= 3u) ? pdu[2] : 1u;
            if (table == 0u) {
                tx_accepted_ext(lmp, LMP_ESCAPE_4, LMP_EXT_PACKET_TYPE_TABLE_REQ, tid);
            } else {
                tx_not_accepted_ext(lmp, LMP_ESCAPE_4, LMP_EXT_PACKET_TYPE_TABLE_REQ, 0x1Au, tid);
            }
            break;
        }
        case LMP_EXT_CHANNEL_CLASS_REQ:
            tx_accepted_ext(lmp, LMP_ESCAPE_4, LMP_EXT_CHANNEL_CLASS_REQ, tid);
            break;
        case LMP_EXT_CHANNEL_CLASS:
            break;
        case LMP_EXT_IO_CAPABILITY_REQ: {
            if (len < 5u) break;
            if (lmp->ssp_active && lmp->ssp_we_initiated && !lmp->is_slave_sim) {
                /* Master wins simultaneous SSP initiation collision (Core Spec Vol 2 Part C §4.3.2) */
                tx_not_accepted_ext(lmp, LMP_ESCAPE_4, LMP_EXT_IO_CAPABILITY_REQ, 0x23u, tid);
                break;
            }
            memcpy(lmp->peer_iocap, &pdu[2], 3u);
            if (!lmp->ssp_active) {
                /* Peer initiated SSP: we become SSP Responder */
                lmp->ssp_active = true;
                lmp->ssp_we_initiated = false;
                lmp->auth_started = true;
                uint8_t seed[24];
                fill_rand(lmp, seed, 24u);
                btc_p192_gen_keypair(seed, lmp->priv_d_le, lmp->local_pk_le);
                fill_rand(lmp, lmp->local_nonce_le, 16u);
            }
            uint8_t res[5] = {
                (uint8_t)((LMP_ESCAPE_4 << 1) | tid),
                LMP_EXT_IO_CAPABILITY_RES,
                lmp->local_iocap[0],
                lmp->local_iocap[1],
                lmp->local_iocap[2],
            };
            tx_pdu(lmp, res, 5u);
            break;
        }
        case LMP_EXT_IO_CAPABILITY_RES: {
            if (len < 5u || !lmp->ssp_active) break;
            memcpy(lmp->peer_iocap, &pdu[2], 3u);
            if (lmp->ssp_we_initiated) {
                send_encap_pubkey_header(lmp);
            }
            break;
        }
        case LMP_EXT_POWER_CONTROL_REQ: {
            uint8_t res[3] = { (uint8_t)((LMP_ESCAPE_4 << 1) | tid), LMP_EXT_POWER_CONTROL_RES, 0xAAu /* max reached */ };
            tx_pdu(lmp, res, 3u);
            break;
        }
        case LMP_EXT_ACCEPTED:
        case LMP_EXT_NOT_ACCEPTED:
            break;
        default:
            tx_not_accepted_ext(lmp, LMP_ESCAPE_4, ext_op, 0x1Au, tid);
            break;
        }
        return;
    }

    /* ---- Standard 7-bit LMP Opcodes ---- */
    switch (opcode) {
    case LMP_VERSION_REQ: {
        uint8_t res[6] = { (uint8_t)((LMP_VERSION_RES << 1) | tid), 0x09u, 0xE5u, 0x02u, 0x50u, 0x01u };
        tx_pdu(lmp, res, 6u);
        break;
    }
    case LMP_VERSION_RES:
        break;

    case LMP_FEATURES_REQ: {
        if (len >= 9u) {
            lmp->peer_feat_rcvd = true;
            lmp->peer_afh_slave = (pdu[5] & 0x08u) != 0u;
            lmp->peer_ssp_ctrl  = (pdu[7] & 0x08u) != 0u;
        }
        uint8_t res[9];
        res[0] = (uint8_t)((LMP_FEATURES_RES << 1) | tid);
        memcpy(&res[1], kLocalFeaturesPage0, 8u);
        tx_pdu(lmp, res, 9u);
        break;
    }
    case LMP_FEATURES_RES: {
        if (len < 9u) break;
        lmp->peer_feat_rcvd = true;
        lmp->peer_afh_slave = (pdu[5] & 0x08u) != 0u;
        lmp->peer_ssp_ctrl  = (pdu[7] & 0x08u) != 0u;
        bool has_ext        = (pdu[8] & 0x80u) != 0u;

        if (!lmp->is_slave_sim && lmp->goal == BTC_LMP_GOAL_CONNECT) {
            if (has_ext) {
                uint8_t ext[12];
                ext[0] = (uint8_t)((LMP_ESCAPE_4 << 1) | my_init_tid(lmp));
                ext[1] = LMP_EXT_FEATURES_REQ;
                ext[2] = 1u;
                ext[3] = 1u;
                memcpy(&ext[4], kLocalFeaturesPage1, 8u);
                tx_pdu(lmp, ext, 12u);
            } else if (!lmp->host_conn_sent) {
                lmp->host_conn_sent = true;
                uint8_t nr[2] = { (uint8_t)((LMP_NAME_REQ << 1) | my_init_tid(lmp)), 0u };
                tx_pdu(lmp, nr, 2u);
                tx_simple(lmp, LMP_HOST_CONNECTION_REQ, my_init_tid(lmp));
            }
        }
        break;
    }

    case LMP_NAME_REQ: {
        uint8_t offset = (len >= 2u) ? pdu[1] : 0u;
        size_t total = strlen(lmp->local_name);
        if (total > 62u) total = 62u;
        uint8_t res[17];
        memset(res, 0, sizeof(res));
        res[0] = (uint8_t)((LMP_NAME_RES << 1) | tid);
        res[1] = offset;
        res[2] = (uint8_t)total;
        if (offset < total) {
            size_t rem = total - offset;
            if (rem > 14u) rem = 14u;
            memcpy(&res[3], &lmp->local_name[offset], rem);
        }
        tx_pdu(lmp, res, 17u);
        break;
    }

    case LMP_NAME_RES: {
        if (len < 17u) break;
        uint8_t offset = pdu[1];
        uint8_t total  = pdu[2];
        if (total > sizeof(lmp->remote_name) - 1u) {
            total = (uint8_t)(sizeof(lmp->remote_name) - 1u);
        }
        lmp->remote_name_total = total;
        if (offset < sizeof(lmp->remote_name) - 1u) {
            size_t max_copy = (sizeof(lmp->remote_name) - 1u) - offset;
            if (max_copy > 14u) max_copy = 14u;
            memcpy(&lmp->remote_name[offset], &pdu[3], max_copy);
            lmp->remote_name[sizeof(lmp->remote_name) - 1u] = '\0';
        }
        uint8_t next_off = (uint8_t)(offset + 14u);
        if (next_off < total && next_off < 56u) {
            uint8_t nr[2] = { (uint8_t)((LMP_NAME_REQ << 1) | my_init_tid(lmp)), next_off };
            tx_pdu(lmp, nr, 2u);
        } else {
            if (total < sizeof(lmp->remote_name)) {
                lmp->remote_name[total] = '\0';
            }
            lmp->remote_name_done = true;
            if (lmp->ops.on_remote_name && lmp->remote_name[0] != '\0') {
                lmp->ops.on_remote_name(lmp->ops.ctx, lmp->remote_name);
            }
            if (lmp->goal == BTC_LMP_GOAL_NAME_ONLY) {
                finish_setup(lmp, true, 0u);
            }
        }
        break;
    }

    case LMP_SWITCH_REQ:
        /* Soft-BR operates strictly as Master: always reject Role Switch (0x21 Role Change Not Allowed) */
        tx_not_accepted(lmp, LMP_SWITCH_REQ, 0x21u, tid);
        break;

    case LMP_SNIFF_REQ:
        tx_not_accepted(lmp, LMP_SNIFF_REQ, 0x1Au, tid);
        break;

    case LMP_MAX_SLOT:
        if (len >= 2u) {
            peer_max_slots(lmp, pdu[1], 0u, 0u);
        }
        break;

    case LMP_MAX_SLOT_REQ: {
        uint8_t req_slots = (len >= 2u) ? pdu[1] : 1u;
        if (lmp->is_slave_sim || req_slots <= 1u) {
            tx_accepted(lmp, LMP_MAX_SLOT_REQ, tid);
        } else {
            /* Refused, but not at once: see btc_lmp_on_tick. */
            lmp->peer_slot_req_waiting = true;
            lmp->peer_slot_req_tid     = tid;
        }
        break;
    }

    /* Power control (Core Spec Vol 2 Part C 4.1.3): the transmit power is fixed, and a device that cannot follow
     * a request says so with LMP_max_power or LMP_min_power. */
    case LMP_INCR_POWER_REQ:
        tx_simple(lmp, LMP_MAX_POWER, tid);
        break;

    case LMP_DECR_POWER_REQ:
        tx_simple(lmp, LMP_MIN_POWER, tid);
        break;

    /* The peer's word on its own power or on the packet types it would like: nothing to answer. */
    case LMP_MAX_POWER:
    case LMP_MIN_POWER:
    case LMP_AUTO_RATE:
    case LMP_PREFERRED_RATE:
        break;

    case LMP_HOST_CONNECTION_REQ:
        tx_accepted(lmp, LMP_HOST_CONNECTION_REQ, tid);
        break;

    case LMP_SETUP_COMPLETE:
        tx_simple(lmp, LMP_SETUP_COMPLETE, my_init_tid(lmp));
        break;

    case LMP_CLKOFFSET_REQ: {
        uint8_t res[3] = { (uint8_t)((LMP_CLKOFFSET_RES << 1) | tid), 0u, 0u };
        tx_pdu(lmp, res, 3u);
        break;
    }

    case LMP_TIMING_ACCURACY_REQ: {
        uint8_t res[3] = { (uint8_t)((LMP_TIMING_ACCURACY_RES << 1) | tid), 20u, 10u };
        tx_pdu(lmp, res, 3u);
        break;
    }

    case LMP_SUPERVISION_TIMEOUT:
    case LMP_SLOT_OFFSET:
    case LMP_SET_AFH:
        break;

    case LMP_PAGE_MODE_REQ:
    case LMP_PAGE_SCAN_MODE_REQ:
        tx_accepted(lmp, opcode, tid);
        break;

    case LMP_DETACH: {
        uint8_t err = (len >= 2u) ? pdu[1] : 0x13u;
        finish_setup(lmp, false, err);
        break;
    }

    /* ---- Authentication & Legacy PIN ---- */
    case LMP_AU_RAND: {
        if (len < 17u) break;
        if (!lmp->has_link_key) {
            tx_not_accepted(lmp, LMP_AU_RAND, 0x06u /* PIN or Key Missing */, tid);
            break;
        }
        uint8_t sres[4];
        br_crypto_e1(lmp->link_key, &pdu[1], lmp->local_bdaddr, sres, lmp->latest_aco);
        lmp->has_aco = true;
        uint8_t res[5];
        res[0] = (uint8_t)((LMP_SRES << 1) | tid);
        memcpy(&res[1], sres, 4u);
        tx_pdu(lmp, res, 5u);
        break;
    }

    case LMP_SRES: {
        if (len < 5u || !lmp->waiting_sres) break;
        lmp->waiting_sres = false;
        if (memcmp(&pdu[1], lmp->expected_sres, 4u) == 0) {
            memcpy(lmp->latest_aco, lmp->pending_aco, 12u);
            lmp->has_aco = true;
            lmp->authenticated = true;
            begin_encryption_flow(lmp);
        } else {
            /* Stale Link Key: clear and fall back to fresh pairing! */
            btc_lmp_clear_link_key(lmp);
            if (lmp->peer_ssp_ctrl && lmp->peer_ssp_host) {
                start_ssp_pairing(lmp);
            } else {
                start_legacy_pin_pairing(lmp);
            }
        }
        break;
    }

    case LMP_IN_RAND: {
        if (len < 17u) break;
        lmp->legacy_active = true;
        lmp->legacy_we_initiated = false;
        lmp->comb_sent = false;
        /* Peer sent LMP_in_rand -> we are Responder -> E22 uses our local BD_ADDR */
        br_crypto_e22((const uint8_t *)lmp->pin_code, lmp->pin_len, &pdu[1], lmp->local_bdaddr, lmp->k_init);
        tx_accepted(lmp, LMP_IN_RAND, tid);
        break;
    }

    case LMP_COMB_KEY: {
        if (len < 17u || !lmp->legacy_active) break;
        if (!lmp->comb_sent) {
            send_comb_key(lmp);
        }
        uint8_t peer_rand[16], comb_kb[16];
        for (int i = 0; i < 16; i++) {
            peer_rand[i] = (uint8_t)(pdu[1 + i] ^ lmp->k_init[i]);
        }
        br_crypto_e21(peer_rand, lmp->peer_bdaddr, comb_kb);
        for (int i = 0; i < 16; i++) {
            lmp->link_key[i] = (uint8_t)(lmp->comb_ka_local[i] ^ comb_kb[i]);
        }
        lmp->has_link_key = true;
        lmp->legacy_active = false;
        if (lmp->ops.on_link_key) {
            lmp->ops.on_link_key(lmp->ops.ctx, lmp->peer_bdaddr, lmp->link_key);
        }
        if (!lmp->is_slave_sim) {
            start_au_rand_challenge(lmp);
        }
        break;
    }

    /* ---- Encryption Negotiation ---- */
    case LMP_ENCRYPTION_MODE_REQ: {
        uint8_t mode = (len >= 2u) ? pdu[1] : 1u;
        if (mode <= 2u) {
            tx_accepted(lmp, LMP_ENCRYPTION_MODE_REQ, tid);
        } else {
            tx_not_accepted(lmp, LMP_ENCRYPTION_MODE_REQ, 0x20u, tid);
        }
        break;
    }

    case LMP_ENCRYPTION_KEY_SIZE_REQ: {
        uint8_t ksz = (len >= 2u) ? pdu[1] : 16u;
        if (ksz >= 1u && ksz <= 16u) {
            lmp->enc_key_size = ksz;
            tx_accepted(lmp, LMP_ENCRYPTION_KEY_SIZE_REQ, tid);
        } else {
            tx_not_accepted(lmp, LMP_ENCRYPTION_KEY_SIZE_REQ, 0x20u, tid);
        }
        break;
    }

    case LMP_START_ENCRYPTION_REQ: {
        if (len < 17u) break;
        uint8_t cof[12];
        if (lmp->has_aco) {
            memcpy(cof, lmp->latest_aco, 12u);
        } else {
            const uint8_t *resp_bd = lmp->is_slave_sim ? lmp->local_bdaddr : lmp->peer_bdaddr;
            memcpy(&cof[0], resp_bd, 6u);
            memcpy(&cof[6], resp_bd, 6u);
        }
        uint8_t kc[16];
        br_crypto_e3(lmp->link_key, &pdu[1], cof, kc);
        br_crypto_kc_prime(kc, lmp->enc_key_size, lmp->last_kc_prime);
        tx_accepted(lmp, LMP_START_ENCRYPTION_REQ, tid);
        lmp->encrypted = true;
        break;
    }

    case LMP_STOP_ENCRYPTION_REQ:
        lmp->encrypted = false;
        tx_accepted(lmp, LMP_STOP_ENCRYPTION_REQ, tid);
        break;

    /* ---- Secure Simple Pairing (SSP P-192 ECDH) ---- */
    case LMP_ENCAPSULATED_HEADER: {
        if (len < 4u || !lmp->ssp_active) break;
        if (pdu[1] == 1u && pdu[2] == 1u && pdu[3] == 48u) {
            lmp->rx_encap_bytes = 0u;
            tx_accepted(lmp, LMP_ENCAPSULATED_HEADER, tid);
        } else {
            tx_not_accepted(lmp, LMP_ENCAPSULATED_HEADER, 0x20u, tid);
        }
        break;
    }

    case LMP_ENCAPSULATED_PAYLOAD: {
        if (len < 17u || !lmp->ssp_active) break;
        if (lmp->rx_encap_bytes + 16u <= 48u) {
            memcpy(&lmp->peer_pk_le[lmp->rx_encap_bytes], &pdu[1], 16u);
            lmp->rx_encap_bytes = (uint8_t)(lmp->rx_encap_bytes + 16u);
        }
        tx_accepted(lmp, LMP_ENCAPSULATED_PAYLOAD, tid);

        if (lmp->rx_encap_bytes == 48u && !lmp->peer_pk_rcvd) {
            lmp->peer_pk_rcvd = true;
            if (!btc_p192_compute_dhkey(lmp->priv_d_le, lmp->peer_pk_le, lmp->dhkey_le)) {
                finish_setup(lmp, false, 0x05u /* Invalid peer P-192 point */);
                break;
            }
            lmp->dhkey_ready = true;
            if (!lmp->ssp_we_initiated && !lmp->local_pk_sent) {
                /* SSP Responder now sends its 48-byte P-192 public key */
                send_encap_pubkey_header(lmp);
            }
        }
        break;
    }

    case LMP_SIMPLE_PAIRING_CONFIRM: {
        if (len < 17u || !lmp->ssp_active) break;
        memcpy(lmp->peer_confirm_le, &pdu[1], 16u);
        lmp->peer_confirm_rcvd = true;
        if (lmp->ssp_we_initiated && !lmp->local_nonce_sent) {
            /* Numeric Comparison / Just Works: Initiator reveals Na directly on receiving Cb */
            lmp->local_nonce_sent = true;
            uint8_t p[17];
            p[0] = (uint8_t)((LMP_SIMPLE_PAIRING_NUMBER << 1) | my_init_tid(lmp));
            memcpy(&p[1], lmp->local_nonce_le, 16u);
            tx_pdu(lmp, p, 17u);
        } else if (!lmp->ssp_we_initiated) {
            /* If peer used Passkey/OOB confirm first, accept cleanly */
            tx_accepted(lmp, LMP_SIMPLE_PAIRING_CONFIRM, tid);
        }
        break;
    }

    case LMP_SIMPLE_PAIRING_NUMBER: {
        if (len < 17u || !lmp->ssp_active) break;
        memcpy(lmp->peer_nonce_le, &pdu[1], 16u);
        lmp->peer_nonce_rcvd = true;

        if (lmp->ssp_we_initiated) {
            /* Verify Responder's commitment Cb == f1(PKbx, PKax, Nb, 0) */
            uint8_t expected_cb[16];
            br_ssp_f1(&lmp->peer_pk_le[0], &lmp->local_pk_le[0], lmp->peer_nonce_le, 0u, expected_cb);
            if (lmp->peer_confirm_rcvd && memcmp(expected_cb, lmp->peer_confirm_le, 16u) != 0) {
                tx_not_accepted(lmp, LMP_SIMPLE_PAIRING_NUMBER, 0x05u /* Authentication Failure */, tid);
                finish_setup(lmp, false, 0x05u);
                break;
            }
            tx_accepted(lmp, LMP_SIMPLE_PAIRING_NUMBER, tid);

            /* Authentication Stage 2: Initiator sends Ea = f3(DHKey, Na, Nb, 0, IOcapA, A, B) */
            uint8_t r_zero[16] = {0};
            uint8_t ea[16];
            br_ssp_f3(lmp->dhkey_le, lmp->local_nonce_le, lmp->peer_nonce_le,
                      r_zero, lmp->local_iocap, lmp->local_bdaddr, lmp->peer_bdaddr, ea);
            lmp->dhkey_check_sent = true;
            uint8_t p[17];
            p[0] = (uint8_t)((LMP_DHKEY_CHECK << 1) | my_init_tid(lmp));
            memcpy(&p[1], ea, 16u);
            tx_pdu(lmp, p, 17u);
        } else {
            /* SSP Responder received Na: accept and send Nb */
            tx_accepted(lmp, LMP_SIMPLE_PAIRING_NUMBER, tid);
            if (!lmp->local_nonce_sent) {
                lmp->local_nonce_sent = true;
                uint8_t p[17];
                p[0] = (uint8_t)((LMP_SIMPLE_PAIRING_NUMBER << 1) | my_init_tid(lmp));
                memcpy(&p[1], lmp->local_nonce_le, 16u);
                tx_pdu(lmp, p, 17u);
            }
        }
        break;
    }

    case LMP_DHKEY_CHECK: {
        if (len < 17u || !lmp->ssp_active || !lmp->dhkey_ready) break;
        uint8_t r_zero[16] = {0};
        if (lmp->ssp_we_initiated) {
            /* Initiator verifies Responder's Eb = f3(DHKey, Nb, Na, 0, IOcapB, B, A) */
            uint8_t exp_eb[16];
            br_ssp_f3(lmp->dhkey_le, lmp->peer_nonce_le, lmp->local_nonce_le,
                      r_zero, lmp->peer_iocap, lmp->peer_bdaddr, lmp->local_bdaddr, exp_eb);
            if (memcmp(exp_eb, &pdu[1], 16u) != 0) {
                tx_not_accepted(lmp, LMP_DHKEY_CHECK, 0x05u, tid);
                finish_setup(lmp, false, 0x05u);
                break;
            }
            tx_accepted(lmp, LMP_DHKEY_CHECK, tid);
            derive_ssp_link_key(lmp);
            lmp->ssp_active = false;
            if (!lmp->is_slave_sim) {
                start_au_rand_challenge(lmp);
            }
        } else {
            /* Responder verifies Initiator's Ea = f3(DHKey, Na, Nb, 0, IOcapA, A, B) */
            uint8_t exp_ea[16];
            br_ssp_f3(lmp->dhkey_le, lmp->peer_nonce_le, lmp->local_nonce_le,
                      r_zero, lmp->peer_iocap, lmp->peer_bdaddr, lmp->local_bdaddr, exp_ea);
            if (memcmp(exp_ea, &pdu[1], 16u) != 0) {
                tx_not_accepted(lmp, LMP_DHKEY_CHECK, 0x05u, tid);
                finish_setup(lmp, false, 0x05u);
                break;
            }
            tx_accepted(lmp, LMP_DHKEY_CHECK, tid);
            /* Responder now sends Eb = f3(DHKey, Nb, Na, 0, IOcapB, B, A) */
            uint8_t eb[16];
            br_ssp_f3(lmp->dhkey_le, lmp->local_nonce_le, lmp->peer_nonce_le,
                      r_zero, lmp->local_iocap, lmp->local_bdaddr, lmp->peer_bdaddr, eb);
            lmp->dhkey_check_sent = true;
            uint8_t p[17];
            p[0] = (uint8_t)((LMP_DHKEY_CHECK << 1) | my_init_tid(lmp));
            memcpy(&p[1], eb, 16u);
            tx_pdu(lmp, p, 17u);
        }
        break;
    }

    /* ---- LMP_accepted / LMP_not_accepted ---- */
    case LMP_ACCEPTED: {
        if (len < 2u) break;
        uint8_t acc_op = pdu[1];
        switch (acc_op) {
        case LMP_MAX_SLOT_REQ:
            peer_max_slots(lmp, 3u, 1u, 0u);
            /* Sound trial 10: right after this LMP_accepted the speaker's packets came in with a bad CRC, 50 a
             * second, for as long as the setup waited. What we may send says nothing about what it may send. */
            tx_max_slot_1(lmp);
            break;
        case LMP_HOST_CONNECTION_REQ:
            lmp->host_conn_accepted = true;
            if (lmp->encrypted) {
                finish_setup(lmp, true, 0u);
            } else {
                start_auth_or_pairing_if_ready(lmp);
            }
            break;
        case LMP_IN_RAND:
            if (lmp->legacy_active && lmp->legacy_we_initiated) {
                send_comb_key(lmp);
            }
            break;
        case LMP_ENCRYPTION_MODE_REQ: {
            uint8_t p[2] = { (uint8_t)((LMP_ENCRYPTION_KEY_SIZE_REQ << 1) | my_init_tid(lmp)), lmp->enc_key_size };
            tx_pdu(lmp, p, 2u);
            break;
        }
        case LMP_ENCRYPTION_KEY_SIZE_REQ:
            send_start_enc_to_controller(lmp);
            break;
        case LMP_ENCAPSULATED_HEADER:
            send_next_encap_pubkey_chunk(lmp);
            break;
        case LMP_ENCAPSULATED_PAYLOAD:
            if (lmp->tx_encap_idx < 3u) {
                send_next_encap_pubkey_chunk(lmp);
            } else {
                lmp->local_pk_sent = true;
                if (!lmp->ssp_we_initiated && lmp->peer_pk_rcvd) {
                    /* SSP Responder finished sending PKb -> send Cb = f1(PKbx, PKax, Nb, 0) */
                    uint8_t cb[16];
                    br_ssp_f1(&lmp->local_pk_le[0], &lmp->peer_pk_le[0], lmp->local_nonce_le, 0u, cb);
                    uint8_t p[17];
                    p[0] = (uint8_t)((LMP_SIMPLE_PAIRING_CONFIRM << 1) | my_init_tid(lmp));
                    memcpy(&p[1], cb, 16u);
                    tx_pdu(lmp, p, 17u);
                }
            }
            break;
        case LMP_DHKEY_CHECK:
            if (!lmp->ssp_we_initiated && lmp->dhkey_check_sent) {
                derive_ssp_link_key(lmp);
                lmp->ssp_active = false;
            }
            break;
        default:
            break;
        }
        break;
    }

    case LMP_NOT_ACCEPTED: {
        if (len < 3u) break;
        uint8_t rej_op = pdu[1];
        uint8_t err    = pdu[2];
        switch (rej_op) {
        case LMP_MAX_SLOT_REQ:
            peer_max_slots(lmp, lmp->peer_max_slots_allowed, 2u, err); /* a refusal leaves what was allowed */
            tx_max_slot_1(lmp);
            break;
        case LMP_HOST_CONNECTION_REQ:
            if (err == 0x05u || err == 0x06u) {
                /* Speaker requires authentication before accepting host connection */
                lmp->host_conn_rejected_auth = true;
                start_auth_or_pairing_if_ready(lmp);
            } else {
                finish_setup(lmp, false, err);
            }
            break;
        case LMP_AU_RAND:
            /* Saved Link Key missing on speaker (0x06): automatically run fresh SSP or Legacy PIN pairing! */
            lmp->waiting_sres = false;
            btc_lmp_clear_link_key(lmp);
            if (lmp->peer_ssp_ctrl && lmp->peer_ssp_host) {
                start_ssp_pairing(lmp);
            } else {
                start_legacy_pin_pairing(lmp);
            }
            break;
        case LMP_IN_RAND:
        case LMP_SRES:
            if (!lmp->tried_fallback_pin && strcmp(lmp->pin_code, "0000") == 0) {
                lmp->tried_fallback_pin = true;
                strcpy(lmp->pin_code, "1234");
                lmp->pin_len = 4u;
                start_legacy_pin_pairing(lmp);
            } else {
                finish_setup(lmp, false, err);
            }
            break;
        default:
            break;
        }
        break;
    }

    default:
        tx_not_accepted(lmp, opcode, 0x1Au /* Unsupported Remote Feature / LMP PDU */, tid);
        break;
    }
}
