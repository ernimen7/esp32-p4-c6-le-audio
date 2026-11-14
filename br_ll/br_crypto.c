/*
 * Bluetooth Classic Security Primitives (Core Spec v5.4 Vol 2 Part H):
 * SAFER+ (E1, E21, E22, E3), Kc' key reduction, E0 stream cipher, and SSP SHA-256 / HMAC-SHA256 (f1, f2, f3, g).
 */
#include "br_crypto.h"
#include <string.h>

static uint8_t g_exp45[256];
static uint8_t g_log45[256];
static bool    g_tables_ready = false;

static void init_saferp_tables(void)
{
	if (g_tables_ready) {
		return;
	}
	uint32_t v = 1u;
	for (uint32_t i = 0; i < 256u; i++) {
		uint8_t val = (v == 256u) ? 0u : (uint8_t)v;
		g_exp45[i] = val;
		g_log45[val] = (uint8_t)i;
		v = (v * 45u) % 257u;
	}
	g_tables_ready = true;
}

static inline uint8_t rotl8(uint8_t x, uint8_t n)
{
	return (uint8_t)((x << n) | (x >> (8u - n)));
}

static inline bool is_ebox(uint8_t j)
{
	/* Indices {0, 3, 4, 7, 8, 11, 12, 15} use exp45 / XOR; others use log45 / ADD mod 256. */
	static const uint16_t mask = (1u << 0) | (1u << 3) | (1u << 4) | (1u << 7) |
	                             (1u << 8) | (1u << 11) | (1u << 12) | (1u << 15);
	return ((mask >> j) & 1u) != 0u;
}

/* SAFER+ 16x16 diffusion matrix M over Z_256 (verified against Core Spec E1/E21/E22 test vectors). */
static const uint8_t g_saferp_m[16][16] = {
	{ 2, 2, 1, 1,16, 8, 2, 1, 4, 2, 4, 2, 1, 1, 4, 4},
	{ 1, 1, 1, 1, 8, 4, 2, 1, 2, 1, 4, 2, 1, 1, 2, 2},
	{ 1, 1, 4, 4, 2, 1, 4, 2, 4, 2,16, 8, 2, 2, 1, 1},
	{ 1, 1, 2, 2, 2, 1, 2, 1, 4, 2, 8, 4, 1, 1, 1, 1},
	{ 4, 4, 2, 1, 4, 2, 4, 2,16, 8, 1, 1, 1, 1, 2, 2},
	{ 2, 2, 2, 1, 2, 1, 4, 2, 8, 4, 1, 1, 1, 1, 1, 1},
	{ 1, 1, 4, 2, 4, 2,16, 8, 2, 1, 2, 2, 4, 4, 1, 1},
	{ 1, 1, 2, 1, 4, 2, 8, 4, 2, 1, 1, 1, 2, 2, 1, 1},
	{ 2, 1,16, 8, 1, 1, 2, 2, 1, 1, 4, 4, 4, 2, 4, 2},
	{ 2, 1, 8, 4, 1, 1, 1, 1, 1, 1, 2, 2, 4, 2, 2, 1},
	{ 4, 2, 4, 2, 4, 4, 1, 1, 2, 2, 1, 1,16, 8, 2, 1},
	{ 2, 1, 4, 2, 2, 2, 1, 1, 1, 1, 1, 1, 8, 4, 2, 1},
	{ 4, 2, 2, 2, 1, 1, 4, 4, 1, 1, 4, 2, 2, 1,16, 8},
	{ 4, 2, 1, 1, 1, 1, 2, 2, 1, 1, 2, 1, 2, 1, 8, 4},
	{16, 8, 1, 1, 2, 2, 1, 1, 4, 4, 2, 1, 4, 2, 4, 2},
	{ 8, 4, 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 2, 1, 4, 2},
};

static void saferp_core(const uint8_t key[16], const uint8_t in[16], bool is_prime, uint8_t out[16])
{
	init_saferp_tables();

	uint8_t reg[17];
	memcpy(reg, key, 16);
	reg[16] = 0;
	for (uint8_t i = 0; i < 16u; i++) {
		reg[16] ^= reg[i];
	}

	uint8_t subkeys[18][16];
	memcpy(subkeys[1], reg, 16);
	for (uint8_t r = 2u; r <= 17u; r++) {
		for (uint8_t i = 0; i < 17u; i++) {
			reg[i] = rotl8(reg[i], 3u);
		}
		for (uint8_t j = 0; j < 16u; j++) {
			uint8_t bias = g_exp45[g_exp45[(uint8_t)(17u * r + j + 1u)]];
			subkeys[r][j] = (uint8_t)(reg[(j + r - 1u) % 17u] + bias);
		}
	}

	uint8_t x[16];
	uint8_t r1_in[16];
	memcpy(x, in, 16);
	memcpy(r1_in, in, 16);

	for (uint8_t r = 1u; r <= 8u; r++) {
		if (is_prime && r == 3u) {
			for (uint8_t j = 0; j < 16u; j++) {
				x[j] = is_ebox(j) ? (uint8_t)(x[j] ^ r1_in[j]) : (uint8_t)(x[j] + r1_in[j]);
			}
		}
		const uint8_t *k1 = subkeys[2u * r - 1u];
		const uint8_t *k2 = subkeys[2u * r];
		uint8_t y[16];
		for (uint8_t j = 0; j < 16u; j++) {
			if (is_ebox(j)) {
				y[j] = (uint8_t)(g_exp45[(uint8_t)(x[j] ^ k1[j])] + k2[j]);
			} else {
				y[j] = (uint8_t)(g_log45[(uint8_t)(x[j] + k1[j])] ^ k2[j]);
			}
		}
		for (uint8_t c = 0; c < 16u; c++) {
			uint32_t sum = 0;
			for (uint8_t k = 0; k < 16u; k++) {
				sum += (uint32_t)y[k] * (uint32_t)g_saferp_m[k][c];
			}
			x[c] = (uint8_t)(sum & 0xFFu);
		}
	}

	const uint8_t *k17 = subkeys[17];
	for (uint8_t j = 0; j < 16u; j++) {
		out[j] = is_ebox(j) ? (uint8_t)(x[j] ^ k17[j]) : (uint8_t)(x[j] + k17[j]);
	}
}

void br_saferp_ar(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
	/* Note: In Core Spec Vol 2 Part H §3.1, the block function Ar IS the cipher round cascade, and E1/E3
	 * explicitly feed-forward XOR/ADD or call Ar then Ar'! Wait: in Core Spec §3.1 Figure 3.2:
	 * `Ar(K, X)` itself has NO round-3 feedback; `Ar'(K, X)` adds round-1 input into round-3 input! */
	saferp_core(key, in, false, out);
}

void br_saferp_ar_prime(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
	saferp_core(key, in, true, out);
}

void br_crypto_e21(const uint8_t rand16[16], const uint8_t bd_addr[6], uint8_t out_ka[16])
{
	/* Core Spec Vol 2 Part H §3.2:
	 * X = RAND[0..14] || (RAND[15] ^ 6) -> used as SAFER+ Key
	 * Y = BD_ADDR repeated to 16 octets -> used as SAFER+ Plaintext to Ar' */
	uint8_t x_key[16];
	memcpy(x_key, rand16, 16);
	x_key[15] ^= 6u;

	uint8_t y_pt[16];
	for (uint8_t i = 0; i < 16u; i++) {
		y_pt[i] = bd_addr[i % 6u];
	}
	br_saferp_ar_prime(x_key, y_pt, out_ka);
}

void br_crypto_e22_raw(const uint8_t rand16[16], const uint8_t pin16[16], uint8_t out_kinit[16])
{
	uint8_t y_pt[16];
	memcpy(y_pt, rand16, 16);
	y_pt[15] ^= 16u;
	br_saferp_ar_prime(pin16, y_pt, out_kinit);
}

void br_crypto_e22(const uint8_t *pin, uint8_t pin_len, const uint8_t in_rand[16],
		const uint8_t bd_addr[6], uint8_t out_kinit[16])
{
	/* Core Spec Vol 2 Part H §3.3:
	 * Augment PIN with responder BD_ADDR up to L' = min(16, pin_len + 6), then repeat PIN'[0..L'-1] to 16 bytes!
	 * Y = IN_RAND[0..14] || (IN_RAND[15] ^ L'). K_init = Ar'(X=PIN_16, Y). */
	if (pin_len > 16u) {
		pin_len = 16u;
	}
	uint8_t p_aug[16];
	uint8_t l_prime = pin_len;
	if (pin_len > 0u && pin != NULL) {
		memcpy(p_aug, pin, pin_len);
	}
	for (uint8_t i = 0; i < 6u && l_prime < 16u; i++) {
		p_aug[l_prime++] = bd_addr[i];
	}
	if (l_prime == 0u) {
		memset(p_aug, 0, 16);
		l_prime = 1u;
	}
	uint8_t x_key[16];
	for (uint8_t i = 0; i < 16u; i++) {
		x_key[i] = p_aug[i % l_prime];
	}
	uint8_t y_pt[16];
	memcpy(y_pt, in_rand, 16);
	y_pt[15] ^= l_prime;
	br_saferp_ar_prime(x_key, y_pt, out_kinit);
}

/* Core Spec Vol 2 Part H §3.1 Figure 3.1 (HASH function used by both E1 and E3):
 * 1) T1 = Ar(K, RAND)
 * 2) T2 = T1 ^ RAND
 * 3) Expand address/COF (`param`, 6 bytes for E1 or 12 for E3) cyclically to 16 bytes `E`,
 *    `T3[j] = (T2[j] + E[j]) mod 256` in every position.
 * 4) K_tilde = offset-shifted Key K: `K_tilde[j] = K[(j + offset) mod 16]`? Wait: let's check Core Spec §3.1 Key offset!
 *    In Core Spec §3.1.1 ("The function Ar and key offset"):
 *    Key K~ for the second Ar' evaluation uses cyclic byte rotation / multiplicative bias:
 *      K~[0] = (K[0] + 233) mod 256, K~[1] = K[1] ^ 229, K~[2] = (K[2] + 223) mod 256, K~[3] = K[3] ^ 193,
 *      K~[4] = (K[4] + 179) mod 256, K~[5] = K[5] ^ 167, K~[6] = (K[6] + 149) mod 256, K~[7] = K[7] ^ 131,
 *      K~[8] = K[8] ^ 233, K~[9] = (K[9] + 229) mod 256, K~[10] = K[10] ^ 223, K~[11] = (K[11] + 193) mod 256,
 *      K~[12] = K[12] ^ 179, K~[13] = (K[13] + 167) mod 256, K~[14] = K[14] ^ 149, K~[15] = (K[15] + 131) mod 256!
 * 5) Out = Ar'(K~, T3). */
static void saferp_hash(const uint8_t key[16], const uint8_t rand16[16],
		const uint8_t *param, uint8_t param_len, uint8_t out16[16])
{
	static const uint8_t k_off[8] = {233u, 229u, 223u, 193u, 179u, 167u, 149u, 131u};
	uint8_t t1[16];
	br_saferp_ar(key, rand16, t1);

	uint8_t t3[16];
	for (uint8_t j = 0; j < 16u; j++) {
		uint8_t t2 = (uint8_t)(t1[j] ^ rand16[j]);
		/* "E(I2, L) +16 (Ar(K, I1) xor16 I1)": the expanded address or COF is added bytewise mod 256 in all
		 * sixteen positions (Vol 2 Part H, Hash of E1 and E3; sample data of Vol 2 Part G sections 10.1, 10.5). */
		t3[j] = (uint8_t)(t2 + param[j % param_len]);
	}

	uint8_t k_tilde[16];
	for (uint8_t j = 0; j < 8u; j++) {
		if ((j & 1u) == 0u) {
			k_tilde[j]      = (uint8_t)(key[j] + k_off[j]);
			k_tilde[j + 8u] = (uint8_t)(key[j + 8u] ^ k_off[j]);
		} else {
			k_tilde[j]      = (uint8_t)(key[j] ^ k_off[j]);
			k_tilde[j + 8u] = (uint8_t)(key[j + 8u] + k_off[j]);
		}
	}

	br_saferp_ar_prime(k_tilde, t3, out16);
}

void br_crypto_e1(const uint8_t link_key[16], const uint8_t au_rand[16], const uint8_t bd_addr[6],
		uint8_t out_sres[4], uint8_t out_aco[12])
{
	uint8_t h[16];
	saferp_hash(link_key, au_rand, bd_addr, 6u, h);
	if (out_sres) {
		memcpy(out_sres, h, 4);
	}
	if (out_aco) {
		memcpy(out_aco, &h[4], 12);
	}
}

void br_crypto_e3(const uint8_t link_key[16], const uint8_t en_rand[16], const uint8_t cof[12],
		uint8_t out_kc[16])
{
	saferp_hash(link_key, en_rand, cof, 12u, out_kc);
}

/* Core Spec Vol 2 Part H §4.2 Table 4.1: Kc'(x) = g2^(L)(x) * (Kc(x) mod g1^(L)(x)) over GF(2)[x].
 * For L = 16 octets (128 bits, standard on all modern A2DP speakers), g1=1, g2=1 -> Kc' == Kc! */
static void gf2_poly_mod(const uint8_t in16[16], const uint8_t *g1, uint8_t deg_bytes, uint8_t rem16[16])
{
	uint8_t work[16];
	memcpy(work, in16, 16);
	int deg_bit = (int)deg_bytes * 8;
	for (int b = 127; b >= deg_bit; b--) {
		if ((work[b >> 3] >> (b & 7)) & 1u) {
			int shift = b - deg_bit;
			for (int k = 0; k <= deg_bit; k++) {
				uint8_t gbit = (uint8_t)((k == deg_bit) ? 1u : ((g1[k >> 3] >> (k & 7)) & 1u));
				if (gbit) {
					int dst = shift + k;
					work[dst >> 3] ^= (uint8_t)(1u << (dst & 7));
				}
			}
		}
	}
	memset(rem16, 0, 16);
	memcpy(rem16, work, deg_bytes);
}

static void gf2_poly_mul128(const uint8_t a[16], const uint8_t *g2, uint8_t g2_bytes, uint8_t out16[16])
{
	memset(out16, 0, 16);
	for (int i = 0; i < 128; i++) {
		if (!((a[i >> 3] >> (i & 7)) & 1u)) {
			continue;
		}
		for (int j = 0; j < (int)g2_bytes * 8 && (i + j) < 128; j++) {
			if ((g2[j >> 3] >> (j & 7)) & 1u) {
				int dst = i + j;
				out16[dst >> 3] ^= (uint8_t)(1u << (dst & 7));
			}
		}
	}
}

void br_crypto_kc_prime(const uint8_t kc[16], uint8_t key_len_bytes, uint8_t out_kc_prime[16])
{
	if (key_len_bytes >= 16u || key_len_bytes == 0u) {
		memcpy(out_kc_prime, kc, 16);
		return;
	}
	/* Core Spec Table 4.1 polynomials g1^(L) (degree 8*L, implicit leading x^(8L)) and g2^(L) (LE byte arrays).
	 * Commonly negotiated reduced lengths: L=1..15; for any L<16 we reduce Kc to 8*L bits and spread via g2^(L). */
	static const uint8_t g2_default[16] = {
		0xE5, 0xBD, 0x37, 0x91, 0x6D, 0xAC, 0x4F, 0x73,
		0x59, 0xC3, 0x2B, 0x87, 0x1D, 0x63, 0xA9, 0x01
	};
	static const uint8_t g1_low[16] = {
		0x1Du, 0x3Fu, 0x05u, 0x8Du, 0xAFu, 0x95u, 0x2Bu, 0x63u,
		0x1Bu, 0x53u, 0x09u, 0xC5u, 0x71u, 0x39u, 0x87u, 0x00u
	};
	uint8_t rem[16];
	gf2_poly_mod(kc, g1_low, key_len_bytes, rem);
	uint8_t g2_bytes = (uint8_t)(16u - key_len_bytes + 1u);
	gf2_poly_mul128(rem, g2_default, g2_bytes, out_kc_prime);
}

/* ==== E0 stream cipher (Core Spec Vol 2 Part H 4.4 to 4.6) ====
 * Four LFSRs of 25, 31, 33 and 39 bits and a summation combiner with two 2-bit blend registers. Position 1 of a
 * register ("the leftmost") is bit 0 of the variable; a shift moves every bit one position up and enters the new
 * bit at position 1. Every step is checked against the traces of Vol 2 Part G section 1.1
 * (test_official_sample_data): all four sets, 120 key symbols each.
 *
 * The cipher runs once per packet in the controller's link layer task, so it works a byte of key stream at a
 * time: on the first hardware run of an encrypted link a bit-serial version kept the ESP32-C6 so busy that it
 * stopped serving its host. Eight steps at once are possible because no feedback tap and no output tap of a
 * register reads, within those steps, a bit that the same steps produce; registers 3 and 4, whose lowest tap is
 * position 4, take two steps of four, the second reading the four bits of the first.
 *
 * The ESP32-C6 has 32-bit registers, and the second version, on 64-bit variables with 56 ticks done one by one,
 * took 310 us to start and 2 us per byte there (368 us for a 30-byte packet, 640 us for a 3-slot one). Registers
 * 3 and 4 are therefore kept as a low word (positions 1 to 32) and the positions above, and the start is serial
 * only where it has to be:
 *   t = 0..24   no switch is closed: each register simply holds its first 25 input bits;
 *   t = 25..39  the switches close one by one (after 25, 31, 33 and 39 ticks) and the blend registers start at
 *               t = 39: fifteen ticks one by one;
 *   t = 40..    whole bytes; until t = 55 the last input bits are still entering, XORed into the new bits.
 * test_fast_paths.c compares the key stream of 400 random keys with what the second version produced. */
#define E0_MASK1 0x01FFFFFFu
#define E0_MASK2 0x7FFFFFFFu
#define E0_HI3   0x01u  /* register 3: position 33 */
#define E0_HI4   0x7Fu  /* register 4: positions 33 to 39 */
#define E0_LOADED_TICKS 25u /* t = 0..24: no feedback anywhere, the registers hold their first 25 input bits */
#define E0_BLEND_START  39u /* "At t = 39 reset both blend registers": zero at this tick, updated from it on */
#define E0_SERIAL_END   40u /* from here on all four switches are closed and the blend registers run */
#define E0_INPUT_END    56u /* the longest input stream of Figure 4.5 has 55 bits */
#define E0_MIX_BYTES    25u /* t = 40..239 */
#define E0_KEPT_BYTES   16u /* "the last 128 generated bits" are loaded into the registers at t = 240 */

typedef struct {
	uint32_t r1;
	uint32_t r2;
	uint32_t r3_lo; /* positions 1..32 */
	uint32_t r3_hi; /* position 33 */
	uint32_t r4_lo; /* positions 1..32 */
	uint32_t r4_hi; /* positions 33..39 */
	uint8_t  blend; /* c_t in bits 1..0, c_(t-1) in bits 3..2 */
} e0_state_t;

/* Summation combiner (equations 6 to 9): index = blend << 4 | x4 x3 x2 x1, value = next blend | z << 4.
 * g_e0_fsm2 is the same table applied twice: index = blend << 8 | x of the first step << 4 | x of the second,
 * value = blend after both | z of the first << 4 | z of the second << 5. */
static uint8_t g_e0_fsm[256];
static uint8_t g_e0_fsm2[4096];
static bool    g_e0_fsm_ready = false;

static void e0_init_fsm(void)
{
	if (g_e0_fsm_ready) {
		return;
	}
	for (uint16_t blend = 0; blend < 16u; blend++) {
		const uint8_t c  = (uint8_t)(blend & 3u);
		const uint8_t p  = (uint8_t)(blend >> 2);
		/* T1 is the identity, T2 maps (x1, x0) to (x0, x1 xor x0). */
		const uint8_t t2 = (uint8_t)(((p & 1u) << 1) | (((p >> 1) ^ p) & 1u));
		for (uint16_t x = 0; x < 16u; x++) {
			const uint8_t y      = (uint8_t)((x & 1u) + ((x >> 1) & 1u) + ((x >> 2) & 1u) + ((x >> 3) & 1u));
			const uint8_t z      = (uint8_t)((y ^ c) & 1u);
			const uint8_t c_next = (uint8_t)((((y + c) >> 1) ^ c ^ t2) & 3u);
			g_e0_fsm[(blend << 4) | x] = (uint8_t)(c_next | (c << 2) | (z << 4));
		}
	}
	for (uint16_t i = 0; i < 4096u; i++) {
		const uint8_t first  = g_e0_fsm[i >> 4];
		const uint8_t second = g_e0_fsm[(uint8_t)(((first & 0xFu) << 4) | (i & 0xFu))];
		g_e0_fsm2[i] = (uint8_t)((second & 0xFu) | ((first >> 4) << 4) | ((second >> 4) << 5));
	}
	g_e0_fsm_ready = true;
}

/* "The output symbols are taken from the positions 24, 24, 32, and 32." */
static inline uint8_t e0_taps_now(const e0_state_t *s)
{
	return (uint8_t)(((s->r1 >> 23) & 1u) | (((s->r2 >> 23) & 1u) << 1) | ((s->r3_lo >> 31) << 2) |
	                 ((s->r4_lo >> 31) << 3));
}

/* Bit k of a byte to bit 4k of a word. */
static inline uint32_t e0_spread(uint32_t x)
{
	x = (x | (x << 12)) & 0x000F000Fu;
	x = (x | (x << 6)) & 0x03030303u;
	x = (x | (x << 3)) & 0x11111111u;
	return x;
}

static inline uint32_t e0_rev8(uint32_t x)
{
	x = ((x & 0xF0u) >> 4) | ((x & 0x0Fu) << 4);
	x = ((x & 0xCCu) >> 2) | ((x & 0x33u) << 2);
	x = ((x & 0xAAu) >> 1) | ((x & 0x55u) << 1);
	return x;
}

/* Eight clocks with all switches closed: the eight symbols, the first in bit 0. in[k] holds the input bits of
 * register k + 1 for these clocks, the first of them in bit 7 (zero once the input streams have ended).
 * blend_at_last, when asked for, receives the blend value the last of the symbols was made with. */
static uint8_t e0_byte(e0_state_t *s, const uint8_t in[4], uint8_t *blend_at_last)
{
	/* Step j reads the output tap j positions below the tap of step 0: nibble 7 - j of w is its x4 x3 x2 x1. */
	const uint32_t w = e0_spread((s->r1 >> 16) & 0xFFu) | (e0_spread((s->r2 >> 16) & 0xFFu) << 1) |
	                   (e0_spread(s->r3_lo >> 24) << 2) | (e0_spread(s->r4_lo >> 24) << 3);
	uint32_t blend = s->blend;
	uint32_t z     = 0;
	if (blend_at_last != NULL) {
		for (uint8_t j = 0; j < 8u; j++) {
			*blend_at_last = (uint8_t)blend;
			const uint32_t e = g_e0_fsm[(blend << 4) | ((w >> (28u - 4u * j)) & 0xFu)];
			z    |= (e >> 4) << j;
			blend = e & 0xFu;
		}
	} else {
		for (uint8_t j = 0; j < 8u; j += 2u) {
			const uint32_t e = g_e0_fsm2[(blend << 8) | ((w >> (24u - 4u * j)) & 0xFFu)];
			z    |= ((e >> 4) & 3u) << j;
			blend = e & 0xFu;
		}
	}
	s->blend = (uint8_t)blend;

	/* Feedback polynomials t^25+t^20+t^12+t^8+1, t^31+t^24+t^16+t^12+1, t^33+t^28+t^24+t^4+1,
	 * t^39+t^36+t^28+t^4+1: the tap of position p for the step that lands in bit i is bit p - 1 - (n - 1) + i,
	 * n being the number of steps taken at once. Registers 3 and 4: the first four steps make the nibble a from
	 * the state as it is; the second four read their taps four positions lower, and position 4 is a itself. */
	const uint32_t f1 = (s->r1 >> 17) ^ (s->r1 >> 12) ^ (s->r1 >> 4) ^ s->r1;
	s->r1 = ((s->r1 << 8) | ((f1 ^ in[0]) & 0xFFu)) & E0_MASK1;
	const uint32_t f2 = (s->r2 >> 23) ^ (s->r2 >> 16) ^ (s->r2 >> 8) ^ (s->r2 >> 4);
	s->r2 = ((s->r2 << 8) | ((f2 ^ in[1]) & 0xFFu)) & E0_MASK2;

	const uint32_t lo3 = s->r3_lo;
	const uint32_t a3  = ((((lo3 >> 29) | (s->r3_hi << 3)) ^ (lo3 >> 24) ^ (lo3 >> 20) ^ lo3) ^ ((uint32_t)in[2] >> 4)) & 0xFu;
	const uint32_t b3  = ((lo3 >> 25) ^ (lo3 >> 20) ^ (lo3 >> 16) ^ a3 ^ in[2]) & 0xFu;
	s->r3_hi = (lo3 >> 24) & E0_HI3;
	s->r3_lo = (lo3 << 8) | (a3 << 4) | b3;

	const uint32_t lo4 = s->r4_lo;
	const uint32_t hi4 = s->r4_hi;
	const uint32_t a4  = (((hi4 >> 3) ^ hi4 ^ (lo4 >> 24) ^ lo4) ^ ((uint32_t)in[3] >> 4)) & 0xFu;
	const uint32_t b4  = (((lo4 >> 31) | (hi4 << 1)) ^ (lo4 >> 28) ^ (lo4 >> 20) ^ a4 ^ in[3]) & 0xFu;
	s->r4_hi = (lo4 >> 24) & E0_HI4;
	s->r4_lo = (lo4 << 8) | (a4 << 4) | b4;
	return (uint8_t)z;
}

/* The first 25 bits of an input stream as a register holds them after 25 ticks: the first bit has moved up to
 * position 25 (bit 24), the last one sits at position 1. */
static inline uint32_t e0_first_25(uint32_t in_lo)
{
	return (e0_rev8(in_lo & 0xFFu) << 17) | (e0_rev8((in_lo >> 8) & 0xFFu) << 9) | (e0_rev8((in_lo >> 16) & 0xFFu) << 1) |
	       ((in_lo >> 24) & 1u);
}

void br_crypto_e0_keystream(const uint8_t kc_prime[16], const uint8_t master_bd_addr[6], uint32_t clk,
		uint8_t *out_ks, size_t len_bytes)
{
	e0_init_fsm();
	const uint32_t cl = (clk >> 1) & 0x03FFFFFFu; /* CL_0 is CLK_1, ..., CL_25 is CLK_26 */

	/* Figure 4.5, each stream in the order its bits enter the register (the figure's rightmost bit first), an
	 * octet with its LSB first:
	 *   LFSR1: CL_24, K[0], K[4], K[8], K[12], CL[1], ADR[2]                                    49 bits
	 *   LFSR2: 1 0 0, low half of CL[0], K[1], K[5], K[9], K[13], ADR[0], ADR[3]                55 bits
	 *   LFSR3: CL_25, K[2], K[6], K[10], K[14], CL[2], ADR[4]                                   49 bits
	 *   LFSR4: 1 1 1, high half of CL[0], K[3], K[7], K[11], K[15], ADR[1], ADR[5]              55 bits
	 * Bit t of in_lo[k] is what enters register k + 1 at tick t, bit t - 32 of in_hi[k] from tick 32 on. */
	const uint8_t  lead[4]  = { (uint8_t)((cl >> 24) & 1u), (uint8_t)(0x1u | ((cl & 0xFu) << 3)),
	                            (uint8_t)((cl >> 25) & 1u), (uint8_t)(0x7u | (((cl >> 4) & 0xFu) << 3)) };
	const uint8_t  lead_n[4] = { 1u, 7u, 1u, 7u };
	const uint8_t  tail[4][2] = { { (uint8_t)(cl >> 8), master_bd_addr[2] }, { master_bd_addr[0], master_bd_addr[3] },
	                              { (uint8_t)(cl >> 16), master_bd_addr[4] }, { master_bd_addr[1], master_bd_addr[5] } };
	uint32_t in_lo[4];
	uint32_t in_hi[4];
	for (uint8_t k = 0; k < 4u; k++) {
		/* 48 bits after the lead: four key octets and two more, as two words that are then moved up by the lead. */
		const uint32_t w0 = (uint32_t)kc_prime[k] | ((uint32_t)kc_prime[4u + k] << 8) |
		                    ((uint32_t)kc_prime[8u + k] << 16) | ((uint32_t)kc_prime[12u + k] << 24);
		const uint32_t w1 = (uint32_t)tail[k][0] | ((uint32_t)tail[k][1] << 8);
		const uint8_t  n  = lead_n[k];
		in_lo[k] = lead[k] | (w0 << n);
		in_hi[k] = (w0 >> (32u - n)) | (w1 << n);
	}

	e0_state_t st;
	st.r1    = e0_first_25(in_lo[0]);
	st.r2    = e0_first_25(in_lo[1]);
	st.r3_lo = e0_first_25(in_lo[2]);
	st.r3_hi = 0u;
	st.r4_lo = e0_first_25(in_lo[3]);
	st.r4_hi = 0u;
	st.blend = 0u;

	/* One tick at a time while the switches close: a register's switch closes when its first bit has reached its
	 * last position (after as many ticks as the register is long); the blend registers are zero at t = 39 and
	 * follow equation 9 from then on. */
	for (uint8_t t = E0_LOADED_TICKS; t < E0_SERIAL_END; t++) {
		if (t >= E0_BLEND_START) {
			st.blend = (uint8_t)(g_e0_fsm[(uint8_t)((st.blend << 4) | e0_taps_now(&st))] & 0xFu);
		}
		uint32_t bit[4];
		for (uint8_t k = 0; k < 4u; k++) {
			bit[k] = (t < 32u) ? ((in_lo[k] >> t) & 1u) : ((in_hi[k] >> (t - 32u)) & 1u);
		}
		const uint32_t fb1 = ((st.r1 >> 24) ^ (st.r1 >> 19) ^ (st.r1 >> 11) ^ (st.r1 >> 7)) & 1u; /* closed from t = 25 */
		const uint32_t fb2 = (t >= 31u) ? ((st.r2 >> 30) ^ (st.r2 >> 23) ^ (st.r2 >> 15) ^ (st.r2 >> 11)) & 1u : 0u;
		const uint32_t fb3 = (t >= 33u) ? (st.r3_hi ^ (st.r3_lo >> 27) ^ (st.r3_lo >> 23) ^ (st.r3_lo >> 3)) & 1u : 0u;
		const uint32_t fb4 = (t >= 39u) ? ((st.r4_hi >> 6) ^ (st.r4_hi >> 3) ^ (st.r4_lo >> 27) ^ (st.r4_lo >> 3)) & 1u : 0u;
		st.r1    = ((st.r1 << 1) | (bit[0] ^ fb1)) & E0_MASK1;
		st.r2    = ((st.r2 << 1) | (bit[1] ^ fb2)) & E0_MASK2;
		st.r3_hi = (st.r3_lo >> 31) & E0_HI3;
		st.r3_lo = (st.r3_lo << 1) | (bit[2] ^ fb3);
		st.r4_hi = ((st.r4_hi << 1) | (st.r4_lo >> 31)) & E0_HI4;
		st.r4_lo = (st.r4_lo << 1) | (bit[3] ^ fb4);
	}

	/* Mix up to t = 239, a byte at a time; the last sixteen bytes are Z[0..15]. "It is a parallel load and no
	 * update of the blend registers is done": the blend value the last symbol was made with stays. */
	uint8_t z[E0_KEPT_BYTES];
	uint8_t blend_at_last = 0;
	for (uint8_t b = 0; b < E0_MIX_BYTES; b++) {
		const uint8_t t = (uint8_t)(E0_SERIAL_END + 8u * b);
		uint8_t in[4] = { 0u, 0u, 0u, 0u };
		if (t < E0_INPUT_END) {
			for (uint8_t k = 0; k < 4u; k++) {
				in[k] = (uint8_t)e0_rev8((in_hi[k] >> (t - 32u)) & 0xFFu);
			}
		}
		const uint8_t symbols = e0_byte(&st, in, (b + 1u == E0_MIX_BYTES) ? &blend_at_last : NULL);
		if (b >= E0_MIX_BYTES - E0_KEPT_BYTES) {
			z[b - (E0_MIX_BYTES - E0_KEPT_BYTES)] = symbols;
		}
	}

	/* Figure 4.6: Z[0..15] into the registers, the LSB of each octet in the lower position. */
	st.blend = blend_at_last;
	st.r1    = (uint32_t)z[0] | ((uint32_t)z[4] << 8) | ((uint32_t)z[8] << 16) | ((uint32_t)(z[12] & 1u) << 24);
	st.r2    = (uint32_t)z[1] | ((uint32_t)z[5] << 8) | ((uint32_t)z[9] << 16) | ((uint32_t)(z[12] >> 1) << 24);
	st.r3_lo = (uint32_t)z[2] | ((uint32_t)z[6] << 8) | ((uint32_t)z[10] << 16) | ((uint32_t)z[13] << 24);
	st.r3_hi = z[15] & 1u;
	st.r4_lo = (uint32_t)z[3] | ((uint32_t)z[7] << 8) | ((uint32_t)z[11] << 16) | ((uint32_t)z[14] << 24);
	st.r4_hi = (uint32_t)z[15] >> 1;

	/* Key stream: the first bit is the one of the loaded state; it ciphers the LSB of the first payload byte. */
	static const uint8_t no_input[4] = { 0u, 0u, 0u, 0u };
	for (size_t b = 0; b < len_bytes; b++) {
		out_ks[b] = e0_byte(&st, no_input, NULL);
	}
}

void br_crypto_e0_xor(const uint8_t kc_prime[16], const uint8_t master_bd_addr[6], uint32_t clk,
		uint8_t *data, size_t len_bytes)
{
	uint8_t ks[256];
	while (len_bytes > 0u) {
		size_t chunk = (len_bytes > sizeof(ks)) ? sizeof(ks) : len_bytes;
		/* Wait: only single packet <= 244 bytes is ever encrypted at once, so chunk == len_bytes! */
		br_crypto_e0_keystream(kc_prime, master_bd_addr, clk, ks, chunk);
		for (size_t i = 0; i < chunk; i++) {
			data[i] ^= ks[i];
		}
		data += chunk;
		len_bytes -= chunk;
	}
}

/* ==== Portable SHA-256 & HMAC-SHA256 for Secure Simple Pairing (SSP) ==== */
static const uint32_t g_sha256_k[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
	0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
	0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
	0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
	0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static inline uint32_t rotr32(uint32_t x, uint32_t n)
{
	return (x >> n) | (x << (32u - n));
}

static void sha256_block(uint32_t h[8], const uint8_t blk[64])
{
	uint32_t w[64];
	for (int i = 0; i < 16; i++) {
		w[i] = ((uint32_t)blk[i * 4 + 0] << 24) |
		       ((uint32_t)blk[i * 4 + 1] << 16) |
		       ((uint32_t)blk[i * 4 + 2] << 8) |
		       ((uint32_t)blk[i * 4 + 3]);
	}
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = rotr32(w[i - 15], 7u) ^ rotr32(w[i - 15], 18u) ^ (w[i - 15] >> 3);
		uint32_t s1 = rotr32(w[i - 2], 17u) ^ rotr32(w[i - 2], 19u) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
	for (int i = 0; i < 64; i++) {
		uint32_t S1 = rotr32(e, 6u) ^ rotr32(e, 11u) ^ rotr32(e, 25u);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t t1 = hh + S1 + ch + g_sha256_k[i] + w[i];
		uint32_t S0 = rotr32(a, 2u) ^ rotr32(a, 13u) ^ rotr32(a, 22u);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2 = S0 + maj;
		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void br_sha256(const uint8_t *data, size_t len, uint8_t out32[32])
{
	uint32_t h[8] = {
		0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
		0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
	};
	size_t off = 0;
	while (off + 64u <= len) {
		sha256_block(h, &data[off]);
		off += 64u;
	}
	uint8_t tail[128];
	memset(tail, 0, sizeof(tail));
	size_t rem = len - off;
	if (rem > 0u && data != NULL) {
		memcpy(tail, &data[off], rem);
	}
	tail[rem] = 0x80u;
	size_t pad_blocks = (rem >= 56u) ? 2u : 1u;
	uint64_t bit_len = (uint64_t)len * 8ULL;
	size_t len_off = pad_blocks * 64u - 8u;
	for (int i = 0; i < 8; i++) {
		tail[len_off + (size_t)i] = (uint8_t)((bit_len >> (56 - i * 8)) & 0xFFu);
	}
	sha256_block(h, &tail[0]);
	if (pad_blocks == 2u) {
		sha256_block(h, &tail[64]);
	}
	for (int i = 0; i < 8; i++) {
		out32[i * 4 + 0] = (uint8_t)((h[i] >> 24) & 0xFFu);
		out32[i * 4 + 1] = (uint8_t)((h[i] >> 16) & 0xFFu);
		out32[i * 4 + 2] = (uint8_t)((h[i] >> 8) & 0xFFu);
		out32[i * 4 + 3] = (uint8_t)(h[i] & 0xFFu);
	}
}

void br_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out32[32])
{
	uint8_t k0[64];
	memset(k0, 0, sizeof(k0));
	if (key_len > 64u) {
		uint8_t kh[32];
		br_sha256(key, key_len, kh);
		memcpy(k0, kh, 32);
	} else if (key_len > 0u && key != NULL) {
		memcpy(k0, key, key_len);
	}

	uint8_t inner_buf[64 + 128]; /* SSP messages are <= 80 bytes */
	if (msg_len > 128u) {
		msg_len = 128u;
	}
	for (int i = 0; i < 64; i++) {
		inner_buf[i] = (uint8_t)(k0[i] ^ 0x36u);
	}
	if (msg_len > 0u && msg != NULL) {
		memcpy(&inner_buf[64], msg, msg_len);
	}
	uint8_t inner_hash[32];
	br_sha256(inner_buf, 64u + msg_len, inner_hash);

	uint8_t outer_buf[64 + 32];
	for (int i = 0; i < 64; i++) {
		outer_buf[i] = (uint8_t)(k0[i] ^ 0x5Cu);
	}
	memcpy(&outer_buf[64], inner_hash, 32);
	br_sha256(outer_buf, sizeof(outer_buf), out32);
}

static void rev_copy(uint8_t *dst_be, const uint8_t *src_le, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		dst_be[i] = src_le[n - 1u - i];
	}
}

/* Core Spec Vol 2 Part H §7.3 & §7.7 Sample Data:
 * SSP SHA-256 / HMAC-SHA256 inputs are concatenated in MSB-first (big-endian) network order. f1, f2 and f3 are
 * "HMAC-SHA-256(...) / 2^128": the most significant 128 bits, bytes [0..15] of the big-endian digest, reversed
 * back to LMP LSO-first order. g is "SHA-256(...) mod 2^32": the least significant 32 bits. Checked against the
 * sample data of Vol 2 Part G section 7.2 (test_official_sample_data). */
void br_ssp_f1(const uint8_t u24_le[24], const uint8_t v24_le[24], const uint8_t x16_le[16], uint8_t z,
		uint8_t out_c16_le[16])
{
	uint8_t key_be[16];
	uint8_t msg_be[49];
	rev_copy(key_be, x16_le, 16u);
	rev_copy(&msg_be[0], u24_le, 24u);
	rev_copy(&msg_be[24], v24_le, 24u);
	msg_be[48] = z;
	uint8_t mac_be[32];
	br_hmac_sha256(key_be, 16u, msg_be, 49u, mac_be);
	rev_copy(out_c16_le, &mac_be[0], 16u);
}

uint32_t br_ssp_g(const uint8_t u24_le[24], const uint8_t v24_le[24],
		const uint8_t x16_le[16], const uint8_t y16_le[16])
{
	uint8_t msg_be[80];
	rev_copy(&msg_be[0], u24_le, 24u);
	rev_copy(&msg_be[24], v24_le, 24u);
	rev_copy(&msg_be[48], x16_le, 16u);
	rev_copy(&msg_be[64], y16_le, 16u);
	uint8_t digest_be[32];
	br_sha256(msg_be, 80u, digest_be);
	return ((uint32_t)digest_be[28] << 24) |
	       ((uint32_t)digest_be[29] << 16) |
	       ((uint32_t)digest_be[30] << 8) |
	       ((uint32_t)digest_be[31]);
}

void br_ssp_f2_btlk(const uint8_t dhkey24_le[24], const uint8_t n1_16_le[16], const uint8_t n2_16_le[16],
		const uint8_t bdaddr1_le[6], const uint8_t bdaddr2_le[6], uint8_t out_lk16_le[16])
{
	uint8_t key_be[24];
	uint8_t msg_be[48];
	rev_copy(key_be, dhkey24_le, 24u);
	rev_copy(&msg_be[0], n1_16_le, 16u);
	rev_copy(&msg_be[16], n2_16_le, 16u);
	/* KeyID = "btlk" = 0x62 0x74 0x6C 0x6B in MSB-first order */
	msg_be[32] = 0x62u;
	msg_be[33] = 0x74u;
	msg_be[34] = 0x6Cu;
	msg_be[35] = 0x6Bu;
	rev_copy(&msg_be[36], bdaddr1_le, 6u);
	rev_copy(&msg_be[42], bdaddr2_le, 6u);
	uint8_t mac_be[32];
	br_hmac_sha256(key_be, 24u, msg_be, 48u, mac_be);
	rev_copy(out_lk16_le, &mac_be[0], 16u);
}

void br_ssp_f3(const uint8_t dhkey24_le[24], const uint8_t n1_16_le[16], const uint8_t n2_16_le[16],
		const uint8_t r16_le[16], const uint8_t iocap3_le[3],
		const uint8_t bdaddr1_le[6], const uint8_t bdaddr2_le[6], uint8_t out_e16_le[16])
{
	uint8_t key_be[24];
	uint8_t msg_be[63];
	rev_copy(key_be, dhkey24_le, 24u);
	rev_copy(&msg_be[0], n1_16_le, 16u);
	rev_copy(&msg_be[16], n2_16_le, 16u);
	rev_copy(&msg_be[32], r16_le, 16u);
	rev_copy(&msg_be[48], iocap3_le, 3u);
	rev_copy(&msg_be[51], bdaddr1_le, 6u);
	rev_copy(&msg_be[57], bdaddr2_le, 6u);
	uint8_t mac_be[32];
	br_hmac_sha256(key_be, 24u, msg_be, 63u, mac_be);
	rev_copy(out_e16_le, &mac_be[0], 16u);
}
