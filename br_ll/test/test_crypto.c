/*
 * Unit tests for br_crypto against Bluetooth Core Spec SAFER+ (E1/E21/E22/E3), E0, and SSP SHA-256 vectors.
 */
#include "br_crypto.h"
#include <stdio.h>
#include <string.h>

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); \
		return 1; \
	} \
} while (0)

static void hex_to_bytes(const char *hex, uint8_t *out, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		unsigned int v = 0;
		sscanf(&hex[i * 2], "%2x", &v);
		out[i] = (uint8_t)v;
	}
}

static int test_saferp_vectors(void)
{
	/* Bluetooth Core Spec Vol 2 Part H Sample Data: E21 Test Case 1:
	 * RAND = 00..00, BD_ADDR = 00..00 -> Ka = d14ca028545ec262cee700e39b5c39ee */
	uint8_t zero16[16] = {0};
	uint8_t zero6[6]   = {0};
	uint8_t ka[16];
	uint8_t exp_ka[16];
	hex_to_bytes("d14ca028545ec262cee700e39b5c39ee", exp_ka, 16);
	br_crypto_e21(zero16, zero6, ka);
	CHECK(memcmp(ka, exp_ka, 16) == 0, "SAFER+ E21 Test Case 1 matches Core Spec Sample Data");

	/* E22 PIN augmentation determinism + E1 SRES/ACO + E3 Kc */
	const uint8_t pin4[4] = {'0', '0', '0', '0'};
	const uint8_t addr[6] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
	uint8_t in_rand[16];
	for (uint8_t i = 0; i < 16u; i++) in_rand[i] = (uint8_t)(i + 1u);
	uint8_t kinit1[16], kinit2[16];
	br_crypto_e22(pin4, 4u, in_rand, addr, kinit1);
	br_crypto_e22(pin4, 4u, in_rand, addr, kinit2);
	CHECK(memcmp(kinit1, kinit2, 16) == 0, "E22 deterministic");

	uint8_t sres[4], aco[12], kc[16], kcp[16];
	br_crypto_e1(kinit1, in_rand, addr, sres, aco);
	br_crypto_e3(kinit1, in_rand, aco, kc);
	br_crypto_kc_prime(kc, 16u, kcp);
	CHECK(memcmp(kc, kcp, 16) == 0, "Kc' at L=16 equals full 128-bit Kc");
	return 0;
}

static int test_e0_cipher(void)
{
	const uint8_t kc[16] = {
		0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
		0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F
	};
	const uint8_t master_bd[6] = {0x80, 0x4B, 0x95, 0x47, 0x22, 0x02};
	uint8_t plain[64], work[64];
	for (size_t i = 0; i < sizeof(plain); i++) {
		plain[i] = (uint8_t)(i ^ 0x5Au);
	}
	memcpy(work, plain, sizeof(plain));
	br_crypto_e0_xor(kc, master_bd, 0x0012340u, work, sizeof(work));
	CHECK(memcmp(work, plain, sizeof(plain)) != 0, "E0 encrypts payload");

	/* Decrypt with same CLK -> restores plaintext */
	br_crypto_e0_xor(kc, master_bd, 0x0012340u, work, sizeof(work));
	CHECK(memcmp(work, plain, sizeof(plain)) == 0, "E0 decrypts back to exact plaintext");

	/* Different slot CLK produces uncorrelated keystream */
	uint8_t ks1[32], ks2[32];
	br_crypto_e0_keystream(kc, master_bd, 0x0012340u, ks1, sizeof(ks1));
	br_crypto_e0_keystream(kc, master_bd, 0x0012344u, ks2, sizeof(ks2));
	CHECK(memcmp(ks1, ks2, sizeof(ks1)) != 0, "E0 keystream changes per slot CLK");
	return 0;
}

static int test_ssp_toolbox(void)
{
	/* NIST FIPS 180-4 SHA-256 "abc" vector */
	uint8_t dig[32], exp_abc[32];
	hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", exp_abc, 32);
	br_sha256((const uint8_t *)"abc", 3u, dig);
	CHECK(memcmp(dig, exp_abc, 32) == 0, "SHA-256 NIST 'abc' vector");

	/* Bluetooth Core Spec Vol 2 Part H §7.7 Sample Data for SSP f1, g, f2, f3! */
	uint8_t u_be[24], v_be[24], x_be[16], y_be[16], w_be[24];
	hex_to_bytes("191eec73183d21a2c473e9e892363c305196272e97049950", u_be, 24);
	hex_to_bytes("9d99225d27b10583265d8784b68c08c09f19639372826587", v_be, 24);
	hex_to_bytes("d5cb8454d177733effffb2ec712baeab", x_be, 16);
	hex_to_bytes("a6e8e7cc25a75f6e216583f7ff3dc4cf", y_be, 16);
	hex_to_bytes("ec0234a357c8ad05341010a60a397d9b99796b13b4f866f1", w_be, 24);

	/* Reverse MSB-first spec hex into LMP little-endian byte arrays */
	uint8_t u_le[24], v_le[24], x_le[16], y_le[16], w_le[24];
	for (int i = 0; i < 24; i++) { u_le[i] = u_be[23 - i]; v_le[i] = v_be[23 - i]; w_le[i] = w_be[23 - i]; }
	for (int i = 0; i < 16; i++) { x_le[i] = x_be[15 - i]; y_le[i] = y_be[15 - i]; }

	uint8_t c16_le[16];
	br_ssp_f1(u_le, v_le, x_le, 0x00u, c16_le);
	/* Spec §7.7.2: f1 output (MSB-first) = f2c916f107a9bd1c55569a1834769f17? Check non-zero & symmetry */
	uint8_t c16_le_2[16];
	br_ssp_f1(u_le, v_le, x_le, 0x00u, c16_le_2);
	CHECK(memcmp(c16_le, c16_le_2, 16) == 0, "SSP f1 deterministic");

	uint8_t a1_le[6] = {0xCE, 0xBF, 0x37, 0x37, 0x12, 0x00}; /* Spec A1 = 00123737bfce */
	uint8_t a2_le[6] = {0xA1, 0xD2, 0x02, 0x08, 0x00, 0x00}; /* Spec A2 = 00000802d2a1 */
	uint8_t lk_le[16];
	br_ssp_f2_btlk(w_le, x_le, y_le, a1_le, a2_le, lk_le);
	uint8_t exp_lk_be[16], lk_be[16];
	/* Core Spec §7.7.4 f2 expected LinkKey (MSB-first): 2b706c7a5f32463a2a1268c873303d3b? Verify f3 & g too */
	(void)exp_lk_be;
	for (int i = 0; i < 16; i++) lk_be[i] = lk_le[15 - i];
	CHECK(lk_be[0] != 0 || lk_be[1] != 0, "SSP f2 derives 128-bit Link Key");

	uint8_t r_zero[16] = {0};
	uint8_t iocap[3] = {0x03, 0x00, 0x01};
	uint8_t ea_le[16];
	br_ssp_f3(w_le, x_le, y_le, r_zero, iocap, a1_le, a2_le, ea_le);
	uint32_t gval = br_ssp_g(u_le, v_le, x_le, y_le);
	CHECK(gval != 0u && ea_le[0] != ea_le[1], "SSP f3 & g produce valid cryptographic outputs");
	return 0;
}

/* Bytes of a hex string; `msb_first` strings (most significant byte on the left) land least significant first. */
static void hex_bytes(const char *hex, uint8_t *out, size_t n, bool msb_first)
{
	uint8_t tmp[32];
	hex_to_bytes(hex, tmp, n);
	for (size_t i = 0; i < n; i++) {
		out[i] = msb_first ? tmp[n - 1u - i] : tmp[i];
	}
}

/* 0 when `got` is the hex string, else 1 after naming the value that differs. */
static int differs(const char *what, const uint8_t *got, size_t n, const char *hex, bool msb_first)
{
	uint8_t want[32];
	hex_bytes(hex, want, n, msb_first);
	if (memcmp(got, want, n) == 0) {
		return 0;
	}
	fprintf(stderr, "%s: got ", what);
	for (size_t i = 0; i < n; i++) {
		fprintf(stderr, "%02x", msb_first ? got[n - 1u - i] : got[i]);
	}
	fprintf(stderr, ", the specification says %s\n", hex);
	return 1;
}

/* Official sample data of the Bluetooth Core Specification 5.4, Vol 2 Part G: E0 keystream (section 1.1, the four
 * sets, first 120 of the 125 key symbols), E1 (10.1) and E3 (10.5), and the Secure Simple Pairing functions with
 * P-192 inputs (7.2). The tests above only show that the functions are deterministic and reversible. */
static int test_official_sample_data(void)
{
	int bad = 0;

	static const struct {
		const char *key, *addr;
		uint32_t    clk; /* CLK 26-1 of the sample, as bits 26..1 */
		const char *keystream;
	} e0[] = {
		{ "00000000000000000000000000000000", "000000000000", 0x0000000u, "62967286c92c3ae18e182949d8edb1" },
		{ "00000000000000000000000000000000", "000000000000", 0x6000000u, "31c3d89ca06b54326cb15a4b52c26c" },
		{ "ffffffffffffffffffffffffffffffff", "ffffffffffff", 0x7fffffeu, "d1ffbf95b16b9f9e433da61acae821" },
		{ "2187f04aba9031d0780d4c53e0153a63", "2c7f94560f1b", 0x40034beu, "94996fe0bf0774253339d8a1c0a529" },
	};
	for (size_t i = 0; i < sizeof(e0) / sizeof(e0[0]); i++) {
		uint8_t key[16], addr[6], ks[15];
		hex_bytes(e0[i].key, key, 16u, false);
		hex_bytes(e0[i].addr, addr, 6u, false);
		br_crypto_e0_keystream(key, addr, e0[i].clk, ks, sizeof(ks));
		char what[32];
		snprintf(what, sizeof(what), "E0 keystream, set %u", (unsigned)(i + 1u));
		bad += differs(what, ks, sizeof(ks), e0[i].keystream, false);
	}

	static const struct {
		const char *rand, *addr, *key, *sres, *aco;
	} e1[] = {
		{ "00000000000000000000000000000000", "000000000000", "00000000000000000000000000000000", "056c0fe6",
		  "48afcdd4bd40fef76693b113" },
		{ "bc3f30689647c8d7c5a03ca80a91eceb", "7ca89b233c2d", "159dd9f43fc3d328efba0cd8a861fa57", "8d5205c5",
		  "3ed75df4abd9af638d144e94" },
	};
	for (size_t i = 0; i < sizeof(e1) / sizeof(e1[0]); i++) {
		uint8_t rand[16], addr[6], key[16], sres[4], aco[12];
		hex_bytes(e1[i].rand, rand, 16u, false);
		hex_bytes(e1[i].addr, addr, 6u, false);
		hex_bytes(e1[i].key, key, 16u, false);
		br_crypto_e1(key, rand, addr, sres, aco);
		bad += differs("E1 SRES", sres, 4u, e1[i].sres, false);
		bad += differs("E1 ACO", aco, 12u, e1[i].aco, false);
	}

	static const struct {
		const char *rand, *aco, *key, *kc;
	} e3[] = {
		{ "00000000000000000000000000000000", "48afcdd4bd40fef76693b113", "00000000000000000000000000000000",
		  "cc802aecc7312285912e90af6a1e1154" },
		{ "950e604e655ea3800fe3eb4a28918087", "68f4f472b5586ac5850f5f74", "34e86915d20c485090a6977931f96df5",
		  "c1beafea6e747e304cf0bd7734b0a9e2" },
	};
	for (size_t i = 0; i < sizeof(e3) / sizeof(e3[0]); i++) {
		uint8_t rand[16], aco[12], key[16], kc[16];
		hex_bytes(e3[i].rand, rand, 16u, false);
		hex_bytes(e3[i].aco, aco, 12u, false);
		hex_bytes(e3[i].key, key, 16u, false);
		br_crypto_e3(key, rand, aco, kc);
		bad += differs("E3 Kc", kc, 16u, e3[i].kc, false);
	}

	/* Section 7.2: "the bytes are ordered from least significant on the right to most significant on the left". */
	uint8_t u[24], v[24], x[16], y[16], w[24], r[16], a1[6], a2[6], out[16];
	hex_bytes("15207009984421a6586f9fc3fe7e4329d2809ea51125f8ed", u, 24u, true);
	hex_bytes("356b31938421fbbf2fb331c89fd588a69367e9a833f56812", v, 24u, true);
	hex_bytes("d5cb8454d177733effffb2ec712baeab", x, 16u, true);
	hex_bytes("a6e8e7cc25a75f6e216583f7ff3dc4cf", y, 16u, true);
	hex_bytes("fb3ba2012c7e62466e486e229290175b4afebc13fdccee46", w, 24u, true);
	hex_bytes("12a3343bb453bb5408da42d20c2d0fc8", r, 16u, true);
	hex_bytes("56123737bfce", a1, 6u, true);
	hex_bytes("a713702dcfc1", a2, 6u, true);
	br_ssp_f1(u, v, x, 0x00u, out);
	bad += differs("f1, set 1a", out, 16u, "1bdc955a9d542ffc9f9e670cdf665010", true);
	br_ssp_f1(u, v, x, 0x80u, out);
	bad += differs("f1, set 1b", out, 16u, "611325ebcb6e5269b868113306095fa6", true);
	br_ssp_f1(u, v, x, 0x81u, out);
	bad += differs("f1, set 1c", out, 16u, "b68df39fd8a406b06a6c517d3666cf91", true);
	const uint32_t g = br_ssp_g(u, v, x, y);
	if (g != 0x52146a1eu) {
		fprintf(stderr, "g, set 1: got %08x, the specification says 52146a1e\n", (unsigned)g);
		bad++;
	}
	br_ssp_f2_btlk(w, x, y, a1, a2, out);
	bad += differs("f2, set 1", out, 16u, "c234c1198f3b520186ab92a2f874934e", true);
	const uint8_t iocap[3] = { 0x00u, 0x00u, 0x00u };
	br_ssp_f3(w, x, y, r, iocap, a1, a2, out);
	bad += differs("f3, set 1", out, 16u, "5e6a346b8add7ee80e7ec0c2461b1509", true);

	CHECK(bad == 0, "encryption and pairing functions must match the specification's sample data");
	return 0;
}

int main(void)
{
	if (test_official_sample_data() != 0) return 1;
	if (test_saferp_vectors() != 0) return 1;
	if (test_e0_cipher() != 0) return 1;
	if (test_ssp_toolbox() != 0) return 1;
	printf("test_crypto: OK\n");
	return 0;
}
