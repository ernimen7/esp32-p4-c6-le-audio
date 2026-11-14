/*
 * The per-packet work of the engine against its first, bit-by-bit versions.
 *
 * Building one encrypted 3-slot packet took up to 1.7 ms on the ESP32-C6 (sound trials 2 to 12), which is why a
 * 3-slot pair took 5 ms instead of 3.75. The CRC, the whitening, the packing and the start of E0 were written a
 * bit at a time; they are being rewritten a byte at a time. The official sample data (test_air_hop.c,
 * test_crypto.c) check the first bytes of each; this file checks everything else: thousands of random packets,
 * of every type and length, must come out bit for bit as the bit-by-bit code made them. The numbers below were
 * recorded from that code (commit f0d1581) with this same file, built with clang on Windows and with gcc on
 * Linux: both gave the same four numbers.
 */
#include "br_air.h"
#include "br_crypto.h"
#include "br_proto.h"
#include <stdio.h>
#include <string.h>

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); \
		return 1; \
	} \
} while (0)

static uint32_t g_rng; /* each test starts it from its own value */

static uint32_t rnd(void)
{
	g_rng ^= g_rng << 13;
	g_rng ^= g_rng >> 17;
	g_rng ^= g_rng << 5;
	return g_rng;
}

static void rnd_bytes(uint8_t *b, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		b[i] = (uint8_t)(rnd() & 0xFFu);
	}
}

/* FNV-1a, 64 bit. */
static uint64_t g_hash;

static void hash_start(void)
{
	g_hash = 0xCBF29CE484222325ULL;
}

static void hash_bytes(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	for (size_t i = 0; i < n; i++) {
		g_hash ^= b[i];
		g_hash *= 0x100000001B3ULL;
	}
}

static void hash_u32(uint32_t v)
{
	const uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
	hash_bytes(b, sizeof(b));
}

static int same(const char *what, uint64_t recorded)
{
	if (g_hash != recorded) {
		fprintf(stderr, "FAIL: %s differs from the bit-by-bit code: 0x%016llxULL, recorded 0x%016llxULL\n", what,
				(unsigned long long)g_hash, (unsigned long long)recorded);
		return 1;
	}
	return 0;
}

/* A stand-in for the cipher: any reversible change of the bytes will do for the packing. */
static void xor_cipher(void *ctx, uint8_t *buf, size_t len)
{
	uint8_t k = *(const uint8_t *)ctx;
	for (size_t i = 0; i < len; i++) {
		buf[i] ^= k;
		k = (uint8_t)(k * 29u + 7u);
	}
}

static int test_crc(void)
{
	g_rng = 0x2545F491u;
	hash_start();
	for (int i = 0; i < 3000; i++) {
		uint8_t data[244];
		const size_t len = rnd() % (sizeof(data) + 1u);
		rnd_bytes(data, len);
		hash_u32(br_crc16_compute(data, len, (uint8_t)(rnd() & 0xFFu)));
	}
	return same("CRC of 3000 random payloads", 0xCAC85C476DB9C1ADULL);
}

static int test_whitening(void)
{
	g_rng = 0x9E3779B9u;
	hash_start();
	for (uint32_t seed = 0; seed < 128u; seed++) {
		for (int rep = 0; rep < 8; rep++) {
			uint8_t buf[250];
			const size_t len = rnd() % (sizeof(buf) + 1u);
			rnd_bytes(buf, sizeof(buf));
			uint8_t lfsr = (uint8_t)seed;
			br_whiten_bytes(&lfsr, buf, len);
			hash_bytes(buf, sizeof(buf));
			hash_u32(lfsr);
			/* A header's 18 bits first, then bytes, as a packet does it; and any odd number of bits. */
			const size_t bits = 1u + rnd() % 200u;
			lfsr = (uint8_t)seed;
			br_whiten_bits(&lfsr, buf, bits);
			br_whiten_bytes(&lfsr, buf + 30u, len > 200u ? 200u : len);
			hash_bytes(buf, sizeof(buf));
			hash_u32(lfsr);
		}
	}
	return same("whitening from all 128 states", 0xCD9E075AE9AE7BA3ULL);
}

typedef struct {
	uint8_t  type;
	uint16_t min_body;
	uint16_t max_body;
} pkt_kind_t;

static const pkt_kind_t g_kinds[] = {
	{ BR_PKT_NULL, 0u, 0u },   { BR_PKT_POLL, 0u, 0u },   { BR_PKT_FHS, 18u, 18u }, { BR_PKT_DM1, 1u, 18u },
	{ BR_PKT_DH1, 1u, 28u },   { BR_PKT_DM3, 2u, 123u },  { BR_PKT_DH3, 2u, 185u },
};

/* Every packet type at every length, with and without a cipher, in both ways of handing it to the modem; and
 * each one read back the way the engine reads a received packet. */
static int test_packets(void)
{
	g_rng = 0x7F4A7C15u;
	hash_start();
	uint32_t built = 0, read_back = 0;
	for (int i = 0; i < 6000; i++) {
		const pkt_kind_t *k   = &g_kinds[rnd() % (sizeof(g_kinds) / sizeof(g_kinds[0]))];
		const uint64_t sw     = br_syncword_from_lap(rnd() & 0xFFFFFFu);
		const uint8_t uap     = (uint8_t)(rnd() & 0xFFu);
		const uint8_t seed    = (uint8_t)(rnd() & 0x7Fu);
		const uint16_t len    = (uint16_t)(k->min_body + rnd() % (uint32_t)(k->max_body - k->min_body + 1u));
		const br_tx_mode_t mode = (rnd() & 1u) ? BR_TX_MODE_DIRECT_AA : BR_TX_MODE_IN_PAYLOAD;
		const bool ciphered   = (k->type != BR_PKT_FHS) && (rnd() & 1u);
		uint8_t key           = (uint8_t)(rnd() & 0xFFu);
		const uint8_t key0    = key;
		/* One draw per statement: the order in which a compiler evaluates the arguments of one call, or the
		 * members of one initializer, is its own choice, and the numbers below must not depend on it. */
		br_pkt_hdr_t hdr;
		hdr.type    = k->type;
		hdr.lt_addr = (uint8_t)(rnd() & 7u);
		hdr.flow    = (uint8_t)(rnd() & 1u);
		hdr.arqn    = (uint8_t)(rnd() & 1u);
		hdr.seqn    = (uint8_t)(rnd() & 1u);
		const uint8_t chan    = (uint8_t)(rnd() % 79u);
		const uint32_t anchor = rnd();
		const int8_t slip     = (int8_t)((int)(rnd() % 3u) - 1);
		uint8_t body[190];
		rnd_bytes(body, sizeof(body));
		/* A body the receiver can take apart: the payload header carries the length. */
		if (k->type == BR_PKT_DM1 || k->type == BR_PKT_DH1) {
			(void)br_acl_hdr_pack(false, BR_LLID_L2CAP_START, 1u, (uint16_t)(len - 1u), body);
		} else if (k->type == BR_PKT_DM3 || k->type == BR_PKT_DH3) {
			(void)br_acl_hdr_pack(true, BR_LLID_L2CAP_START, 1u, (uint16_t)(len - 2u), body);
		}
		br_radio_tx_req_t tx;
		memset(&tx, 0xEE, sizeof(tx));
		const bool ok = br_air_build_packet_tx(sw, uap, seed, &hdr, body, len, ciphered ? xor_cipher : NULL,
				ciphered ? &key : NULL, chan, anchor, mode, &tx);
		hash_u32(ok ? 1u : 0u);
		if (!ok) {
			continue;
		}
		built++;
		hash_u32(tx.anchor_us);
		hash_u32(tx.lead_us);
		hash_u32(tx.duration_us);
		hash_u32(tx.chan_1mhz);
		hash_u32(tx.access_addr);
		hash_u32(tx.tx_hdr);
		hash_u32(tx.tx_len);
		hash_bytes(tx.tx_payload, sizeof(tx.tx_payload));

		uint8_t air[320];
		size_t air_bits = 0;
		if (br_air_tx_to_bitstream(&tx, air, sizeof(air), &air_bits) == 0u) {
			continue;
		}
		br_radio_rx_ind_t ind;
		memset(&ind, 0, sizeof(ind));
		uint8_t raw[256];
		memset(raw, 0, sizeof(raw));
		if (!br_air_bitstream_to_c6_rx(air, air_bits, sw, false, slip, &ind.rx_hdr, &ind.rx_len, raw, &ind.raw_len)) {
			continue;
		}
		ind.sync_matched = true;
		ind.raw_payload  = raw;
		br_rx_decoded_t dec;
		memset(&dec, 0, sizeof(dec));
		key = key0;
		const bool got = br_air_extract_rx(sw, uap, seed, false, ciphered ? xor_cipher : NULL, ciphered ? &key : NULL,
				&ind, &dec);
		hash_u32((got ? 1u : 0u) | (got && dec.hec_ok ? 2u : 0u));
		if (!got || !dec.hec_ok) {
			continue; /* a capture that ends inside the header: see below */
		}
		CHECK(dec.hdr.type == hdr.type && dec.hdr.lt_addr == hdr.lt_addr && dec.hdr.seqn == hdr.seqn &&
		      dec.hdr.arqn == hdr.arqn && dec.hdr.flow == hdr.flow, "the header comes back as it was sent");
		/* The modem takes its length byte from the sync word, so with a random address the capture can end before
		 * the packet does and the CRC fails for that reason; what matters here is that it fails or holds as it
		 * did, and that a packet whose CRC holds is the packet that was sent. */
		if (br_pkt_has_crc(hdr.type) && dec.crc_ok) {
			CHECK(dec.body_len == len && memcmp(dec.body, body, len) == 0, "the payload comes back as it was sent");
		}
		read_back++;
		hash_u32(dec.crc_ok ? 1u : 0u);
		hash_u32(dec.body_len);
		hash_bytes(dec.body, dec.body_len);
		hash_u32((uint32_t)dec.fec23_fixes | ((uint32_t)dec.fec13_flips << 16) | ((uint32_t)(uint8_t)dec.bit_slip << 24));
	}
	CHECK(built >= 5000u && read_back >= 4000u, "nearly all of the 6000 packets were built and read back");
	return same("6000 random packets, built and read back", 0xF94D7CFF6117A90FULL);
}

static int test_e0(void)
{
	g_rng = 0x1B873593u;
	hash_start();
	for (int i = 0; i < 400; i++) {
		uint8_t kc[16], addr[6], ks[244];
		rnd_bytes(kc, sizeof(kc));
		rnd_bytes(addr, sizeof(addr));
		const size_t len   = 1u + rnd() % sizeof(ks);
		const uint32_t clk = rnd() & 0x0FFFFFFFu;
		memset(ks, 0, sizeof(ks));
		br_crypto_e0_keystream(kc, addr, clk, ks, len);
		hash_bytes(ks, sizeof(ks));
	}
	return same("E0 key stream for 400 random keys, addresses and clocks", 0x37BDCE7FD7EC1764ULL);
}

int main(void)
{
	int rc = 0;
	rc |= test_crc();
	rc |= test_whitening();
	rc |= test_packets();
	rc |= test_e0();
	if (rc == 0) {
		printf("test_fast_paths: OK\n");
	}
	return rc;
}
