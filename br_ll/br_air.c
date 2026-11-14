/*
 * Bluetooth Classic Baseband Air-Framing, FEC, Whitening, HEC, CRC-16, and ESP32-C6 Mode-0 codecs.
 */
#include "br_air.h"
#include <string.h>

/* Core Spec Vol 2 Part B §6.3.3.1:
 * Generator polynomial g(D) = octal 260534236651 = 0x585713DA9 (degree 34),
 * PN sequence P_0..P_63 (bit 0 = P_0 transmitted first) = 0x83848D96BBCC54FC. */
#define BR_BCH_POLY64   0x0000000585713DA9ULL
#define BR_PN_SEQ64     0x83848D96BBCC54FCULL

uint64_t br_syncword_from_lap(uint32_t lap)
{
	lap &= 0x00FFFFFFu;
	uint64_t barker = (lap & 0x00800000u) ? 0x13ULL : 0x2CULL;
	uint64_t a_tilde = (barker << 24) | (uint64_t)lap;
	uint64_t x_tilde = a_tilde ^ ((BR_PN_SEQ64 >> 34) & 0x3FFFFFFFULL);
	uint64_t rem = x_tilde << 34;
	for (int bit = 63; bit >= 34; bit--) {
		if ((rem >> bit) & 1ULL) {
			rem ^= (BR_BCH_POLY64 << (bit - 34));
		}
	}
	uint64_t s_tilde = (x_tilde << 34) | (rem & 0x3FFFFFFFFULL);
	return s_tilde ^ BR_PN_SEQ64;
}

bool br_access_addr_quality_ok(uint32_t aa)
{
	if (aa == 0x8E89BED6u || aa == 0x00000000u || aa == 0xFFFFFFFFu) {
		return false;
	}
	uint8_t b0 = (uint8_t)(aa & 0xFFu);
	if (b0 == (uint8_t)((aa >> 8) & 0xFFu) &&
	    b0 == (uint8_t)((aa >> 16) & 0xFFu) &&
	    b0 == (uint8_t)((aa >> 24) & 0xFFu)) {
		return false;
	}
	uint8_t run_len = 1u;
	uint8_t prev = (uint8_t)(aa & 1u);
	uint8_t transitions = 0u;
	uint8_t ms6_trans = 0u;
	for (uint8_t i = 1u; i < 32u; i++) {
		uint8_t cur = (uint8_t)((aa >> i) & 1u);
		if (cur == prev) {
			run_len++;
			if (run_len > 6u) {
				return false;
			}
		} else {
			run_len = 1u;
			transitions++;
			if (i >= 26u) {
				ms6_trans++;
			}
		}
		prev = cur;
	}
	return transitions >= 10u && transitions <= 22u && ms6_trans >= 2u;
}

uint8_t br_preamble4(uint64_t sw_air)
{
	/* Core Spec §6.3.2: if s_0 == 1 -> 1010 (bit0=1 -> 0x5); if s_0 == 0 -> 0101 (bit0=0 -> 0xA). */
	return (sw_air & 1ULL) ? 0x05u : 0x0Au;
}

uint8_t br_trailer4(uint64_t sw_air)
{
	/* Core Spec §6.3.4: if s_63 == 1 -> 0101 (bit0=0 -> 0xA); if s_63 == 0 -> 1010 (bit0=1 -> 0x5). */
	return ((sw_air >> 63) & 1ULL) ? 0x0Au : 0x05u;
}

static uint8_t bitrev8(uint8_t v)
{
	v = (uint8_t)(((v & 0xF0u) >> 4) | ((v & 0x0Fu) << 4));
	v = (uint8_t)(((v & 0xCCu) >> 2) | ((v & 0x33u) << 2));
	v = (uint8_t)(((v & 0xAAu) >> 1) | ((v & 0x55u) << 1));
	return v;
}

static uint16_t bitrev16(uint16_t v)
{
	return (uint16_t)(((uint16_t)bitrev8((uint8_t)(v & 0xFFu)) << 8) |
	                  (uint16_t)bitrev8((uint8_t)((v >> 8) & 0xFFu)));
}

/* Core Spec Vol 2 Part B §7.1.1:
 * g(D) = D^8 + D^7 + D^5 + D^2 + D + 1.
 * Before the 10 header bits are shifted in (LSB first) the register holds the UAP, "the LSB of the UAP goes to the
 * left-most shift register element", which is position 0, and UAP_7 to position 7. Read out from position 7 down.
 * Checked against the sample data of Vol 2 Part G section 4 (test_official_sample_data). */
uint8_t br_hec_compute(uint16_t hdr10, uint8_t uap)
{
	/* Bit i of the variable is position i of the register. */
	uint8_t lfsr = uap;
	for (uint8_t i = 0; i < 10u; i++) {
		uint8_t in_bit = (uint8_t)((hdr10 >> i) & 1u);
		uint8_t fb = (uint8_t)(((lfsr >> 7) & 1u) ^ in_bit);
		lfsr = (uint8_t)((lfsr << 1) & 0xFFu);
		if (fb) {
			/* Taps at D7(bit7), D5(bit5), D2(bit2), D1(bit1), D0(bit0) -> 0xA7 */
			lfsr ^= 0xA7u;
		}
	}
	/* Output bits transmitted first-to-last are D7, D6, ..., D0 -> bitrev8(lfsr) puts D7 at bit 0! */
	return bitrev8(lfsr);
}

/* Core Spec Vol 2 Part B §7.2 Figure 7.4:
 * g(D) = D^7 + D^4 + 1.
 * Register [D6..D0] initialized with:
 *   Connection: [D6=1, D5=CLK6, D4=CLK5, D3=CLK4, D2=CLK3, D1=CLK2, D0=CLK1] -> seed = 0x40 | CLK[6:1]
 *   FHS X-mode: [D6=1, D5=1,    D4=X4,   D3=X3,   D2=X2,   D1=X1,   D0=X0]   -> seed = 0x60 | X[4:0]
 * At each bit clock: output whitening bit is D6; feedback D6 inserts into D0 and XORs into D4! */
uint8_t br_whiten_step_bit(uint8_t *lfsr7)
{
	uint8_t s = (uint8_t)(*lfsr7 & 0x7Fu);
	uint8_t out = (uint8_t)((s >> 6) & 1u);
	s = (uint8_t)((s << 1) & 0x7Fu);
	if (out) {
		s ^= 0x11u; /* D4 (bit 4) and D0 (bit 0) */
	}
	*lfsr7 = s;
	return out;
}

/* Core Spec Vol 2 Part B §7.1.2:
 * g(D) = D^16 + D^12 + D^5 + 1.
 * "The 8 left-most bits shall be initially loaded with the 8-bit UAP (UAP_0 to the left and UAP_7 to the right)":
 * positions 0..7 hold UAP_0..UAP_7, positions 8..15 are zero. Data shifted in LSB first; the CRC leaves from
 * position 15 down (2 bytes, LSB first on air). Checked against the sample data of Vol 2 Part G section 5. */
static uint16_t crc16_bit_by_bit(uint16_t lfsr, uint8_t byte)
{
	for (uint8_t i = 0; i < 8u; i++) {
		uint8_t in_bit = (uint8_t)((byte >> i) & 1u);
		uint8_t fb = (uint8_t)(((lfsr >> 15) & 1u) ^ in_bit);
		lfsr = (uint16_t)((lfsr << 1) & 0xFFFFu);
		if (fb) {
			/* D12, D5, D0 -> 0x1021 */
			lfsr ^= 0x1021u;
		}
	}
	return lfsr;
}

/* The per-packet work a byte at a time. Building one encrypted 3-slot packet a bit at a time took up to 1.7 ms on
 * the ESP32-C6, and that time decides how soon after an answer the next packet can leave (sound trials 2 to 12:
 * a 3-slot pair every 5 ms instead of every 3.75). The tables are made once, from the bit-by-bit steps above and
 * below, so they hold nothing those steps do not say; test_fast_paths.c compares thousands of whole packets with
 * what the bit-by-bit code produced.
 *  - CRC: eight steps change the register by its own top byte and by the byte that enters, and only by their
 *    XOR (the feedback of step i is register bit 15 - i xor data bit i): g_crc_step[top ^ reversed data byte].
 *  - Whitening: the next eight bits and the state after them depend on the 7-bit state alone. */
static uint16_t g_crc_step[256];
static uint8_t  g_rev8[256];
static uint8_t  g_whiten_bits8[128];
static uint8_t  g_whiten_next[128];
static bool     g_byte_tables_ready = false;

static void byte_tables_init(void)
{
	if (g_byte_tables_ready) {
		return;
	}
	for (uint16_t v = 0; v < 256u; v++) {
		g_rev8[v]     = bitrev8((uint8_t)v);
		g_crc_step[v] = crc16_bit_by_bit((uint16_t)(v << 8), 0u);
	}
	for (uint8_t state = 0; state < 128u; state++) {
		uint8_t s = state;
		uint8_t bits = 0;
		for (uint8_t i = 0; i < 8u; i++) {
			bits = (uint8_t)(bits | (br_whiten_step_bit(&s) << i));
		}
		g_whiten_bits8[state] = bits;
		g_whiten_next[state]  = s;
	}
	g_byte_tables_ready = true;
}

uint16_t br_crc16_compute(const uint8_t *data, size_t len_bytes, uint8_t uap)
{
	byte_tables_init();
	uint16_t lfsr = uap; /* bit i of the variable is position i of the register */
	for (size_t b = 0; b < len_bytes; b++) {
		lfsr = (uint16_t)((uint16_t)(lfsr << 8) ^ g_crc_step[(uint8_t)(lfsr >> 8) ^ g_rev8[data[b]]]);
	}
	return bitrev16(lfsr);
}

void br_whiten_bits(uint8_t *lfsr7, uint8_t *bit_buf_lsb, size_t num_bits)
{
	br_whiten_bytes(lfsr7, bit_buf_lsb, num_bits >> 3);
	for (size_t i = num_bits & ~(size_t)7u; i < num_bits; i++) {
		uint8_t w = br_whiten_step_bit(lfsr7);
		if (w) {
			bit_buf_lsb[i >> 3] ^= (uint8_t)(1u << (i & 7u));
		}
	}
}

void br_whiten_bytes(uint8_t *lfsr7, uint8_t *bytes, size_t num_bytes)
{
	byte_tables_init();
	uint8_t s = (uint8_t)(*lfsr7 & 0x7Fu);
	for (size_t i = 0; i < num_bytes; i++) {
		bytes[i] ^= g_whiten_bits8[s];
		s = g_whiten_next[s];
	}
	*lfsr7 = s;
}

void br_fec13_encode18(uint32_t hdr18, uint64_t *out_air54)
{
	uint64_t v = 0;
	for (uint8_t i = 0; i < 18u; i++) {
		if ((hdr18 >> i) & 1u) {
			v |= (7ULL << (i * 3u));
		}
	}
	*out_air54 = v;
}

uint32_t br_fec13_decode54(uint64_t air54, uint8_t *out_bit_flips)
{
	uint32_t hdr18 = 0;
	uint8_t flips = 0;
	for (uint8_t i = 0; i < 18u; i++) {
		uint8_t tri = (uint8_t)((air54 >> (i * 3u)) & 0x07u);
		uint8_t ones = (uint8_t)((tri & 1u) + ((tri >> 1) & 1u) + ((tri >> 2) & 1u));
		if (ones >= 2u) {
			hdr18 |= (1u << i);
			flips = (uint8_t)(flips + (3u - ones));
		} else {
			flips = (uint8_t)(flips + ones);
		}
	}
	if (out_bit_flips) {
		*out_bit_flips = flips;
	}
	return hdr18;
}

/* Core Spec Vol 2 Part B §7.4 (15,10) shortened Hamming FEC:
 * Generator polynomial g(D) = (D + 1)(D^4 + D + 1) = D^5 + D^4 + D^2 + 1 (octal 65).
 * 10 information bits (bit 0 first .. bit 9 last) followed by 5 parity bits (bit 10 .. bit 14). */
static uint8_t fec23_parity5(uint16_t info10)
{
	/* 5-stage LFSR [D4..D0], feedback from D4(bit4) ^ in_bit into D4(bit4? no: D^5+D^4+D^2+1 -> taps D4,D2,D0 = 0x15). */
	uint8_t lfsr = 0;
	for (uint8_t i = 0; i < 10u; i++) {
		uint8_t in_bit = (uint8_t)((info10 >> i) & 1u);
		uint8_t fb = (uint8_t)(((lfsr >> 4) & 1u) ^ in_bit);
		lfsr = (uint8_t)((lfsr << 1) & 0x1Fu);
		if (fb) {
			lfsr ^= 0x15u; /* D4(0x10) | D2(0x04) | D0(0x01) */
		}
	}
	/* Output D4 first .. D0 last -> bit-reverse 5 bits. */
	uint8_t p5 = 0;
	for (uint8_t i = 0; i < 5u; i++) {
		if ((lfsr >> (4u - i)) & 1u) {
			p5 |= (uint8_t)(1u << i);
		}
	}
	return p5;
}

uint16_t br_fec23_encode_block10(uint16_t info10)
{
	info10 &= 0x03FFu;
	uint8_t p5 = fec23_parity5(info10);
	return (uint16_t)(info10 | ((uint16_t)p5 << 10));
}

uint16_t br_fec23_decode_block15(uint16_t code15, bool *corrected)
{
	code15 &= 0x7FFFu;
	uint16_t info = (uint16_t)(code15 & 0x03FFu);
	uint8_t rx_p = (uint8_t)((code15 >> 10) & 0x1Fu);
	uint8_t syn = (uint8_t)(fec23_parity5(info) ^ rx_p);
	if (corrected) {
		*corrected = false;
	}
	if (syn == 0u) {
		return info;
	}
	/* Single-bit error in parity bits (syn has weight 1) -> info10 is already error-free! */
	if ((syn & (syn - 1u)) == 0u) {
		if (corrected) {
			*corrected = true;
		}
		return info;
	}
	/* Check each of the 10 info bit error syndromes. */
	for (uint8_t bit = 0; bit < 10u; bit++) {
		if (fec23_parity5((uint16_t)(1u << bit)) == syn) {
			if (corrected) {
				*corrected = true;
			}
			return (uint16_t)(info ^ (uint16_t)(1u << bit));
		}
	}
	return info;
}

static inline void bitstream_append_bits(uint8_t *buf, size_t *bit_pos, uint64_t val, uint8_t nbits)
{
	size_t p = *bit_pos;
	for (uint8_t i = 0; i < nbits; i++) {
		if ((val >> i) & 1ULL) {
			buf[p >> 3] |= (uint8_t)(1u << (p & 7u));
		}
		p++;
	}
	*bit_pos = p;
}

/* Whole bytes into a zeroed bit stream at any bit position: each byte lands in at most two bytes of the stream. */
static void bitstream_append_bytes(uint8_t *buf, size_t *bit_pos, const uint8_t *bytes, size_t num_bytes)
{
	if (num_bytes == 0u) {
		return; /* an ID packet has nothing after its sync word, and no buffer to copy nothing from */
	}
	size_t p            = *bit_pos;
	const uint8_t shift = (uint8_t)(p & 7u);
	uint8_t *out        = &buf[p >> 3];
	if (shift == 0u) {
		memcpy(out, bytes, num_bytes);
	} else {
		for (size_t i = 0; i < num_bytes; i++) {
			out[i]      = (uint8_t)(out[i] | (uint8_t)(bytes[i] << shift));
			out[i + 1u] = (uint8_t)(bytes[i] >> (8u - shift));
		}
	}
	*bit_pos = p + num_bytes * 8u;
}

/* The first `num_bits` bits of `bits` (bit i of the stream is bit i & 7 of byte i >> 3). */
static void bitstream_append_stream(uint8_t *buf, size_t *bit_pos, const uint8_t *bits, size_t num_bits)
{
	bitstream_append_bytes(buf, bit_pos, bits, num_bits >> 3);
	if ((num_bits & 7u) != 0u) {
		const uint8_t last = (uint8_t)(bits[num_bits >> 3] & (uint8_t)((1u << (num_bits & 7u)) - 1u));
		bitstream_append_bits(buf, bit_pos, last, (uint8_t)(num_bits & 7u));
	}
}

static inline uint64_t bitstream_read_bits(const uint8_t *buf, size_t total_bits, int64_t bit_pos, uint8_t nbits)
{
	uint64_t v = 0;
	for (uint8_t i = 0; i < nbits; i++) {
		int64_t p = bit_pos + (int64_t)i;
		if (p >= 0 && (size_t)p < total_bits) {
			size_t up = (size_t)p;
			if ((buf[up >> 3] >> (up & 7u)) & 1u) {
				v |= (1ULL << i);
			}
		}
	}
	return v;
}

size_t br_fec23_encode_bytes(const uint8_t *in_bytes, size_t in_len, uint8_t *out_bits_packed, size_t out_cap)
{
	size_t total_in_bits = in_len * 8u;
	size_t nblocks = (total_in_bits + 9u) / 10u;
	size_t total_out_bits = nblocks * 15u;
	size_t out_bytes = (total_out_bits + 7u) / 8u;
	if (out_bytes > out_cap) {
		return 0;
	}
	memset(out_bits_packed, 0, out_bytes);
	size_t out_pos = 0;
	for (size_t blk = 0; blk < nblocks; blk++) {
		uint16_t info10 = (uint16_t)bitstream_read_bits(in_bytes, total_in_bits, (int64_t)(blk * 10u), 10u);
		uint16_t code15 = br_fec23_encode_block10(info10);
		bitstream_append_bits(out_bits_packed, &out_pos, code15, 15u);
	}
	return total_out_bits;
}

size_t br_fec23_decode_bytes(const uint8_t *in_bits_packed, size_t num_blocks15,
		uint8_t *out_bytes, size_t out_cap, uint16_t *out_corrections)
{
	size_t total_info_bits = num_blocks15 * 10u;
	size_t req_bytes = (total_info_bits + 7u) / 8u;
	if (req_bytes > out_cap) {
		return 0;
	}
	memset(out_bytes, 0, req_bytes);
	size_t in_total_bits = num_blocks15 * 15u;
	size_t out_pos = 0;
	uint16_t fixes = 0;
	for (size_t blk = 0; blk < num_blocks15; blk++) {
		uint16_t code15 = (uint16_t)bitstream_read_bits(in_bits_packed, in_total_bits, (int64_t)(blk * 15u), 15u);
		bool fixed = false;
		uint16_t info10 = br_fec23_decode_block15(code15, &fixed);
		if (fixed) {
			fixes++;
		}
		bitstream_append_bits(out_bytes, &out_pos, info10, 10u);
	}
	if (out_corrections) {
		*out_corrections = fixes;
	}
	return total_info_bits / 8u;
}

/* Pack arbitrary air bitstream (starting immediately after preamble) into C6 Mode-0 TX descriptor. */
static bool pack_c6_tx_request(uint64_t sw_air, const uint8_t *post_sw_bits, size_t post_sw_nbits,
		uint8_t chan_1mhz, uint32_t anchor_us, br_tx_mode_t mode, br_radio_tx_req_t *out_tx)
{
	memset(out_tx, 0, sizeof(*out_tx));
	out_tx->anchor_us = anchor_us;
	out_tx->chan_1mhz = chan_1mhz;

	if (mode == BR_TX_MODE_DIRECT_AA && post_sw_nbits == 0u) {
		/* Note: Direct-AA requires at least 16 bits after Byte 5 (TXD_LEN) because Byte 4 is TXD_HDR
		 * and Byte 5 is TXD_LEN! For 68-bit ID packets (only 64b syncword, 0 post_sw_bits), TXD_LEN would
		 * equal sw_air[47:40] (e.g. 44 B), transmitting 44 garbage bytes after ID!
		 * Therefore 68-bit ID packets ALWAYS use TX_MODE_IN_PAYLOAD, which transmits exact 68-bit ID! */
		mode = BR_TX_MODE_IN_PAYLOAD;
	}

	if (mode == BR_TX_MODE_DIRECT_AA) {
		/* C6 sends: 8b BLE preamble + 32b AA (sw[31:0]) + 8b TXD_HDR (sw[39:32]) + 8b TXD_LEN (MUST match sw[47:40]!).
		 * Only usable if post_sw_nbits fits exact sw[47:40], so fall back automatically to IN_PAYLOAD whenever
		 * total air length != sw[47:40]. */
		size_t rem_bits = 16u + post_sw_nbits; /* sw[63:48] + post_sw */
		size_t rem_bytes = (rem_bits + 7u) / 8u;
		uint8_t sw_b5 = (uint8_t)((sw_air >> 40) & 0xFFu);
		if (rem_bytes == sw_b5 && rem_bytes <= BR_RAW_BUF_MAX) {
			out_tx->lead_us     = 4u; /* 8b BLE preamble vs 4b BR preamble */
			out_tx->access_addr = (uint32_t)(sw_air & 0xFFFFFFFFULL);
			out_tx->tx_hdr      = (uint8_t)((sw_air >> 32) & 0xFFu);
			out_tx->tx_len      = sw_b5;
			size_t bpos = 0;
			bitstream_append_bits(out_tx->tx_payload, &bpos, sw_air >> 48, 16u);
			bitstream_append_stream(out_tx->tx_payload, &bpos, post_sw_bits, post_sw_nbits);
			out_tx->duration_us = (uint16_t)(8u + 32u + 16u + rem_bytes * 8u + 24u);
			return true;
		}
	}

	/* Universal TX_MODE_IN_PAYLOAD:
	 * C6 sends at (anchor_us - 64 us):
	 *   8b BLE preamble (0xAA since AA[0]=1)  [8 us]
	 *   32b AA = 0x55555555                   [32 us]
	 *   8b TXD_HDR = 0x55                     [8 us]
	 *   8b TXD_LEN = total_payload_bytes      [8 us]
	 *   8b TXD_PAYLOAD[0] = 0x55 (if s0=1) or 0xAA (if s0=0) -> last 4 bits ARE the exact BR 4-bit preamble! [8 us]
	 * Total pre-SyncWord carrier warm-up = 8 + 32 + 8 + 8 + 8 = 64 us -> s_0 lands at exact anchor_us + 4 us
	 * (matching native BR 4-us preamble + s_0 timing to the microsecond!). */
	size_t total_bits = 8u + 64u + post_sw_nbits;
	size_t total_bytes = (total_bits + 7u) / 8u;
	if (total_bytes > BR_RAW_BUF_MAX) {
		return false;
	}
	out_tx->lead_us     = 60u; /* 60 us + 4 us BR preamble = 64 us before s_0! */
	out_tx->access_addr = 0x55555555u;
	out_tx->tx_hdr      = 0x55u;
	out_tx->tx_len      = (uint8_t)total_bytes;

	size_t bpos = 0;
	uint8_t pre_byte = (sw_air & 1ULL) ? 0x55u : 0xAAu;
	bitstream_append_bits(out_tx->tx_payload, &bpos, pre_byte, 8u);
	bitstream_append_bits(out_tx->tx_payload, &bpos, sw_air, 64u);
	bitstream_append_stream(out_tx->tx_payload, &bpos, post_sw_bits, post_sw_nbits);
	out_tx->duration_us = (uint16_t)(56u + total_bytes * 8u + 24u);
	return true;
}

#define BLE_CRC24_POLY 0x00065Bu /* x^10 + x^9 + x^6 + x^4 + x^3 + x + 1 below x^24 */

uint32_t br_air_ble_crc24(uint32_t preset, const uint8_t *pdu, size_t len)
{
	uint32_t reg = preset & 0x00FFFFFFu;
	for (size_t i = 0; i < len; i++) {
		for (uint8_t bit = 0; bit < 8u; bit++) {
			const uint32_t top = (reg >> 23) & 1u;
			reg = (reg << 1) & 0x00FFFFFFu;
			if (top != (((uint32_t)pdu[i] >> bit) & 1u)) {
				reg ^= BLE_CRC24_POLY;
			}
		}
	}
	return reg;
}

uint32_t br_air_ble_crc24_preset(uint32_t wanted, const uint8_t *pdu, size_t len)
{
	/* The steps of br_air_ble_crc24 backwards. A step leaves bit 0 set exactly when it applied the polynomial
	 * (the shift clears it, the polynomial has it), and it applied it when the bit shifted out differed from the
	 * data bit. */
	uint32_t reg = wanted & 0x00FFFFFFu;
	for (size_t i = len; i-- > 0u;) {
		for (uint8_t bit = 8u; bit-- > 0u;) {
			const uint32_t applied = reg & 1u;
			if (applied != 0u) {
				reg ^= BLE_CRC24_POLY;
			}
			const uint32_t top = (((uint32_t)pdu[i] >> bit) & 1u) ^ applied;
			reg = (reg >> 1) | (top << 23);
		}
	}
	return reg;
}

void br_air_build_id_tx(uint64_t sw_air, uint8_t chan_1mhz, uint32_t anchor_us,
		br_tx_mode_t mode, bool ends_with_sync, br_radio_tx_req_t *out_tx)
{
	if (!ends_with_sync) {
		(void)pack_c6_tx_request(sw_air, NULL, 0u, chan_1mhz, anchor_us, mode, out_tx);
		return;
	}
	/* As TX_MODE_IN_PAYLOAD up to sync word bit 39; bits 40..63 leave as the modem's CRC, first sent bit = register
	 * bit 23. Nothing follows the sync word. */
	memset(out_tx, 0, sizeof(*out_tx));
	out_tx->anchor_us   = anchor_us;
	out_tx->chan_1mhz   = chan_1mhz;
	out_tx->lead_us     = 60u;
	out_tx->access_addr = 0x55555555u;
	out_tx->tx_hdr      = 0x55u;
	out_tx->tx_len      = 6u;
	out_tx->tx_payload[0] = (sw_air & 1ULL) ? 0x55u : 0xAAu;
	for (uint8_t i = 0; i < 5u; i++) {
		out_tx->tx_payload[1u + i] = (uint8_t)(sw_air >> (8u * i));
	}
	uint32_t wanted = 0u;
	for (uint8_t i = 0; i < 24u; i++) {
		wanted |= (uint32_t)((sw_air >> (40u + i)) & 1ULL) << (23u - i);
	}
	uint8_t pdu[8];
	pdu[0] = out_tx->tx_hdr;
	pdu[1] = out_tx->tx_len;
	memcpy(&pdu[2], out_tx->tx_payload, 6u);
	out_tx->crc_preset     = br_air_ble_crc24_preset(wanted, pdu, sizeof(pdu));
	out_tx->crc_preset_set = true;
	out_tx->duration_us    = (uint16_t)(56u + 6u * 8u + 24u);
}

bool br_air_build_packet_tx(uint64_t sw_air, uint8_t uap, uint8_t whiten_seed7,
		const br_pkt_hdr_t *hdr, const uint8_t *body, uint16_t body_len,
		br_payload_cipher_fn cipher_fn, void *cipher_ctx,
		uint8_t chan_1mhz, uint32_t anchor_us, br_tx_mode_t mode,
		br_radio_tx_req_t *out_tx)
{
	/* Step 1: 10-bit header + 8-bit HEC */
	uint16_t h10 = br_pkt_hdr_pack10(hdr);
	uint8_t hec8 = br_hec_compute(h10, uap);
	uint32_t hdr18 = (uint32_t)h10 | ((uint32_t)hec8 << 10);

	/* Step 2: Whiten 18-bit header using continuous LFSR */
	uint8_t lfsr = (uint8_t)(whiten_seed7 & 0x7Fu);
	uint8_t hdr_buf[3] = {
		(uint8_t)(hdr18 & 0xFFu),
		(uint8_t)((hdr18 >> 8) & 0xFFu),
		(uint8_t)((hdr18 >> 16) & 0x03u),
	};
	br_whiten_bits(&lfsr, hdr_buf, 18u);
	uint32_t wh_hdr18 = (uint32_t)hdr_buf[0] | ((uint32_t)hdr_buf[1] << 8) |
	                    (((uint32_t)hdr_buf[2] & 0x03u) << 16);

	/* Step 3: 1/3 FEC encode header -> 54 air bits */
	uint64_t air_hdr54 = 0;
	br_fec13_encode18(wh_hdr18, &air_hdr54);

	/* Step 4: Optional payload + CRC16 -> Encrypt -> Whiten -> Optional 2/3 FEC */
	uint8_t post_sw[256];
	memset(post_sw, 0, sizeof(post_sw));
	size_t post_bits = 0;

	/* 4-bit Trailer after SyncWord */
	bitstream_append_bits(post_sw, &post_bits, br_trailer4(sw_air), 4u);
	/* 54-bit FEC1/3 Header */
	bitstream_append_bits(post_sw, &post_bits, air_hdr54, 54u);

	if (br_pkt_has_crc(hdr->type)) {
		if (body_len > 240u) {
			return false;
		}
		uint8_t pay_crc[244];
		if (body_len > 0u && body != NULL) {
			memcpy(pay_crc, body, body_len);
		}
		uint16_t crc = br_crc16_compute(pay_crc, body_len, uap);
		pay_crc[body_len]     = (uint8_t)(crc & 0xFFu);
		pay_crc[body_len + 1] = (uint8_t)((crc >> 8) & 0xFFu);
		size_t pay_crc_len = (size_t)body_len + 2u;

		/* Encrypt payload + CRC BEFORE whitening (never on FHS: caller passes cipher_fn=NULL for FHS) */
		if (cipher_fn != NULL) {
			cipher_fn(cipher_ctx, pay_crc, pay_crc_len);
		}

		/* Whiten payload + CRC continuing the SAME 7-bit LFSR state from the header! */
		br_whiten_bytes(&lfsr, pay_crc, pay_crc_len);

		if (br_pkt_uses_fec23(hdr->type)) {
			uint8_t fec_buf[256];
			size_t fec_bits = br_fec23_encode_bytes(pay_crc, pay_crc_len, fec_buf, sizeof(fec_buf));
			if (fec_bits == 0u || (post_bits + fec_bits + 72u) > (BR_RAW_BUF_MAX * 8u)) {
				return false;
			}
			bitstream_append_stream(post_sw, &post_bits, fec_buf, fec_bits);
		} else {
			if ((post_bits + pay_crc_len * 8u + 72u) > (BR_RAW_BUF_MAX * 8u)) {
				return false;
			}
			bitstream_append_bytes(post_sw, &post_bits, pay_crc, pay_crc_len);
		}
	}

	return pack_c6_tx_request(sw_air, post_sw, post_bits, chan_1mhz, anchor_us, mode, out_tx);
}

static bool try_decode_at_slip(uint64_t expected_sw_air, uint8_t expected_uap, uint8_t whiten_seed7,
		br_payload_cipher_fn decipher_fn, void *cipher_ctx,
		const uint8_t *stream, size_t stream_bits, int8_t slip,
		br_rx_decoded_t *out)
{
	/* In C6 Mode-0 RX, `stream` starts at bit 32 of `expected_sw_air` (rx_hdr = bits[39:32], rx_len = bits[47:40],
	 * raw_payload[0..1] = bits[63:48], followed by 4b trailer + 54b header + payload). */
	uint32_t exp_hi32 = (uint32_t)(expected_sw_air >> 32);
	uint32_t rx_hi32  = (uint32_t)bitstream_read_bits(stream, stream_bits, (int64_t)slip, 32u);
	uint32_t sw_diff  = exp_hi32 ^ rx_hi32;
	/* Allow up to 3 bit errors in upper 32 bits of 64-bit BCH SyncWord */
	uint8_t sw_errs = 0;
	for (uint8_t i = 0; i < 32u; i++) {
		sw_errs = (uint8_t)(sw_errs + ((sw_diff >> i) & 1u));
	}
	if (sw_errs > 3u) {
		return false;
	}

	/* Read 54-bit 1/3 FEC header starting after 32b upper syncword + 4b trailer = bit offset 36 + slip */
	int64_t hdr_off = 36 + (int64_t)slip;
	if ((int64_t)stream_bits < hdr_off + 54) {
		return false;
	}
	uint64_t air54 = bitstream_read_bits(stream, stream_bits, hdr_off, 54u);
	uint8_t flips13 = 0;
	uint32_t wh_hdr18 = br_fec13_decode54(air54, &flips13);
	if (flips13 > 12u) {
		return false;
	}

	uint8_t lfsr = (uint8_t)(whiten_seed7 & 0x7Fu);
	uint8_t hbuf[3] = {
		(uint8_t)(wh_hdr18 & 0xFFu),
		(uint8_t)((wh_hdr18 >> 8) & 0xFFu),
		(uint8_t)((wh_hdr18 >> 16) & 0x03u),
	};
	br_whiten_bits(&lfsr, hbuf, 18u);
	uint16_t hdr10 = (uint16_t)((uint16_t)hbuf[0] | (((uint16_t)hbuf[1] & 0x03u) << 8));
	uint8_t rx_hec = (uint8_t)(((hbuf[1] >> 2) & 0x3Fu) | ((hbuf[2] & 0x03u) << 6));
	if (br_hec_compute(hdr10, expected_uap) != rx_hec) {
		return false;
	}

	br_pkt_hdr_t hdr;
	br_pkt_hdr_unpack10(hdr10, &hdr);

	memset(out, 0, sizeof(*out));
	out->sync_ok          = true;
	out->hec_ok           = true;
	out->bit_slip         = slip;
	out->fec13_flips      = flips13;
	out->whiten_seed_used = whiten_seed7;
	out->hdr              = hdr;

	if (!br_pkt_has_crc(hdr.type)) {
		out->crc_ok = true;
		out->body_len = 0;
		return true;
	}

	int64_t pay_off = hdr_off + 54;
	if (hdr.type == BR_PKT_FHS) {
		/* FHS: 144b payload + 16b CRC = 160b = 16 blocks of 10b -> 240 air bits (30 bytes) */
		if ((int64_t)stream_bits < pay_off + 240) {
			return false;
		}
		uint8_t fec_raw[30];
		memset(fec_raw, 0, sizeof(fec_raw));
		for (uint16_t i = 0; i < 240u; i++) {
			uint8_t bit = (uint8_t)bitstream_read_bits(stream, stream_bits, pay_off + i, 1u);
			if (bit) {
				fec_raw[i >> 3] |= (uint8_t)(1u << (i & 7u));
			}
		}
		uint8_t un_fec[20];
		uint16_t fixes = 0;
		if (br_fec23_decode_bytes(fec_raw, 16u, un_fec, sizeof(un_fec), &fixes) != 20u) {
			return false;
		}
		br_whiten_bytes(&lfsr, un_fec, 20u);
		uint16_t rx_crc = (uint16_t)((uint16_t)un_fec[18] | ((uint16_t)un_fec[19] << 8));
		if (br_crc16_compute(un_fec, 18u, expected_uap) != rx_crc) {
			return false;
		}
		out->crc_ok      = true;
		out->fec23_fixes = fixes;
		out->body_len    = 18u;
		memcpy(out->body, un_fec, 18u);
		return true;
	}

	/* ACL packet (DM1/DH1/DM3/DH3): first decode 1 or 2 header bytes to learn exact payload_len! */
	bool multislot = br_pkt_is_multislot(hdr.type);
	bool use_fec23 = br_pkt_uses_fec23(hdr.type);

	if (use_fec23) {
		/* First 15-bit FEC block gives 10 bits (>= 1B header; for multislot 2 blocks give 20 bits >= 2B header) */
		size_t probe_blks = multislot ? 2u : 1u;
		if ((int64_t)stream_bits < pay_off + (int64_t)(probe_blks * 15u)) {
			return false;
		}
		uint8_t probe_fec[4] = {0};
		for (size_t i = 0; i < probe_blks * 15u; i++) {
			if (bitstream_read_bits(stream, stream_bits, pay_off + (int64_t)i, 1u)) {
				probe_fec[i >> 3] |= (uint8_t)(1u << (i & 7u));
			}
		}
		uint8_t probe_dec[3] = {0};
		br_fec23_decode_bytes(probe_fec, probe_blks, probe_dec, sizeof(probe_dec), NULL);
		uint8_t probe_lfsr = lfsr;
		size_t hdr_sz = multislot ? 2u : 1u;
		br_whiten_bytes(&probe_lfsr, probe_dec, hdr_sz);
		if (decipher_fn != NULL) {
			/* Note: E0 is a stream cipher; decrypting prefix bytes produces exact plaintext ACL header! */
			decipher_fn(cipher_ctx, probe_dec, hdr_sz);
		}
		uint8_t llid = 0, flow = 0, hb = 0;
		uint16_t plen = 0;
		/* Validate length ceiling before full decode */
		if (!multislot) {
			plen = (uint16_t)((probe_dec[0] >> 3) & 0x1Fu);
			hb = 1u;
			if (plen > BR_MAX_DM1_BYTES) {
				return false;
			}
		} else {
			uint16_t w = (uint16_t)((uint16_t)probe_dec[0] | ((uint16_t)probe_dec[1] << 8));
			if ((w & 0xF000u) != 0u) {
				return false;
			}
			plen = (uint16_t)((w >> 3) & 0x01FFu);
			hb = 2u;
			if (plen > BR_MAX_DM3_BYTES) {
				return false;
			}
		}
		(void)llid;
		(void)flow;
		size_t total_bytes = (size_t)hb + (size_t)plen + 2u; /* + 2B CRC16 */
		size_t nblocks = (total_bytes * 8u + 9u) / 10u;
		if ((int64_t)stream_bits < pay_off + (int64_t)(nblocks * 15u)) {
			return false;
		}
		uint8_t fec_all[256];
		memset(fec_all, 0, sizeof(fec_all));
		for (size_t i = 0; i < nblocks * 15u; i++) {
			if (bitstream_read_bits(stream, stream_bits, pay_off + (int64_t)i, 1u)) {
				fec_all[i >> 3] |= (uint8_t)(1u << (i & 7u));
			}
		}
		uint8_t dec_all[256];
		uint16_t fixes = 0;
		if (br_fec23_decode_bytes(fec_all, nblocks, dec_all, sizeof(dec_all), &fixes) < total_bytes) {
			return false;
		}
		br_whiten_bytes(&lfsr, dec_all, total_bytes);
		if (decipher_fn != NULL) {
			decipher_fn(cipher_ctx, dec_all, total_bytes);
		}
		uint16_t rx_crc = (uint16_t)((uint16_t)dec_all[total_bytes - 2u] |
		                             ((uint16_t)dec_all[total_bytes - 1u] << 8));
		if (br_crc16_compute(dec_all, total_bytes - 2u, expected_uap) != rx_crc) {
			out->crc_ok = false;
			return true; /* HEC matched; report CRC failure to engine so ARQN=NAK is kept */
		}
		out->crc_ok      = true;
		out->fec23_fixes = fixes;
		out->body_len    = (uint16_t)(total_bytes - 2u);
		memcpy(out->body, dec_all, out->body_len);
		return true;
	}

	/* Uncoded DH1 / DH3 / AUX1 */
	size_t hdr_sz = multislot ? 2u : 1u;
	if ((int64_t)stream_bits < pay_off + (int64_t)((hdr_sz + 2u) * 8u)) {
		return false;
	}
	uint8_t probe[2] = {0};
	for (size_t b = 0; b < hdr_sz; b++) {
		probe[b] = (uint8_t)bitstream_read_bits(stream, stream_bits, pay_off + (int64_t)(b * 8u), 8u);
	}
	uint8_t probe_lfsr = lfsr;
	br_whiten_bytes(&probe_lfsr, probe, hdr_sz);
	if (decipher_fn != NULL) {
		decipher_fn(cipher_ctx, probe, hdr_sz);
	}
	uint16_t plen = 0;
	if (!multislot) {
		plen = (uint16_t)((probe[0] >> 3) & 0x1Fu);
		if (plen > BR_MAX_DH1_BYTES) {
			return false;
		}
	} else {
		uint16_t w = (uint16_t)((uint16_t)probe[0] | ((uint16_t)probe[1] << 8));
		if ((w & 0xF000u) != 0u) {
			return false;
		}
		plen = (uint16_t)((w >> 3) & 0x01FFu);
		if (plen > BR_MAX_DH3_BYTES) {
			return false;
		}
	}
	size_t total_bytes = hdr_sz + (size_t)plen + 2u;
	if ((int64_t)stream_bits < pay_off + (int64_t)(total_bytes * 8u)) {
		return false;
	}
	uint8_t dec_all[256];
	for (size_t b = 0; b < total_bytes; b++) {
		dec_all[b] = (uint8_t)bitstream_read_bits(stream, stream_bits, pay_off + (int64_t)(b * 8u), 8u);
	}
	br_whiten_bytes(&lfsr, dec_all, total_bytes);
	if (decipher_fn != NULL) {
		decipher_fn(cipher_ctx, dec_all, total_bytes);
	}
	uint16_t rx_crc = (uint16_t)((uint16_t)dec_all[total_bytes - 2u] |
	                             ((uint16_t)dec_all[total_bytes - 1u] << 8));
	if (br_crc16_compute(dec_all, total_bytes - 2u, expected_uap) != rx_crc) {
		out->crc_ok = false;
		return true;
	}
	out->crc_ok   = true;
	out->body_len = (uint16_t)(total_bytes - 2u);
	memcpy(out->body, dec_all, out->body_len);
	return true;
}

bool br_air_extract_rx(uint64_t expected_sw_air, uint8_t expected_uap, uint8_t whiten_seed7,
		bool search_fhs_seeds, br_payload_cipher_fn decipher_fn, void *cipher_ctx,
		const br_radio_rx_ind_t *rx_ind, br_rx_decoded_t *out)
{
	memset(out, 0, sizeof(*out));
	if (!rx_ind || rx_ind->skipped || !rx_ind->sync_matched) {
		return false;
	}

	/* Reassemble continuous captured bitstream starting at bit 32 of SyncWord:
	 * byte 0 = rx_hdr, byte 1 = rx_len, bytes 2..2+raw_len-1 = raw_payload[]. */
	uint8_t stream[260];
	memset(stream, 0, sizeof(stream));
	stream[0] = rx_ind->rx_hdr;
	stream[1] = rx_ind->rx_len;
	uint16_t copy_len = rx_ind->raw_len;
	if (copy_len > 256u) {
		copy_len = 256u;
	}
	if (copy_len > 0u && rx_ind->raw_payload != NULL) {
		memcpy(&stream[2], rx_ind->raw_payload, copy_len);
	}
	size_t stream_bits = (size_t)(2u + copy_len) * 8u;

	/* Fast path for 68-bit ID packet (Page Slave Response / FHS ACK):
	 * Only 64-bit SyncWord exists on air (32 bits matched in AA + 32 upper bits in stream[0..3]). */
	static const int8_t slips[7] = {0, -1, 1, -2, 2, -3, 3};
	if (stream_bits >= 32u) {
		/* First try full header+payload decode across slips */
		for (size_t s = 0; s < 7u; s++) {
			int8_t slip = slips[s];
			if (try_decode_at_slip(expected_sw_air, expected_uap, whiten_seed7,
					decipher_fn, cipher_ctx, stream, stream_bits, slip, out)) {
				if (out->crc_ok) {
					return true;
				}
			}
			if (search_fhs_seeds) {
				/* Inquiry FHS: Slave's X_ir[4:0] (or CLK[6:1]) may be unknown to Inquiring Master.
				 * Test all 32 X-seeds (0x60|x) and 64 CLK-seeds (0x40|c): validated by 8b HEC + 16b CRC + TYPE=FHS! */
				for (uint8_t cand = 0x40u; cand <= 0x7Fu; cand++) {
					if (cand == whiten_seed7) {
						continue;
					}
					br_rx_decoded_t tmp;
					if (try_decode_at_slip(expected_sw_air, expected_uap, cand,
							NULL, NULL, stream, stream_bits, slip, &tmp)) {
						if (tmp.crc_ok && tmp.hdr.type == BR_PKT_FHS) {
							*out = tmp;
							return true;
						}
					}
				}
			}
		}

		/* If HEC matched with CRC error on slip 0, keep that diagnostic result unless ID packet expected */
		if (out->hec_ok) {
			return true;
		}

		/* Check if upper 32 bits of SyncWord match cleanly -> valid 68-bit ID packet! */
		for (size_t s = 0; s < 7u; s++) {
			int8_t slip = slips[s];
			uint32_t exp_hi32 = (uint32_t)(expected_sw_air >> 32);
			uint32_t rx_hi32  = (uint32_t)bitstream_read_bits(stream, stream_bits, (int64_t)slip, 32u);
			uint32_t diff = exp_hi32 ^ rx_hi32;
			uint8_t errs = 0;
			for (uint8_t i = 0; i < 32u; i++) {
				errs = (uint8_t)(errs + ((diff >> i) & 1u));
			}
			if (errs <= 2u) {
				out->sync_ok   = true;
				out->is_id_pkt = true;
				out->bit_slip  = slip;
				return true;
			}
		}
	}
	return false;
}

size_t br_air_tx_to_bitstream(const br_radio_tx_req_t *tx, uint8_t *out_air_bytes, size_t max_bytes, size_t *out_bits)
{
	/* Reconstruct exact physical bits emitted by C6 Mode-0 radio:
	 * [8b BLE preamble] + [32b access_addr] + [8b tx_hdr] + [8b tx_len] + [tx_len * 8b tx_payload] */
	size_t total_bytes = 7u + (size_t)tx->tx_len;
	if (total_bytes > max_bytes) {
		return 0;
	}
	memset(out_air_bytes, 0, total_bytes);
	out_air_bytes[0] = (tx->access_addr & 1u) ? 0xAAu : 0x55u;
	out_air_bytes[1] = (uint8_t)(tx->access_addr & 0xFFu);
	out_air_bytes[2] = (uint8_t)((tx->access_addr >> 8) & 0xFFu);
	out_air_bytes[3] = (uint8_t)((tx->access_addr >> 16) & 0xFFu);
	out_air_bytes[4] = (uint8_t)((tx->access_addr >> 24) & 0xFFu);
	out_air_bytes[5] = tx->tx_hdr;
	out_air_bytes[6] = tx->tx_len;
	if (tx->tx_len > 0u) {
		memcpy(&out_air_bytes[7], tx->tx_payload, tx->tx_len);
	}
	if (out_bits) {
		*out_bits = total_bytes * 8u;
	}
	return total_bytes;
}

bool br_air_bitstream_to_c6_rx(const uint8_t *air_bytes, size_t air_bits, uint64_t target_sw_air,
		bool id_only, int8_t inject_bit_slip,
		uint8_t *rx_hdr_out, uint8_t *rx_len_out, uint8_t *raw_payload_out, uint16_t *raw_len_out)
{
	/* Simulate C6 hardware 32-bit Access Address correlator searching for target_sw_air[31:0] */
	uint32_t target_aa = (uint32_t)(target_sw_air & 0xFFFFFFFFULL);
	for (size_t pos = 0; pos + 32u <= air_bits; pos++) {
		uint32_t cand = (uint32_t)bitstream_read_bits(air_bytes, air_bits, (int64_t)pos, 32u);
		uint32_t diff = cand ^ target_aa;
		uint8_t errs = 0;
		for (uint8_t i = 0; i < 32u; i++) {
			errs = (uint8_t)(errs + ((diff >> i) & 1u));
		}
		if (errs == 0u) {
			int64_t after_aa = (int64_t)(pos + 32u) - (int64_t)inject_bit_slip;
			uint8_t rxh = (uint8_t)bitstream_read_bits(air_bytes, air_bits, after_aa, 8u);
			uint8_t rxl = (uint8_t)bitstream_read_bits(air_bytes, air_bits, after_aa + 8, 8u);
			*rx_hdr_out = rxh;
			*rx_len_out = rxl;
			uint16_t cap_len = id_only ? 4u : (uint16_t)rxl;
			if (cap_len > BR_RAW_BUF_MAX) {
				cap_len = BR_RAW_BUF_MAX;
			}
			for (uint16_t b = 0; b < cap_len; b++) {
				raw_payload_out[b] = (uint8_t)bitstream_read_bits(
						air_bytes, air_bits, after_aa + 16 + (int64_t)b * 8, 8u);
			}
			*raw_len_out = cap_len;
			return true;
		}
	}
	return false;
}
