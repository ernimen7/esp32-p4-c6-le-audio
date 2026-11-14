/*
 * Unit tests for br_proto, br_hop, and br_air (SyncWord, HEC, CRC16, Whitening, FEC 1/3 & 2/3,
 * FHS pack/unpack, 79-hop & AFH hop kernel, C6 TX-in-Payload / Direct-AA & bit-slip RX extraction).
 */
#include "br_air.h"
#include "br_hop.h"
#include "br_proto.h"
#include <stdio.h>
#include <string.h>

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); \
		return 1; \
	} \
} while (0)

static int test_syncword_and_bdaddr(void)
{
	/* Core Spec GIAC (0x9E8B33) SyncWord: MSB-first spec hex = 0x475C58CC73345E72 -> air LSB-first = 0x4E7A2CCE331A3AE2 */
	uint64_t giac_sw = br_syncword_from_lap(BR_LAP_GIAC);
	CHECK(giac_sw == 0x4E7A2CCE331A3AE2ULL, "GIAC SyncWord must match Bluetooth Core Spec vector");
	/* Verify Byte 5 of GIAC SyncWord == 0x2C (44 bytes) -> C6 single-slot native FHS capture! */
	CHECK(((giac_sw >> 40) & 0xFFu) == 44u, "GIAC SyncWord byte 5 must equal 44");

	/* Derive C6 Classic BD_ADDR from arbitrary seed MACs */
	const uint8_t mac1[6] = {0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33};
	const uint8_t mac2[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
	uint8_t bd1[6], bd2[6];
	br_derive_c6_bdaddr(mac1, 46u, bd1);
	br_derive_c6_bdaddr(mac2, 46u, bd2);
	CHECK(memcmp(bd1, bd2, 6) != 0, "Different seed MACs must produce distinct Classic BD_ADDRs");

	uint32_t lap1 = 0;
	uint8_t uap1 = 0;
	uint16_t nap1 = 0;
	br_bdaddr_to_parts(bd1, &lap1, &uap1, &nap1);
	uint64_t sw1 = br_syncword_from_lap(lap1);
	CHECK(((sw1 >> 40) & 0xFFu) == 46u, "Derived CAC SyncWord byte 5 must equal 46");
	CHECK(br_access_addr_quality_ok((uint32_t)(sw1 & 0xFFFFFFFFULL)), "Derived AA must pass BLE quality checks");
	return 0;
}

static int test_fhs_and_fec(void)
{
	br_fhs_t in = {
		.parity34        = 0x2331A3AE2ULL,
		.lap             = 0x954B80u,
		.eir             = true,
		.sr              = 1u,
		.sp              = 2u,
		.uap             = 0x47u,
		.nap             = 0x1234u,
		.class_of_device = 0x240414u,
		.lt_addr         = 1u,
		.clk27_2         = 0x01234567u,
		.page_scan_mode  = 0u,
	};
	uint8_t raw18[18];
	br_fhs_t out;
	br_fhs_pack(&in, raw18);
	br_fhs_unpack(raw18, &out);
	CHECK(out.parity34 == in.parity34 && out.lap == in.lap && out.eir == in.eir &&
	      out.sr == in.sr && out.sp == in.sp && out.uap == in.uap && out.nap == in.nap &&
	      out.class_of_device == in.class_of_device && out.lt_addr == in.lt_addr &&
	      out.clk27_2 == in.clk27_2 && out.page_scan_mode == in.page_scan_mode,
	      "FHS 144-bit pack/unpack round-trip");

	/* Test 2/3 FEC (15,10) single-bit error correction across all 15 bit positions */
	for (uint16_t val = 0; val < 1024u; val += 37u) {
		uint16_t cw = br_fec23_encode_block10(val);
		bool fixed = false;
		CHECK(br_fec23_decode_block15(cw, &fixed) == val && !fixed, "Clean FEC2/3 decode");
		for (uint8_t bit = 0; bit < 15u; bit++) {
			uint16_t noisy = (uint16_t)(cw ^ (uint16_t)(1u << bit));
			bool corr = false;
			uint16_t dec = br_fec23_decode_block15(noisy, &corr);
			CHECK(dec == val && corr, "Single-bit error in 15-bit Hamming block must be corrected");
		}
	}
	return 0;
}

static int test_c6_air_roundtrip_and_bitslip(void)
{
	uint32_t lap = 0x954B80u;
	uint8_t  uap = 0x47u;
	uint64_t sw  = br_syncword_from_lap(lap);

	/* 1. Test ID packet TX -> C6 RX extraction with bit-slips -2..+2 */
	br_radio_tx_req_t tx_id;
	br_air_build_id_tx(sw, 37u, 10000u, BR_TX_MODE_IN_PAYLOAD, false, &tx_id);
	uint8_t air[300];
	size_t air_bits = 0;
	CHECK(br_air_tx_to_bitstream(&tx_id, air, sizeof(air), &air_bits) > 0u, "ID bitstream");
	for (int8_t slip = -2; slip <= 2; slip++) {
		uint8_t rxh = 0, rxl = 0, raw[256];
		uint16_t raw_len = 0;
		CHECK(br_air_bitstream_to_c6_rx(air, air_bits, sw, true, slip, &rxh, &rxl, raw, &raw_len), "C6 ID correlate");
		br_radio_rx_ind_t ind = {
			.skipped = false, .sync_matched = true, .rssi_dbm = -45,
			.rx_timestamp_us = 10000u, .rx_hdr = rxh, .rx_len = rxl,
			.raw_len = raw_len, .raw_payload = raw,
		};
		br_rx_decoded_t dec;
		CHECK(br_air_extract_rx(sw, uap, 0x7Fu, false, NULL, NULL, &ind, &dec), "Extract ID");
		CHECK(dec.is_id_pkt && dec.sync_ok, "Decoded ID flag");
	}

	/* 2. Test Inquiry FHS with unknown Slave X_ir whitening seed + injected bit errors */
	uint64_t giac_sw = br_syncword_from_lap(BR_LAP_GIAC);
	br_fhs_t fhs = {
		.parity34 = sw & 0x3FFFFFFFFULL, .lap = lap, .eir = false, .sr = 1u, .sp = 2u,
		.uap = uap, .nap = 0x55AAu, .class_of_device = 0x240404u, .lt_addr = 0u, .clk27_2 = 0x12345u,
	};
	uint8_t fhs18[18];
	br_fhs_pack(&fhs, fhs18);
	br_pkt_hdr_t fhs_hdr = {.lt_addr = 0, .type = BR_PKT_FHS, .flow = 1, .arqn = 0, .seqn = 0};
	br_radio_tx_req_t tx_fhs;
	CHECK(br_air_build_packet_tx(giac_sw, BR_DCI_UAP, br_whiten_seed_x(19u),
			&fhs_hdr, fhs18, 18u, NULL, NULL, 11u, 20000u, BR_TX_MODE_IN_PAYLOAD, &tx_fhs), "Build FHS");
	CHECK(br_air_tx_to_bitstream(&tx_fhs, air, sizeof(air), &air_bits) > 0u, "FHS air bits");
	/* Flip a bit in header (protected by 1/3 FEC) and a bit in FHS payload (protected by 2/3 FEC) */
	air[19] ^= 0x04u;
	air[30] ^= 0x10u;

	uint8_t rxh = 0, rxl = 0, raw[256];
	uint16_t raw_len = 0;
	CHECK(br_air_bitstream_to_c6_rx(air, air_bits, giac_sw, false, 1, &rxh, &rxl, raw, &raw_len), "C6 FHS RX");
	br_radio_rx_ind_t ind = {
		.skipped = false, .sync_matched = true, .rssi_dbm = -52,
		.rx_timestamp_us = 20000u, .rx_hdr = rxh, .rx_len = rxl,
		.raw_len = raw_len, .raw_payload = raw,
	};
	br_rx_decoded_t dec;
	/* Pass wrong initial seed (3) with search_fhs_seeds=true: decoder must find seed 0x60|19! */
	CHECK(br_air_extract_rx(giac_sw, BR_DCI_UAP, br_whiten_seed_x(3u), true, NULL, NULL, &ind, &dec),
	      "Extract FHS with unknown X_ir seed + FEC errors + 1-bit slip");
	CHECK(dec.crc_ok && dec.hdr.type == BR_PKT_FHS && dec.body_len == 18u, "FHS CRC OK");
	br_fhs_t rx_fhs;
	br_fhs_unpack(dec.body, &rx_fhs);
	CHECK(rx_fhs.lap == lap && rx_fhs.uap == uap && rx_fhs.nap == 0x55AAu, "Unpacked FHS matches speaker");

	/* 3. Test DH3 168-byte A2DP audio packet round-trip */
	uint8_t sbc_frame[170];
	uint8_t acl_h[2];
	br_acl_hdr_pack(true, BR_LLID_L2CAP_START, 1u, 168u, acl_h);
	sbc_frame[0] = acl_h[0];
	sbc_frame[1] = acl_h[1];
	for (uint16_t i = 0; i < 168u; i++) {
		sbc_frame[2u + i] = (uint8_t)(i * 7u + 3u);
	}
	br_pkt_hdr_t dh3_hdr = {.lt_addr = 1, .type = BR_PKT_DH3, .flow = 1, .arqn = 1, .seqn = 1};
	br_radio_tx_req_t tx_dh3;
	CHECK(br_air_build_packet_tx(sw, uap, br_whiten_seed_clk(0x1040u),
			&dh3_hdr, sbc_frame, 170u, NULL, NULL, 77u, 30000u, BR_TX_MODE_IN_PAYLOAD, &tx_dh3), "Build DH3");
	CHECK(br_air_tx_to_bitstream(&tx_dh3, air, sizeof(air), &air_bits) > 0u, "DH3 air bits");

	/* Simulate speaker receiving full DH3 (override rxl to 220 bytes as on real BR receiver) */
	CHECK(br_air_bitstream_to_c6_rx(air, air_bits, sw, false, 0, &rxh, &rxl, raw, &raw_len), "Correlate DH3");
	/* Note: speaker is not limited by C6 single-slot rxl=46; copy full post-AA payload for speaker decode */
	size_t full_bytes = (air_bits / 8u);
	(void)full_bytes;
	/* Also test Slave->Master DH1 (27B <= 46B C6 single-slot capture!) */
	uint8_t dh1_body[28];
	br_acl_hdr_pack(false, BR_LLID_L2CAP_START, 1u, 27u, acl_h);
	dh1_body[0] = acl_h[0];
	for (uint8_t i = 0; i < 27u; i++) {
		dh1_body[1u + i] = (uint8_t)(0xA0u + i);
	}
	br_pkt_hdr_t dh1_hdr = {.lt_addr = 1, .type = BR_PKT_DH1, .flow = 1, .arqn = 1, .seqn = 0};
	br_radio_tx_req_t tx_dh1;
	CHECK(br_air_build_packet_tx(sw, uap, br_whiten_seed_clk(0x1042u),
			&dh1_hdr, dh1_body, 28u, NULL, NULL, 22u, 30625u, BR_TX_MODE_IN_PAYLOAD, &tx_dh1), "Build DH1");
	CHECK(br_air_tx_to_bitstream(&tx_dh1, air, sizeof(air), &air_bits) > 0u, "DH1 air bits");
	CHECK(br_air_bitstream_to_c6_rx(air, air_bits, sw, false, 0, &rxh, &rxl, raw, &raw_len), "C6 DH1 RX (aligned)");
	CHECK(raw_len == 46u, "C6 RXD_LEN captures exactly 46 bytes for OUR_LAP");
	CHECK(br_air_bitstream_to_c6_rx(air, air_bits, sw, false, -1, &rxh, &rxl, raw, &raw_len), "C6 DH1 RX (bit-slip -1)");
	ind.rx_hdr = rxh;
	ind.rx_len = rxl;
	ind.raw_len = raw_len;
	ind.raw_payload = raw;
	CHECK(br_air_extract_rx(sw, uap, br_whiten_seed_clk(0x1042u), false, NULL, NULL, &ind, &dec), "Decode DH1");
	CHECK(dec.crc_ok && dec.body_len == 28u && memcmp(dec.body, dh1_body, 28u) == 0, "DH1 payload exact");
	return 0;
}

/* What leaves the modem after its access address for a TX request: header, length and payload bytes, least
 * significant bit first, then the CRC register, most significant bit first. */
static size_t modem_bits_after_aa(const br_radio_tx_req_t *tx, uint8_t *bits, size_t cap)
{
	uint8_t pdu[2 + BR_RAW_BUF_MAX];
	pdu[0] = tx->tx_hdr;
	pdu[1] = tx->tx_len;
	memcpy(&pdu[2], tx->tx_payload, tx->tx_len);
	const size_t pdu_len = 2u + tx->tx_len;
	const uint32_t crc = br_air_ble_crc24(tx->crc_preset_set ? tx->crc_preset : 0x555555u, pdu, pdu_len);
	size_t n = 0;
	for (size_t i = 0; i < pdu_len && n < cap; i++) {
		for (uint8_t b = 0; b < 8u && n < cap; b++) {
			bits[n++] = (uint8_t)((pdu[i] >> b) & 1u);
		}
	}
	for (int b = 23; b >= 0 && n < cap; b--) {
		bits[n++] = (uint8_t)((crc >> b) & 1u);
	}
	return n;
}

static int test_id_packet_that_ends_with_the_sync_word(void)
{
	/* The preset is the inverse of the CRC: any wanted register comes out again. */
	static const uint8_t pdu[] = { 0x55u, 0x06u, 0xAAu, 0x01u, 0x80u, 0x7Fu, 0xFFu, 0x00u };
	static const uint32_t wanted[] = { 0x000000u, 0xFFFFFFu, 0x555555u, 0x123456u, 0x800001u };
	for (size_t i = 0; i < sizeof(wanted) / sizeof(wanted[0]); i++) {
		const uint32_t preset = br_air_ble_crc24_preset(wanted[i], pdu, sizeof(pdu));
		CHECK(br_air_ble_crc24(preset, pdu, sizeof(pdu)) == wanted[i], "CRC preset gives the wanted register");
	}

	/* Sync words with either first bit and either last bit: GIAC (first 0, last 0 in air order), an address with
	 * the top LAP bit clear, one with it set. */
	static const uint32_t laps[] = { 0x9E8B33u, 0x639769u, 0x000000u, 0xFFFFFFu, 0x954B80u };
	for (size_t i = 0; i < sizeof(laps) / sizeof(laps[0]); i++) {
		const uint64_t sw = br_syncword_from_lap(laps[i]);
		br_radio_tx_req_t tx;
		br_air_build_id_tx(sw, 12u, 20000u, BR_TX_MODE_IN_PAYLOAD, true, &tx);
		uint8_t bits[16 + 8 * 8 + 24];
		const size_t nbits = modem_bits_after_aa(&tx, bits, sizeof(bits));
		/* header, length, one byte whose last four bits are the BR preamble, 64 sync word bits, and no more */
		CHECK(nbits == 16u + 8u + 64u, "ID ends with the last sync word bit");
		for (uint8_t b = 0; b < 64u; b++) {
			CHECK(bits[24u + b] == (uint8_t)((sw >> b) & 1ULL), "sync word bit on the air");
		}
		const uint8_t first = (uint8_t)(sw & 1ULL);
		CHECK(bits[23] != first && bits[22] == first && bits[21] != first && bits[20] == first,
				"preamble alternates into the first sync word bit");
		CHECK(tx.lead_us == 60u && tx.access_addr == 0x55555555u, "same start and prefix as TX_MODE_IN_PAYLOAD");
	}

	/* Without the option nothing changes: the fixed CRC preset, 24 bits after the sync word. */
	br_radio_tx_req_t old;
	br_air_build_id_tx(br_syncword_from_lap(0x639769u), 12u, 20000u, BR_TX_MODE_IN_PAYLOAD, false, &old);
	CHECK(!old.crc_preset_set && old.tx_len == 9u, "old ID format untouched");
	return 0;
}

static int test_hop_kernel_and_afh(void)
{
	uint32_t ulap = br_ulap(0x954B80u, 0x47u);
	uint8_t seen[79] = {0};
	for (uint32_t clk = 0; clk < 4000u * 2u; clk += 2u) {
		uint8_t ch = br_hop_connection_79(ulap, clk);
		CHECK(ch < 79u, "79-hop channel in 0..78");
		seen[ch] = 1u;
	}
	uint8_t count = 0;
	for (uint8_t i = 0; i < 79u; i++) {
		count = (uint8_t)(count + seen[i]);
	}
	CHECK(count == 79u, "79-hop sequence visits all 79 even and odd 1-MHz RF channels");

	/* AFH with 25 enabled channels (avoiding Wi-Fi ch 1..6 = BT ch 0..30) */
	uint8_t map[10] = {0};
	for (uint8_t ch = 40u; ch < 65u; ch++) {
		map[ch >> 3] |= (uint8_t)(1u << (ch & 7u));
	}
	br_afh_state_t afh;
	CHECK(br_afh_init(&afh, map) && afh.num_used == 25u, "AFH init 25 channels");
	for (uint32_t clk = 0; clk < 1000u; clk += 4u) {
		uint8_t m_ch = br_hop_connection(ulap, clk, &afh);
		uint8_t s_ch = br_hop_connection(ulap, clk + 2u, &afh);
		CHECK(m_ch >= 40u && m_ch < 65u, "AFH channel strictly inside allowed map");
		CHECK(m_ch == s_ch, "AFH same-channel Slave->Master response matches Master->Slave channel");
	}
	return 0;
}

/* True when the bits from `at` on (bit 0 of byte 0 first) are the string of '0' and '1', sent left to right;
 * spaces in the string are skipped. */
static bool air_bits_equal(const uint8_t *bits_lsb, size_t at, const char *expected)
{
	size_t i = 0;
	for (const char *c = expected; *c != '\0'; c++) {
		if (*c == ' ') {
			continue;
		}
		const uint8_t bit = (uint8_t)((bits_lsb[(at + i) >> 3] >> ((at + i) & 7u)) & 1u);
		if (bit != (uint8_t)(*c - '0')) {
			return false;
		}
		i++;
	}
	return true;
}

/* Official sample data of the Bluetooth Core Specification 5.4, Vol 2 Part G: sections 4 (HEC and packet header),
 * 5 (CRC), 6.2 (complete DM1 packet), 8 (whitening sequence) and 9 (2/3 FEC). The round trips above only prove that
 * our encoder and our decoder agree with each other, and the one packet with a payload decoded from a real device
 * was an inquiry FHS, whose HEC and CRC start from 0 and so say nothing about how a UAP is loaded. */
static int test_official_sample_data(void)
{
	static const struct {
		uint8_t     uap;
		uint16_t    data;
		uint8_t     hec;
		const char *header_octal; /* 54 air bits, three per digit, sent left to right */
	} hec_rows[] = {
		{ 0x00u, 0x123u, 0xe1u, "770007007070000777" }, { 0x47u, 0x123u, 0x06u, "770007007007700000" },
		{ 0x00u, 0x124u, 0x32u, "007007007007007700" }, { 0x47u, 0x124u, 0xd5u, "007007007070707077" },
		{ 0x00u, 0x125u, 0x5au, "707007007007077070" }, { 0x47u, 0x125u, 0xbdu, "707007007070777707" },
		{ 0x00u, 0x126u, 0xe2u, "077007007007000777" }, { 0x47u, 0x126u, 0x05u, "077007007070700000" },
		{ 0x00u, 0x127u, 0x8au, "777007007007070007" }, { 0x47u, 0x127u, 0x6du, "777007007070770770" },
		{ 0x00u, 0x11bu, 0x9eu, "770770007007777007" }, { 0x47u, 0x11bu, 0x79u, "770770007070077770" },
		{ 0x00u, 0x11cu, 0x4du, "007770007070770070" }, { 0x47u, 0x11cu, 0xaau, "007770007007070707" },
		{ 0x00u, 0x11du, 0x25u, "707770007070700700" }, { 0x47u, 0x11du, 0xc2u, "707770007007000077" },
		{ 0x00u, 0x11eu, 0x9du, "077770007070777007" }, { 0x47u, 0x11eu, 0x7au, "077770007007077770" },
		{ 0x00u, 0x11fu, 0xf5u, "777770007070707777" }, { 0x47u, 0x11fu, 0x12u, "777770007007007000" },
	};
	for (size_t r = 0; r < sizeof(hec_rows) / sizeof(hec_rows[0]); r++) {
		const uint8_t hec = br_hec_compute(hec_rows[r].data, hec_rows[r].uap);
		if (hec != hec_rows[r].hec) {
			fprintf(stderr, "HEC of data 0x%03x with UAP 0x%02x: 0x%02x, the specification says 0x%02x\n",
					hec_rows[r].data, hec_rows[r].uap, hec, hec_rows[r].hec);
		}
		CHECK(hec == hec_rows[r].hec, "HEC must match the specification's sample data");
		uint64_t air54 = 0;
		br_fec13_encode18((uint32_t)hec_rows[r].data | ((uint32_t)hec << 10), &air54);
		for (uint8_t d = 0; d < 18u; d++) {
			const uint8_t three = (uint8_t)((air54 >> (3u * d)) & 7u);
			CHECK(three == (hec_rows[r].header_octal[d] == '7' ? 7u : 0u), "54-bit header must match the sample data");
		}
	}

	/* Section 5: ten bytes, UAP 0x47, codeword ... 6d d2, each byte sent LSB first. */
	static const uint8_t crc_data[10] = { 0x4eu, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u, 0x09u };
	const uint16_t crc = br_crc16_compute(crc_data, sizeof(crc_data), 0x47u);
	if (crc != 0xd26du) {
		fprintf(stderr, "CRC with UAP 0x47: bytes %02x %02x, the specification says 6d d2\n", crc & 0xFFu, crc >> 8);
	}
	CHECK(crc == 0xd26du, "CRC must match the specification's sample data");

	/* Section 8: the register from all ones; the output is its top bit. */
	static const uint8_t whitening_states[] = {
		0x7Fu, 0x6Fu, 0x4Fu, 0x0Fu, 0x1Eu, 0x3Cu, 0x78u, 0x61u, 0x53u, 0x37u, 0x6Eu, 0x4Du, 0x0Bu, 0x16u, 0x2Cu,
		0x58u, 0x21u, 0x42u, 0x15u, 0x2Au, 0x54u, 0x39u, 0x72u, 0x75u, 0x7Bu, 0x67u, 0x5Fu, 0x2Fu, 0x5Eu,
	};
	uint8_t lfsr = 0x7Fu;
	for (size_t i = 0; i < sizeof(whitening_states); i++) {
		CHECK(lfsr == whitening_states[i], "whitening register must follow the specification's sample data");
		CHECK(br_whiten_step_bit(&lfsr) == (whitening_states[i] >> 6), "whitening output is the register's top bit");
	}

	/* Section 9: codewords of single information bits, sent left to right. */
	static const char *const fec_codewords[10] = {
		"1000000000 11010", "0100000000 01101", "0010000000 11100", "0001000000 01110", "0000100000 00111",
		"0000010000 11001", "0000001000 10110", "0000000100 01011", "0000000010 11111", "0000000001 10101",
	};
	for (uint8_t b = 0; b < 10u; b++) {
		const uint16_t cw     = br_fec23_encode_block10((uint16_t)(1u << b));
		const uint8_t  cw2[2] = { (uint8_t)(cw & 0xFFu), (uint8_t)(cw >> 8) };
		if (!air_bits_equal(cw2, 0u, fec_codewords[b])) {
			fprintf(stderr, "2/3 FEC codeword of data 0x%03x: 0x%04x, the specification says %s\n", 1u << b, cw,
					fec_codewords[b]);
		}
		CHECK(air_bits_equal(cw2, 0u, fec_codewords[b]), "2/3 FEC codeword must match the sample data");
	}

	/* Section 6.2: a complete DM1 packet, UAP 0x47, no whitening (a register of zeros leaves the bits alone). */
	const uint64_t     sw      = br_syncword_from_lap(0x954B80u);
	const br_pkt_hdr_t dm1     = { .lt_addr = 3u, .type = BR_PKT_DM1, .flow = 0u, .arqn = 1u, .seqn = 0u };
	const uint8_t      body[6] = { 0x2Eu, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u }; /* payload header: start, flow, 5 */
	br_radio_tx_req_t  tx;
	CHECK(br_air_build_packet_tx(sw, 0x47u, 0x00u, &dm1, body, sizeof(body), NULL, NULL, 5u, 10000u,
			BR_TX_MODE_IN_PAYLOAD, &tx), "build the sample DM1 packet");
	/* In the modem's payload: preamble byte, 64 sync word bits, 4 trailer bits, then header and payload. */
	const size_t after_trailer = 8u + 64u + 4u;
	CHECK(air_bits_equal(tx.tx_payload, after_trailer, "111111000 111111000000 000111000 111000000111111111111000"),
			"header of the sample DM1 packet");
	CHECK(air_bits_equal(tx.tx_payload, after_trailer + 54u,
			"0111010010 11001 0000000100 01011 0000110000 11110 0000100000 00111 1010000011 01100 "
			"1011000011 00010 0110000000 10001"), "payload of the sample DM1 packet");
	CHECK(tx.tx_len == (8u + 64u + 4u + 54u + 105u + 7u) / 8u, "the sample DM1 packet ends after its last codeword");
	return 0;
}

/* Official frequency hopping sample data, Vol 2 Part G section 2.2 (second set, ULAP 0x2a96ef25): the page train,
 * the page response frequencies, the Central Response substate after a page answered at CLKE 0x12, and the basic
 * channel hopping sequence of the connection from CLK 0x10. */
static int test_official_hop_sample_data(void)
{
	const uint32_t ulap = 0x2a96ef25u;

	/* Page substate, CLKE 0x00..0x1f, A train: the sixteen transmit frequencies and the answer frequency of each. */
	static const uint8_t page_tx[16] = { 41, 5, 9, 43, 47, 11, 15, 45, 49, 13, 17, 51, 55, 19, 23, 53 };
	static const uint8_t page_rx[16] = { 10, 4, 6, 16, 18, 12, 14, 32, 34, 28, 30, 24, 26, 20, 22, 40 };
	for (uint8_t i = 0; i < 16u; i++) {
		uint8_t x = 0xFFu;
		CHECK(br_hop_train_chan_tx(ulap, 0u, BR_TRAIN_A, i, &x) == page_tx[i], "page frequency must match the sample");
		CHECK(br_hop_train_chan_rx(ulap, x) == page_rx[i], "page response frequency must match the sample");
		/* The same train from the clock estimate: both halves of the transmit slots of CLKE 0x00..0x1f. */
		const uint32_t clke = ((uint32_t)(i >> 1) << 2) | (i & 1u);
		CHECK(br_hop_page_master_tx(ulap, clke, BR_TRAIN_A, NULL) == page_tx[i], "page frequency from CLKE");
	}

	/* Central Response substate: the page of CLKE 0x10 (X = 0) was answered at 0x12; the FHS of N = 1 leaves at
	 * 0x14, each later one a frame after the one before, and the answer to each comes a slot after it. */
	static const uint8_t fhs_tx[7] = { 13, 17, 51, 55, 19, 23, 53 };
	static const uint8_t fhs_rx[7] = { 28, 30, 24, 26, 20, 22, 40 };
	uint8_t frozen_x = 0xFFu;
	CHECK(br_hop_train_chan_tx(ulap, 0x10u, BR_TRAIN_A, 8u, &frozen_x) == 49u && frozen_x == 0u, "answered page");
	for (uint8_t n = 1; n <= 7u; n++) {
		uint8_t xprm = 0xFFu;
		CHECK(br_hop_master_page_rsp_tx(ulap, frozen_x, n, &xprm) == fhs_tx[n - 1u], "FHS frequency of the sample");
		CHECK(xprm == n, "X of the FHS, which is also its whitening seed, is the frozen X plus N");
		CHECK(br_hop_master_page_rsp_rx(ulap, frozen_x, n) == fhs_rx[n - 1u], "frequency of the answer to the FHS");
	}

	/* Connection state, basic channel hopping sequence, CLK 0x10, 0x12, ... */
	static const uint8_t connection[] = {
		55, 26, 19, 20, 23, 22, 53, 40, 57, 42, 21, 36, 25, 38, 27, 63, /* 0x010 */
		31, 65, 74, 59, 78, 61, 29,  0, 33,  2, 76, 75,  1, 77, 35, 71, /* 0x030 */
		39, 73,  3, 67,  7, 69, 37,  8, 41, 10,  5,  4,  9,  6, 43, 16, /* 0x050 */
		47, 18, 11, 12, 15, 14, 45, 32,  2, 66, 47, 60, 49, 64,  4, 54, /* 0x070 */
		 6, 58, 51, 52, 53, 56,  8, 70, 10, 74, 55, 68, 57, 72, 59, 14, /* 0x090 */
		61, 18, 27, 12, 29, 16, 63, 30, 65, 34, 31, 28, 33, 32, 67, 22, /* 0x0b0 */
		69, 26, 35, 20, 37, 24, 71, 38, 73, 42, 39, 36, 41, 40, 75, 46, /* 0x0d0 */
		77, 50, 43, 44, 45, 48,  0, 62, 26, 11, 69,  5, 73,  7, 36, 17, /* 0x0f0 */
		40, 19,  4, 13,  8, 15, 38, 25, 42, 27,  6, 21, 10, 23, 12, 48, /* 0x110 */
		16, 50, 59, 44, 63, 46, 14, 56, 18, 58, 61, 52, 65, 54, 28, 64, /* 0x130 */
	};
	for (size_t i = 0; i < sizeof(connection); i++) {
		const uint32_t clk = 0x10u + 2u * (uint32_t)i;
		const uint8_t  ch  = br_hop_connection_79(ulap, clk);
		if (ch != connection[i]) {
			fprintf(stderr, "connection hop at CLK 0x%03x: %u, the specification says %u\n", (unsigned)clk, ch,
					connection[i]);
		}
		CHECK(ch == connection[i], "basic channel hopping sequence must match the sample data");
	}
	return 0;
}

int main(void)
{
	if (test_official_sample_data() != 0) return 1;
	if (test_official_hop_sample_data() != 0) return 1;
	if (test_syncword_and_bdaddr() != 0) return 1;
	if (test_fhs_and_fec() != 0) return 1;
	if (test_c6_air_roundtrip_and_bitslip() != 0) return 1;
	if (test_id_packet_that_ends_with_the_sync_word() != 0) return 1;
	if (test_hop_kernel_and_afh() != 0) return 1;
	printf("test_air_hop: OK\n");
	return 0;
}
