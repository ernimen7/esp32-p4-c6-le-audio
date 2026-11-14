/*
 * Bluetooth Classic Baseband Air-Framing, FEC, Whitening, HEC, CRC-16, and ESP32-C6 Mode-0 codecs.
 */
#pragma once

#include "br_platform.h"
#include "br_proto.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compute 64-bit Bluetooth Sync Word from 24-bit LAP (bit 0 = s_0 transmitted first on air). */
uint64_t br_syncword_from_lap(uint32_t lap);

/* Check whether low 32 bits of a Sync Word have clean autocorrelation / transition properties for C6 AA. */
bool br_access_addr_quality_ok(uint32_t aa);

/* 4-bit Preamble (bit 0 first) and 4-bit Trailer (bit 0 first) for a 64-bit Sync Word. */
uint8_t br_preamble4(uint64_t sw_air);
uint8_t br_trailer4(uint64_t sw_air);

/* 8-bit HEC over 10-bit header (Core Spec Vol 2 Part B §7.1.1, g(D) = D^8+D^7+D^5+D^2+D+1). */
uint8_t br_hec_compute(uint16_t hdr10, uint8_t uap);

/* 16-bit CRC-CCITT over payload bits/bytes (Core Spec Vol 2 Part B §7.1.2, g(D) = D^16+D^12+D^5+1). */
uint16_t br_crc16_compute(const uint8_t *data, size_t len_bytes, uint8_t uap);

/* 7-bit Data Whitening LFSR (g(D) = D^7 + D^4 + 1).
 * For Connection: seed = 0x40 | ((clk >> 1) & 0x3F)  ([D6=1, CLK6..CLK1]).
 * For Page/Inquiry FHS: seed = 0x60 | (x5 & 0x1F)    ([D6=1, D5=1, X4..X0]). */
static inline uint8_t br_whiten_seed_clk(uint32_t clk)
{
	return (uint8_t)(0x40u | ((clk >> 1) & 0x3Fu));
}

static inline uint8_t br_whiten_seed_x(uint8_t x5)
{
	return (uint8_t)(0x60u | (x5 & 0x1Fu));
}

uint8_t br_whiten_step_bit(uint8_t *lfsr7);
void br_whiten_bits(uint8_t *lfsr7, uint8_t *bit_buf_lsb, size_t num_bits);
void br_whiten_bytes(uint8_t *lfsr7, uint8_t *bytes, size_t num_bytes);

/* 1/3 FEC (3x bit repetition) for 18-bit whitened header -> 54 air bits, plus majority vote decoder. */
void br_fec13_encode18(uint32_t hdr18, uint64_t *out_air54);
uint32_t br_fec13_decode54(uint64_t air54, uint8_t *out_bit_flips);

/* 2/3 FEC (15,10) shortened Hamming code (g(D) = D^5 + D^4 + D^2 + 1 = 0o65):
 * encodes 10-bit blocks (zero-padded to multiple of 10 bits) into 15-bit codewords, and decodes
 * with 1-bit error correction per 15-bit block. Returns number of output bytes/bits. */
uint16_t br_fec23_encode_block10(uint16_t info10);
uint16_t br_fec23_decode_block15(uint16_t code15, bool *corrected);
size_t br_fec23_encode_bytes(const uint8_t *in_bytes, size_t in_len, uint8_t *out_bits_packed, size_t out_cap);
size_t br_fec23_decode_bytes(const uint8_t *in_bits_packed, size_t num_blocks15,
		uint8_t *out_bytes, size_t out_cap, uint16_t *out_corrections);

/* Optional E0 payload+CRC cipher callback invoked between CRC append and Whitening on TX (and inverse on RX). */
typedef void (*br_payload_cipher_fn)(void *cipher_ctx, uint8_t *payload_and_crc, size_t len_bytes);

/* The 24-bit CRC the C6 modem appends to every packet (x^24 + x^10 + x^9 + x^6 + x^4 + x^3 + x + 1): the register
 * after the PDU bytes (header, length, payload), each taken least significant bit first. The modem sends the
 * register most significant bit first. */
uint32_t br_air_ble_crc24(uint32_t preset, const uint8_t *pdu, size_t len);
/* The preset with which the register ends as `wanted` after the same PDU bytes. */
uint32_t br_air_ble_crc24_preset(uint32_t wanted, const uint8_t *pdu, size_t len);

/* Build a complete C6 Mode-0 TX slot request for an ID packet (68 air bits: 4b preamble + 64b syncword).
 * ends_with_sync: the packet ends with the last sync word bit, as an ID packet has to: the 24 bits the modem
 * appends as its CRC are sync word bits 40..63 (crc_preset is solved for that). Without it 24 more bits follow the
 * sync word, which a device in inquiry scan accepts and a device in page scan does not answer (hardware runs 8 to
 * 12, 2026-11-10). */
void br_air_build_id_tx(uint64_t sw_air, uint8_t chan_1mhz, uint32_t anchor_us,
		br_tx_mode_t mode, bool ends_with_sync, br_radio_tx_req_t *out_tx);

/* Build a complete C6 Mode-0 TX slot request for any header+payload packet (NULL, POLL, FHS, DM1, DH1, DM3, DH3). */
bool br_air_build_packet_tx(uint64_t sw_air, uint8_t uap, uint8_t whiten_seed7,
		const br_pkt_hdr_t *hdr, const uint8_t *body, uint16_t body_len,
		br_payload_cipher_fn cipher_fn, void *cipher_ctx,
		uint8_t chan_1mhz, uint32_t anchor_us, br_tx_mode_t mode,
		br_radio_tx_req_t *out_tx);

/* Decoded RX baseband packet output. */
typedef struct {
	bool         sync_ok;
	bool         is_id_pkt;
	bool         hec_ok;
	bool         crc_ok;
	int8_t       bit_slip;       /* Detected timing offset in bits (-3..+3) */
	uint8_t      fec13_flips;
	uint16_t     fec23_fixes;
	uint8_t      whiten_seed_used;
	br_pkt_hdr_t hdr;
	uint16_t     body_len;       /* Bytes in body[] (excludes 2-byte CRC16; includes ACL payload hdr or 18B FHS) */
	uint8_t      body[256];
} br_rx_decoded_t;

/* Extract and decode a Bluetooth Classic packet from an ESP32-C6 Mode-0 raw RX buffer.
 * Supports bit-slip search (-3..+3 bits) and optional multi-seed Inquiry FHS unwhitening (`search_fhs_seeds`). */
bool br_air_extract_rx(uint64_t expected_sw_air, uint8_t expected_uap, uint8_t whiten_seed7,
		bool search_fhs_seeds, br_payload_cipher_fn decipher_fn, void *cipher_ctx,
		const br_radio_rx_ind_t *rx_ind, br_rx_decoded_t *out);

/* Convert a TX request into raw air bitstream (1 bit per LSB-packed byte stream starting at preamble) for sim/tests,
 * and convert an air bitstream at `expected_sw_air` into a simulated C6 `br_radio_rx_ind_t`. */
size_t br_air_tx_to_bitstream(const br_radio_tx_req_t *tx, uint8_t *out_air_bytes, size_t max_bytes, size_t *out_bits);
bool br_air_bitstream_to_c6_rx(const uint8_t *air_bytes, size_t air_bits, uint64_t target_sw_air,
		bool id_only, int8_t inject_bit_slip,
		uint8_t *rx_hdr_out, uint8_t *rx_len_out, uint8_t *raw_payload_out, uint16_t *raw_len_out);

#ifdef __cplusplus
}
#endif
