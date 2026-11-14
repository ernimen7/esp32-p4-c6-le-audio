/*
 * Soft-BR protocol helpers: BD_ADDR splitting, 10-bit packet header, 144-bit FHS, and ACL payload header.
 */
#include "br_proto.h"
#include <string.h>

void br_bdaddr_to_parts(const uint8_t bd_addr[6], uint32_t *lap, uint8_t *uap, uint16_t *nap)
{
	if (lap) {
		*lap = (uint32_t)bd_addr[0] | ((uint32_t)bd_addr[1] << 8) | ((uint32_t)bd_addr[2] << 16);
	}
	if (uap) {
		*uap = bd_addr[3];
	}
	if (nap) {
		*nap = (uint16_t)((uint16_t)bd_addr[4] | ((uint16_t)bd_addr[5] << 8));
	}
}

void br_parts_to_bdaddr(uint32_t lap, uint8_t uap, uint16_t nap, uint8_t bd_addr[6])
{
	bd_addr[0] = (uint8_t)(lap & 0xFFu);
	bd_addr[1] = (uint8_t)((lap >> 8) & 0xFFu);
	bd_addr[2] = (uint8_t)((lap >> 16) & 0xFFu);
	bd_addr[3] = uap;
	bd_addr[4] = (uint8_t)(nap & 0xFFu);
	bd_addr[5] = (uint8_t)((nap >> 8) & 0xFFu);
}

uint16_t br_pkt_hdr_pack10(const br_pkt_hdr_t *h)
{
	return (uint16_t)(((uint16_t)(h->lt_addr & 0x07u)) |
	                  ((uint16_t)(h->type & 0x0Fu) << 3) |
	                  ((uint16_t)(h->flow & 0x01u) << 7) |
	                  ((uint16_t)(h->arqn & 0x01u) << 8) |
	                  ((uint16_t)(h->seqn & 0x01u) << 9));
}

void br_pkt_hdr_unpack10(uint16_t raw10, br_pkt_hdr_t *out)
{
	out->lt_addr = (uint8_t)(raw10 & 0x07u);
	out->type    = (uint8_t)((raw10 >> 3) & 0x0Fu);
	out->flow    = (uint8_t)((raw10 >> 7) & 0x01u);
	out->arqn    = (uint8_t)((raw10 >> 8) & 0x01u);
	out->seqn    = (uint8_t)((raw10 >> 9) & 0x01u);
}

static void put_bits_le(uint8_t *buf, uint16_t bit_pos, uint8_t num_bits, uint64_t val)
{
	for (uint8_t i = 0; i < num_bits; i++) {
		uint16_t p = (uint16_t)(bit_pos + i);
		if ((val >> i) & 1ULL) {
			buf[p >> 3] |= (uint8_t)(1u << (p & 7u));
		}
	}
}

static uint64_t get_bits_le(const uint8_t *buf, uint16_t bit_pos, uint8_t num_bits)
{
	uint64_t v = 0;
	for (uint8_t i = 0; i < num_bits; i++) {
		uint16_t p = (uint16_t)(bit_pos + i);
		if ((buf[p >> 3] >> (p & 7u)) & 1u) {
			v |= (1ULL << i);
		}
	}
	return v;
}

void br_fhs_pack(const br_fhs_t *fhs, uint8_t out18[18])
{
	memset(out18, 0, 18);
	put_bits_le(out18, 0,   34, fhs->parity34 & 0x3FFFFFFFFULL);
	put_bits_le(out18, 34,  24, fhs->lap & 0xFFFFFFu);
	put_bits_le(out18, 58,  1,  fhs->eir ? 1u : 0u);
	put_bits_le(out18, 59,  1,  0u); /* Reserved */
	put_bits_le(out18, 60,  2,  fhs->sr & 0x03u);
	put_bits_le(out18, 62,  2,  fhs->sp & 0x03u);
	put_bits_le(out18, 64,  8,  fhs->uap);
	put_bits_le(out18, 72,  16, fhs->nap);
	put_bits_le(out18, 88,  24, fhs->class_of_device & 0xFFFFFFu);
	put_bits_le(out18, 112, 3,  fhs->lt_addr & 0x07u);
	put_bits_le(out18, 115, 26, fhs->clk27_2 & 0x3FFFFFFu);
	put_bits_le(out18, 141, 3,  fhs->page_scan_mode & 0x07u);
}

void br_fhs_unpack(const uint8_t in18[18], br_fhs_t *out)
{
	memset(out, 0, sizeof(*out));
	out->parity34        = get_bits_le(in18, 0,   34);
	out->lap             = (uint32_t)get_bits_le(in18, 34,  24);
	out->eir             = get_bits_le(in18, 58,  1) != 0;
	out->sr              = (uint8_t)get_bits_le(in18, 60,  2);
	out->sp              = (uint8_t)get_bits_le(in18, 62,  2);
	out->uap             = (uint8_t)get_bits_le(in18, 64,  8);
	out->nap             = (uint16_t)get_bits_le(in18, 72,  16);
	out->class_of_device = (uint32_t)get_bits_le(in18, 88,  24);
	out->lt_addr         = (uint8_t)get_bits_le(in18, 112, 3);
	out->clk27_2         = (uint32_t)get_bits_le(in18, 115, 26);
	out->page_scan_mode  = (uint8_t)get_bits_le(in18, 141, 3);
}

bool br_pkt_is_multislot(uint8_t pkt_type)
{
	return pkt_type == BR_PKT_DM3 || pkt_type == BR_PKT_DH3 ||
	       pkt_type == BR_PKT_DM5 || pkt_type == BR_PKT_DH5;
}

bool br_pkt_uses_fec23(uint8_t pkt_type)
{
	return pkt_type == BR_PKT_FHS || pkt_type == BR_PKT_DM1 ||
	       pkt_type == BR_PKT_DM3 || pkt_type == BR_PKT_DM5;
}

bool br_pkt_has_crc(uint8_t pkt_type)
{
	return pkt_type == BR_PKT_FHS || pkt_type == BR_PKT_DM1 || pkt_type == BR_PKT_DH1 ||
	       pkt_type == BR_PKT_DM3 || pkt_type == BR_PKT_DH3 ||
	       pkt_type == BR_PKT_DM5 || pkt_type == BR_PKT_DH5;
}

uint8_t br_pkt_slot_count(uint8_t pkt_type)
{
	if (pkt_type == BR_PKT_DM3 || pkt_type == BR_PKT_DH3) {
		return 3u;
	}
	if (pkt_type == BR_PKT_DM5 || pkt_type == BR_PKT_DH5) {
		return 5u;
	}
	return 1u;
}

uint16_t br_acl_hdr_pack(bool multislot, uint8_t llid, uint8_t flow, uint16_t payload_len, uint8_t out_hdr[2])
{
	if (!multislot) {
		out_hdr[0] = (uint8_t)((llid & 0x03u) |
		                       ((flow & 0x01u) << 2) |
		                       ((payload_len & 0x1Fu) << 3));
		out_hdr[1] = 0;
		return 1u;
	}
	uint16_t w = (uint16_t)((uint16_t)(llid & 0x03u) |
	                        ((uint16_t)(flow & 0x01u) << 2) |
	                        ((uint16_t)(payload_len & 0x01FFu) << 3));
	out_hdr[0] = (uint8_t)(w & 0xFFu);
	out_hdr[1] = (uint8_t)((w >> 8) & 0xFFu);
	return 2u;
}

bool br_acl_hdr_unpack(bool multislot, const uint8_t *buf, uint16_t buf_len,
		uint8_t *llid, uint8_t *flow, uint16_t *payload_len, uint8_t *hdr_bytes)
{
	if (!multislot) {
		if (buf_len < 1u) {
			return false;
		}
		uint8_t b = buf[0];
		*llid        = (uint8_t)(b & 0x03u);
		*flow        = (uint8_t)((b >> 2) & 0x01u);
		*payload_len = (uint16_t)((b >> 3) & 0x1Fu);
		*hdr_bytes   = 1u;
		return (uint16_t)(1u + *payload_len) <= buf_len;
	}
	if (buf_len < 2u) {
		return false;
	}
	uint16_t w = (uint16_t)((uint16_t)buf[0] | ((uint16_t)buf[1] << 8));
	if ((w & 0xF000u) != 0u) {
		/* Upper 4 undefined bits in 2-byte ACL payload header must be 0. */
		return false;
	}
	*llid        = (uint8_t)(w & 0x03u);
	*flow        = (uint8_t)((w >> 2) & 0x01u);
	*payload_len = (uint16_t)((w >> 3) & 0x01FFu);
	*hdr_bytes   = 2u;
	return (uint16_t)(2u + *payload_len) <= buf_len;
}
