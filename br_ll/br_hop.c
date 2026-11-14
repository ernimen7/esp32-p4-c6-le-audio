/*
 * Bluetooth Classic 79-Hop Selection Kernel (Core Spec v5.4 Vol 2 Part B §2.6).
 */
#include "br_hop.h"
#include "br_air.h"
#include <string.h>

static uint8_t addr_c5(uint32_t ulap)
{
	return (uint8_t)(((ulap >> 0) & 1u) |
	                 (((ulap >> 2) & 1u) << 1) |
	                 (((ulap >> 4) & 1u) << 2) |
	                 (((ulap >> 6) & 1u) << 3) |
	                 (((ulap >> 8) & 1u) << 4));
}

static uint8_t addr_e7(uint32_t ulap)
{
	return (uint8_t)(((ulap >> 1) & 1u) |
	                 (((ulap >> 3) & 1u) << 1) |
	                 (((ulap >> 5) & 1u) << 2) |
	                 (((ulap >> 7) & 1u) << 3) |
	                 (((ulap >> 9) & 1u) << 4) |
	                 (((ulap >> 11) & 1u) << 5) |
	                 (((ulap >> 13) & 1u) << 6));
}

static inline uint8_t swap_pair(uint8_t z, uint8_t b0, uint8_t b1, bool do_swap)
{
	if (!do_swap) {
		return z;
	}
	uint8_t diff = (uint8_t)(((z >> b0) ^ (z >> b1)) & 1u);
	return (uint8_t)(z ^ (uint8_t)((diff << b0) | (diff << b1)));
}

/* Core Spec Vol 2 Part B §2.6.2.2 Table 2.3:
 * Stage 1 (first applied to Z): P13 {1,2}, P12 {0,3}
 * Stage 2:                      P11 {1,3}, P10 {2,4}
 * Stage 3:                      P9  {0,3}, P8  {1,4}
 * Stage 4:                      P7  {3,4}, P6  {0,2}
 * Stage 5:                      P5  {1,3}, P4  {0,4}
 * Stage 6:                      P3  {3,4}, P2  {1,2}
 * Stage 7 (last):               P1  {2,3}, P0  {0,1} */
uint8_t br_hop_perm5(uint8_t z5, uint16_t p14)
{
	static const uint8_t pairs[14][2] = {
		{0, 1}, /* P0 */
		{2, 3}, /* P1 */
		{1, 2}, /* P2 */
		{3, 4}, /* P3 */
		{0, 4}, /* P4 */
		{1, 3}, /* P5 */
		{0, 2}, /* P6 */
		{3, 4}, /* P7 */
		{1, 4}, /* P8 */
		{0, 3}, /* P9 */
		{2, 4}, /* P10 */
		{1, 3}, /* P11 */
		{0, 3}, /* P12 */
		{1, 2}, /* P13 */
	};
	uint8_t z = (uint8_t)(z5 & 0x1Fu);
	for (int i = 13; i >= 0; i--) {
		z = swap_pair(z, pairs[i][0], pairs[i][1], ((p14 >> i) & 1u) != 0u);
	}
	return z;
}

static uint8_t compute_z5(uint8_t x, uint8_t y1, uint8_t a, uint8_t b, uint8_t c, uint16_t d)
{
	/* Step 1: ADD mod 32 */
	uint8_t z1 = (uint8_t)((x + a) & 0x1Fu);
	/* Step 2: XOR low 4 bits with B[3:0] */
	uint8_t z2 = (uint8_t)(z1 ^ (b & 0x0Fu));
	/* Step 3: PERM5 with P[13:9] = C ^ (5x Y1), P[8:0] = D[8:0] */
	uint8_t c_xor = (uint8_t)((c & 0x1Fu) ^ (y1 ? 0x1Fu : 0x00u));
	uint16_t p14 = (uint16_t)(((uint16_t)c_xor << 9) | (d & 0x01FFu));
	return br_hop_perm5(z2, p14);
}

static uint8_t reg_bank_79(uint8_t idx79)
{
	/* [0, 2, 4, ..., 78, 1, 3, 5, ..., 77] */
	if (idx79 < 40u) {
		return (uint8_t)(idx79 * 2u);
	}
	return (uint8_t)((idx79 - 40u) * 2u + 1u);
}

uint8_t br_hop_kernel_79(uint8_t x, uint8_t y1, uint8_t y2,
		uint8_t a, uint8_t b, uint8_t c, uint16_t d, uint8_t e, uint8_t f)
{
	uint8_t z = compute_z5(x, y1, a, b, c, d);
	uint8_t idx = (uint8_t)(((uint16_t)z + (uint16_t)(e & 0x7Fu) + (uint16_t)f + (uint16_t)y2) % 79u);
	return reg_bank_79(idx);
}

static void static_addr_abcde(uint32_t ulap, uint8_t *a, uint8_t *b, uint8_t *c, uint16_t *d, uint8_t *e)
{
	*a = (uint8_t)((ulap >> 23) & 0x1Fu);
	*b = (uint8_t)((ulap >> 19) & 0x0Fu);
	*c = addr_c5(ulap);
	*d = (uint16_t)((ulap >> 10) & 0x01FFu);
	*e = addr_e7(ulap);
}

uint8_t br_hop_page_scan(uint32_t ulap, uint32_t clkn)
{
	uint8_t a, b, c, e;
	uint16_t d;
	static_addr_abcde(ulap, &a, &b, &c, &d, &e);
	uint8_t x = (uint8_t)((clkn >> 12) & 0x1Fu);
	return br_hop_kernel_79(x, 0u, 0u, a, b, c, d, e, 0u);
}

uint8_t br_hop_inquiry_scan(uint32_t giac_ulap, uint32_t clkn, uint8_t n_inq)
{
	uint8_t a, b, c, e;
	uint16_t d;
	static_addr_abcde(giac_ulap, &a, &b, &c, &d, &e);
	uint8_t x = (uint8_t)(((clkn >> 12) + n_inq) & 0x1Fu);
	return br_hop_kernel_79(x, 0u, 0u, a, b, c, d, e, 0u);
}

uint8_t br_hop_page_master_tx(uint32_t paged_ulap, uint32_t clke, br_train_t train, uint8_t *out_xp)
{
	uint8_t a, b, c, e;
	uint16_t d;
	static_addr_abcde(paged_ulap, &a, &b, &c, &d, &e);
	uint8_t clke16_12 = (uint8_t)((clke >> 12) & 0x1Fu);
	uint8_t clke4_2_0 = (uint8_t)((((clke >> 2) & 0x07u) << 1) | (clke & 0x01u));
	uint8_t k_off = (train == BR_TRAIN_A) ? 24u : 8u;
	uint8_t inner = (uint8_t)((clke4_2_0 + 32u - (clke16_12 & 0x0Fu)) & 0x0Fu);
	uint8_t xp = (uint8_t)((clke16_12 + k_off + inner) & 0x1Fu);
	if (out_xp) {
		*out_xp = xp;
	}
	return br_hop_kernel_79(xp, 0u, 0u, a, b, c, d, e, 0u);
}

uint8_t br_hop_page_master_rx_from_xp(uint32_t paged_ulap, uint8_t xp_tx)
{
	uint8_t a, b, c, e;
	uint16_t d;
	static_addr_abcde(paged_ulap, &a, &b, &c, &d, &e);
	return br_hop_kernel_79((uint8_t)(xp_tx & 0x1Fu), 1u, 32u, a, b, c, d, e, 0u);
}

uint8_t br_hop_train_chan_tx(uint32_t ulap, uint32_t clk_est, br_train_t train, uint8_t idx16, uint8_t *out_x)
{
	uint8_t a, b, c, e;
	uint16_t d;
	static_addr_abcde(ulap, &a, &b, &c, &d, &e);
	uint8_t clk16_12 = (uint8_t)((clk_est >> 12) & 0x1Fu);
	uint8_t k_off = (train == BR_TRAIN_A) ? 24u : 8u;
	uint8_t x = (uint8_t)((clk16_12 + k_off + (idx16 & 0x0Fu)) & 0x1Fu);
	if (out_x) {
		*out_x = x;
	}
	return br_hop_kernel_79(x, 0u, 0u, a, b, c, d, e, 0u);
}

uint8_t br_hop_train_chan_rx(uint32_t ulap, uint8_t x_tx)
{
	return br_hop_page_master_rx_from_xp(ulap, x_tx);
}

uint8_t br_hop_master_page_rsp_tx(uint32_t paged_ulap, uint32_t clke_frozen, uint8_t n_prm, uint8_t *out_xprm)
{
	uint8_t a, b, c, e;
	uint16_t d;
	static_addr_abcde(paged_ulap, &a, &b, &c, &d, &e);
	/* Core Spec Table 2.2: X_prm = (CLKE*_16-12 + k_offset + (CLKE*_4-2,0 - CLKE*_16-12) mod 16 + N_prm) mod 32.
	 * Wait: let's double check X_prm vs X_prs!
	 * In Slave Page Response, Slave uses X_prs = (CLKN*_16-12 + N_prs) mod 32!
	 * And Master Page Response MUST land on the SAME frequency as Slave Page Response!
	 * Look: when Slave received Master's ID on X_p = CLKN*_16-12, Master froze CLKE* such that
	 * X_prm(N_prm=0) == X_p(of the matched ID) + 1 (since N increments by 1 before FHS)!
	 * Specifically, if Master stores `xp_matched` (which equals Slave's `CLKN*_16-12`), then
	 * `X_prm = (xp_matched + n_prm) & 0x1Fu` matches `X_prs = (CLKN*_16-12 + n_prs) & 0x1Fu` identically! */
	uint8_t xprm = (uint8_t)(((clke_frozen & 0x1Fu) + n_prm) & 0x1Fu);
	if (out_xprm) {
		*out_xprm = xprm;
	}
	return br_hop_kernel_79(xprm, 0u, 0u, a, b, c, d, e, 0u);
}

uint8_t br_hop_master_page_rsp_rx(uint32_t paged_ulap, uint32_t clke_frozen, uint8_t n_prm)
{
	uint8_t a, b, c, e;
	uint16_t d;
	static_addr_abcde(paged_ulap, &a, &b, &c, &d, &e);
	uint8_t xprm = (uint8_t)(((clke_frozen & 0x1Fu) + n_prm) & 0x1Fu);
	return br_hop_kernel_79(xprm, 1u, 32u, a, b, c, d, e, 0u);
}

uint8_t br_hop_slave_page_rsp(uint32_t slave_ulap, uint32_t clkn_frozen, uint8_t n_prs)
{
	uint8_t a, b, c, e;
	uint16_t d;
	static_addr_abcde(slave_ulap, &a, &b, &c, &d, &e);
	uint8_t y1 = (uint8_t)((clkn_frozen >> 1) & 1u);
	uint8_t xprs = (uint8_t)((((clkn_frozen >> 12) & 0x1Fu) + n_prs) & 0x1Fu);
	return br_hop_kernel_79(xprs, y1, (uint8_t)(32u * y1), a, b, c, d, e, 0u);
}

uint8_t br_hop_inquiry_rsp(uint32_t giac_ulap, uint32_t clkn_frozen, uint8_t n_ir, uint8_t *out_xir)
{
	uint8_t a, b, c, e;
	uint16_t d;
	static_addr_abcde(giac_ulap, &a, &b, &c, &d, &e);
	uint8_t xir = (uint8_t)((((clkn_frozen >> 12) & 0x1Fu) + n_ir) & 0x1Fu);
	if (out_xir) {
		*out_xir = xir;
	}
	return br_hop_kernel_79(xir, 1u, 32u, a, b, c, d, e, 0u);
}

static void conn_params_from_clk(uint32_t master_ulap, uint32_t clk,
		uint8_t *x, uint8_t *y1, uint8_t *y2,
		uint8_t *a, uint8_t *b, uint8_t *c, uint16_t *d, uint8_t *e)
{
	*x  = (uint8_t)((clk >> 2) & 0x1Fu);
	*y1 = (uint8_t)((clk >> 1) & 0x01u);
	*y2 = (uint8_t)(32u * (*y1));
	*a  = (uint8_t)(((master_ulap >> 23) & 0x1Fu) ^ ((clk >> 21) & 0x1Fu));
	*b  = (uint8_t)((master_ulap >> 19) & 0x0Fu);
	*c  = (uint8_t)(addr_c5(master_ulap) ^ ((clk >> 16) & 0x1Fu));
	*d  = (uint16_t)(((master_ulap >> 10) & 0x01FFu) ^ ((clk >> 7) & 0x01FFu));
	*e  = addr_e7(master_ulap);
}

uint8_t br_hop_connection_79(uint32_t master_ulap, uint32_t clk)
{
	uint8_t x, y1, y2, a, b, c, e;
	uint16_t d;
	conn_params_from_clk(master_ulap, clk, &x, &y1, &y2, &a, &b, &c, &d, &e);
	uint8_t f = (uint8_t)((16u * ((clk >> 7) & 0x1FFFFFu)) % 79u);
	return br_hop_kernel_79(x, y1, y2, a, b, c, d, e, f);
}

bool br_afh_init(br_afh_state_t *afh, const uint8_t chan_map[10])
{
	memset(afh, 0, sizeof(*afh));
	memcpy(afh->map, chan_map, 10);
	afh->map[9] &= 0x7Fu; /* Only 79 channels (0..78) exist in BR */

	uint8_t n = 0;
	for (uint8_t ch = 0; ch < 79u; ch += 2u) {
		if ((afh->map[ch >> 3] >> (ch & 7u)) & 1u) {
			afh->bank[n++] = ch;
		}
	}
	for (uint8_t ch = 1; ch < 79u; ch += 2u) {
		if ((afh->map[ch >> 3] >> (ch & 7u)) & 1u) {
			afh->bank[n++] = ch;
		}
	}
	if (n < 20u) {
		afh->enabled = false;
		return false;
	}
	afh->num_used = n;
	afh->enabled  = true;
	return true;
}

uint8_t br_hop_connection(uint32_t master_ulap, uint32_t clk, br_afh_state_t *afh)
{
	uint8_t fk = br_hop_connection_79(master_ulap, clk);
	if (!afh || !afh->enabled) {
		return fk;
	}
	uint8_t clk1 = (uint8_t)((clk >> 1) & 1u);
	/* Core Spec Vol 2 Part B §2.6.4.7: In AFH, Slave->Master slot uses the SAME RF channel
	 * as the immediately preceding Master->Slave slot! */
	if (clk1 == 1u) {
		/* Compute Master->Slave channel at clk & ~2u so stateless calls at any slot work too. */
		uint32_t mclk = clk & ~0x03u;
		uint8_t mfk = br_hop_connection_79(master_ulap, mclk);
		if ((afh->map[mfk >> 3] >> (mfk & 7u)) & 1u) {
			return mfk;
		}
		uint8_t x, y1, y2, a, b, c, e;
		uint16_t d;
		conn_params_from_clk(master_ulap, mclk, &x, &y1, &y2, &a, &b, &c, &d, &e);
		uint8_t z = compute_z5(x, y1, a, b, c, d);
		uint8_t f_prime = (uint8_t)((16u * ((mclk >> 7) & 0x1FFFFFu)) % afh->num_used);
		uint8_t k_prime = (uint8_t)(((uint16_t)z + (uint16_t)e + (uint16_t)f_prime + (uint16_t)y2) % afh->num_used);
		return afh->bank[k_prime];
	}

	if ((afh->map[fk >> 3] >> (fk & 7u)) & 1u) {
		afh->last_master_ch = fk;
		afh->last_was_remapped = false;
		return fk;
	}
	uint8_t x, y1, y2, a, b, c, e;
	uint16_t d;
	conn_params_from_clk(master_ulap, clk, &x, &y1, &y2, &a, &b, &c, &d, &e);
	uint8_t z = compute_z5(x, y1, a, b, c, d);
	uint8_t f_prime = (uint8_t)((16u * ((clk >> 7) & 0x1FFFFFu)) % afh->num_used);
	uint8_t k_prime = (uint8_t)(((uint16_t)z + (uint16_t)e + (uint16_t)f_prime + (uint16_t)y2) % afh->num_used);
	uint8_t ch = afh->bank[k_prime];
	afh->last_master_ch = ch;
	afh->last_was_remapped = true;
	return ch;
}

void br_derive_c6_bdaddr(const uint8_t seed_mac[6], uint8_t rxd_len_target, uint8_t out_bdaddr[6])
{
	uint8_t rxd = (rxd_len_target >= 40u && rxd_len_target <= 60u) ? rxd_len_target : 46u;
	uint32_t base_lap = (uint32_t)seed_mac[0] | ((uint32_t)seed_mac[1] << 8) | ((uint32_t)seed_mac[2] << 16);
	/* Avoid reserved Inquiry LAP range 0x9E8B00..0x9E8B3F */
	uint8_t uap = (uint8_t)(seed_mac[3] ^ 0x5Au);
	/* Locally-administered non-multicast NAP */
	uint16_t nap = (uint16_t)(((uint16_t)seed_mac[4] | ((uint16_t)seed_mac[5] << 8) | 0x0200u) & 0xFEFFu);

	for (uint32_t salt = 0; salt < 64u; salt++) {
		uint32_t lap = (base_lap ^ (salt * 0x040001u)) & 0xFFC03Fu;
		lap |= ((uint32_t)rxd << 6);
		if ((lap & 0xFFFFC0u) == 0x9E8B00u) {
			lap ^= 0x100000u;
		}
		uint64_t sw = br_syncword_from_lap(lap);
		uint32_t aa = (uint32_t)(sw & 0xFFFFFFFFULL);
		if (br_access_addr_quality_ok(aa)) {
			br_parts_to_bdaddr(lap, uap, nap, out_bdaddr);
			return;
		}
	}
	/* Guaranteed fallback LAP=0x954B80 (rxd=46, AA=0x51ED565C) */
	uint32_t fallback_lap = (0x954B80u & 0xFFC03Fu) | ((uint32_t)rxd << 6);
	br_parts_to_bdaddr(fallback_lap, uap, nap, out_bdaddr);
}
