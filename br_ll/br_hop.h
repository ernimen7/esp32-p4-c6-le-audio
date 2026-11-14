/*
 * Bluetooth Classic 79-Hop Selection Kernel (Core Spec v5.4 Vol 2 Part B §2.6).
 *
 * Covers Inquiry, Inquiry Scan, Inquiry Response, Page, Page Scan, Slave Page Response,
 * Master Page Response, Connection Basic (79-hop), and Adaptive Frequency Hopping (AFH).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	BR_TRAIN_A = 0, /* k_offset = 24 */
	BR_TRAIN_B = 1, /* k_offset = 8 */
} br_train_t;

typedef struct {
	bool    enabled;
	uint8_t map[10];            /* 79 bits LSB-first: bit k = 1 if RF channel k (2402+k MHz) is used */
	uint8_t num_used;           /* N (20..79) */
	uint8_t bank[79];           /* Partitioned AFH register bank: [even used asc, odd used asc] */
	uint8_t last_master_ch;     /* For AFH same-channel Slave->Master response when remapped */
	bool    last_was_remapped;
} br_afh_state_t;

/* Extract 28-bit ULAP (UAP[3:0] << 24 | LAP[23:0]) used by the hop selection kernel. */
static inline uint32_t br_ulap(uint32_t lap, uint8_t uap)
{
	return (((uint32_t)uap & 0x0Fu) << 24) | (lap & 0x00FFFFFFu);
}

/* 5-bit Butterfly Permutation PERM5(z, p13_0) per Core Spec Vol 2 Part B §2.6.2.2 Table 2.3. */
uint8_t br_hop_perm5(uint8_t z5, uint16_t p14);

/* Core kernel evaluation given precomputed X(5b), Y1(1b), Y2(6b), A(5b), B(4b), C(5b), D(9b), E(7b), F(7b). */
uint8_t br_hop_kernel_79(uint8_t x, uint8_t y1, uint8_t y2,
		uint8_t a, uint8_t b, uint8_t c, uint16_t d, uint8_t e, uint8_t f);

/* Scan states (used by simulated speaker in br_ll/sim and test vectors). */
uint8_t br_hop_page_scan(uint32_t ulap, uint32_t clkn);
uint8_t br_hop_inquiry_scan(uint32_t giac_ulap, uint32_t clkn, uint8_t n_inq);

/* Master Inquiry / Page TX (clk_1 == 0) and RX frequency f'(k) (clk_1 == 1) + 5-bit X parameter. */
uint8_t br_hop_page_master_tx(uint32_t paged_ulap, uint32_t clke, br_train_t train, uint8_t *out_xp);
uint8_t br_hop_page_master_rx_from_xp(uint32_t paged_ulap, uint8_t xp_tx);

/* Direct indexed frequency f(m) and return frequency f'(m) for m = 0..15 within Train A or B around clke. */
uint8_t br_hop_train_chan_tx(uint32_t ulap, uint32_t clk_est, br_train_t train, uint8_t idx16, uint8_t *out_x);
uint8_t br_hop_train_chan_rx(uint32_t ulap, uint8_t x_tx);

/* Master Page Response (FHS TX at frozen clke_f + n_prm, and ID ACK RX). Also outputs 5-bit X_prm for FHS whitening. */
uint8_t br_hop_master_page_rsp_tx(uint32_t paged_ulap, uint32_t clke_frozen, uint8_t n_prm, uint8_t *out_xprm);
uint8_t br_hop_master_page_rsp_rx(uint32_t paged_ulap, uint32_t clke_frozen, uint8_t n_prm);

/* Slave Page Response / Inquiry Response (for unit tests and air simulator peripheral). */
uint8_t br_hop_slave_page_rsp(uint32_t slave_ulap, uint32_t clkn_frozen, uint8_t n_prs);
uint8_t br_hop_inquiry_rsp(uint32_t giac_ulap, uint32_t clkn_frozen, uint8_t n_ir, uint8_t *out_xir);

/* Active Connection 79-hop Basic channel for 28-bit Master clock `clk`. */
uint8_t br_hop_connection_79(uint32_t master_ulap, uint32_t clk);

/* Active Connection AFH state setup and channel calculation (Core Spec Vol 2 Part B §2.6.4). */
bool br_afh_init(br_afh_state_t *afh, const uint8_t chan_map[10]);
uint8_t br_hop_connection(uint32_t master_ulap, uint32_t clk, br_afh_state_t *afh);

/* Derive a board-unique Classic BD_ADDR from a 6-byte seed MAC such that:
 *  - LAP[13:6] == rxd_len_target (default 46 = 0x2E) so C6 single-slot RX captures full Slave packets, and
 *  - CAC SyncWord low 32 bits satisfy BLE Access Address correlation quality rules. */
void br_derive_c6_bdaddr(const uint8_t seed_mac[6], uint8_t rxd_len_target, uint8_t out_bdaddr[6]);

#ifdef __cplusplus
}
#endif
