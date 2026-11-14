/*
 * Bluetooth Classic Security Primitives (Core Spec v5.4 Vol 2 Part H):
 *  - SAFER+ modified A_r / A'_r block functions: E1, E21, E22, E3
 *  - Effective Encryption Key Reduction K'_c (1..16 octets)
 *  - E0 Stream Cipher (25/31/33/39-bit LFSRs + 4-bit FSM, 200-cycle warm-up)
 *  - Secure Simple Pairing (SSP) SHA-256 & HMAC-SHA256 functions f1, f2, f3, g
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SAFER+ Ar (non-invertible, used in E1/E3) and Ar' (used in E21/E22).
 * Byte order matches Bluetooth Core Spec Sample Data (index 0 = first/LSB octet in LMP air order). */
void br_saferp_ar(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void br_saferp_ar_prime(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/* E21: Unit / Combination key component Ka = E21(RAND, BD_ADDR). */
void br_crypto_e21(const uint8_t rand16[16], const uint8_t bd_addr[6], uint8_t out_ka[16]);

/* E22: Initialization key K_init = E22(PIN, L_pin, IN_RAND, responder_bd_addr). */
void br_crypto_e22(const uint8_t *pin, uint8_t pin_len, const uint8_t in_rand[16],
		const uint8_t bd_addr[6], uint8_t out_kinit[16]);
/* Raw E22 internal helper taking already-augmented 16-byte PIN' (for Core Spec Sample Data vector testing). */
void br_crypto_e22_raw(const uint8_t rand16[16], const uint8_t pin16[16], uint8_t out_kinit[16]);

/* E1: Authentication MAC -> 4-byte SRES and 12-byte ACO from 16-byte Link Key, 16-byte AU_RAND, 6-byte BD_ADDR. */
void br_crypto_e1(const uint8_t link_key[16], const uint8_t au_rand[16], const uint8_t bd_addr[6],
		uint8_t out_sres[4], uint8_t out_aco[12]);

/* E3: Encryption key Kc = E3(Link_Key, EN_RAND, COF) where COF = ACO (12B) or responder BD_ADDR || BD_ADDR (12B). */
void br_crypto_e3(const uint8_t link_key[16], const uint8_t en_rand[16], const uint8_t cof[12],
		uint8_t out_kc[16]);

/* Polynomial reduction Kc (16B) -> Kc' (effective length L = 1..16 octets, Core Spec Vol 2 Part H §4.2). */
void br_crypto_kc_prime(const uint8_t kc[16], uint8_t key_len_bytes, uint8_t out_kc_prime[16]);

/* E0 Stream Cipher: generates keystream bytes and XORs `data[0..len-1]` (LSB of each byte encrypted first).
 * `clk` is the 28-bit Master piconet clock of the first slot of the packet (`CLK[26:1]` = 26 bits used by E0). */
void br_crypto_e0_keystream(const uint8_t kc_prime[16], const uint8_t master_bd_addr[6], uint32_t clk,
		uint8_t *out_ks, size_t len_bytes);
void br_crypto_e0_xor(const uint8_t kc_prime[16], const uint8_t master_bd_addr[6], uint32_t clk,
		uint8_t *data, size_t len_bytes);

/* Portable SHA-256 + HMAC-SHA256 + Secure Simple Pairing (SSP) cryptographic toolbox (Core Spec Vol 2 Part H §7).
 * Multi-octet SSP inputs (PKax, PKbx, Na, Nb, r) are passed in Bluetooth little-endian LSO-first order (index 0 = LSO)
 * or converted internally per Core Spec §7.3 so callers pass native LMP little-endian byte arrays directly! */
void br_sha256(const uint8_t *data, size_t len, uint8_t out32[32]);
void br_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out32[32]);

/* SSP f1(U=PKax[24], V=PKbx[24], X=Nx[16], Z=z8) -> 16-byte commitment C (LSO-first). */
void br_ssp_f1(const uint8_t u24_le[24], const uint8_t v24_le[24], const uint8_t x16_le[16], uint8_t z,
		uint8_t out_c16_le[16]);
/* SSP g(U=PKax[24], V=PKbx[24], X=Na[16], Y=Nb[16]) -> 32-bit numeric comparison value (mod 10^6 by caller). */
uint32_t br_ssp_g(const uint8_t u24_le[24], const uint8_t v24_le[24],
		const uint8_t x16_le[16], const uint8_t y16_le[16]);
/* SSP f2(W=DHKey[24], N1[16], N2[16], KeyID="btlk", A1=bdaddr1[6], A2=bdaddr2[6]) -> 16-byte Link Key (LSO-first). */
void br_ssp_f2_btlk(const uint8_t dhkey24_le[24], const uint8_t n1_16_le[16], const uint8_t n2_16_le[16],
		const uint8_t bdaddr1_le[6], const uint8_t bdaddr2_le[6], uint8_t out_lk16_le[16]);
/* SSP f3(W=DHKey[24], N1[16], N2[16], R[16], IOcap[3], A1=bdaddr1[6], A2=bdaddr2[6]) -> 16-byte Ea/Eb check (LSO-first). */
void br_ssp_f3(const uint8_t dhkey24_le[24], const uint8_t n1_16_le[16], const uint8_t n2_16_le[16],
		const uint8_t r16_le[16], const uint8_t iocap3_le[3],
		const uint8_t bdaddr1_le[6], const uint8_t bdaddr2_le[6], uint8_t out_e16_le[16]);

#ifdef __cplusplus
}
#endif
