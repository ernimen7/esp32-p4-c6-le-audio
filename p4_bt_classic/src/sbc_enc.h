/*
 * Bluetooth A2DP SBC (Low Complexity Subband Coding) Encoder & Reference Decoder
 * Compliant with Bluetooth A2DP Specification v1.3.2 Appendix B (8 subbands, 4..16 blocks,
 * Mono / Dual-Channel / Stereo / Joint-Stereo, Loudness / SNR bit allocation).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SBC_SYNCWORD 0x9Cu

typedef enum {
    SBC_FREQ_16000 = 0,
    SBC_FREQ_32000 = 1,
    SBC_FREQ_44100 = 2,
    SBC_FREQ_48000 = 3,
} sbc_freq_t;

typedef enum {
    SBC_MODE_MONO         = 0,
    SBC_MODE_DUAL_CHANNEL = 1,
    SBC_MODE_STEREO       = 2,
    SBC_MODE_JOINT_STEREO = 3,
} sbc_mode_t;

typedef enum {
    SBC_ALLOC_LOUDNESS = 0,
    SBC_ALLOC_SNR      = 1,
} sbc_alloc_t;

typedef struct {
    sbc_freq_t  freq;
    uint8_t     blocks;     /* 4, 8, 12, or 16 (standard A2DP = 16) */
    sbc_mode_t  mode;       /* MONO, DUAL_CHANNEL, STEREO, or JOINT_STEREO */
    sbc_alloc_t alloc;      /* LOUDNESS (0) or SNR (1) */
    uint8_t     subbands;   /* 8 (mandatory A2DP) */
    uint8_t     bitpool;    /* 2..250 (typical 32..53) */
} sbc_params_t;

typedef struct {
    sbc_params_t params;
    float        x[2][80];       /* Per-channel polyphase analysis ring/shift state */
    float        ana_cos[8][16]; /* Precomputed cos((sb + 0.5) * (k - 4) * pi / 8) */
} sbc_enc_t;

typedef struct {
    float syn_v[2][160];     /* Per-channel polyphase synthesis state */
    float syn_cos[16][8];    /* Precomputed cos((sb + 0.5) * (k + 4) * pi / 8) */
} sbc_dec_t;

void sbc_enc_init(sbc_enc_t *enc, const sbc_params_t *params);
uint16_t sbc_frame_length(const sbc_params_t *params);
uint32_t sbc_sample_rate_hz(sbc_freq_t freq);
uint16_t sbc_pcm_samples_per_frame(const sbc_params_t *params); /* blocks * subbands (128 for 16x8) */

/* Encodes one SBC frame (`blocks * 8` PCM sample frames, interleaved stereo `[L0, R0, L1, R1, ...]`
 * when mode != MONO, or `[M0, M1, ...]` / `[L0, R0, ...]` according to `pcm_channels`).
 * Writes exact `sbc_frame_length(&enc->params)` bytes to `out_buf` and returns bytes written (0 on error). */
size_t sbc_encode_frame(sbc_enc_t *enc, const int16_t *pcm, int pcm_channels,
                        uint8_t *out_buf, size_t out_cap);

/* Reference A2DP Appendix B §12.6.2 Synthesis Decoder (used by host unit tests for SNR verification). */
void sbc_dec_init(sbc_dec_t *dec);
size_t sbc_decode_frame(sbc_dec_t *dec, const uint8_t *in_buf, size_t in_len,
                        int16_t *out_pcm_stereo, size_t max_frames, sbc_params_t *out_params);

#ifdef __cplusplus
}
#endif
