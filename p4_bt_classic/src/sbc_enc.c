/*
 * Bluetooth A2DP SBC (Low Complexity Subband Coding) Encoder & Reference Decoder
 * Compliant with Bluetooth A2DP Specification v1.3.2 Appendix B.
 */
#include "sbc_enc.h"

#include <math.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* A2DP Spec v1.3.2 Appendix B Table 12.2: 8-subband 80-tap prototype filter C[0..40].
 * Indices [41..79] follow exact polyphase QMF symmetry:
 *   h[n] = (-1)^(n/16) * C[n], h[80 - n] = h[n], C[n] = (-1)^(n/16) * h[n]. */
static const float kProto8Half[41] = {
     0.00000000e+00f,  1.56575398e-04f,  3.43256425e-04f,  5.54620202e-04f,
     8.23919506e-04f,  1.13992507e-03f,  1.47640169e-03f,  1.78371725e-03f,
     2.01182542e-03f,  2.10371989e-03f,  1.99454554e-03f,  1.61656283e-03f,
     9.02154502e-04f, -1.78805361e-04f, -1.64973098e-03f, -3.49717454e-03f,
     5.65949473e-03f,  8.02941163e-03f,  1.04584443e-02f,  1.27472335e-02f,
     1.46525263e-02f,  1.59045603e-02f,  1.62208471e-02f,  1.53184106e-02f,
     1.29371806e-02f,  8.85757540e-03f,  2.92408442e-03f, -4.91578024e-03f,
    -1.46404076e-02f, -2.61098752e-02f, -3.90751381e-02f, -5.31873032e-02f,
     6.79989431e-02f,  8.29847578e-02f,  9.75753918e-02f,  1.11196689e-01f,
     1.23264548e-01f,  1.33264415e-01f,  1.40753505e-01f,  1.45389847e-01f,
     1.46955068e-01f,
};

static float s_proto_c80[80];
static bool  s_proto_ready = false;

static void ensure_proto_table(void)
{
    if (s_proto_ready) {
        return;
    }
    for (int n = 0; n <= 40; n++) {
        s_proto_c80[n] = kProto8Half[n];
    }
    for (int n = 41; n < 80; n++) {
        int m_src = (80 - n) / 16;
        int m_dst = n / 16;
        float sign = (((m_src ^ m_dst) & 1) != 0) ? -1.0f : 1.0f;
        s_proto_c80[n] = sign * kProto8Half[80 - n];
    }
    s_proto_ready = true;
}

/* A2DP Spec Appendix B Table 12.6: Loudness offset table for 8 subbands */
static const int8_t kOffset8[4][8] = {
    { -2, 0, 0, 0, 0, 0, 0, 1 }, /* 16 kHz */
    { -3, 0, 0, 0, 0, 0, 1, 2 }, /* 32 kHz */
    { -4, 0, 0, 0, 0, 0, 1, 2 }, /* 44.1 kHz */
    { -4, 0, 0, 0, 0, 0, 1, 2 }, /* 48 kHz */
};

/* A2DP Spec Appendix B §12.5.1: CRC-8 polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x1D), init 0x0F, MSB-first */
static uint8_t sbc_crc8_bits(const uint8_t *data, size_t total_bits)
{
    uint8_t crc = 0x0Fu;
    size_t full_bytes = total_bits >> 3;
    for (size_t i = 0; i < full_bytes; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x80u) ? (uint8_t)((crc << 1) ^ 0x1Du) : (uint8_t)(crc << 1);
        }
    }
    size_t rem_bits = total_bits & 7u;
    if (rem_bits > 0u) {
        uint8_t byte = data[full_bytes];
        for (size_t b = 0; b < rem_bits; b++) {
            uint8_t in_bit = (uint8_t)((byte >> (7u - b)) & 1u);
            uint8_t top    = (uint8_t)((crc >> 7) & 1u);
            crc = (uint8_t)(crc << 1);
            if (in_bit ^ top) {
                crc ^= 0x1Du;
            }
        }
    }
    return crc;
}

uint32_t sbc_sample_rate_hz(sbc_freq_t freq)
{
    switch (freq) {
    case SBC_FREQ_16000: return 16000u;
    case SBC_FREQ_32000: return 32000u;
    case SBC_FREQ_44100: return 44100u;
    case SBC_FREQ_48000: return 48000u;
    default:             return 44100u;
    }
}

uint16_t sbc_pcm_samples_per_frame(const sbc_params_t *params)
{
    if (!params) {
        return 128u;
    }
    return (uint16_t)params->blocks * (uint16_t)params->subbands;
}

uint16_t sbc_frame_length(const sbc_params_t *params)
{
    if (!params) {
        return 0u;
    }
    uint32_t m = params->subbands ? params->subbands : 8u;
    uint32_t b = params->blocks ? params->blocks : 16u;
    uint32_t bp = params->bitpool;
    uint32_t c = (params->mode == SBC_MODE_MONO) ? 1u : 2u;

    uint32_t sf_bytes = (4u * m * c) / 8u;
    uint32_t payload_bits = 0u;
    if (params->mode == SBC_MODE_MONO || params->mode == SBC_MODE_DUAL_CHANNEL) {
        payload_bits = b * c * bp;
    } else if (params->mode == SBC_MODE_STEREO) {
        payload_bits = b * bp;
    } else {
        /* JOINT_STEREO: M join flags (including last subband RFA=0) + B * bitpool */
        payload_bits = m + b * bp;
    }
    return (uint16_t)(4u + sf_bytes + ((payload_bits + 7u) / 8u));
}

/* Arithmetic floor division by 2 matching A2DP spec `loudness div 2` for negative integers:
 * In C99+, `-1 / 2 == 0`, whereas `(-1) >> 1 == -1` (`div 2` toward -infinity).
 * Wait: let's check both `loudness < 0`: in A2DP Appendix B §12.7.3.1:
 *   if (loudness < 0) bitneed = loudness / 2; (integer division truncating toward 0 in C!).
 * Note: for offset8 at 44.1/48kHz, offset is {-4, 0, 0, 0, 0, 0, 1, 2}:
 *   when sf == 0 -> bitneed = -5 directly!
 *   when sf >= 1 -> loudness = sf - offset >= 1 - 2 = -1 -> `-1 / 2 == 0` in C (exact match to BlueZ & FFmpeg!). */
static void sbc_calculate_bits(const sbc_params_t *p, const uint8_t sf[2][8], int bits[2][8])
{
    const int subbands = 8;
    const int f_idx = ((int)p->freq) & 3;

    memset(bits, 0, sizeof(int) * 2 * 8);

    if (p->mode == SBC_MODE_MONO || p->mode == SBC_MODE_DUAL_CHANNEL) {
        int channels = (p->mode == SBC_MODE_MONO) ? 1 : 2;
        for (int ch = 0; ch < channels; ch++) {
            int bitneed[8];
            int max_bitneed = 0;
            if (p->alloc == SBC_ALLOC_SNR) {
                for (int sb = 0; sb < subbands; sb++) {
                    bitneed[sb] = (int)sf[ch][sb];
                    if (bitneed[sb] > max_bitneed) max_bitneed = bitneed[sb];
                }
            } else {
                for (int sb = 0; sb < subbands; sb++) {
                    if (sf[ch][sb] == 0u) {
                        bitneed[sb] = -5;
                    } else {
                        int loudness = (int)sf[ch][sb] - (int)kOffset8[f_idx][sb];
                        bitneed[sb] = (loudness > 0) ? (loudness / 2) : loudness;
                    }
                    if (bitneed[sb] > max_bitneed) max_bitneed = bitneed[sb];
                }
            }

            int bitcount = 0;
            int slicecount = 0;
            int bitslice = max_bitneed + 1;
            do {
                bitslice--;
                bitcount += slicecount;
                slicecount = 0;
                for (int sb = 0; sb < subbands; sb++) {
                    if (bitneed[sb] > bitslice + 1 && bitneed[sb] < bitslice + 16) {
                        slicecount++;
                    } else if (bitneed[sb] == bitslice + 1) {
                        slicecount += 2;
                    }
                }
            } while (bitcount + slicecount < (int)p->bitpool);

            if (bitcount + slicecount == (int)p->bitpool) {
                bitcount += slicecount;
                bitslice--;
            }

            for (int sb = 0; sb < subbands; sb++) {
                if (bitneed[sb] < bitslice + 2) {
                    bits[ch][sb] = 0;
                } else {
                    int b = bitneed[sb] - bitslice;
                    bits[ch][sb] = (b > 16) ? 16 : b;
                }
            }

            int sb = 0;
            while (bitcount < (int)p->bitpool && sb < subbands) {
                if (bits[ch][sb] >= 2 && bits[ch][sb] < 16) {
                    bits[ch][sb]++;
                    bitcount++;
                } else if (bitneed[sb] == bitslice + 1 && (int)p->bitpool > bitcount + 1) {
                    bits[ch][sb] = 2;
                    bitcount += 2;
                }
                sb++;
            }
            sb = 0;
            while (bitcount < (int)p->bitpool && sb < subbands) {
                if (bits[ch][sb] < 16) {
                    bits[ch][sb]++;
                    bitcount++;
                }
                sb++;
            }
        }
    } else {
        /* STEREO or JOINT_STEREO */
        int bitneed[2][8];
        int max_bitneed = 0;
        if (p->alloc == SBC_ALLOC_SNR) {
            for (int ch = 0; ch < 2; ch++) {
                for (int sb = 0; sb < subbands; sb++) {
                    bitneed[ch][sb] = (int)sf[ch][sb];
                    if (bitneed[ch][sb] > max_bitneed) max_bitneed = bitneed[ch][sb];
                }
            }
        } else {
            for (int ch = 0; ch < 2; ch++) {
                for (int sb = 0; sb < subbands; sb++) {
                    if (sf[ch][sb] == 0u) {
                        bitneed[ch][sb] = -5;
                    } else {
                        int loudness = (int)sf[ch][sb] - (int)kOffset8[f_idx][sb];
                        bitneed[ch][sb] = (loudness > 0) ? (loudness / 2) : loudness;
                    }
                    if (bitneed[ch][sb] > max_bitneed) max_bitneed = bitneed[ch][sb];
                }
            }
        }

        int bitcount = 0;
        int slicecount = 0;
        int bitslice = max_bitneed + 1;
        do {
            bitslice--;
            bitcount += slicecount;
            slicecount = 0;
            for (int ch = 0; ch < 2; ch++) {
                for (int sb = 0; sb < subbands; sb++) {
                    if (bitneed[ch][sb] > bitslice + 1 && bitneed[ch][sb] < bitslice + 16) {
                        slicecount++;
                    } else if (bitneed[ch][sb] == bitslice + 1) {
                        slicecount += 2;
                    }
                }
            }
        } while (bitcount + slicecount < (int)p->bitpool);

        if (bitcount + slicecount == (int)p->bitpool) {
            bitcount += slicecount;
            bitslice--;
        }

        for (int ch = 0; ch < 2; ch++) {
            for (int sb = 0; sb < subbands; sb++) {
                if (bitneed[ch][sb] < bitslice + 2) {
                    bits[ch][sb] = 0;
                } else {
                    int b = bitneed[ch][sb] - bitslice;
                    bits[ch][sb] = (b > 16) ? 16 : b;
                }
            }
        }

        int ch = 0;
        int sb = 0;
        while (bitcount < (int)p->bitpool && sb < subbands) {
            if (bits[ch][sb] >= 2 && bits[ch][sb] < 16) {
                bits[ch][sb]++;
                bitcount++;
            } else if (bitneed[ch][sb] == bitslice + 1 && (int)p->bitpool > bitcount + 1) {
                bits[ch][sb] = 2;
                bitcount += 2;
            }
            if (ch == 1) {
                ch = 0;
                sb++;
            } else {
                ch = 1;
            }
        }

        ch = 0;
        sb = 0;
        while (bitcount < (int)p->bitpool && sb < subbands) {
            if (bits[ch][sb] < 16) {
                bits[ch][sb]++;
                bitcount++;
            }
            if (ch == 1) {
                ch = 0;
                sb++;
            } else {
                ch = 1;
            }
        }
    }
}

static uint8_t calc_scale_factor(float max_abs)
{
    /* Find smallest sf in 0..15 such that max_abs < 2^(sf + 1). */
    uint8_t sf = 0u;
    float thr = 2.0f;
    while (sf < 15u && max_abs >= thr) {
        thr *= 2.0f;
        sf++;
    }
    return sf;
}

void sbc_enc_init(sbc_enc_t *enc, const sbc_params_t *params)
{
    if (!enc) {
        return;
    }
    ensure_proto_table();
    memset(enc, 0, sizeof(*enc));
    if (params) {
        enc->params = *params;
    } else {
        enc->params.freq     = SBC_FREQ_44100;
        enc->params.blocks   = 16u;
        enc->params.mode     = SBC_MODE_JOINT_STEREO;
        enc->params.alloc    = SBC_ALLOC_LOUDNESS;
        enc->params.subbands = 8u;
        enc->params.bitpool  = 35u;
    }
    if (enc->params.blocks != 4u && enc->params.blocks != 8u &&
        enc->params.blocks != 12u && enc->params.blocks != 16u) {
        enc->params.blocks = 16u;
    }
    enc->params.subbands = 8u;
    if (enc->params.bitpool < 2u) {
        enc->params.bitpool = 2u;
    }

    for (int sb = 0; sb < 8; sb++) {
        for (int k = 0; k < 16; k++) {
            enc->ana_cos[sb][k] = (float)cos(((double)sb + 0.5) * ((double)k - 4.0) * (M_PI / 8.0));
        }
    }
}

typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   byte_pos;
    uint8_t  bit_used; /* 0..7 in current byte (MSB first) */
} bit_writer_t;

static void bw_put(bit_writer_t *bw, uint32_t val, int nbits)
{
    for (int i = nbits - 1; i >= 0; i--) {
        if (bw->byte_pos >= bw->cap) {
            return;
        }
        if (bw->bit_used == 0u) {
            bw->buf[bw->byte_pos] = 0u;
        }
        uint8_t bit = (uint8_t)((val >> i) & 1u);
        bw->buf[bw->byte_pos] |= (uint8_t)(bit << (7u - bw->bit_used));
        bw->bit_used++;
        if (bw->bit_used == 8u) {
            bw->bit_used = 0u;
            bw->byte_pos++;
        }
    }
}

size_t sbc_encode_frame(sbc_enc_t *enc, const int16_t *pcm, int pcm_channels,
                        uint8_t *out_buf, size_t out_cap)
{
    if (!enc || !pcm || !out_buf || pcm_channels < 1) {
        return 0u;
    }
    ensure_proto_table();

    const sbc_params_t *p = &enc->params;
    const uint16_t frame_len = sbc_frame_length(p);
    if (out_cap < frame_len) {
        return 0u;
    }

    const int n_blocks = (int)p->blocks;
    const int n_ch     = (p->mode == SBC_MODE_MONO) ? 1 : 2;
    float sb_sample[16][2][8];

    /* 1. Polyphase Analysis Filterbank (A2DP Appendix B §12.6.1) */
    for (int blk = 0; blk < n_blocks; blk++) {
        for (int ch = 0; ch < n_ch; ch++) {
            float *x = enc->x[ch];
            memmove(&x[8], &x[0], 72u * sizeof(float));
            for (int k = 0; k < 8; k++) {
                int sample_idx = blk * 8 + k;
                float s = 0.0f;
                if (pcm_channels == 1) {
                    s = (float)pcm[sample_idx];
                } else if (n_ch == 1) {
                    s = 0.5f * ((float)pcm[sample_idx * 2] + (float)pcm[sample_idx * 2 + 1]);
                } else {
                    s = (float)pcm[sample_idx * 2 + ch];
                }
                x[7 - k] = s;
            }

            float y[16];
            for (int i = 0; i < 16; i++) {
                y[i] = s_proto_c80[i]      * x[i]      +
                       s_proto_c80[i + 16] * x[i + 16] +
                       s_proto_c80[i + 32] * x[i + 32] +
                       s_proto_c80[i + 48] * x[i + 48] +
                       s_proto_c80[i + 64] * x[i + 64];
            }

            for (int sb = 0; sb < 8; sb++) {
                const float *cm = enc->ana_cos[sb];
                float acc = 0.0f;
                for (int k = 0; k < 16; k++) {
                    acc += cm[k] * y[k];
                }
                sb_sample[blk][ch][sb] = acc;
            }
        }
    }

    /* 2. Joint Stereo Coupling & Scale Factors (A2DP Appendix B §12.7.1 & §12.7.2) */
    uint8_t join_byte = 0u;
    uint8_t sf[2][8];
    memset(sf, 0, sizeof(sf));

    if (p->mode == SBC_MODE_JOINT_STEREO) {
        for (int sb = 0; sb < 7; sb++) { /* sb=7 MUST never be joined */
            float max_l = 0.0f, max_r = 0.0f, max_m = 0.0f, max_s = 0.0f;
            for (int blk = 0; blk < n_blocks; blk++) {
                float l = sb_sample[blk][0][sb];
                float r = sb_sample[blk][1][sb];
                float al = fabsf(l);
                float ar = fabsf(r);
                float am = fabsf(0.5f * (l + r));
                float as = fabsf(0.5f * (l - r));
                if (al > max_l) max_l = al;
                if (ar > max_r) max_r = ar;
                if (am > max_m) max_m = am;
                if (as > max_s) max_s = as;
            }
            uint8_t sf_l = calc_scale_factor(max_l);
            uint8_t sf_r = calc_scale_factor(max_r);
            uint8_t sf_m = calc_scale_factor(max_m);
            uint8_t sf_s = calc_scale_factor(max_s);
            if ((uint16_t)sf_m + (uint16_t)sf_s < (uint16_t)sf_l + (uint16_t)sf_r) {
                join_byte |= (uint8_t)(1u << (7 - sb));
                sf[0][sb] = sf_m;
                sf[1][sb] = sf_s;
                for (int blk = 0; blk < n_blocks; blk++) {
                    float l = sb_sample[blk][0][sb];
                    float r = sb_sample[blk][1][sb];
                    sb_sample[blk][0][sb] = 0.5f * (l + r);
                    sb_sample[blk][1][sb] = 0.5f * (l - r);
                }
            } else {
                sf[0][sb] = sf_l;
                sf[1][sb] = sf_r;
            }
        }
        /* Top subband sb = 7 is always uncoupled */
        float max_l = 0.0f, max_r = 0.0f;
        for (int blk = 0; blk < n_blocks; blk++) {
            float al = fabsf(sb_sample[blk][0][7]);
            float ar = fabsf(sb_sample[blk][1][7]);
            if (al > max_l) max_l = al;
            if (ar > max_r) max_r = ar;
        }
        sf[0][7] = calc_scale_factor(max_l);
        sf[1][7] = calc_scale_factor(max_r);
    } else {
        for (int ch = 0; ch < n_ch; ch++) {
            for (int sb = 0; sb < 8; sb++) {
                float mx = 0.0f;
                for (int blk = 0; blk < n_blocks; blk++) {
                    float a = fabsf(sb_sample[blk][ch][sb]);
                    if (a > mx) mx = a;
                }
                sf[ch][sb] = calc_scale_factor(mx);
            }
        }
    }

    /* 3. Bit Allocation (A2DP Appendix B §12.7.3) */
    int bits[2][8];
    sbc_calculate_bits(p, sf, bits);

    /* 4. Pack Header, Join Flags, Scale Factors, and CRC-8 (A2DP Appendix B §12.5) */
    memset(out_buf, 0, frame_len);
    uint8_t blk_code = (uint8_t)((p->blocks / 4u) - 1u) & 0x03u;
    out_buf[0] = SBC_SYNCWORD;
    out_buf[1] = (uint8_t)((((uint8_t)p->freq & 0x03u) << 6) |
                           (blk_code << 4) |
                           (((uint8_t)p->mode & 0x03u) << 2) |
                           (((uint8_t)p->alloc & 0x01u) << 1) |
                           0x01u); /* subbands = 8 */
    out_buf[2] = p->bitpool;

    size_t pos = 4u;
    uint8_t crc_input[2 + 1 + 8];
    size_t  crc_bytes = 0u;
    crc_input[crc_bytes++] = out_buf[1];
    crc_input[crc_bytes++] = out_buf[2];

    if (p->mode == SBC_MODE_JOINT_STEREO) {
        out_buf[pos++] = join_byte;
        crc_input[crc_bytes++] = join_byte;
    }

    for (int ch = 0; ch < n_ch; ch++) {
        for (int sb = 0; sb < 8; sb += 2) {
            uint8_t packed_sf = (uint8_t)((sf[ch][sb] << 4) | (sf[ch][sb + 1] & 0x0Fu));
            out_buf[pos++] = packed_sf;
            crc_input[crc_bytes++] = packed_sf;
        }
    }
    out_buf[3] = sbc_crc8_bits(crc_input, crc_bytes * 8u);

    /* 5. Quantize & Bit-Pack Subband Samples (A2DP Appendix B §12.7.4) */
    bit_writer_t bw = {
        .buf      = out_buf,
        .cap      = frame_len,
        .byte_pos = pos,
        .bit_used = 0u,
    };

    for (int blk = 0; blk < n_blocks; blk++) {
        for (int ch = 0; ch < n_ch; ch++) {
            for (int sb = 0; sb < 8; sb++) {
                int b = bits[ch][sb];
                if (b <= 0) {
                    continue;
                }
                uint32_t levels = (1u << b) - 1u;
                float inv_scale = 1.0f / (float)(1u << (sf[ch][sb] + 1u));
                float norm = (sb_sample[blk][ch][sb] * inv_scale + 1.0f) * 0.5f * (float)levels;
                int32_t q = (norm <= 0.0f) ? 0 : (int32_t)norm;
                if ((uint32_t)q >= levels) {
                    q = (int32_t)(levels - 1u);
                }
                bw_put(&bw, (uint32_t)q, b);
            }
        }
    }
    return frame_len;
}

/* ==== Reference Synthesis Decoder (A2DP Appendix B §12.8) ==== */
void sbc_dec_init(sbc_dec_t *dec)
{
    if (!dec) {
        return;
    }
    ensure_proto_table();
    memset(dec, 0, sizeof(*dec));
    for (int k = 0; k < 16; k++) {
        for (int sb = 0; sb < 8; sb++) {
            dec->syn_cos[k][sb] = (float)cos(((double)sb + 0.5) * ((double)k + 4.0) * (M_PI / 8.0));
        }
    }
}

typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         byte_pos;
    uint8_t        bit_used;
} bit_reader_t;

static uint32_t br_get(bit_reader_t *br, int nbits)
{
    uint32_t val = 0u;
    for (int i = 0; i < nbits; i++) {
        val <<= 1;
        if (br->byte_pos < br->len) {
            uint8_t bit = (uint8_t)((br->buf[br->byte_pos] >> (7u - br->bit_used)) & 1u);
            val |= bit;
            br->bit_used++;
            if (br->bit_used == 8u) {
                br->bit_used = 0u;
                br->byte_pos++;
            }
        }
    }
    return val;
}

size_t sbc_decode_frame(sbc_dec_t *dec, const uint8_t *in_buf, size_t in_len,
                        int16_t *out_pcm_stereo, size_t max_frames, sbc_params_t *out_params)
{
    if (!dec || !in_buf || in_len < 4u || in_buf[0] != SBC_SYNCWORD) {
        return 0u;
    }
    ensure_proto_table();

    /* Only 8-subband frames supported in this decoder */
    if ((in_buf[1] & 0x01u) == 0u) {
        return 0u;
    }

    sbc_params_t p;
    p.freq     = (sbc_freq_t)((in_buf[1] >> 6) & 0x03u);
    p.blocks   = (uint8_t)((((in_buf[1] >> 4) & 0x03u) + 1u) * 4u);
    p.mode     = (sbc_mode_t)((in_buf[1] >> 2) & 0x03u);
    p.alloc    = (sbc_alloc_t)((in_buf[1] >> 1) & 0x01u);
    p.subbands = 8u;
    p.bitpool  = in_buf[2];

    uint16_t flen = sbc_frame_length(&p);
    if (in_len < flen || (out_pcm_stereo && max_frames < (size_t)p.blocks * 8u)) {
        return 0u;
    }

    const int n_ch = (p.mode == SBC_MODE_MONO) ? 1 : 2;
    size_t pos = 4u;
    uint8_t crc_input[2 + 1 + 8];
    size_t  crc_bytes = 0u;
    crc_input[crc_bytes++] = in_buf[1];
    crc_input[crc_bytes++] = in_buf[2];

    uint8_t join_byte = 0u;
    if (p.mode == SBC_MODE_JOINT_STEREO) {
        join_byte = in_buf[pos++];
        crc_input[crc_bytes++] = join_byte;
    }

    uint8_t sf[2][8];
    memset(sf, 0, sizeof(sf));
    for (int ch = 0; ch < n_ch; ch++) {
        for (int sb = 0; sb < 8; sb += 2) {
            uint8_t b = in_buf[pos++];
            crc_input[crc_bytes++] = b;
            sf[ch][sb]     = (uint8_t)((b >> 4) & 0x0Fu);
            sf[ch][sb + 1] = (uint8_t)(b & 0x0Fu);
        }
    }

    if (sbc_crc8_bits(crc_input, crc_bytes * 8u) != in_buf[3]) {
        return 0u; /* CRC mismatch */
    }

    int bits[2][8];
    sbc_calculate_bits(&p, sf, bits);

    bit_reader_t br = {
        .buf      = in_buf,
        .len      = flen,
        .byte_pos = pos,
        .bit_used = 0u,
    };

    float sb_sample[16][2][8];
    memset(sb_sample, 0, sizeof(sb_sample));

    for (int blk = 0; blk < (int)p.blocks; blk++) {
        for (int ch = 0; ch < n_ch; ch++) {
            for (int sb = 0; sb < 8; sb++) {
                int b = bits[ch][sb];
                if (b <= 0) {
                    sb_sample[blk][ch][sb] = 0.0f;
                } else {
                    uint32_t q = br_get(&br, b);
                    uint32_t levels = (1u << b) - 1u;
                    float scale = (float)(1u << (sf[ch][sb] + 1u));
                    sb_sample[blk][ch][sb] = scale * (((float)(q * 2u + 1u) / (float)levels) - 1.0f);
                }
            }
        }
        if (p.mode == SBC_MODE_JOINT_STEREO) {
            for (int sb = 0; sb < 7; sb++) {
                if (join_byte & (uint8_t)(1u << (7 - sb))) {
                    float m = sb_sample[blk][0][sb];
                    float s = sb_sample[blk][1][sb];
                    sb_sample[blk][0][sb] = m + s;
                    sb_sample[blk][1][sb] = m - s;
                }
            }
        }
    }

    if (out_pcm_stereo) {
        for (int blk = 0; blk < (int)p.blocks; blk++) {
            int16_t ch_out[2][8];
            for (int ch = 0; ch < n_ch; ch++) {
                float *v = dec->syn_v[ch];
                memmove(&v[16], &v[0], 144u * sizeof(float));
                for (int k = 0; k < 16; k++) {
                    float acc = 0.0f;
                    for (int sb = 0; sb < 8; sb++) {
                        acc += dec->syn_cos[k][sb] * sb_sample[blk][ch][sb];
                    }
                    v[k] = acc;
                }
                float u[80];
                for (int i = 0; i < 5; i++) {
                    memcpy(&u[i * 16],     &v[i * 32],      8u * sizeof(float));
                    memcpy(&u[i * 16 + 8], &v[i * 32 + 24], 8u * sizeof(float));
                }
                float w[80];
                for (int i = 0; i < 80; i++) {
                    /* Synthesis D[i] = -8 * C[i] (A2DP Appendix B Table 12.3) */
                    w[i] = (-8.0f * s_proto_c80[i]) * u[i];
                }
                for (int j = 0; j < 8; j++) {
                    float s = 0.0f;
                    for (int m = 0; m < 10; m++) {
                        s += w[j + 8 * m];
                    }
                    if (s > 32767.0f) s = 32767.0f;
                    if (s < -32768.0f) s = -32768.0f;
                    ch_out[ch][j] = (int16_t)lrintf(s);
                }
            }
            for (int j = 0; j < 8; j++) {
                size_t idx = ((size_t)blk * 8u + (size_t)j) * 2u;
                out_pcm_stereo[idx]     = ch_out[0][j];
                out_pcm_stereo[idx + 1] = (n_ch == 2) ? ch_out[1][j] : ch_out[0][j];
            }
        }
    }

    if (out_params) {
        *out_params = p;
    }
    return flen;
}
