/*
 * How much sound quality the link can carry: the SBC bitpool, and how many frames go into one media packet.
 *
 * The radio sends 3-slot packets of at most BR_DEFAULT_DH3_CAP bytes, one every 3.75 to 5 ms, and the speaker is
 * away about 30 % of the time (it keeps scanning for other devices; sound trials 11 and 12, 2026-11-11). What
 * that leaves is not known beforehand and changes with the speaker, so the bitpool is not a fixed number: it
 * starts low and follows the room the link shows.
 *
 * Packing: a media packet is one L2CAP frame (4 bytes of L2CAP header, 12 of RTP, 1 of SBC payload header, then
 * whole SBC frames), and the controller cuts it into 3-slot packets. Three packets filled to the brim carry more
 * frames than three that are each two thirds full, so for every frame size the number of frames per media packet
 * is the one that needs the fewest 3-slot packets per frame. Several bitpools in a row then cost the same number
 * of 3-slot packets; of those the highest is used, it is free.
 *
 * Control: the caller measures, over a window of a few seconds, the share of the time in which the controller
 * held data that had not yet gone out (`busy_pct`): the link's load, the speaker's absences included. The bitpool
 * goes up a step when that load, scaled to what the next step would send, stays under BTC_RATE_UP_PCT for
 * BTC_RATE_UP_WINDOWS windows, and down a step at once when a packet was lost or the load passes
 * BTC_RATE_DOWN_PCT; after a step down it stays for BTC_RATE_HOLD_WINDOWS windows.
 *
 * Plain data and functions: the stream task owns one btc_rate_t.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BTC_RATE_MEDIA_OVERHEAD 17u /* L2CAP header 4, RTP header 12, SBC payload header 1 */
#define BTC_RATE_MAX_DH3        3u  /* 3-slot packets per media packet */
#define BTC_RATE_MAX_FRAMES     15u /* the SBC payload header counts frames in four bits */
#define BTC_RATE_UP_PCT         85u /* sound trial 13: 74 % busy at bitpool 20 with nothing lost and 3 packets waiting at most */
#define BTC_RATE_DOWN_PCT       95u
#define BTC_RATE_UP_WINDOWS     3u
#define BTC_RATE_HOLD_WINDOWS   10u

/* Frames per media packet for SBC frames of `frame_bytes`, and the 3-slot packets of `dh3_cap` bytes such a
 * media packet takes; the L2CAP payload (RTP header and all) stays within `mtu`. False: not even one frame fits. */
static inline bool btc_rate_packing(uint16_t frame_bytes, uint16_t dh3_cap, uint16_t mtu, uint8_t *frames,
                                    uint8_t *dh3)
{
    uint8_t best_k = 0u, best_m = 0u;
    for (uint8_t m = 1u; m <= BTC_RATE_MAX_DH3; m++) {
        uint32_t room = (uint32_t)m * dh3_cap;
        if (room > (uint32_t)mtu + 4u) {
            room = (uint32_t)mtu + 4u;
        }
        if (frame_bytes == 0u || room < BTC_RATE_MEDIA_OVERHEAD + (uint32_t)frame_bytes) {
            continue;
        }
        uint32_t k = (room - BTC_RATE_MEDIA_OVERHEAD) / frame_bytes;
        if (k > BTC_RATE_MAX_FRAMES) {
            k = BTC_RATE_MAX_FRAMES;
        }
        /* More frames per 3-slot packet wins: k / m > best_k / best_m. A tie keeps the smaller packet. */
        if (best_m == 0u || k * best_m > (uint32_t)best_k * m) {
            best_k = (uint8_t)k;
            best_m = m;
        }
    }
    if (best_m == 0u) {
        return false;
    }
    *frames = best_k;
    *dh3    = best_m;
    return true;
}

/* The length of an SBC frame at a bitpool, for the stream's sampling and channel settings (the encoder knows). */
typedef uint16_t (*btc_rate_frame_fn)(void *ctx, uint8_t bitpool);

typedef struct {
    uint8_t  bitpool;      /* in use now */
    uint8_t  min_bitpool;
    uint8_t  max_bitpool;
    uint16_t dh3_cap;
    uint16_t mtu;
    btc_rate_frame_fn frame_bytes;
    void    *frame_ctx;
    uint8_t  up_windows;   /* windows in a row that allowed a step up */
    uint8_t  hold_windows; /* windows left in which no step up is taken */
    uint8_t  up_pct;       /* the loads that move the bitpool (btc_rate_set_limits) */
    uint8_t  down_pct;
} btc_rate_t;

/* 3-slot packets per 1000 SBC frames at a bitpool: what the link has to carry, up to a constant factor. */
static inline uint32_t btc_rate_load(const btc_rate_t *r, uint8_t bitpool)
{
    uint8_t k = 0u, m = 0u;
    if (!btc_rate_packing(r->frame_bytes(r->frame_ctx, bitpool), r->dh3_cap, r->mtu, &k, &m)) {
        return 0xFFFFFFFFu;
    }
    return 1000u * m / k;
}

/* The highest bitpool that costs the same as `bitpool`. */
static inline uint8_t btc_rate_top_of_step(const btc_rate_t *r, uint8_t bitpool)
{
    const uint32_t load = btc_rate_load(r, bitpool);
    while (bitpool < r->max_bitpool && btc_rate_load(r, (uint8_t)(bitpool + 1u)) == load) {
        bitpool++;
    }
    return bitpool;
}

/* The bitpool of the next dearer step; `from` when it is the highest already. */
static inline uint8_t btc_rate_step_up(const btc_rate_t *r, uint8_t from)
{
    const uint8_t top = btc_rate_top_of_step(r, from);
    if (top >= r->max_bitpool || btc_rate_load(r, (uint8_t)(top + 1u)) == 0xFFFFFFFFu) {
        return top;
    }
    return btc_rate_top_of_step(r, (uint8_t)(top + 1u));
}

/* The bitpool of the next cheaper step; `from` when there is none. */
static inline uint8_t btc_rate_step_down(const btc_rate_t *r, uint8_t from)
{
    const uint32_t load = btc_rate_load(r, from);
    for (int bp = (int)from - 1; bp >= (int)r->min_bitpool; bp--) {
        if (btc_rate_load(r, (uint8_t)bp) < load) {
            return (uint8_t)bp;
        }
    }
    return from;
}

/* The loads that move the bitpool, in place of BTC_RATE_UP_PCT and BTC_RATE_DOWN_PCT: lower ones leave the
 * radio time for what shares it. After btc_rate_init, which starts with the defaults. */
static inline void btc_rate_set_limits(btc_rate_t *r, uint8_t up_pct, uint8_t down_pct)
{
    r->down_pct = (down_pct < 2u) ? 2u : (down_pct > 100u) ? 100u : down_pct;
    r->up_pct   = (up_pct < 1u) ? 1u : (up_pct >= r->down_pct) ? (uint8_t)(r->down_pct - 1u) : up_pct;
}

/* Starts at the top of the step `start_bitpool` is on: the bitpools above it that cost the same are free. */
static inline void btc_rate_init(btc_rate_t *r, uint8_t start_bitpool, uint8_t min_bitpool, uint8_t max_bitpool,
                                 uint16_t dh3_cap, uint16_t mtu, btc_rate_frame_fn frame_bytes, void *frame_ctx)
{
    r->min_bitpool  = min_bitpool;
    r->max_bitpool  = (max_bitpool < min_bitpool) ? min_bitpool : max_bitpool;
    r->dh3_cap      = dh3_cap;
    r->mtu          = mtu;
    r->frame_bytes  = frame_bytes;
    r->frame_ctx    = frame_ctx;
    r->up_windows   = 0u;
    r->hold_windows = 0u;
    r->up_pct       = BTC_RATE_UP_PCT;
    r->down_pct     = BTC_RATE_DOWN_PCT;
    r->bitpool      = (start_bitpool < r->min_bitpool) ? r->min_bitpool
                    : (start_bitpool > r->max_bitpool) ? r->max_bitpool : start_bitpool;
    r->bitpool      = btc_rate_top_of_step(r, r->bitpool);
}

/* End of a window: decides the bitpool for the next one and returns it. `busy_pct`: share of the window in which
 * data was waiting in the controller; `lost`: media packets given up in it. */
static inline uint8_t btc_rate_end_window(btc_rate_t *r, uint32_t busy_pct, uint32_t lost)
{
    if (lost > 0u || busy_pct > r->down_pct) {
        r->bitpool      = btc_rate_step_down(r, r->bitpool);
        r->up_windows   = 0u;
        r->hold_windows = BTC_RATE_HOLD_WINDOWS;
        return r->bitpool;
    }
    if (r->hold_windows > 0u) {
        r->hold_windows--;
        return r->bitpool;
    }
    const uint8_t next = btc_rate_step_up(r, r->bitpool);
    if (next == r->bitpool) {
        return r->bitpool;
    }
    const uint32_t now_load  = btc_rate_load(r, r->bitpool);
    const uint32_t next_load = btc_rate_load(r, next);
    if (busy_pct * next_load < (uint32_t)r->up_pct * now_load) {
        if (++r->up_windows >= BTC_RATE_UP_WINDOWS) {
            r->bitpool    = next;
            r->up_windows = 0u;
        }
    } else {
        r->up_windows = 0u;
    }
    return r->bitpool;
}

#ifdef __cplusplus
}
#endif
