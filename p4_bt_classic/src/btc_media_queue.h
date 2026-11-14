/*
 * Media packets waiting for room in the controller.
 *
 * The link to the speaker stops for 60 to 120 ms several times a second (sound trial 11, 2026-11-11: a run of 9 to
 * 20 unanswered pairs in every second, while the average rate was enough for the stream). The controller holds
 * eight packets, 70 ms of sound; what did not fit was thrown away at once, 1.3 packets a second. Here the packets
 * wait until the link has caught up, which it does at nearly twice the rate of the stream. Only when this queue is
 * full as well is a packet lost, and then the oldest one, so that the delay stays bounded.
 *
 * Plain data and functions, no locking: one task fills and empties it.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 32 packets of three SBC frames are 279 ms of sound at 44.1 kHz; with more frames to a packet, more. */
#define BTC_MEDIA_QUEUE_DEPTH 32u
/* The SBC frames of the largest media packet: three 3-slot packets of 168 bytes less the 17 bytes of headers. */
#define BTC_MEDIA_PKT_MAX     512u

typedef struct {
    uint16_t len;
    uint8_t  frames;
    uint8_t  data[BTC_MEDIA_PKT_MAX];
} btc_media_pkt_t;

typedef struct {
    btc_media_pkt_t slot[BTC_MEDIA_QUEUE_DEPTH];
    uint16_t head;       /* index of the oldest packet */
    uint16_t count;
    uint16_t high_water; /* most packets waiting at once since the reset */
    uint32_t dropped;    /* packets lost because the queue was full */
} btc_media_queue_t;

static inline void btc_media_queue_reset(btc_media_queue_t *q)
{
    q->head       = 0u;
    q->count      = 0u;
    q->high_water = 0u;
    q->dropped    = 0u;
}

/* Puts a packet at the end. A full queue loses its oldest packet for it. False: the packet is empty or too long
 * and was not taken. */
static inline bool btc_media_queue_push(btc_media_queue_t *q, const uint8_t *data, uint16_t len, uint8_t frames)
{
    if (len == 0u || len > BTC_MEDIA_PKT_MAX) {
        return false;
    }
    if (q->count == BTC_MEDIA_QUEUE_DEPTH) {
        q->head = (uint16_t)((q->head + 1u) % BTC_MEDIA_QUEUE_DEPTH);
        q->count--;
        q->dropped++;
    }
    btc_media_pkt_t *p = &q->slot[(q->head + q->count) % BTC_MEDIA_QUEUE_DEPTH];
    p->len    = len;
    p->frames = frames;
    memcpy(p->data, data, len);
    q->count++;
    if (q->count > q->high_water) {
        q->high_water = q->count;
    }
    return true;
}

/* The oldest packet, or NULL when nothing waits. */
static inline const btc_media_pkt_t *btc_media_queue_front(const btc_media_queue_t *q)
{
    return q->count ? &q->slot[q->head] : NULL;
}

static inline void btc_media_queue_pop(btc_media_queue_t *q)
{
    if (q->count) {
        q->head = (uint16_t)((q->head + 1u) % BTC_MEDIA_QUEUE_DEPTH);
        q->count--;
    }
}

#ifdef __cplusplus
}
#endif
