/*
 * The Classic devices the host remembers: for each its address, link key, name and what the last page needed.
 * Most recently used first, so that "connect the saved one" means the one used last and a new device pushes out
 * the one used longest ago. Pure C, tested on the host (tests/host/test_bt_classic.cpp).
 *
 * The first version of the host stored one record alone ('BTC1'); a device holding that still has its speaker
 * paired after the update (btc_bonds_load reads both forms).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BTC_BONDS_MAX      4u
#define BTC_BOND_MAGIC     0x42544331u /* 'BTC1': in every record, and the whole of the first stored form */
#define BTC_BONDS_MAGIC_V2 0x42544332u /* 'BTC2': header of the stored list */

typedef struct {
    uint32_t magic; /* BTC_BOND_MAGIC */
    uint8_t  addr[6];
    uint8_t  page_scan_rep;
    uint8_t  reserved;
    uint16_t clock_offset;
    uint16_t flags;
    uint8_t  link_key[16];
    char     name[64];
} btc_bond_t;

typedef struct {
    uint8_t    count;
    btc_bond_t items[BTC_BONDS_MAX]; /* most recently used first */
} btc_bonds_t;

/* 'BTC2', the count in one byte, three bytes of zero, then the records. */
#define BTC_BONDS_STORE_MAX (8u + BTC_BONDS_MAX * sizeof(btc_bond_t))

/* The place of the device in the list, -1 when it is not remembered. */
static inline int btc_bonds_find(const btc_bonds_t *b, const uint8_t addr[6])
{
    for (uint8_t i = 0u; i < b->count && i < BTC_BONDS_MAX; i++) {
        if (memcmp(b->items[i].addr, addr, 6u) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* The record of the device, moved to the front. A device not yet remembered gets an empty record there (address
 * and magic set); with the list full the one used longest ago makes room. */
static inline btc_bond_t *btc_bonds_touch(btc_bonds_t *b, const uint8_t addr[6])
{
    btc_bond_t rec;
    int at = btc_bonds_find(b, addr);
    if (at >= 0) {
        rec = b->items[at];
    } else {
        memset(&rec, 0, sizeof(rec));
        rec.magic = BTC_BOND_MAGIC;
        memcpy(rec.addr, addr, 6u);
        if (b->count < BTC_BONDS_MAX) {
            b->count++;
        }
        at = (int)b->count - 1; /* the free place at the end, or the one used longest ago */
    }
    memmove(&b->items[1], &b->items[0], (size_t)at * sizeof(btc_bond_t));
    b->items[0] = rec;
    return &b->items[0];
}

/* Forgets the device. False: it was not remembered. */
static inline bool btc_bonds_remove(btc_bonds_t *b, const uint8_t addr[6])
{
    const int at = btc_bonds_find(b, addr);
    if (at < 0) {
        return false;
    }
    memmove(&b->items[at], &b->items[at + 1], (size_t)(b->count - 1 - at) * sizeof(btc_bond_t));
    b->count--;
    memset(&b->items[b->count], 0, sizeof(btc_bond_t)); /* no key left behind */
    return true;
}

/* The stored form of the list. Returns its length, 0 when `cap` is too small. */
static inline size_t btc_bonds_store(const btc_bonds_t *b, uint8_t *out, size_t cap)
{
    const uint8_t n    = (b->count > BTC_BONDS_MAX) ? (uint8_t)BTC_BONDS_MAX : b->count;
    const size_t  need = 8u + (size_t)n * sizeof(btc_bond_t);
    if (cap < need) {
        return 0u;
    }
    const uint32_t magic = BTC_BONDS_MAGIC_V2;
    memset(out, 0, 8u);
    memcpy(out, &magic, 4u);
    out[4] = n;
    memcpy(out + 8u, b->items, (size_t)n * sizeof(btc_bond_t));
    return need;
}

/* Reads a stored list, or the single record the first version stored. False: neither - the list is left empty. */
static inline bool btc_bonds_load(btc_bonds_t *b, const uint8_t *in, size_t len)
{
    uint32_t magic = 0u;
    memset(b, 0, sizeof(*b));
    if (in == NULL || len < 8u) {
        return false;
    }
    memcpy(&magic, in, 4u);
    size_t n = 0u;
    const uint8_t *recs = in;
    if (magic == BTC_BOND_MAGIC && len == sizeof(btc_bond_t)) {
        n = 1u;
    } else if (magic == BTC_BONDS_MAGIC_V2 && in[4] <= BTC_BONDS_MAX && len == 8u + (size_t)in[4] * sizeof(btc_bond_t)) {
        n    = in[4];
        recs = in + 8u;
    } else {
        return false;
    }
    memcpy(b->items, recs, n * sizeof(btc_bond_t));
    for (size_t i = 0u; i < n; i++) {
        if (b->items[i].magic != BTC_BOND_MAGIC) {
            memset(b, 0, sizeof(*b));
            return false;
        }
        b->items[i].name[sizeof(b->items[i].name) - 1u] = '\0'; /* stored data: never trust the terminator */
    }
    b->count = (uint8_t)n;
    return true;
}

#ifdef __cplusplus
}
#endif
