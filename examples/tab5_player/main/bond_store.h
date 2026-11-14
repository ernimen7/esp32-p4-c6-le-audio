#pragma once
#include <stddef.h>
#include "bt_classic.h"
#include "le_audio.h"

/* Loads saved bonds from NVS into RAM and fills kv (read-only unless CONFIG_TAB5_PLAYER_SAVE_BONDS) and identity
 * (address mode the earbuds were paired with). Call once from app_main. true = a saved LE Audio bond list exists. */
bool bond_store_load(le_audio_kv_t *kv, int *identity);
/* Number of entries in the saved LE Audio bond list (0 = none). Call after bond_store_load. */
int bond_store_count(void);

/* Fills the Bluetooth Classic host's store callbacks (RAM copy; NVS is written from a task with an internal stack).
 * Call after bond_store_load(). Returns true if remembered Classic devices were found in NVS. */
bool bond_store_load_classic(bt_classic_kv_t *kv);

/* The LE devices the player connected, most recently used first: one "address|type|name" line each. The LE host
 * keeps keys but no names, so remembered earbuds that are switched off would otherwise have nothing to show.
 * bond_store_known_le copies the text (empty when there is none) and returns its length;
 * bond_store_set_known_le replaces it (and saves it with CONFIG_TAB5_PLAYER_SAVE_BONDS). */
size_t bond_store_known_le(char *out, size_t cap);
void bond_store_set_known_le(const char *text);
