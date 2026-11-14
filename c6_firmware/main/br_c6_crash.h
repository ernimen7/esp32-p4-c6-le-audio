/*
 * Cyberdeck Soft-BR: self-disable of the Bluetooth Classic Soft-BR adapter after crashes (pure logic, host tested).
 *
 * Mirrors cis_c6_crash.h: keeps a separate RTC "BR live" marker and NVS record ("br_crash") per firmware image
 * so a bug during Soft-BR disables only Soft-BR after BR_CRASH_LIMIT panics while leaving BLE, LE Audio (CIS),
 * Wi-Fi/SDIO, and fw_guard completely unaffected. Unlike the CIS fuse it is not for good: the crashes on record
 * are forgotten after BR_CRASH_FORGIVE_SECS of running without one (br_crash_forgive), so only crashes in quick
 * succession count and a disabled adapter is back at the next start.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BR_CRASH_IMG_LEN 8
#define BR_CRASH_LIMIT   2

typedef struct {
	uint8_t ver;
	uint8_t img[BR_CRASH_IMG_LEN];
	uint8_t crashes;
} br_crash_rec_t;

#define BR_CRASH_REC_VER 1

typedef struct {
	br_crash_rec_t rec;
	bool write;
	bool disabled;
} br_crash_boot_t;

br_crash_boot_t br_crash_boot(const br_crash_rec_t *stored, const uint8_t img[BR_CRASH_IMG_LEN],
			      bool live_at_reset, bool crash_reset);

/* How long the adapter has to run without a crash before the crashes on record are forgotten. The limit stops a
 * loop (start, crash, restart, start again); a crash from last week, or two with the device working in between,
 * are no reason to keep Bluetooth Classic switched off until the next firmware image (Tab5, 2026-11-11: two
 * crashes six minutes apart left a test image without Classic for good). */
#define BR_CRASH_FORGIVE_SECS 180u

/* The record to keep once the adapter has run that long since the start; write: it changed and has to be stored.
 * An image that was disabled at this start stays disabled until the next one, where the cleared record lets it
 * work again. */
br_crash_boot_t br_crash_forgive(const br_crash_rec_t *rec);

#ifdef __cplusplus
}
#endif
