/*
 * Cyberdeck: host test of the Soft-BR adapter's self-disable after crashes (main/br_c6_crash.c).
 * Run: sh test/run_host_tests.sh
 */
#include <stdio.h>
#include <string.h>

#include "br_c6_crash.h"

static int failures;

#define CHECK(cond) do { \
	if (!(cond)) { \
		printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		failures++; \
	} \
} while (0)

static const uint8_t IMG_A[BR_CRASH_IMG_LEN] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
static const uint8_t IMG_B[BR_CRASH_IMG_LEN] = { 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10 };

int main(void)
{
	br_crash_boot_t b0 = br_crash_boot(NULL, IMG_A, false, false);
	CHECK(!b0.disabled && !b0.write && b0.rec.crashes == 0);

	br_crash_boot_t b1 = br_crash_boot(NULL, IMG_A, true, true);
	CHECK(!b1.disabled && b1.write && b1.rec.crashes == 1);

	/* Normal P4 reset while BR was active must NOT increment crash counter */
	br_crash_boot_t b_norm = br_crash_boot(&b1.rec, IMG_A, true, false);
	CHECK(!b_norm.disabled && !b_norm.write && b_norm.rec.crashes == 1);

	/* Second panic while BR live disables Soft-BR */
	br_crash_boot_t b2 = br_crash_boot(&b1.rec, IMG_A, true, true);
	CHECK(b2.disabled && b2.write && b2.rec.crashes == 2);

	/* Stays disabled across normal boots of the same image until the crashes are forgiven (below) */
	br_crash_boot_t b3 = br_crash_boot(&b2.rec, IMG_A, false, false);
	CHECK(b3.disabled && !b3.write);

	/* Flashing a new image resets counter and re-enables */
	br_crash_boot_t b4 = br_crash_boot(&b2.rec, IMG_B, false, false);
	CHECK(!b4.disabled && b4.write && b4.rec.crashes == 0);

	/* The limit is there to stop a loop of crashes, not to remember one: a crash is forgotten once the adapter
	 * has run BR_CRASH_FORGIVE_SECS without another, so the next one is the first again. */
	CHECK(BR_CRASH_FORGIVE_SECS >= 60u && BR_CRASH_FORGIVE_SECS <= 600u);
	br_crash_boot_t f1 = br_crash_forgive(&b1.rec);
	CHECK(f1.write && !f1.disabled && f1.rec.crashes == 0 && f1.rec.ver == BR_CRASH_REC_VER);
	CHECK(memcmp(f1.rec.img, IMG_A, BR_CRASH_IMG_LEN) == 0);
	br_crash_boot_t b5 = br_crash_boot(&f1.rec, IMG_A, true, true);
	CHECK(!b5.disabled && b5.write && b5.rec.crashes == 1);

	/* Two crashes with no quiet stretch between them switch Soft-BR off for that start (b2). The quiet stretch
	 * after them brings it back at the next start, with the same image. */
	br_crash_boot_t f2 = br_crash_forgive(&b2.rec);
	CHECK(f2.write && f2.rec.crashes == 0);
	br_crash_boot_t b6 = br_crash_boot(&f2.rec, IMG_A, false, false);
	CHECK(!b6.disabled && !b6.write && b6.rec.crashes == 0);

	/* Nothing on record: nothing to write. */
	br_crash_boot_t f0 = br_crash_forgive(&b0.rec);
	CHECK(!f0.write && !f0.disabled && f0.rec.crashes == 0);

	if (failures) {
		printf("br_c6_crash: %d FAILURES\n", failures);
		return 1;
	}
	printf("br_c6_crash: OK\n");
	return 0;
}
