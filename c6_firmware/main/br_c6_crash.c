/* Cyberdeck Soft-BR: self-disable of the Soft-BR adapter after crashes (see br_c6_crash.h). */
#include <string.h>

#include "br_c6_crash.h"

br_crash_boot_t br_crash_boot(const br_crash_rec_t *stored, const uint8_t img[BR_CRASH_IMG_LEN],
			      bool live_at_reset, bool crash_reset)
{
	br_crash_boot_t out = { .write = false, .disabled = false };
	const bool same_img = stored != NULL && stored->ver == BR_CRASH_REC_VER &&
			      memcmp(stored->img, img, BR_CRASH_IMG_LEN) == 0;

	out.rec.ver = BR_CRASH_REC_VER;
	memcpy(out.rec.img, img, BR_CRASH_IMG_LEN);
	out.rec.crashes = same_img ? stored->crashes : 0;
	if (!same_img && stored != NULL) {
		out.write = true;
	}
	if (live_at_reset && crash_reset && out.rec.crashes < UINT8_MAX) {
		out.rec.crashes++;
		out.write = true;
	}
	out.disabled = out.rec.crashes >= BR_CRASH_LIMIT;
	return out;
}

br_crash_boot_t br_crash_forgive(const br_crash_rec_t *rec)
{
	br_crash_boot_t out = { .write = false, .disabled = false };
	out.rec = *rec;
	if (out.rec.crashes != 0u) {
		out.rec.crashes = 0u;
		out.write = true;
	}
	return out;
}
