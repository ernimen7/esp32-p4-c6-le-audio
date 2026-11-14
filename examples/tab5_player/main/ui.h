#pragma once
#ifdef __cplusplus
extern "C" {
#endif

/* Display + touch (Tab5 BSP, LVGL) and the one-screen UI. On failure logs and returns: serial log only. */
void ui_start(void);

typedef enum { UI_STAGE_PENDING = 0, UI_STAGE_OK, UI_STAGE_FAIL } ui_stage_state_t;
/* Boot stage n (1..5: board, C6 link, SD card, bonds, Bluetooth hosts) with a short detail; thread-safe, also
 * before ui_start(). */
void ui_stage(int n, ui_stage_state_t state, const char *detail);

#ifdef __cplusplus
}
#endif
