#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Starts the player task: every *.mp3 under music_dir (recursive), forever. music_dir must stay valid. The sound
 * goes to the Bluetooth Classic stream when a Classic device is connected and to the LE Audio stream when earbuds
 * are; with neither, the player waits. */
void player_start(const char *music_dir);
void player_title(char *out, size_t cap);
bool player_paused(void);
uint32_t player_tracks_started(void);
uint32_t player_position_ms(void);  /* decoded position in the current track */
void player_toggle_pause(void);
void player_next(void);
void player_previous(void);

#ifdef __cplusplus
}
#endif
