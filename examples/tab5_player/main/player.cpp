// MP3 player for the example: every *.mp3 under the music directory (recursive, sorted), in a loop forever.
// The sound follows the connection: to the Bluetooth Classic stream (A2DP, SBC) when a Classic device is connected,
// to the LE Audio stream (CIS, LC3) when earbuds are. devices.cpp sees to it that only one of them is.
#include "player.h"

#include "resample.h"

#include <dr_mp3.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include <dirent.h>
#include <sys/stat.h>

#include "bt_classic.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "le_audio.h"

namespace {

constexpr const char* kTag = "player";
constexpr size_t kReadBuf  = 16 * 1024;  // stdio buffer: one 16 kB SD transaction instead of many small reads
constexpr size_t kChunk    = 1152;       // one MPEG-1 Layer III frame
// A paused player keeps a Classic stream open this long, then suspends it (AVDTP SUSPEND): a speaker with an open
// stream and no sound keeps its amplifier on, and the stream fills the radio time Wi-Fi could use.
constexpr int64_t kSuspendAfterUs = 5 * 1000 * 1000;

std::atomic<bool> g_paused{false};
std::atomic<int> g_skip{0};  // +1 next, -1 previous (consumed by the decode loop)
std::mutex g_titleLock;
std::string g_title;  // under g_titleLock
std::atomic<uint32_t> g_tracks{0};
std::atomic<uint64_t> g_posFrames{0};  // decoded frames of the current track
std::atomic<uint32_t> g_rate{0};

bool isMp3(const char* name)
{
    const size_t n = std::strlen(name);
    return n > 4 && strcasecmp(name + n - 4, ".mp3") == 0;
}

void collect(const std::string& dir, std::vector<std::string>& out, int depth)
{
    if (depth > 8) {
        return;
    }
    DIR* d = opendir(dir.c_str());
    if (d == nullptr) {
        return;
    }
    while (dirent* e = readdir(d)) {
        if (e->d_name[0] == '.') {
            continue;
        }
        const std::string p = dir + "/" + e->d_name;
        struct stat st;
        if (stat(p.c_str(), &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            collect(p, out, depth + 1);
        } else if (isMp3(e->d_name)) {
            out.push_back(p);
        }
    }
    closedir(d);
}

size_t onRead(void* f, void* buf, size_t n)
{
    return std::fread(buf, 1, n, static_cast<FILE*>(f));
}

drmp3_bool32 onSeek(void* f, int offset, drmp3_seek_origin origin)
{
    const int whence = origin == DRMP3_SEEK_SET ? SEEK_SET : origin == DRMP3_SEEK_END ? SEEK_END : SEEK_CUR;
    return std::fseek(static_cast<FILE*>(f), offset, whence) == 0;
}

drmp3_bool32 onTell(void* f, drmp3_int64* cursor)
{
    const long p = std::ftell(static_cast<FILE*>(f));
    if (p < 0) {
        return DRMP3_FALSE;
    }
    *cursor = p;
    return DRMP3_TRUE;
}

void pollMediaCommands()
{
    le_audio_media_cmd_t c;
    while (le_audio_take_media_command(&c)) {
        switch (c) {
            case LE_AUDIO_MEDIA_PLAY: g_paused = false; break;
            case LE_AUDIO_MEDIA_PAUSE:
            case LE_AUDIO_MEDIA_STOP: g_paused = true; break;
            case LE_AUDIO_MEDIA_NEXT: g_skip = 1; break;
            case LE_AUDIO_MEDIA_PREVIOUS: g_skip = -1; break;
        }
        ESP_LOGI(kTag, "LE Audio gesture: %d", (int)c);
    }

    for (;;) {
        const bt_classic_media_cmd_t bc = bt_classic_take_media_command();
        if (bc == BTC_MEDIA_CMD_NONE) {
            break;
        }
        switch (bc) {
            case BTC_MEDIA_CMD_PLAY: g_paused = false; break;
            case BTC_MEDIA_CMD_PAUSE:
            case BTC_MEDIA_CMD_STOP: g_paused = true; break;
            case BTC_MEDIA_CMD_NEXT: g_skip = 1; break;
            case BTC_MEDIA_CMD_PREV: g_skip = -1; break;
            case BTC_MEDIA_CMD_VOL_UP:
                bt_classic_set_volume((uint8_t)std::clamp((int)bt_classic_get_volume() + 20, 0, 255));
                break;
            case BTC_MEDIA_CMD_VOL_DOWN:
                bt_classic_set_volume((uint8_t)std::clamp((int)bt_classic_get_volume() - 20, 0, 255));
                break;
            default: break;
        }
        ESP_LOGI(kTag, "AVRCP button: %d", (int)bc);
    }
}

std::string baseName(const std::string& p)
{
    const size_t s = p.find_last_of('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

// Plays one file. Returns the skip direction requested during playback (0 = played to the end or failed).
int playFile(const std::string& path, drmp3* mp3, char* fileBuf, int16_t* pcm, std::vector<float>& out48,
             std::vector<int16_t>& s16)
{
    FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) {
        ESP_LOGW(kTag, "cannot open %s", path.c_str());
        return 0;
    }
    std::setvbuf(f, fileBuf, _IOFBF, kReadBuf);
    if (!drmp3_init(mp3, onRead, onSeek, onTell, nullptr, f, nullptr)) {
        ESP_LOGW(kTag, "not an MP3 stream: %s", path.c_str());
        std::fclose(f);
        return 0;
    }
    app::media::Resampler rs;
    rs.configure((int)mp3->sampleRate, (int)mp3->channels);
    const std::string title = baseName(path);
    {
        std::lock_guard<std::mutex> l(g_titleLock);
        g_title = title;
    }
    g_tracks++;
    g_posFrames = 0;
    g_rate      = mp3->sampleRate;
    ESP_LOGI(kTag, "playing %s (%u Hz, %u ch)", title.c_str(), (unsigned)mp3->sampleRate, (unsigned)mp3->channels);
    le_audio_set_media_state(true, !g_paused.load(), title.c_str(), 0);
    bool wasPaused        = g_paused.load();
    int64_t pausedSinceUs = 0;
    int skip              = 0;
    for (;;) {
        pollMediaCommands();
        if ((skip = g_skip.exchange(0)) != 0) {
            break;
        }
        const bool paused = g_paused.load();
        if (paused != wasPaused) {
            wasPaused = paused;
            le_audio_set_media_state(true, !paused, title.c_str(), 0);
        }
        if (paused) {
            if (pausedSinceUs == 0) {
                pausedSinceUs = esp_timer_get_time();
            } else if (esp_timer_get_time() - pausedSinceUs >= kSuspendAfterUs) {
                bt_classic_status_t idle;
                bt_classic_get_status(&idle);
                if (idle.state == BT_CLASSIC_STREAMING) {
                    bt_classic_stop();
                }
            }
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
        pausedSinceUs = 0;

        if (bt_classic_ready()) {
            bt_classic_status_t bst;
            bt_classic_get_status(&bst);
            if (bst.state != BT_CLASSIC_STREAMING) {
                if (bt_classic_start() != ESP_OK) {
                    vTaskDelay(pdMS_TO_TICKS(200));
                    continue;
                }
            }
            const drmp3_uint64 got = drmp3_read_pcm_frames_s16(mp3, kChunk, pcm);
            if (got == 0) {
                break;
            }
            g_posFrames += got;
            // The stream task is the clock: the write waits until it has read the buffer down, which paces the
            // decoder. A link that went down ends the loop; the frames it did not take are not played.
            size_t done = 0;
            for (int tries = 0; done < (size_t)got && bt_classic_ready() && tries < 20; tries++) {
                done += bt_classic_write_pcm(pcm + done * mp3->channels, (size_t)got - done, mp3->sampleRate,
                                             (int)mp3->channels, 100);
            }
        } else if (!le_audio_ready()) {
            vTaskDelay(pdMS_TO_TICKS(50));
        } else {
            const drmp3_uint64 got = drmp3_read_pcm_frames_s16(mp3, kChunk, pcm);
            if (got == 0) {
                break;
            }
            g_posFrames += got;
            out48.clear();
            rs.process(pcm, (size_t)got, out48);
            const size_t frames = out48.size() / 2;
            s16.resize(out48.size());
            for (size_t i = 0; i < out48.size(); i++) {
                const float v = std::clamp(out48[i] * 32768.0f, -32768.0f, 32767.0f);
                s16[i]        = (int16_t)std::lrintf(v);
            }
            size_t done = 0;
            while (done < frames && le_audio_ready()) {
                done += le_audio_write_pcm(s16.data() + done * 2, frames - done, 200);
            }
        }
    }
    drmp3_uninit(mp3);
    std::fclose(f);
    return skip;
}

void playerTask(void* arg)
{
    const std::string dir = static_cast<const char*>(arg);
    auto* mp3     = static_cast<drmp3*>(heap_caps_calloc(1, sizeof(drmp3), MALLOC_CAP_SPIRAM));
    auto* fileBuf = static_cast<char*>(heap_caps_malloc(kReadBuf, MALLOC_CAP_SPIRAM));
    auto* pcm     = static_cast<int16_t*>(heap_caps_malloc(kChunk * 2 * sizeof(int16_t), MALLOC_CAP_SPIRAM));
    if (mp3 == nullptr || fileBuf == nullptr || pcm == nullptr) {
        ESP_LOGE(kTag, "out of memory");
        vTaskDelete(nullptr);
        return;
    }
    std::vector<float> out48;
    std::vector<int16_t> s16;
    for (;;) {
        std::vector<std::string> files;
        collect(dir, files, 0);
        std::sort(files.begin(), files.end());
        if (files.empty()) {
            ESP_LOGW(kTag, "no .mp3 files under %s - checking again in 10 s", dir.c_str());
            le_audio_set_media_state(false, false, "", 0);
            vTaskDelay(pdMS_TO_TICKS(10000));
            continue;
        }
        ESP_LOGI(kTag, "%u track(s) under %s", (unsigned)files.size(), dir.c_str());
        const uint32_t started = g_tracks.load();
        for (size_t i = 0; i < files.size();) {
            const int skip = playFile(files[i], mp3, fileBuf, pcm, out48, s16);
            if (skip < 0) {
                i = i == 0 ? files.size() - 1 : i - 1;
            } else {
                i++;
            }
        }
        if (g_tracks.load() == started) {
            ESP_LOGW(kTag, "no file could be played - checking again in 10 s");
            vTaskDelay(pdMS_TO_TICKS(10000));
        }
    }
}

}  // namespace

void player_start(const char* music_dir)
{
    // Internal-RAM stack: FATFS and the decoder run here.
    xTaskCreatePinnedToCore(playerTask, "player", 12 * 1024, (void*)music_dir, 6, nullptr, 0);
}

void player_title(char* out, size_t cap)
{
    std::lock_guard<std::mutex> l(g_titleLock);
    std::snprintf(out, cap, "%s", g_title.c_str());
}

uint32_t player_position_ms(void)
{
    const uint32_t r = g_rate.load();
    return r != 0 ? (uint32_t)(g_posFrames.load() * 1000 / r) : 0;
}

void player_toggle_pause(void)
{
    g_paused = !g_paused.load();
}

void player_next(void)
{
    g_skip = 1;
}

void player_previous(void)
{
    g_skip = -1;
}

uint32_t player_tracks_started(void)
{
    return g_tracks.load();
}

bool player_paused(void)
{
    return g_paused.load();
}
