// tab5_player - a music player for the M5Stack Tab5 (ESP32-P4 + ESP32-C6) with one list of Bluetooth audio devices:
// LE Audio earbuds (CIS, LC3) and Bluetooth Classic speakers and headphones (A2DP, SBC, through Soft-BR in the C6
// firmware of this project).
//
// Boot: board (IO expanders power the C6), SDIO transport to the C6, SD card, saved bonds from NVS, the LE Audio and
// the Bluetooth Classic host, then the connection manager (devices.cpp) connects a remembered device if one
// answers. MP3 files from the SD card play to whichever device is connected.
//
// SAFETY when testing on a device that runs other firmware: this app NEVER calls
// esp_ota_mark_app_valid_cancel_rollback(). Installed by OTA into the inactive slot it stays "pending verify", so the
// next reset boots the previous firmware again.
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

#include "board_tab5.h"
#include "bond_store.h"
#include "bt_classic.h"
#include "c6_update.h"
#include "devices.h"
#include "esp_app_desc.h"
#include "esp_hosted_cyberdeck.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "le_audio.h"
#include "log_sink.h"
#include "player.h"
#include "sdkconfig.h"
#include "ui.h"

namespace {

constexpr const char* kTag    = "tab5_player";
constexpr const char* kSdPath = "/sd";
#if CONFIG_TAB5_PLAYER_ALLOW_PAIRING
constexpr bool kAllowPairing = true;
#else
constexpr bool kAllowPairing = false;
#endif

const char* otaStateName(esp_ota_img_states_t s)
{
    switch (s) {
        case ESP_OTA_IMG_NEW: return "new";
        case ESP_OTA_IMG_PENDING_VERIFY: return "PENDING_VERIFY (next reset returns to the previous firmware)";
        case ESP_OTA_IMG_VALID: return "valid";
        case ESP_OTA_IMG_INVALID: return "invalid";
        case ESP_OTA_IMG_ABORTED: return "aborted";
        default: return "undefined (flashed over USB)";
    }
}

void logBoot()
{
    const esp_app_desc_t* d    = esp_app_get_description();
    const esp_partition_t* run = esp_ota_get_running_partition();
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    if (run != nullptr) {
        esp_ota_get_state_partition(run, &state);
    }
    ESP_LOGI(kTag, "%s %s (%s %s), running from %s, image state: %s", d->project_name, d->version, d->date, d->time,
             run != nullptr ? run->label : "?", otaStateName(state));
    ESP_LOGI(kTag, "this firmware never confirms itself (no esp_ota_mark_app_valid_cancel_rollback)");
}

// A player put on the device for a trial runs from an image that is not confirmed: a reset brings the previous
// firmware back. Left alone in that state (the owner asleep, the trial over) it would keep the screen on until the
// battery is empty, so after this long without a scan, a connection attempt or a link it resets itself.
constexpr int kTrialIdleLimitS = 15 * 60;

bool runsAsTrial()
{
    const esp_partition_t* run = esp_ota_get_running_partition();
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    return run != nullptr && esp_ota_get_state_partition(run, &state) == ESP_OK &&
           state == ESP_OTA_IMG_PENDING_VERIFY;
}

const char* linkName(le_audio_link_state_t s)
{
    static const char* const k[] = {"off", "idle", "scanning", "connecting", "connected", "failed"};
    return (unsigned)s < 6 ? k[s] : "?";
}

const char* phaseName(le_audio_stream_phase_t p)
{
    static const char* const k[] = {"off", "configuring", "streaming", "failed"};
    return (unsigned)p < 4 ? k[p] : "?";
}

const char* classicStateShort(bt_classic_link_state_t s)
{
    static const char* const k[] = {"idle", "scanning", "connecting", "pairing", "configuring", "ready", "streaming"};
    return (unsigned)s < 7 ? k[s] : "?";
}

void logStatus()
{
    char title[64];
    player_title(title, sizeof(title));

    bt_classic_status_t bs = {};
    bt_classic_get_status(&bs);
    if (bs.state != BT_CLASSIC_IDLE) {
        bt_classic_diag_t d = {};
        bt_classic_get_diag(&d);
        ESP_LOGI(kTag,
                 "[BT Classic] %s, phase %d, peer '%s', enc %d, avrcp %d | SBC %" PRIu32 " Hz bitpool %u, link busy "
                 "%u %% | media sent %" PRIu32 " lost %" PRIu32 " | size level %u, given up %u, strikes %u, probes "
                 "%u | %s%s",
                 classicStateShort(bs.state), (int)bs.phase, bs.peer_name, bs.encrypted, bs.avrcp_connected,
                 bs.sample_rate, (unsigned)d.bitpool, (unsigned)d.link_busy_pct, d.media_sent, d.media_lost,
                 (unsigned)d.tx_size_level, (unsigned)d.tx_flushes, (unsigned)d.size_strikes, (unsigned)d.probes,
                 player_paused() ? "paused: " : "", title);
        return;
    }

    le_audio_status_t s;
    le_audio_get_status(&s);
    ESP_LOGI(kTag, "[LE Audio] link %s, peer %s (%s), paired %d, L/R: main %s, second %s%s, battery %d %%, C6 %s",
             linkName(s.link), s.peer_addr, s.peer_name, s.paired, s.link == LE_AUDIO_LINK_CONNECTED ? "up" : "down",
             s.second_joined ? "up" : "down", s.set_missing ? " (missing)" : "", s.battery_pct, s.coprocessor_fw);
    ESP_LOGI(kTag,
             "stream %s, members %d%s, LC3 %d Hz/%d B, PD %" PRIu32 " us | sdu tx %" PRIu32 " drop %" PRIu32
             " | %s%s",
             phaseName(s.phase), s.members, s.stereo ? " stereo" : "", s.sink_rate_hz, s.sink_octets,
             s.presentation_delay_us, s.tx_sdu, s.tx_dropped, player_paused() ? "paused: " : "", title);
}

void stage(int n, const char* name, ui_stage_state_t state, const char* fmt, ...) __attribute__((format(printf, 4, 5)));
void stage(int n, const char* name, ui_stage_state_t state, const char* fmt, ...)
{
    char msg[160];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    ESP_LOGI(kTag, "STAGE %d/5 %s: %s", n, name, msg);
    ui_stage(n, state, msg);
}

[[noreturn]] void idleForever(const char* why)
{
    ESP_LOGE(kTag, "stopped: %s (status every 10 s; reset to retry)", why);
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(10000));
        ESP_LOGW(kTag, "stopped: %s", why);
    }
}

}  // namespace

extern "C" void app_main(void)
{
    log_sink_usb_init();
    logBoot();

    ESP_ERROR_CHECK(board_tab5_init());
    stage(1, "board", UI_STAGE_OK, "IO expanders set, ESP32-C6 powered");
    ui_start();

    const int64_t t0   = esp_timer_get_time();
    const esp_err_t tr = esp_hosted_cyberdeck_connect(30000);
    const int waitedMs = (int)((esp_timer_get_time() - t0) / 1000);
    if (tr != ESP_OK) {
        stage(2, "transport", UI_STAGE_FAIL, "C6 SDIO transport NOT up after %d ms (%s)", waitedMs, esp_err_to_name(tr));
        idleForever("no SDIO transport to the ESP32-C6");
    }
    stage(2, "transport", UI_STAGE_OK, "C6 SDIO transport up after %d ms", waitedMs);

    const bool sdOk = board_tab5_sd_mount(kSdPath) == ESP_OK;
    if (sdOk) {
        log_sink_sd_start(kSdPath);
    }
    stage(3, "sd", sdOk ? UI_STAGE_OK : UI_STAGE_FAIL, "%s", sdOk ? board_tab5_sd_info() : "NOT mounted - nothing to play");

    le_audio_config_t leCfg   = LE_AUDIO_CONFIG_DEFAULT();
    int identity              = 1;
    const bool haveLeBonds    = bond_store_load(&leCfg.kv, &identity);
    leCfg.identity            = (le_audio_identity_t)identity;
    leCfg.allow_pairing       = kAllowPairing;
    // The connection manager connects, on request: earbuds reconnecting in the background would cut across a
    // Classic connection (one audio device at a time, see devices.h).
    leCfg.auto_connect        = false;
    leCfg.auto_start          = true;
    leCfg.device_name         = "Tab5 LE Audio";

    bt_classic_config_t btcCfg = BT_CLASSIC_CONFIG_DEFAULT();
    const bool haveClassicBond = bond_store_load_classic(&btcCfg.kv);
    btcCfg.device_name         = "Tab5 player";
    btcCfg.legacy_pin          = "0000";
    // The cheapest step to start from; the stream raises the bitpool itself while the link has room (btc_rate.h).
    btcCfg.sbc_bitpool         = 18;
    btcCfg.prefer_44k1         = true;

    stage(4, "bonds", (haveClassicBond || haveLeBonds || kAllowPairing) ? UI_STAGE_OK : UI_STAGE_FAIL,
          "Classic: %s, LE Audio: %d saved (pairing %s)", haveClassicBond ? "remembered" : "none",
          haveLeBonds ? bond_store_count() : 0, kAllowPairing ? "allowed" : "off");

    // The LE Audio host first: it resets the controller and reads the C6 firmware version.
    esp_err_t leErr = ESP_FAIL;
    for (int i = 0; i < 6; i++) {
        leErr = le_audio_init(&leCfg);
        if (leErr == ESP_OK || leErr == ESP_ERR_NOT_SUPPORTED) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    le_audio_status_t st = {};
    le_audio_get_status(&st);

    // Then the Bluetooth Classic host: its HCI receive callback next to the LE host's, and the question to the C6
    // whether its firmware has Soft-BR.
    const esp_err_t btcErr = bt_classic_init(&btcCfg);
    const bool c6SoftBr    = (btcErr == ESP_OK) && bt_classic_c6_supported();
    const char* carried    = c6_update_embedded_version();
    const char* c6Fw       = st.coprocessor_fw[0] != '\0' ? st.coprocessor_fw : "?";

    le_audio_set_volume(CONFIG_TAB5_PLAYER_VOLUME);
    bt_classic_set_volume((uint8_t)((CONFIG_TAB5_PLAYER_VOLUME * 255) / 100));

    if (leErr != ESP_OK && !c6SoftBr) {
        stage(5, "bluetooth", UI_STAGE_FAIL, "C6 firmware %s has neither LE Audio nor Classic - tap \"C6 firmware\" to install %s",
              c6Fw, carried);
    } else if (leErr != ESP_OK) {
        stage(5, "bluetooth", UI_STAGE_FAIL, "LE Audio host: %s (C6 firmware %s) - Bluetooth Classic only", esp_err_to_name(leErr),
              c6Fw);
    } else if (!c6SoftBr) {
        stage(5, "bluetooth", UI_STAGE_FAIL, "C6 firmware %s has no Bluetooth Classic - LE Audio only; tap \"C6 firmware\" to install %s",
              c6Fw, carried);
    } else {
        stage(5, "bluetooth", UI_STAGE_OK, "LE Audio and Bluetooth Classic ready, C6 firmware %s", c6Fw);
    }

    devices::start();
    devices::connectRemembered();

    if (sdOk) {
        player_start(CONFIG_TAB5_PLAYER_MUSIC_DIR);
    }

    const bool trial = runsAsTrial();
    int idleS        = 0;
    for (int tick = 0;; tick++) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        if (trial) {
            bt_classic_status_t bsIdle = {};
            bt_classic_get_status(&bsIdle);
            le_audio_status_t leIdle = {};
            le_audio_get_status(&leIdle);
            const bool busy = bsIdle.state != BT_CLASSIC_IDLE || leIdle.link == LE_AUDIO_LINK_SCANNING ||
                              leIdle.link == LE_AUDIO_LINK_CONNECTING || leIdle.link == LE_AUDIO_LINK_CONNECTED;
            idleS = busy ? 0 : idleS + 1;
            if (idleS >= kTrialIdleLimitS) {
                ESP_LOGW(kTag, "trial image, nothing happened for %d min: restarting into the previous firmware",
                         kTrialIdleLimitS / 60);
                esp_restart();
            }
        }
        if (tick % 5 == 4) {
            logStatus();
        }
    }
}
