// Touch UI of tab5_player on the M5Stack Tab5 display (1280 x 720 landscape): one list of audio devices for
// Bluetooth LE Audio and Bluetooth Classic - remembered ones on top, found ones below - next to the state of the
// connection and the player. Tap a device to connect it (what is connected is disconnected first), tap the
// connected one to disconnect, hold a remembered one to forget it.
#include "ui.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "bsp/display.h"
#include "bsp/m5stack_tab5.h"
#include "bt_classic.h"
#include "c6_update.h"
#include "devices.h"
#include "esp_log.h"
#include "esp_lvgl_port.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "le_audio.h"
#include "lvgl.h"
#include "player.h"
#include "sdkconfig.h"

namespace {

constexpr const char* kTag = "ui";
constexpr int kStages      = 5;
const char* const kStageNames[kStages] = {"Board", "C6 link", "SD card", "Bonds", "Bluetooth"};

enum class StageState : uint8_t { Pending, Ok, Fail };

#if CONFIG_TAB5_PLAYER_ALLOW_PAIRING
constexpr bool kPairing = true;
#else
constexpr bool kPairing = false;
#endif

// What the poll task reads from the hosts and the player, for the LVGL timer to show.
struct Snapshot {
    StageState stage[kStages]   = {};
    char stageText[kStages][80] = {};
    bt_classic_status_t bst     = {};
    bt_classic_diag_t diag      = {};
    le_audio_status_t st        = {};
    bool cisValid[2]            = {};
    le_audio_cis_stats_t cis[2] = {};
    char title[64]              = {};
    uint32_t posMs              = 0;
    bool paused                 = false;
    int volume                  = CONFIG_TAB5_PLAYER_VOLUME;
    char note[160]              = {};  // a message of the screen itself (C6 update); empty = the manager's action
};

std::mutex g_lock;
Snapshot g_snap;  // under g_lock
int g_volumePct = CONFIG_TAB5_PLAYER_VOLUME;  // under g_lock; one volume for both kinds of device

struct Widgets {
    lv_obj_t* boot;
    lv_obj_t* listTitle;
    lv_obj_t* list;
    lv_obj_t* output;
    lv_obj_t* detail[2];
    lv_obj_t* player;
    lv_obj_t* counters;
    lv_obj_t* action;
    uint32_t listGen = UINT32_MAX;
    std::vector<btlist::Row> rows;  // the rows on the screen (LVGL thread only)
} w;

void setNote(const char* text)
{
    std::lock_guard<std::mutex> l(g_lock);
    std::snprintf(g_snap.note, sizeof(g_snap.note), "%s", text);
}

bool classicUp(const bt_classic_status_t& s)
{
    return s.state == BT_CLASSIC_READY || s.state == BT_CLASSIC_STREAMING;
}

const char* classicPhaseName(bt_classic_stream_phase_t p)
{
    switch (p) {
        case BTC_PHASE_NONE: return "idle";
        case BTC_PHASE_INQUIRY: return "inquiry";
        case BTC_PHASE_NAME_RESOLVE: return "reading names";
        case BTC_PHASE_PAGING: return "paging";
        case BTC_PHASE_LMP_SETUP: return "link setup";
        case BTC_PHASE_AUTH_PAIRING: return "pairing";
        case BTC_PHASE_ENCRYPTING: return "encrypting";
        case BTC_PHASE_SDP: return "service search";
        case BTC_PHASE_AVDTP_CFG: return "stream setup";
        case BTC_PHASE_AVDTP_OPEN: return "stream open";
        case BTC_PHASE_STREAMING: return "streaming";
        default: return "?";
    }
}

const char* sideName(uint32_t loc, int member)
{
    if (loc & 0x1) {
        return "Left";
    }
    if (loc & 0x2) {
        return "Right";
    }
    return member == 0 ? "Earbud 1" : "Earbud 2";
}

const char* earbudState(const le_audio_status_t& s, int i)
{
    if (s.member_streaming[i]) {
        return "streaming";
    }
    if (i == 0) {
        return s.link == LE_AUDIO_LINK_CONNECTED ? "connected" : "down";
    }
    if (s.second_joined) {
        return "connected";
    }
    return s.set_missing ? "down (joining)" : "down";
}

// ---- questions before disconnecting and forgetting ----

struct Ask {
    btlist::Row row;
    bool forget = false;
    lv_obj_t* box = nullptr;
};

void onAskYes(lv_event_t* e)
{
    Ask* a = static_cast<Ask*>(lv_event_get_user_data(e));
    const bool ok = a->forget ? devices::forget(a->row) : devices::disconnect();
    if (!ok) {
        setNote("Busy - try again");
    }
    lv_msgbox_close(a->box);
    delete a;
}

void onAskNo(lv_event_t* e)
{
    Ask* a = static_cast<Ask*>(lv_event_get_user_data(e));
    lv_msgbox_close(a->box);
    delete a;
}

void ask(const btlist::Row& row, bool forget)
{
    Ask* a    = new Ask{row, forget, nullptr};
    a->box    = lv_msgbox_create(nullptr);
    char b[200];
    std::snprintf(b, sizeof(b),
                  forget ? "Forget %.63s?\n\nIts pairing key is erased. To use it again, pair it again."
                         : "Disconnect %.63s?",
                  row.name.c_str());
    lv_msgbox_add_title(a->box, forget ? "Forget device" : "Disconnect");
    lv_obj_t* text = lv_msgbox_add_text(a->box, b);
    lv_obj_set_style_text_font(text, &lv_font_montserrat_20, 0);
    lv_obj_set_width(a->box, LV_PCT(50));
    lv_obj_t* yes = lv_msgbox_add_footer_button(a->box, forget ? "Forget" : "Disconnect");
    lv_obj_add_event_cb(yes, onAskYes, LV_EVENT_CLICKED, a);
    lv_obj_t* no = lv_msgbox_add_footer_button(a->box, "Cancel");
    lv_obj_add_event_cb(no, onAskNo, LV_EVENT_CLICKED, a);
}

// ---- the device list ----

void onRowTap(lv_event_t* e)
{
    const size_t i = (size_t)(intptr_t)lv_event_get_user_data(e);
    if (i >= w.rows.size()) {
        return;
    }
    const btlist::Row& row = w.rows[i];
    setNote("");
    if (row.connected) {
        ask(row, false);
    } else if (!devices::choose(row)) {
        setNote("Busy - try again");
    }
}

void onRowHold(lv_event_t* e)
{
    const size_t i = (size_t)(intptr_t)lv_event_get_user_data(e);
    if (i < w.rows.size() && w.rows[i].saved) {
        setNote("");
        ask(w.rows[i], true);
    }
}

void applyList(const devices::View& v)
{
    if (v.gen == w.listGen) {
        return;
    }
    w.listGen = v.gen;
    w.rows    = v.rows;
    lv_obj_clean(w.list);
    lv_label_set_text(w.listTitle, v.scanning ? "Devices - scanning..." : "Devices");

    if (w.rows.empty()) {
        lv_list_add_text(w.list, v.scanning ? "Looking for devices..."
                                            : "Nothing yet - tap Scan (speaker in pairing mode, earbuds case open)");
        return;
    }
    size_t saved = 0;
    for (const btlist::Row& r : w.rows) {
        saved += r.saved ? 1 : 0;
    }
    char b[200];
    for (size_t i = 0; i < w.rows.size(); i++) {
        const btlist::Row& r = w.rows[i];
        if (i == 0 && saved > 0) {
            lv_list_add_text(w.list, "REMEMBERED");
        }
        if (i == saved) {
            lv_list_add_text(w.list, "FOUND NEARBY");
        }
        char rssi[24] = "";
        if (r.inRange && r.rssi != 0 && r.rssi > -127) {
            std::snprintf(rssi, sizeof(rssi), "   %d dBm", r.rssi);
        }
        std::snprintf(b, sizeof(b), "%.63s   %s%s%s", r.name.c_str(),
                      r.kind == btlist::Kind::Classic ? "Classic" : r.audio ? "LE Audio" : "BLE", rssi,
                      r.connected ? "   connected" : r.connecting ? "   connecting..." : "");
        lv_obj_t* btn = lv_list_add_button(
            w.list, r.connected ? LV_SYMBOL_OK : r.connecting ? LV_SYMBOL_REFRESH : r.audio ? LV_SYMBOL_AUDIO
                                                                                            : LV_SYMBOL_BLUETOOTH,
            b);
        lv_obj_set_height(btn, 60);
        lv_obj_set_style_text_font(btn, &lv_font_montserrat_20, 0);
        if (r.connected) {
            lv_obj_set_style_text_color(btn, lv_palette_main(LV_PALETTE_GREEN), 0);
        } else if (!r.audio) {
            lv_obj_set_style_text_color(btn, lv_palette_main(LV_PALETTE_GREY), 0);
        }
        // A remembered device can always be chosen; a new one only if it is an audio device and pairing is allowed.
        if (!(r.saved || (r.audio && kPairing))) {
            lv_obj_add_state(btn, LV_STATE_DISABLED);
            continue;
        }
        lv_obj_add_event_cb(btn, onRowTap, LV_EVENT_SHORT_CLICKED, (void*)(intptr_t)i);
        lv_obj_add_event_cb(btn, onRowHold, LV_EVENT_LONG_PRESSED, (void*)(intptr_t)i);
    }
}

// ---- the state on the right ----

void applyState(const Snapshot& s)
{
    char b[360];
    // Boot: a failed stage with its reason; while all are fine, one line of marks.
    size_t pos = 0;
    b[0]       = '\0';
    bool bad   = false;
    for (int i = 0; i < kStages; i++) {
        if (s.stage[i] == StageState::Fail) {
            pos += (size_t)std::snprintf(b + pos, sizeof(b) - pos, "%s" LV_SYMBOL_CLOSE " %s: %.79s", pos ? "\n" : "",
                                         kStageNames[i], s.stageText[i]);
            bad = true;
        }
    }
    if (!bad) {
        for (int i = 0; i < kStages; i++) {
            pos += (size_t)std::snprintf(b + pos, sizeof(b) - pos, "%s%s %s", pos ? "   " : "",
                                         s.stage[i] == StageState::Ok ? LV_SYMBOL_OK : "...", kStageNames[i]);
        }
    }
    lv_label_set_text(w.boot, b);
    lv_obj_set_style_text_color(w.boot, lv_palette_main(bad ? LV_PALETTE_RED : LV_PALETTE_GREY), 0);

    if (classicUp(s.bst) || s.bst.state == BT_CLASSIC_CONNECTING || s.bst.state == BT_CLASSIC_PAIRING ||
        s.bst.state == BT_CLASSIC_CONFIGURING) {
        std::snprintf(b, sizeof(b), "Output: %.63s   (Bluetooth Classic, %s)",
                      s.bst.peer_name[0] != '\0' ? s.bst.peer_name : "speaker", classicPhaseName(s.bst.phase));
        lv_label_set_text(w.output, b);
        std::snprintf(b, sizeof(b), "SBC %lu Hz, bitpool %u   link %s   remote control %s",
                      (unsigned long)s.bst.sample_rate, (unsigned)s.diag.bitpool,
                      s.bst.encrypted ? "encrypted" : "not encrypted", s.bst.avrcp_connected ? "connected" : "off");
        lv_label_set_text(w.detail[0], b);
        std::snprintf(b, sizeof(b), "Radio time used %u %%   packets sent %lu, lost %lu", (unsigned)s.diag.link_busy_pct,
                      (unsigned long)s.diag.media_sent, (unsigned long)s.diag.media_lost);
        lv_label_set_text(w.detail[1], b);
        static const char* const kSize[] = {"3-slot", "1-slot", "short 1-slot"};
        std::snprintf(b, sizeof(b),
                      "Packets %s (given up %u time(s)), answered %lu of %lu pairs, resent %lu, buffer %u frames, "
                      "underruns %lu, last disconnect 0x%02X",
                      s.diag.tx_size_level < 3 ? kSize[s.diag.tx_size_level] : "?", (unsigned)s.diag.tx_flushes,
                      (unsigned long)s.diag.rx_sync_ok, (unsigned long)s.diag.slots_tx,
                      (unsigned long)s.diag.tx_retrans, (unsigned)s.diag.pcm_fill_frames,
                      (unsigned long)s.diag.pcm_underruns, (unsigned)s.bst.last_disconnect_reason);
        lv_label_set_text(w.counters, b);
    } else if (s.st.link == LE_AUDIO_LINK_CONNECTED || s.st.link == LE_AUDIO_LINK_CONNECTING) {
        std::snprintf(b, sizeof(b), "Output: %.39s   (LE Audio, %s%s)",
                      s.st.peer_name[0] != '\0' ? s.st.peer_name : "earbuds",
                      s.st.phase == LE_AUDIO_STREAM_STREAMING     ? "streaming"
                      : s.st.phase == LE_AUDIO_STREAM_CONFIGURING ? "starting the stream"
                      : s.st.link == LE_AUDIO_LINK_CONNECTING     ? "connecting"
                                                                  : "connected",
                      s.st.stereo ? ", stereo" : "");
        lv_label_set_text(w.output, b);
        for (int i = 0; i < 2; i++) {
            char extra[64] = "";
            if (i == 0 && s.st.battery_pct >= 0) {
                std::snprintf(extra, sizeof(extra), "   battery %d %%", s.st.battery_pct);
            }
            char loss[48] = "";
            if (s.cisValid[i]) {
                std::snprintf(loss, sizeof(loss), "   air loss %.2f %%", (double)s.cis[i].air_loss_pct);
            }
            std::snprintf(b, sizeof(b), "%s: %s%s%s", sideName(s.st.member_location[i], i), earbudState(s.st, i), extra,
                          loss);
            lv_label_set_text(w.detail[i], b);
        }
        std::snprintf(b, sizeof(b), "LC3 %d Hz / %d B, SDU sent %lu, dropped %lu (no credit %lu, deadline %lu)%s%.95s",
                      s.st.sink_rate_hz, s.st.sink_octets, (unsigned long)s.st.tx_sdu, (unsigned long)s.st.tx_dropped,
                      (unsigned long)s.st.drop_no_credit, (unsigned long)s.st.drop_deadline,
                      s.st.last_error[0] != '\0' ? "\nLast error: " : "", s.st.last_error);
        lv_label_set_text(w.counters, b);
    } else {
        lv_label_set_text(w.output, "Output: none - choose a device from the list");
        std::snprintf(b, sizeof(b), "ESP32-C6 firmware %s, Bluetooth Classic %s",
                      s.st.coprocessor_fw[0] != '\0' ? s.st.coprocessor_fw : "?",
                      s.bst.c6_soft_br_ready ? "available" : "NOT available (tap \"C6 firmware\")");
        lv_label_set_text(w.detail[0], b);
        lv_label_set_text(w.detail[1], "");
        lv_label_set_text(w.counters, "");
    }

    const uint32_t sec = s.posMs / 1000;
    std::snprintf(b, sizeof(b), "%s %.63s   %02u:%02u   volume %d %%", s.paused ? LV_SYMBOL_PAUSE : LV_SYMBOL_PLAY,
                  s.title[0] != '\0' ? s.title : "(no track)", (unsigned)(sec / 60), (unsigned)(sec % 60), s.volume);
    lv_label_set_text(w.player, b);
}

void applySnapshot(lv_timer_t*)
{
    Snapshot s;
    {
        std::lock_guard<std::mutex> l(g_lock);
        s = g_snap;
    }
    const devices::View v = devices::view();
    applyState(s);
    lv_label_set_text(w.action, s.note[0] != '\0' ? s.note : v.action);
    applyList(v);
}

void pollTask(void*)
{
    for (int tick = 0;; tick++) {
        bt_classic_status_t bst = {};
        bt_classic_get_status(&bst);
        bt_classic_diag_t diag = {};
        bt_classic_get_diag(&diag);
        le_audio_status_t st = {};
        le_audio_get_status(&st);

        bool cisValid[2]            = {};
        le_audio_cis_stats_t cis[2] = {};
        const bool cisTick = (tick % 2 == 0) && st.phase == LE_AUDIO_STREAM_STREAMING;
        for (int i = 0; cisTick && i < 2; i++) {
            cisValid[i] = le_audio_get_cis_stats(i, &cis[i]) == ESP_OK;
        }
        char title[64];
        player_title(title, sizeof(title));
        {
            std::lock_guard<std::mutex> l(g_lock);
            g_snap.bst  = bst;
            g_snap.diag = diag;
            g_snap.st   = st;
            if (cisTick) {
                for (int i = 0; i < 2; i++) {
                    g_snap.cisValid[i] = cisValid[i];
                    g_snap.cis[i]      = cis[i];
                }
            } else if (st.phase != LE_AUDIO_STREAM_STREAMING) {
                g_snap.cisValid[0] = g_snap.cisValid[1] = false;
            }
            std::snprintf(g_snap.title, sizeof(g_snap.title), "%s", title);
            g_snap.posMs  = player_position_ms();
            g_snap.paused = player_paused();
            // The speaker's own volume buttons move the Classic volume: follow them while it is connected.
            if (classicUp(bst)) {
                g_volumePct = ((int)bt_classic_get_volume() * 100 + 127) / 255;
            }
            g_snap.volume = g_volumePct;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

void adjustVolume(int deltaPct)
{
    int pct;
    {
        std::lock_guard<std::mutex> l(g_lock);
        g_volumePct   = std::clamp(g_volumePct + deltaPct, 0, 100);
        g_snap.volume = g_volumePct;
        pct           = g_volumePct;
    }
    le_audio_set_volume(pct);
    bt_classic_set_volume((uint8_t)((pct * 255) / 100));
}

// ---- C6 firmware update ----

void installProgress(int pct)
{
    char b[128];
    std::snprintf(b, sizeof(b), "Installing C6 firmware %s: %d %% (do not power off)", c6_update_embedded_version(), pct);
    setNote(b);
}

// On the connection manager's worker, with nothing connected (devices::runDisconnected).
void installC6()
{
    installProgress(0);
    const esp_err_t e = c6_update_install(installProgress);
    char b[140];
    if (e == ESP_OK) {
        std::snprintf(b, sizeof(b), "C6 firmware %s installed - the Tab5 restarts in 8 s", c6_update_embedded_version());
        setNote(b);
        ESP_LOGW(kTag, "%s", b);
        vTaskDelay(pdMS_TO_TICKS(8000));
        esp_restart();
    }
    std::snprintf(b, sizeof(b), "C6 update not done (%s)%s - the C6 keeps its firmware", esp_err_to_name(e),
                  e == ESP_ERR_INVALID_STATE ? ": its new firmware is still being verified, try in a minute" : "");
    setNote(b);
    ESP_LOGW(kTag, "%s", b);
}

void onC6Install(lv_event_t* e)
{
    lv_msgbox_close(static_cast<lv_obj_t*>(lv_event_get_user_data(e)));
    if (!devices::runDisconnected(installC6)) {
        setNote("Busy - try again");
    }
}

void onC6Close(lv_event_t* e)
{
    lv_msgbox_close(static_cast<lv_obj_t*>(lv_event_get_user_data(e)));
}

void showC6Box()
{
    le_audio_status_t st   = {};
    bt_classic_status_t bs = {};
    le_audio_get_status(&st);
    bt_classic_get_status(&bs);
    const char* embedded = c6_update_embedded_version();
    char b[320];
    std::snprintf(b, sizeof(b),
                  "ESP32-C6 now: %s (%s)\nIn this player: %s (LE Audio + Bluetooth Classic)\n\n"
                  "Installing takes about 30 s, then the Tab5 restarts. "
                  "If the new firmware does not work, the C6 goes back to its previous firmware by itself.",
                  st.coprocessor_fw[0] != '\0' ? st.coprocessor_fw : "unknown",
                  bs.c6_soft_br_ready ? "with Bluetooth Classic" : "no Bluetooth Classic",
                  embedded[0] != '\0' ? embedded : "none (build problem)");
    lv_obj_t* box = lv_msgbox_create(nullptr);
    lv_msgbox_add_title(box, "C6 firmware");
    lv_obj_t* text = lv_msgbox_add_text(box, b);
    lv_obj_set_style_text_font(text, &lv_font_montserrat_20, 0);
    lv_obj_set_width(box, LV_PCT(64));
    if (embedded[0] != '\0') {
        lv_obj_t* ok = lv_msgbox_add_footer_button(box, "Install");
        lv_obj_add_event_cb(ok, onC6Install, LV_EVENT_CLICKED, box);
    }
    lv_obj_t* close = lv_msgbox_add_footer_button(box, "Close");
    lv_obj_add_event_cb(close, onC6Close, LV_EVENT_CLICKED, box);
}

// ---- buttons and layout ----

void onButton(lv_event_t* e)
{
    setNote("");
    switch ((intptr_t)lv_event_get_user_data(e)) {
        case 0:
            if (!devices::scan()) {
                setNote("Busy - try again");
            }
            break;
        case 1:
            if (!devices::disconnect()) {
                setNote("Busy - try again");
            }
            break;
        case 2: player_toggle_pause(); break;
        case 3: player_next(); break;
        case 4: adjustVolume(-10); break;
        case 5: adjustVolume(+10); break;
        case 6: showC6Box(); break;
        default: break;
    }
}

lv_obj_t* label(lv_obj_t* parent, const lv_font_t* font)
{
    lv_obj_t* l = lv_label_create(parent);
    lv_obj_set_style_text_font(l, font, 0);
    lv_obj_set_width(l, LV_PCT(100));
    lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
    lv_label_set_text(l, "");
    return l;
}

lv_obj_t* panel(lv_obj_t* parent, int widthPct)
{
    lv_obj_t* p = lv_obj_create(parent);
    lv_obj_set_size(p, LV_PCT(widthPct), LV_PCT(100));
    lv_obj_set_flex_flow(p, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(p, 6, 0);
    return p;
}

void build()
{
    lv_obj_t* scr = lv_screen_active();
    lv_obj_set_style_bg_color(scr, lv_color_hex(0x101418), 0);
    lv_obj_set_style_text_color(scr, lv_color_hex(0xE8E8E8), 0);
    lv_obj_set_flex_flow(scr, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_all(scr, 12, 0);
    lv_obj_set_style_pad_row(scr, 8, 0);

    lv_obj_t* h = label(scr, &lv_font_montserrat_28);
    lv_label_set_text(h, "tab5_player - LE Audio + Bluetooth Classic");
    const esp_partition_t* run = esp_ota_get_running_partition();
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    if (run != nullptr) {
        esp_ota_get_state_partition(run, &state);
    }
    w.boot = label(scr, &lv_font_montserrat_14);
    if (state == ESP_OTA_IMG_PENDING_VERIFY) {
        lv_obj_t* fw = label(scr, &lv_font_montserrat_14);
        lv_label_set_text(fw, "Firmware on trial: not confirmed, a reset returns to the previous firmware");
        lv_obj_set_style_text_color(fw, lv_palette_main(LV_PALETTE_ORANGE), 0);
    }

    lv_obj_t* row = lv_obj_create(scr);
    lv_obj_set_width(row, LV_PCT(100));
    lv_obj_set_flex_grow(row, 1);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_column(row, 10, 0);
    lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(row, 0, 0);
    lv_obj_set_style_pad_all(row, 0, 0);

    lv_obj_t* left = panel(row, 49);
    w.listTitle    = label(left, &lv_font_montserrat_20);
    w.list         = lv_list_create(left);
    lv_obj_set_width(w.list, LV_PCT(100));
    lv_obj_set_flex_grow(w.list, 1);
    lv_obj_t* hint = label(left, &lv_font_montserrat_14);
    lv_label_set_text(hint, "Tap: connect / switch   -   tap the connected one: disconnect   -   hold: forget");
    lv_obj_set_style_text_color(hint, lv_palette_main(LV_PALETTE_GREY), 0);

    lv_obj_t* right = panel(row, 49);
    w.output        = label(right, &lv_font_montserrat_20);
    w.detail[0]     = label(right, &lv_font_montserrat_20);
    w.detail[1]     = label(right, &lv_font_montserrat_20);
    w.player        = label(right, &lv_font_montserrat_20);
    w.counters      = label(right, &lv_font_montserrat_14);

    lv_obj_t* buttons = lv_obj_create(scr);
    lv_obj_set_size(buttons, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(buttons, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_style_pad_column(buttons, 10, 0);
    lv_obj_set_style_pad_row(buttons, 8, 0);
    lv_obj_set_style_bg_opa(buttons, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(buttons, 0, 0);
    const char* names[] = {"Scan", "Disconnect", "Play / Pause", "Next", "Vol -", "Vol +", "C6 firmware"};
    for (int i = 0; i < 7; i++) {
        lv_obj_t* btn = lv_button_create(buttons);
        lv_obj_set_height(btn, 64);
        lv_obj_set_style_pad_hor(btn, 22, 0);
        lv_obj_add_event_cb(btn, onButton, LV_EVENT_CLICKED, (void*)(intptr_t)i);
        lv_obj_t* t = lv_label_create(btn);
        lv_obj_set_style_text_font(t, &lv_font_montserrat_20, 0);
        lv_label_set_text(t, names[i]);
        lv_obj_center(t);
    }
    w.action = label(scr, &lv_font_montserrat_20);
    lv_timer_create(applySnapshot, 500, nullptr);
}

}  // namespace

void ui_start(void)
{
    bsp_reset_tp();
    constexpr int32_t kStripLines = 48;
    bsp_display_cfg_t cfg         = {.lvgl_port_cfg = ESP_LVGL_PORT_INIT_CONFIG(),
                                     .buffer_size   = BSP_LCD_V_RES * kStripLines,
                                     .double_buffer = true,
                                     .flags         = {
                                         .buff_dma    = true,
                                         .buff_spiram = true,
                                         .sw_rotate   = true,
                                     }};
    cfg.lvgl_port_cfg.task_stack    = 12 * 1024;
    cfg.lvgl_port_cfg.task_affinity = 0;
    lv_display_t* disp              = bsp_display_start_with_config(&cfg);
    if (disp == nullptr) {
        ESP_LOGE(kTag, "display / touch did not start - serial log only");
        return;
    }
    bsp_display_lock(0);
    lv_display_set_rotation(disp, LV_DISPLAY_ROTATION_90);
    lv_display_add_event_cb(
        disp,
        [](lv_event_t* e) {
            auto* a = static_cast<lv_area_t*>(lv_event_get_param(e));
            a->x1 &= ~1;
            a->y1 &= ~3;
            a->x2 |= 1;
            a->y2 |= 3;
        },
        LV_EVENT_INVALIDATE_AREA, nullptr);
    build();
    bsp_display_unlock();
    bsp_display_brightness_set(80);
    if (xTaskCreate(pollTask, "ui-poll", 6144, nullptr, 3, nullptr) != pdPASS) {
        ESP_LOGE(kTag, "UI poll task not started - live values do not work");
    }
    ESP_LOGI(kTag, "display and touch ready");
}

void ui_stage(int n, ui_stage_state_t state, const char* detail)
{
    if (n < 1 || n > kStages) {
        return;
    }
    std::lock_guard<std::mutex> l(g_lock);
    g_snap.stage[n - 1] = state == UI_STAGE_OK     ? StageState::Ok
                          : state == UI_STAGE_FAIL ? StageState::Fail
                                                   : StageState::Pending;
    std::snprintf(g_snap.stageText[n - 1], sizeof(g_snap.stageText[0]), "%s", detail != nullptr ? detail : "");
}
