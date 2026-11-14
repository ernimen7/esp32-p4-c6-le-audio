// The player's connection manager - see devices.h.
#include "devices.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

#include "bond_store.h"
#include "bt_classic.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "le_audio.h"
#include "sdkconfig.h"

namespace {

constexpr const char* kTag        = "devices";
constexpr int kMaxFound           = 16;
constexpr int kLeScanS            = 6;
constexpr uint32_t kClassicScanMs = 6500;
constexpr size_t kMaxKnown        = 8;
#if CONFIG_TAB5_PLAYER_ALLOW_PAIRING
constexpr bool kPairing = true;
#else
constexpr bool kPairing = false;
#endif

struct Known {
    std::string addr;
    uint8_t addrType = 1;
    std::string name;
};

struct State {
    std::vector<le_audio_device_t> leScan;
    std::vector<bt_classic_device_t> clScan;
    std::vector<Known> known;  // LE devices the player connected, most recently used first
    btlist::Inputs inputs;
    std::vector<btlist::Row> rows;
    uint32_t gen     = 0;
    bool scanning    = false;
    char action[160] = {};
};
std::mutex g_lock;
State g;  // under g_lock

enum class Cmd : uint8_t { Scan, Choose, Disconnect, Forget, ConnectRemembered, Run };
struct Msg {
    Cmd cmd;
    uint8_t kind;
    char addr[24];
    char name[64];
    void (*fn)();
};
QueueHandle_t g_cmds = nullptr;

void setAction(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void setAction(const char* fmt, ...)
{
    char b[160];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    ESP_LOGI(kTag, "%s", b);
    std::lock_guard<std::mutex> l(g_lock);
    std::snprintf(g.action, sizeof(g.action), "%s", b);
}

std::string fmtAddr(const uint8_t a[6])
{
    char b[24];
    std::snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", a[5], a[4], a[3], a[2], a[1], a[0]);
    return b;
}

bool parseAddr(const char* s, uint8_t out[6])
{
    unsigned v[6];
    if (std::sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x", &v[5], &v[4], &v[3], &v[2], &v[1], &v[0]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        out[i] = (uint8_t)v[i];
    }
    return true;
}

bool classicLinked(const bt_classic_status_t& bs)
{
    return bs.state == BT_CLASSIC_CONNECTING || bs.state == BT_CLASSIC_PAIRING ||
           bs.state == BT_CLASSIC_CONFIGURING || bs.state == BT_CLASSIC_READY || bs.state == BT_CLASSIC_STREAMING;
}

bool leLinked(const le_audio_status_t& st)
{
    return st.link == LE_AUDIO_LINK_CONNECTED || st.link == LE_AUDIO_LINK_CONNECTING;
}

// ---- the names of LE devices the player connected ("address|type|name" lines) ----

std::vector<Known> parseKnown(const char* text)
{
    std::vector<Known> out;
    const char* p = text;
    while (*p != '\0' && out.size() < kMaxKnown) {
        const char* end = std::strchr(p, '\n');
        const std::string line(p, end != nullptr ? (size_t)(end - p) : std::strlen(p));
        p = end != nullptr ? end + 1 : p + line.size();
        const size_t a = line.find('|');
        const size_t b = a == std::string::npos ? a : line.find('|', a + 1);
        if (b == std::string::npos || a == 0) {
            continue;
        }
        Known k;
        k.addr     = line.substr(0, a);
        k.addrType = line[a + 1] == '0' ? 0 : 1;
        k.name     = line.substr(b + 1);
        out.push_back(std::move(k));
    }
    return out;
}

void saveKnownLocked()
{
    std::string text;
    for (const Known& k : g.known) {
        text += k.addr + "|" + (k.addrType == 0 ? "0" : "1") + "|" + k.name + "\n";
    }
    bond_store_set_known_le(text.c_str());
}

// The device goes to the front; an entry with the same address, or the same name (earbuds come back under a new
// private address), is that device.
void rememberLe(const char* addr, int addrType, const char* name)
{
    if (addr == nullptr || addr[0] == '\0') {
        return;
    }
    std::string clean = name != nullptr ? name : "";
    for (char& c : clean) {
        if (c == '|' || c == '\n' || c == '\r') {
            c = ' ';
        }
    }
    std::lock_guard<std::mutex> l(g_lock);
    Known k;
    k.addr = addr;
    k.name = clean;
    for (size_t i = 0; i < g.known.size(); i++) {
        if (g.known[i].addr == k.addr || (!k.name.empty() && g.known[i].name == k.name)) {
            if (i == 0 && g.known[0].addr == k.addr && (k.name.empty() || g.known[0].name == k.name)) {
                return;  // already in front as it is: nothing to write
            }
            k.addrType = g.known[i].addrType;
            if (k.name.empty()) {
                k.name = g.known[i].name;
            }
            g.known.erase(g.known.begin() + (long)i);
            break;
        }
    }
    if (addrType >= 0) {
        k.addrType = (uint8_t)addrType;
    }
    g.known.insert(g.known.begin(), std::move(k));
    if (g.known.size() > kMaxKnown) {
        g.known.resize(kMaxKnown);
    }
    saveKnownLocked();
}

// ---- the list ----

bool sameRows(const std::vector<btlist::Row>& a, const std::vector<btlist::Row>& b)
{
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); i++) {
        const btlist::Row& x = a[i];
        const btlist::Row& y = b[i];
        if (x.kind != y.kind || x.saved != y.saved || x.inRange != y.inRange || x.connected != y.connected ||
            x.connecting != y.connecting || x.audio != y.audio || x.addr != y.addr || x.name != y.name ||
            x.rssi != y.rssi || x.leIndex != y.leIndex) {
            return false;
        }
    }
    return true;
}

void refresh()
{
    le_audio_status_t st = {};
    le_audio_get_status(&st);
    bt_classic_status_t bs = {};
    bt_classic_get_status(&bs);
    bt_classic_saved_t saved[4];
    const int nSaved = bt_classic_saved(saved, 4);

    if (st.link == LE_AUDIO_LINK_CONNECTED && st.peer_addr[0] != '\0') {
        rememberLe(st.peer_addr, -1, st.peer_name);
    }

    std::lock_guard<std::mutex> l(g_lock);
    btlist::Inputs in;
    for (const Known& k : g.known) {
        in.leKnown.push_back({k.addr, k.addrType, k.name});
    }
    for (const le_audio_device_t& d : g.leScan) {
        btlist::LeSeen s;
        s.addr     = d.addr;
        s.addrType = d.addr_type;
        s.label    = d.name;
        s.rssi     = d.rssi;
        s.audio    = d.le_audio;
        s.bonded   = d.bonded;
        in.leSeen.push_back(std::move(s));
    }
    for (int i = 0; i < nSaved; i++) {
        in.clSaved.push_back({fmtAddr(saved[i].addr), saved[i].name, 0, true});
    }
    for (const bt_classic_device_t& d : g.clScan) {
        in.clSeen.push_back({fmtAddr(d.addr), d.name, (int)d.rssi, d.is_audio_sink});
    }
    in.leAddr       = st.peer_addr;
    in.leConnected  = st.link == LE_AUDIO_LINK_CONNECTED;
    in.leConnecting = st.link == LE_AUDIO_LINK_CONNECTING;
    // An idle Classic host still reports the address of the device it used last.
    if (classicLinked(bs)) {
        in.clAddr = fmtAddr(bs.peer_addr);
    }
    in.clConnected  = bs.state == BT_CLASSIC_READY || bs.state == BT_CLASSIC_STREAMING;
    in.clConnecting = classicLinked(bs) && !in.clConnected;

    std::vector<btlist::Row> rows = btlist::build(in);
    if (!sameRows(rows, g.rows)) {
        g.rows = std::move(rows);
        g.gen++;
    }
    g.inputs = std::move(in);
}

void setScanning(bool on)
{
    std::lock_guard<std::mutex> l(g_lock);
    if (g.scanning != on) {
        g.scanning = on;
        g.gen++;
    }
}

// ---- the actions (worker task only) ----

void dropLe()
{
    le_audio_stop();
    le_audio_disconnect();
    for (int i = 0; i < 30; i++) {
        le_audio_status_t st = {};
        le_audio_get_status(&st);
        if (!leLinked(st)) {
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

void dropClassic()
{
    bt_classic_stop();
    bt_classic_disconnect();
    for (int i = 0; i < 60; i++) {
        bt_classic_status_t bs = {};
        bt_classic_get_status(&bs);
        if (!classicLinked(bs)) {
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

int scanLe(int seconds)
{
    le_audio_device_t found[kMaxFound];
    const int raw = le_audio_scan(found, kMaxFound, seconds);
    const int n   = raw > 0 ? raw : 0;
    {
        std::lock_guard<std::mutex> l(g_lock);
        g.leScan.assign(found, found + n);
    }
    refresh();
    return n;
}

void doScan()
{
    bt_classic_status_t bs = {};
    bt_classic_get_status(&bs);
    if (classicLinked(bs)) {
        // An inquiry would end the Classic connection, and the C6 refuses an LE scan while that connection runs.
        setAction("A Bluetooth Classic device is connected - disconnect it to scan");
        return;
    }
    setScanning(true);
    le_audio_status_t st = {};
    le_audio_get_status(&st);
    setAction(st.phase == LE_AUDIO_STREAM_STREAMING ? "Scanning for LE Audio devices (the music may stutter)..."
                                                    : "Scanning for LE Audio devices...");
    const int nLe = scanLe(kLeScanS);

    int nCl = 0;
    le_audio_get_status(&st);
    if (leLinked(st)) {
        // No inquiry next to an LE connection: the same radio work as a page, which locks the C6 up then.
        std::lock_guard<std::mutex> l(g_lock);
        g.clScan.clear();
    } else if (bt_classic_c6_supported()) {
        setAction("Scanning for Bluetooth Classic speakers and headphones...");
        bt_classic_device_t found[kMaxFound];
        const int raw = bt_classic_scan(found, kMaxFound, kClassicScanMs, true);
        nCl           = raw > 0 ? raw : 0;
        std::lock_guard<std::mutex> l(g_lock);
        g.clScan.assign(found, found + nCl);
    }
    setScanning(false);
    refresh();
    setAction("Scan done: %d LE and %d Classic device(s) seen%s", nLe, nCl,
              leLinked(st) ? " (no Classic scan while earbuds are connected)" : "");
}

void connectClassic(const btlist::Row& row)
{
    if (!bt_classic_c6_supported()) {
        setAction("The C6 firmware has no Bluetooth Classic - tap \"C6 firmware\" to install it");
        return;
    }
    le_audio_status_t st = {};
    le_audio_get_status(&st);
    uint8_t addr[6];
    if (leLinked(st) || !parseAddr(row.addr.c_str(), addr)) {
        setAction("Not connecting %.63s: the LE Audio device is still connected", row.name.c_str());
        return;
    }
    if (!row.saved && !kPairing) {
        setAction("Pairing is off (CONFIG_TAB5_PLAYER_ALLOW_PAIRING) - remembered devices only");
        return;
    }
    bt_classic_device_t dev = {};
    bool seen               = false;
    {
        std::lock_guard<std::mutex> l(g_lock);
        for (const bt_classic_device_t& d : g.clScan) {
            if (std::memcmp(d.addr, addr, 6) == 0) {
                dev  = d;
                seen = true;
            }
        }
    }
    setAction("%s %.63s (up to 30 s)...", row.saved ? "Connecting" : "Pairing", row.name.c_str());
    // A remembered device that was not in the scan is paged with the clock offset kept with its key.
    const esp_err_t e = seen ? bt_classic_connect_device(&dev) : bt_classic_connect_addr(addr, 0, 0);
    setAction("%.63s: %s", row.name.c_str(),
              e == ESP_OK ? "connected" : row.saved ? "no answer - is it switched on?" : "pairing failed");
}

void connectLe(const btlist::Row& row)
{
    le_audio_device_t dev = {};
    bool have             = false;
    {
        std::lock_guard<std::mutex> l(g_lock);
        if (row.leIndex >= 0 && row.leIndex < (int)g.leScan.size() && row.addr == g.leScan[row.leIndex].addr) {
            dev  = g.leScan[row.leIndex];
            have = true;
        }
    }
    if (!have) {
        // Remembered, but not in the last scan: look for it now (earbuds advertise once the case is open).
        setAction("Looking for %.39s...", row.name.c_str());
        scanLe(5);
        std::lock_guard<std::mutex> l(g_lock);
        for (const btlist::Row& r : g.rows) {
            if (r.kind == btlist::Kind::Le && r.saved && r.leIndex >= 0 && r.leIndex < (int)g.leScan.size() &&
                (r.addr == row.addr || r.name == row.name)) {
                dev  = g.leScan[r.leIndex];
                have = true;
                break;
            }
        }
    }
    if (!have) {
        setAction("%.39s is not in range - open the case or switch it on", row.name.c_str());
        return;
    }
    if (!dev.bonded && !kPairing) {
        setAction("Pairing is off (CONFIG_TAB5_PLAYER_ALLOW_PAIRING) - remembered devices only");
        return;
    }
    setAction(dev.bonded ? "Connecting %.39s..." : "Pairing %.39s (confirm on the device if it asks)...",
              row.name.c_str());
    const esp_err_t e = le_audio_connect_device(&dev);
    if (e == ESP_OK) {
        rememberLe(dev.addr, dev.addr_type, row.name.c_str());
    }
    setAction("%.39s: %s", row.name.c_str(),
              e == ESP_OK                     ? "connected"
              : e == ESP_ERR_INVALID_RESPONSE ? "it rejected the saved key - forget it and pair again"
                                              : "no connection");
}

// The row as the list has it now: a request waits in the queue and the list may have changed meanwhile.
bool currentRow(const Msg& m, btlist::Row& row, btlist::Inputs& in)
{
    std::lock_guard<std::mutex> l(g_lock);
    in = g.inputs;
    for (const btlist::Row& r : g.rows) {
        if ((uint8_t)r.kind == m.kind && r.addr == m.addr) {
            row = r;
            return true;
        }
    }
    return false;
}

void doChoose(const Msg& m)
{
    refresh();
    btlist::Row row;
    btlist::Inputs in;
    if (!currentRow(m, row, in)) {
        setAction("The list changed - choose %.39s again", m.name);
        return;
    }
    const btlist::Plan plan = btlist::choose(row, in);
    if (plan.step != btlist::Plan::Step::Connect) {
        return;  // connected (the screen asks about disconnecting) or already connecting
    }
    if (plan.dropLe) {
        setAction("Disconnecting the LE Audio device first...");
        dropLe();
    }
    if (plan.dropClassic) {
        setAction("Disconnecting the Bluetooth Classic device first...");
        dropClassic();
    }
    if (row.kind == btlist::Kind::Classic) {
        connectClassic(row);
    } else {
        connectLe(row);
    }
    refresh();
}

void doDisconnect()
{
    setAction("Disconnecting...");
    dropLe();
    dropClassic();
    refresh();
    setAction("Disconnected");
}

void doForget(const Msg& m)
{
    refresh();
    btlist::Row row;
    btlist::Inputs in;
    if (!currentRow(m, row, in) || !row.saved) {
        setAction("%.39s is not a remembered device", m.name);
        return;
    }
    esp_err_t e = ESP_OK;
    if (row.kind == btlist::Kind::Classic) {
        uint8_t addr[6];
        if (!parseAddr(row.addr.c_str(), addr)) {
            return;
        }
        if (row.connected || row.connecting) {
            dropClassic();
        }
        e = bt_classic_forget(addr);
    } else {
        if (row.connected || row.connecting) {
            dropLe();
        }
        // The key answers to the address in the scan and to the one the player remembered (an older private one).
        std::vector<std::string> addrs = {row.addr};
        {
            std::lock_guard<std::mutex> l(g_lock);
            for (size_t i = 0; i < g.known.size();) {
                if (g.known[i].addr == row.addr || g.known[i].name == row.name) {
                    if (g.known[i].addr != row.addr) {
                        addrs.push_back(g.known[i].addr);
                    }
                    g.known.erase(g.known.begin() + (long)i);
                } else {
                    i++;
                }
            }
            saveKnownLocked();
        }
        e = ESP_ERR_NOT_FOUND;
        for (const std::string& a : addrs) {
            if (le_audio_forget(a.c_str()) == ESP_OK) {
                e = ESP_OK;
            }
        }
    }
    refresh();
    setAction(e == ESP_OK ? "Forgot %.39s" : "%.39s: no saved key was found (removed from the list)", row.name.c_str());
}

void doConnectRemembered()
{
    // Earbuds first: with them connected no Classic page follows, which is the order the radio needs.
    bool anyLe = bond_store_count() > 0;
    {
        std::lock_guard<std::mutex> l(g_lock);
        anyLe = anyLe || !g.known.empty();
    }
    if (anyLe) {
        setAction("Looking for remembered earbuds...");
        if (le_audio_connect_bonded(5) == ESP_OK) {
            refresh();
            setAction("Earbuds connected");
            return;
        }
    }
    le_audio_status_t st = {};
    le_audio_get_status(&st);
    bt_classic_saved_t saved[1];
    if (leLinked(st) || !bt_classic_c6_supported() || bt_classic_saved(saved, 1) < 1) {
        refresh();
        setAction(anyLe ? "Remembered earbuds not in range - choose a device or tap Scan"
                        : "No remembered device - tap Scan (speaker in pairing mode, earbuds case open)");
        return;
    }
    setAction("Connecting %.63s...", saved[0].name);
    const esp_err_t e = bt_classic_connect_bonded();
    refresh();
    setAction("%.63s: %s", saved[0].name, e == ESP_OK ? "connected" : "no answer - choose a device or tap Scan");
}

void worker(void*)
{
    Msg m;
    for (;;) {
        if (xQueueReceive(g_cmds, &m, pdMS_TO_TICKS(500)) != pdTRUE) {
            refresh();  // links come and go by themselves too (a speaker switched off, earbuds put in the case)
            continue;
        }
        switch (m.cmd) {
            case Cmd::Scan: doScan(); break;
            case Cmd::Choose: doChoose(m); break;
            case Cmd::Disconnect: doDisconnect(); break;
            case Cmd::Forget: doForget(m); break;
            case Cmd::ConnectRemembered: doConnectRemembered(); break;
            case Cmd::Run:
                dropLe();
                dropClassic();
                refresh();
                m.fn();
                break;
        }
    }
}

bool post(Cmd cmd, const btlist::Row* row = nullptr)
{
    Msg m = {};
    m.cmd = cmd;
    if (row != nullptr) {
        m.kind = (uint8_t)row->kind;
        std::snprintf(m.addr, sizeof(m.addr), "%s", row->addr.c_str());
        std::snprintf(m.name, sizeof(m.name), "%s", row->name.c_str());
    }
    return g_cmds != nullptr && xQueueSend(g_cmds, &m, 0) == pdTRUE;
}

}  // namespace

namespace devices {

void start()
{
    char text[800];
    bond_store_known_le(text, sizeof(text));
    {
        std::lock_guard<std::mutex> l(g_lock);
        g.known = parseKnown(text);
    }
    g_cmds = xQueueCreate(4, sizeof(Msg));
    if (g_cmds == nullptr || xTaskCreate(worker, "devices", 12288, nullptr, 4, nullptr) != pdPASS) {
        ESP_LOGE(kTag, "worker not started - the device list does not work");
        return;
    }
    refresh();
}

View view()
{
    std::lock_guard<std::mutex> l(g_lock);
    View v;
    v.rows     = g.rows;
    v.gen      = g.gen;
    v.scanning = g.scanning;
    std::memcpy(v.action, g.action, sizeof(v.action));
    return v;
}

bool scan()
{
    return post(Cmd::Scan);
}

bool choose(const btlist::Row& row)
{
    return post(Cmd::Choose, &row);
}

bool disconnect()
{
    return post(Cmd::Disconnect);
}

bool forget(const btlist::Row& row)
{
    return post(Cmd::Forget, &row);
}

bool connectRemembered()
{
    return post(Cmd::ConnectRemembered);
}

bool runDisconnected(void (*fn)())
{
    Msg m = {};
    m.cmd = Cmd::Run;
    m.fn  = fn;
    return fn != nullptr && g_cmds != nullptr && xQueueSend(g_cmds, &m, 0) == pdTRUE;
}

}  // namespace devices
