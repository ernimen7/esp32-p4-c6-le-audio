// Bond store of the example: the same NVS layout as the Cyberdeck firmware (partition "nvs", namespace "sec",
// keys "bt.bond" / "bt.irk" for LE Audio and "bt.cbond" for Bluetooth Classic - the Classic host's record of
// remembered devices as a hex string; identity in namespace "cfg", key "bt.ident"), so paired earbuds and Classic
// speakers reconnect without re-pairing. The names of the LE devices the player connected are its own: namespace
// "tab5player", key "le.known".
//
// With CONFIG_TAB5_PLAYER_SAVE_BONDS off: READ-ONLY. NVS is opened through a copy of the partition descriptor
// with readonly = true, so the NVS library skips its start-up clean-up writes and esp_partition_write/erase refuse
// every write (ESP_ERR_NOT_ALLOWED). Values are copied to RAM once, at boot, from the main task (internal stack):
// both BT Classic and LE Audio hosts call the store from threads with PSRAM stacks, which must NEVER touch flash.
#include "bond_store.h"

#include <cstdio>
#include <cstring>
#include <string>

#include "esp_log.h"
#include "esp_partition.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

namespace {

constexpr const char* kTag        = "bonds";
constexpr const char* kClassicKey = "bt.cbond";
constexpr const char* kOwnSpace   = "tab5player";
constexpr const char* kKnownKey   = "le.known";
constexpr size_t kKnownMax        = 760;  // eight devices with long names; fits a write request

std::string g_bond, g_irk;  // RAM copies (LE Audio secrets)
bool g_hasBond = false, g_hasIrk = false;

uint8_t g_classicBlob[400] = {};  // RAM copy: up to four remembered devices (address, link key, name)
size_t g_classicLen        = 0;
bool g_hasClassic          = false;

std::string g_knownLe;  // "address|type|name" per line, most recently used first

SemaphoreHandle_t g_lock = nullptr;
bool g_writerReady       = false;

bool readStr(nvs_handle_t h, const char* key, std::string& out)
{
    size_t len = 0;
    if (nvs_get_str(h, key, nullptr, &len) != ESP_OK || len == 0 || len > 1024) {
        return false;
    }
    out.assign(len, '\0');
    if (nvs_get_str(h, key, out.data(), &len) != ESP_OK) {
        out.clear();
        return false;
    }
    out.resize(len > 0 ? len - 1 : 0);  // without the terminating NUL
    return true;
}

int hexNibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
}

// The Classic record from its hex string. False: missing, odd, too long or not hex - nothing is kept.
bool readHexBlob(nvs_handle_t h, const char* key, uint8_t* out, size_t cap, size_t& outLen)
{
    outLen = 0;
    std::string hex;
    if (!readStr(h, key, hex) || hex.empty() || hex.size() % 2 != 0 || hex.size() / 2 > cap) {
        return false;
    }
    for (size_t i = 0; i < hex.size() / 2; i++) {
        const int hi = hexNibble(hex[i * 2]);
        const int lo = hexNibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    outLen = hex.size() / 2;
    return true;
}

bool kvGet(const char* key, char* out, size_t cap, void*)
{
    xSemaphoreTake(g_lock, portMAX_DELAY);
    const std::string* v = nullptr;
    if (std::strcmp(key, "bt.bond") == 0 && g_hasBond) {
        v = &g_bond;
    } else if (std::strcmp(key, "bt.irk") == 0 && g_hasIrk) {
        v = &g_irk;
    }
    const bool ok = v != nullptr && v->size() < cap;
    if (ok) {
        std::memcpy(out, v->c_str(), v->size() + 1);
    }
    xSemaphoreGive(g_lock);
    return ok;
}

// The Classic host's callbacks. It names its record with a key of its own; there is one record, so the key is
// not looked at.
int kvClassicGet(void*, const char*, uint8_t* buf, size_t buf_size, size_t* out_len)
{
    if (!g_lock || !buf) {
        return -1;
    }
    xSemaphoreTake(g_lock, portMAX_DELAY);
    const bool ok = g_hasClassic && g_classicLen > 0 && g_classicLen <= buf_size;
    if (ok) {
        std::memcpy(buf, g_classicBlob, g_classicLen);
        if (out_len) {
            *out_len = g_classicLen;
        }
    }
    xSemaphoreGive(g_lock);
    return ok ? 0 : -1;
}

#if CONFIG_TAB5_PLAYER_SAVE_BONDS
// Writes go to an internal-stack task (flash access from a PSRAM stack asserts while the cache is disabled).
enum class ReqKind : uint8_t { Str = 0, Erase = 1 };

struct WriteReq {
    ReqKind kind;
    char space[16];
    char key[16];
    char value[800];  // the Classic record as hex is the longest: 2 * 392 characters
};
QueueHandle_t g_writes = nullptr;

void writerTask(void*)
{
    WriteReq r;
    for (;;) {
        if (xQueueReceive(g_writes, &r, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        nvs_handle_t h;
        esp_err_t err = nvs_open(r.space, NVS_READWRITE, &h);
        if (err == ESP_OK) {
            if (r.kind == ReqKind::Str) {
                err = nvs_set_str(h, r.key, r.value);
            } else {
                err = nvs_erase_key(h, r.key);
                if (err == ESP_ERR_NVS_NOT_FOUND) {
                    err = ESP_OK;
                }
            }
            if (err == ESP_OK) {
                err = nvs_commit(h);
            }
            nvs_close(h);
        }
        ESP_LOGI(kTag, "saved %s: %s", r.key, esp_err_to_name(err));
        std::memset(&r, 0, sizeof(r));
    }
}

bool kvSet(const char* key, const char* value, void*)
{
    WriteReq r = {};
    if (std::strlen(key) >= sizeof(r.key) || std::strlen(value) >= sizeof(r.value)) {
        return false;
    }
    r.kind = ReqKind::Str;
    std::strcpy(r.space, "sec");
    std::strcpy(r.key, key);
    std::strcpy(r.value, value);
    xSemaphoreTake(g_lock, portMAX_DELAY);
    if (std::strcmp(key, "bt.bond") == 0) {
        g_bond    = value;
        g_hasBond = true;
    } else if (std::strcmp(key, "bt.irk") == 0) {
        g_irk    = value;
        g_hasIrk = true;
    }
    xSemaphoreGive(g_lock);
    const bool ok = g_writes != nullptr && xQueueSend(g_writes, &r, pdMS_TO_TICKS(100)) == pdTRUE;
    std::memset(&r, 0, sizeof(r));
    return ok;
}
#endif

int kvClassicSet(void*, const char*, const uint8_t* val, size_t len)
{
    if (!g_lock || !val || len == 0 || len > sizeof(g_classicBlob)) {
        return -1;
    }
    xSemaphoreTake(g_lock, portMAX_DELAY);
    std::memcpy(g_classicBlob, val, len);
    g_classicLen = len;
    g_hasClassic = true;
    xSemaphoreGive(g_lock);

#if CONFIG_TAB5_PLAYER_SAVE_BONDS
    if (g_writerReady && g_writes != nullptr && len * 2 < sizeof(WriteReq::value)) {
        static const char* const kDigits = "0123456789abcdef";
        WriteReq r = {};
        r.kind     = ReqKind::Str;
        std::strcpy(r.space, "sec");
        std::strcpy(r.key, kClassicKey);
        for (size_t i = 0; i < len; i++) {
            r.value[i * 2]     = kDigits[val[i] >> 4];
            r.value[i * 2 + 1] = kDigits[val[i] & 0x0F];
        }
        xQueueSend(g_writes, &r, pdMS_TO_TICKS(100));
        std::memset(&r, 0, sizeof(r));
    }
#endif
    return 0;
}

int kvClassicErase(void*, const char*)
{
    if (!g_lock) {
        return -1;
    }
    xSemaphoreTake(g_lock, portMAX_DELAY);
    std::memset(g_classicBlob, 0, sizeof(g_classicBlob));
    g_classicLen = 0;
    g_hasClassic = false;
    xSemaphoreGive(g_lock);

#if CONFIG_TAB5_PLAYER_SAVE_BONDS
    if (g_writerReady && g_writes != nullptr) {
        WriteReq r = {};
        r.kind     = ReqKind::Erase;
        std::strcpy(r.space, "sec");
        std::strcpy(r.key, kClassicKey);
        xQueueSend(g_writes, &r, pdMS_TO_TICKS(100));
        std::memset(&r, 0, sizeof(r));
    }
#endif
    return 0;
}

}  // namespace

int bond_store_count(void)
{
    if (g_lock == nullptr) {
        return 0;
    }
    xSemaphoreTake(g_lock, portMAX_DELAY);
    int n = g_hasBond && !g_bond.empty() ? 1 : 0;
    for (char c : g_bond) {
        n += c == ',' ? 1 : 0;
    }
    xSemaphoreGive(g_lock);
    return n;
}

bool bond_store_load(le_audio_kv_t* kv, int* identity)
{
    g_lock    = xSemaphoreCreateMutex();
    *identity = 1;
    if (g_lock == nullptr) {
        ESP_LOGE(kTag, "out of memory - no saved bonds");
        kv->get = nullptr;
        kv->set = nullptr;
        return false;
    }
    kv->get = kvGet;
    kv->set = nullptr;
    kv->ctx = nullptr;
#if CONFIG_TAB5_PLAYER_START_FRESH
    ESP_LOGW(kTag, "TEST START_FRESH: saved bonds ignored, NVS not opened - new pairings stay in RAM");
    return false;
#endif

    const esp_partition_t* p =
        esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, "nvs");
    if (p == nullptr) {
        ESP_LOGW(kTag, "no \"nvs\" partition - no saved bonds");
        return false;
    }
#if CONFIG_TAB5_PLAYER_SAVE_BONDS
    esp_err_t err = nvs_flash_init_partition_ptr(p);  // writable; never erased on errors
    ESP_LOGW(kTag, "bond store WRITABLE (CONFIG_TAB5_PLAYER_SAVE_BONDS): new pairings are saved to NVS");
#else
    static esp_partition_t ro;  // NVS keeps the pointer for the partition's lifetime
    ro          = *p;
    ro.readonly = true;
    esp_err_t err = nvs_flash_init_partition_ptr(&ro);
#endif
    if (err != ESP_OK) {
        ESP_LOGW(kTag, "NVS not readable (%s) - no saved bonds; nothing was changed", esp_err_to_name(err));
        return false;
    }
    nvs_handle_t h;
    if (nvs_open("sec", NVS_READONLY, &h) == ESP_OK) {
        g_hasBond    = readStr(h, "bt.bond", g_bond);
        g_hasIrk     = readStr(h, "bt.irk", g_irk);
        g_hasClassic = readHexBlob(h, kClassicKey, g_classicBlob, sizeof(g_classicBlob), g_classicLen);
        nvs_close(h);
    }
    if (nvs_open(kOwnSpace, NVS_READONLY, &h) == ESP_OK) {
        (void)readStr(h, kKnownKey, g_knownLe);
        nvs_close(h);
    }
    if (nvs_open("cfg", NVS_READONLY, &h) == ESP_OK) {
        int32_t v = 1;
        if (nvs_get_i32(h, "bt.ident", &v) == ESP_OK && v >= 0 && v <= 2) {
            *identity = (int)v;
        }
        nvs_close(h);
    }
#if CONFIG_TAB5_PLAYER_SAVE_BONDS
    g_writes = xQueueCreate(4, sizeof(WriteReq));
    if (g_writes != nullptr && xTaskCreate(writerTask, "bond-wr", 6144, nullptr, 3, nullptr) == pdPASS) {
        kv->set       = kvSet;
        g_writerReady = true;
    } else {
        ESP_LOGE(kTag, "bond writer not started - new pairings stay in RAM");
    }
#else
    nvs_flash_deinit_partition("nvs");
#endif
    ESP_LOGI(kTag, "remembered Classic devices %s, LE Audio bond list %s, own IRK %s, identity mode %d (%s)",
             g_hasClassic ? "found" : "none", g_hasBond ? "found" : "none", g_hasIrk ? "found" : "none", *identity,
             kv->set != nullptr ? "writable" : "read-only");
    return g_hasBond;
}

bool bond_store_load_classic(bt_classic_kv_t* kv)
{
    if (!kv) {
        return false;
    }
    kv->get   = g_lock != nullptr ? kvClassicGet : nullptr;
    kv->set   = g_lock != nullptr ? kvClassicSet : nullptr;
    kv->erase = g_lock != nullptr ? kvClassicErase : nullptr;
    kv->ctx   = nullptr;
    return g_hasClassic;
}

size_t bond_store_known_le(char* out, size_t cap)
{
    if (out == nullptr || cap == 0) {
        return 0;
    }
    out[0] = '\0';
    if (g_lock == nullptr) {
        return 0;
    }
    xSemaphoreTake(g_lock, portMAX_DELAY);
    const size_t n = g_knownLe.size() < cap ? g_knownLe.size() : 0;
    std::memcpy(out, g_knownLe.c_str(), n);
    out[n] = '\0';
    xSemaphoreGive(g_lock);
    return n;
}

void bond_store_set_known_le(const char* text)
{
    if (g_lock == nullptr || text == nullptr || std::strlen(text) > kKnownMax) {
        return;
    }
    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_knownLe = text;
    xSemaphoreGive(g_lock);
#if CONFIG_TAB5_PLAYER_SAVE_BONDS
    if (g_writerReady && g_writes != nullptr) {
        WriteReq r = {};
        r.kind     = ReqKind::Str;
        std::strcpy(r.space, kOwnSpace);
        std::strcpy(r.key, kKnownKey);
        std::snprintf(r.value, sizeof(r.value), "%s", text);
        xQueueSend(g_writes, &r, pdMS_TO_TICKS(100));
    }
#endif
}
