#pragma once
// The device list of the player, the pure part (no ESP-IDF, no LVGL; host test in test/host/test_bt_list.cpp).
//
// As on a phone: remembered devices on top, found ones below, LE Audio and Bluetooth Classic in one list. The
// radio serves one audio device at a time, so choosing a device other than the connected one disconnects that
// one first (see "Known limitations" in the README: paging a Classic device while an LE connection exists locks
// the ESP32-C6 up).

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace btlist {

enum class Kind : uint8_t { Le, Classic };

// An LE device the application remembers (name and address of what it connected), most recently used first.
struct LeKnown {
    std::string addr;
    uint8_t addrType = 1;
    std::string name;
};

// A device from the last LE scan.
struct LeSeen {
    std::string addr;
    uint8_t addrType = 0;
    std::string label;      // the name to show
    int rssi     = -127;
    bool audio   = false;   // advertises LE Audio
    bool bonded  = false;   // the LE host has its key - also when it shows up under a new private address
};

// A Classic device: remembered (most recently used first) or from the last inquiry.
struct ClDevice {
    std::string addr;
    std::string name;
    int rssi   = 0;
    bool audio = false;  // a speaker or headphones by its class of device
};

struct Inputs {
    std::vector<LeKnown> leKnown;
    std::vector<LeSeen> leSeen;
    std::vector<ClDevice> clSaved;
    std::vector<ClDevice> clSeen;
    std::string leAddr;  // the device the LE host is connected or connecting to
    bool leConnected  = false;
    bool leConnecting = false;
    std::string clAddr;  // the same for Classic
    bool clConnected  = false;
    bool clConnecting = false;
};

struct Row {
    Kind kind       = Kind::Le;
    bool saved      = false;
    bool inRange    = false;  // seen in the last scan
    bool connected  = false;
    bool connecting = false;
    bool audio      = false;
    std::string addr;
    uint8_t addrType = 0;
    std::string name;
    int rssi    = -127;
    int leIndex = -1;  // position in Inputs::leSeen; -1 = not in the scan
};

// The rows of the list. First the remembered ones: connected, then seen in the scan, then the rest. Then the found
// ones: audio devices by signal strength, the others after them by signal strength. The second earbud of a
// remembered pair gets no row of its own; of the Classic devices found only audio devices are listed.
std::vector<Row> build(const Inputs& in);
// How many of the first rows are remembered devices.
size_t savedCount(const std::vector<Row>& rows);

// What to do when a row is chosen.
struct Plan {
    enum class Step : uint8_t {
        None,           // already connecting
        AskDisconnect,  // connected: ask whether to disconnect
        Connect,        // connect (remembered) or pair (found)
    };
    Step step        = Step::None;
    bool dropLe      = false;  // disconnect the LE device first
    bool dropClassic = false;  // disconnect the Classic device first
};
Plan choose(const Row& row, const Inputs& in);

}  // namespace btlist
