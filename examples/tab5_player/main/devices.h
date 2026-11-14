#pragma once
// The player's connection manager: one place that scans, connects, disconnects and forgets, for LE Audio and
// Bluetooth Classic alike, and keeps the list the screen shows (bt_list_model.h).
//
// It exists because the two hosts do not know each other and the radio serves one audio device at a time: paging
// a Classic device while an LE connection exists locks the ESP32-C6 up. Every Bluetooth action of the player goes
// through the one worker task here, which disconnects the other kind before it connects.
#include <cstdint>
#include <vector>

#include "bt_list_model.h"

namespace devices {

struct View {
    std::vector<btlist::Row> rows;
    uint32_t gen     = 0;      // changes whenever the rows change
    bool scanning    = false;
    char action[160] = {};     // what the manager is doing or did last
};

// Starts the worker task. Call once, after le_audio_init() and bt_classic_init().
void start();
View view();

// Requests for the worker; false = it has too much waiting already (try again).
bool scan();                          // LE scan, then a Classic inquiry
bool choose(const btlist::Row& row);  // connect this device; what is connected is disconnected first
bool disconnect();                    // the connected device
bool forget(const btlist::Row& row);  // a remembered device: its key and its place on the list
bool connectRemembered();             // at start: remembered earbuds if they answer, else the last Classic device
// Runs fn on the worker with nothing connected and no other Bluetooth action beside it (the C6 firmware update).
bool runDisconnected(void (*fn)());

}  // namespace devices
