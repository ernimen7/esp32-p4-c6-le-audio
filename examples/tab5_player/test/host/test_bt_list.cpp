// Host test of the player's device list (main/bt_list_model.cpp): remembered devices on top, found ones below,
// LE Audio and Classic together; switching between devices. A program of its own: sh test/host/run.sh.

#include "bt_list_model.h"

#include <cstdio>

namespace {

int g_ok = 0, g_fail = 0;

void expect(bool cond, const char* what)
{
    if (cond) {
        g_ok++;
    } else {
        g_fail++;
        std::printf("  FAIL %s\n", what);
    }
}

using namespace btlist;

// The row, or an empty one when the list is shorter: the test has to fail on its expectation, not on a read past
// the end.
Row at(const std::vector<Row>& rows, size_t i)
{
    return i < rows.size() ? rows[i] : Row{};
}

LeSeen seen(const char* addr, const char* label, int rssi, bool audio = false, bool bonded = false)
{
    LeSeen s;
    s.addr   = addr;
    s.label  = label;
    s.rssi   = rssi;
    s.audio  = audio;
    s.bonded = bonded;
    return s;
}

void testEmpty()
{
    std::printf("empty list\n");
    const Inputs in;
    const auto rows = build(in);
    expect(rows.empty() && savedCount(rows) == 0, "nothing remembered and nothing found - an empty list");
}

void testSavedOnTop()
{
    std::printf("remembered on top, LE and Classic together\n");
    Inputs in;
    in.leKnown = {{"AA:00:00:00:00:01", 1, "Earbuds"}, {"AA:00:00:00:00:02", 1, "Old earbuds"}};
    in.clSaved = {{"CC:00:00:00:00:01", "Speaker", 0, true}, {"CC:00:00:00:00:02", "Soundbar", 0, true}};
    in.leSeen  = {seen("EE:00:00:00:00:09", "Lamp", -40), seen("AA:00:00:00:00:01", "Earbuds", -60, true, true),
                  seen("EE:00:00:00:00:08", "Other earbuds", -70, true)};
    in.clSeen  = {{"CC:00:00:00:00:02", "Soundbar", -55, true}, {"DD:00:00:00:00:07", "New speaker", -65, true},
                  {"DD:00:00:00:00:08", "Phone", -30, false}};
    const auto rows = build(in);
    expect(savedCount(rows) == 4, "four remembered: two LE and two Classic");
    expect(at(rows, 0).name == "Earbuds" && at(rows, 0).kind == Kind::Le && at(rows, 0).saved && at(rows, 0).inRange &&
               at(rows, 0).leIndex == 1 && at(rows, 0).rssi == -60,
           "remembered LE device seen in the scan - with its signal strength and its place in the scan");
    expect(at(rows, 1).name == "Soundbar" && at(rows, 1).kind == Kind::Classic && at(rows, 1).inRange &&
               at(rows, 1).rssi == -55,
           "remembered Classic device seen in the scan - right after it");
    expect(at(rows, 2).name == "Old earbuds" && !at(rows, 2).inRange && at(rows, 2).leIndex == -1 &&
               at(rows, 2).addr == "AA:00:00:00:00:02",
           "remembered LE device out of range stays on the list under its saved address");
    expect(at(rows, 3).name == "Speaker" && at(rows, 3).kind == Kind::Classic && !at(rows, 3).inRange,
           "remembered Classic device out of range");
    expect(rows.size() == 7, "found: two audio devices and the lamp; the Classic phone is left out");
    expect(at(rows, 4).name == "New speaker" && at(rows, 4).kind == Kind::Classic && !at(rows, 4).saved &&
               at(rows, 4).audio,
           "found audio devices first, by signal strength (-65 before -70)");
    expect(at(rows, 5).name == "Other earbuds" && at(rows, 5).kind == Kind::Le && at(rows, 5).leIndex == 2,
           "LE and Classic mixed in one part");
    expect(at(rows, 6).name == "Lamp" && !at(rows, 6).audio, "other BLE devices last, although the signal is stronger");
}

void testConnectedFirst()
{
    std::printf("connected at the very top\n");
    Inputs in;
    in.leKnown     = {{"AA:00:00:00:00:01", 1, "Earbuds"}};
    in.clSaved     = {{"CC:00:00:00:00:01", "Speaker", 0, true}};
    in.leSeen      = {seen("AA:00:00:00:00:01", "Earbuds", -60, true, true)};
    in.clAddr      = "CC:00:00:00:00:01";
    in.clConnected = true;
    auto rows      = build(in);
    expect(at(rows, 0).name == "Speaker" && at(rows, 0).connected && at(rows, 1).name == "Earbuds" &&
               !at(rows, 1).connected,
           "the connected Classic speaker before the earbuds in range, although it was not in the scan");
    in.clConnected  = false;
    in.clConnecting = true;
    rows            = build(in);
    expect(at(rows, 0).name == "Speaker" && at(rows, 0).connecting && !at(rows, 0).connected,
           "a device that is connecting is on top too");
    in.clConnecting = false;
    in.clAddr.clear();
    in.leAddr      = "AA:00:00:00:00:01";
    in.leConnected = true;
    rows           = build(in);
    expect(at(rows, 0).name == "Earbuds" && at(rows, 0).connected, "connected LE earbuds on top");
    // Connected without a scan (after a restart): the remembered entry carries the connection.
    in.leSeen.clear();
    rows = build(in);
    expect(at(rows, 0).name == "Earbuds" && at(rows, 0).connected && !at(rows, 0).inRange,
           "connected earbuds show as connected without any scan");
}

void testEarbudPair()
{
    std::printf("a pair of earbuds and a changing private address\n");
    Inputs in;
    in.leKnown = {{"AA:00:00:00:00:01", 1, "Buds"}};
    // Both earbuds under new private addresses: the LE host recognised the key (bonded), the address differs from
    // the saved one.
    in.leSeen  = {seen("70:00:00:00:00:11", "Buds", -50, true, true), seen("70:00:00:00:00:22", "Buds", -58, true, true)};
    auto rows  = build(in);
    expect(rows.size() == 1 && savedCount(rows) == 1, "a pair of earbuds is one row, not three");
    expect(at(rows, 0).addr == "70:00:00:00:00:11" && at(rows, 0).inRange && at(rows, 0).leIndex == 0,
           "the row connects under the address from the scan (the saved private address is out of date)");
    in.leAddr      = "70:00:00:00:00:22";
    in.leConnected = true;
    rows           = build(in);
    expect(rows.size() == 1 && at(rows, 0).connected, "connected through the second earbud: still one row, connected");
    // A key in the LE host without an entry of the application: remembered all the same.
    in        = Inputs{};
    in.leSeen = {seen("70:00:00:00:00:33", "Stray", -50, true, true)};
    rows      = build(in);
    expect(savedCount(rows) == 1 && at(rows, 0).name == "Stray", "a device with a key in the LE host is remembered");
    // A remembered device without a name shows its address.
    in         = Inputs{};
    in.leKnown = {{"AA:00:00:00:00:05", 1, ""}};
    rows       = build(in);
    expect(at(rows, 0).name == "AA:00:00:00:00:05", "no name - the address");
}

void testChoose()
{
    std::printf("choosing a row\n");
    Inputs in;
    in.leKnown = {{"AA:00:00:00:00:01", 1, "Earbuds"}};
    in.clSaved = {{"CC:00:00:00:00:01", "Speaker", 0, true}, {"CC:00:00:00:00:02", "Soundbar", 0, true}};
    auto rows  = build(in);
    Plan p     = choose(at(rows, 0), in);
    expect(p.step == Plan::Step::Connect && !p.dropLe && !p.dropClassic, "nothing is connected - just connect");

    in.leAddr      = "AA:00:00:00:00:01";
    in.leConnected = true;
    rows           = build(in);
    p              = choose(at(rows, 0), in);
    expect(p.step == Plan::Step::AskDisconnect, "choosing the connected device - ask whether to disconnect");
    p = choose(at(rows, 1), in);
    expect(at(rows, 1).kind == Kind::Classic && p.step == Plan::Step::Connect && p.dropLe && !p.dropClassic,
           "a Classic speaker while LE earbuds are connected: disconnect LE first");

    in.leConnected = false;
    in.leAddr.clear();
    in.clAddr      = "CC:00:00:00:00:01";
    in.clConnected = true;
    rows           = build(in);
    Row le;
    Row other;
    for (const Row& r : rows) {
        if (r.kind == Kind::Le) {
            le = r;
        } else if (r.addr == "CC:00:00:00:00:02") {
            other = r;
        }
    }
    p = choose(le, in);
    expect(p.step == Plan::Step::Connect && p.dropClassic && !p.dropLe,
           "LE earbuds while a speaker is connected: disconnect Classic first");
    p = choose(other, in);
    expect(p.step == Plan::Step::Connect && !p.dropClassic && !p.dropLe,
           "another Classic device: the Classic host closes the previous Classic connection itself");

    in.clConnected  = false;
    in.clConnecting = true;
    rows            = build(in);
    p               = choose(at(rows, 0), in);
    expect(at(rows, 0).connecting && p.step == Plan::Step::None, "a device that is connecting right now - nothing new");
    p = choose(le, in);
    expect(p.step == Plan::Step::Connect && p.dropClassic, "a Classic connection in progress is ended before LE too");
}

}  // namespace

int main()
{
    testEmpty();
    testSavedOnTop();
    testConnectedFirst();
    testEarbudPair();
    testChoose();
    std::printf("bt_list: %d ok, %d failed\n", g_ok, g_fail);
    return g_fail == 0 ? 0 : 1;
}
