// The device list of the player, the pure part - see bt_list_model.h.

#include "bt_list_model.h"

namespace btlist {

namespace {

Row leRow(const LeSeen& s, int index)
{
    Row r;
    r.kind     = Kind::Le;
    r.inRange  = true;
    r.audio    = s.audio;
    r.addr     = s.addr;
    r.addrType = s.addrType;
    r.name     = s.label.empty() ? s.addr : s.label;
    r.rssi     = s.rssi;
    r.leIndex  = index;
    return r;
}

void markLinked(Row& r, const Inputs& in, bool le)
{
    r.connected  = le ? in.leConnected : in.clConnected;
    r.connecting = !r.connected && (le ? in.leConnecting : in.clConnecting);
}

// Order of the remembered rows: connected or connecting, seen in the scan, the rest.
int savedRank(const Row& r)
{
    return (r.connected || r.connecting) ? 0 : r.inRange ? 1 : 2;
}

bool savedClassic(const Inputs& in, const std::string& addr)
{
    for (const ClDevice& c : in.clSaved) {
        if (c.addr == addr) {
            return true;
        }
    }
    return false;
}

}  // namespace

std::vector<Row> build(const Inputs& in)
{
    std::vector<Row> saved;
    std::vector<bool> used(in.leSeen.size(), false);
    const bool leLinked = in.leConnected || in.leConnecting;

    // Remembered LE devices in the application's order (most recently used first). An entry looks for itself in
    // the scan by address, and when the earbuds show up under a new private address - by the key the LE host
    // recognised and the name.
    for (const LeKnown& k : in.leKnown) {
        int at = -1;
        for (size_t i = 0; i < in.leSeen.size() && at < 0; i++) {
            if (!used[i] && in.leSeen[i].addr == k.addr) {
                at = (int)i;
            }
        }
        for (size_t i = 0; i < in.leSeen.size() && at < 0; i++) {
            if (!used[i] && in.leSeen[i].bonded && !k.name.empty() && in.leSeen[i].label == k.name) {
                at = (int)i;
            }
        }
        Row r;
        if (at >= 0) {
            used[at] = true;
            r        = leRow(in.leSeen[at], at);
            if (in.leSeen[at].label.empty() && !k.name.empty()) {
                r.name = k.name;
            }
        } else {
            r.addr     = k.addr;
            r.addrType = k.addrType;
            r.name     = k.name.empty() ? k.addr : k.name;
            r.audio    = true;  // the application remembers what it connected: earbuds
        }
        r.saved = true;
        if (leLinked && (r.addr == in.leAddr || k.addr == in.leAddr)) {
            markLinked(r, in, true);
        }
        saved.push_back(std::move(r));
    }
    // Devices from the scan with a key in the LE host that the application has no entry for. The second earbud of
    // a pair has the name of a row that is already there - it gets none of its own.
    for (size_t i = 0; i < in.leSeen.size(); i++) {
        const LeSeen& s = in.leSeen[i];
        if (used[i] || !s.bonded) {
            continue;
        }
        used[i]           = true;
        const bool linked = leLinked && s.addr == in.leAddr;
        Row* twin         = nullptr;
        for (Row& have : saved) {
            if (have.kind == Kind::Le && !s.label.empty() && have.name == s.label) {
                twin = &have;
            }
        }
        if (twin != nullptr) {
            if (linked) {
                markLinked(*twin, in, true);
            }
            continue;
        }
        Row r   = leRow(s, (int)i);
        r.saved = true;
        if (linked) {
            markLinked(r, in, true);
        }
        saved.push_back(std::move(r));
    }
    // Remembered Classic devices, most recently used first.
    for (const ClDevice& c : in.clSaved) {
        Row r;
        r.kind  = Kind::Classic;
        r.saved = true;
        r.audio = true;
        r.addr  = c.addr;
        r.name  = c.name.empty() ? c.addr : c.name;
        for (const ClDevice& s : in.clSeen) {
            if (s.addr == c.addr) {
                r.inRange = true;
                r.rssi    = s.rssi;
            }
        }
        if (c.addr == in.clAddr) {
            markLinked(r, in, false);
        }
        saved.push_back(std::move(r));
    }

    // The result: the remembered rows by group (every row is in one, the order inside a group stays)...
    std::vector<Row> rows;
    for (int rank = 0; rank < 3; rank++) {
        for (Row& r : saved) {
            if (savedRank(r) == rank) {
                rows.push_back(std::move(r));
            }
        }
    }
    // ...then the found ones: from each group (audio, others) the strongest of those not yet added. A Classic
    // inquiry sees everything that is discoverable (phones, laptops, TV sets): only its audio devices are listed.
    std::vector<Row> found;
    for (size_t i = 0; i < in.leSeen.size(); i++) {
        if (!used[i]) {
            found.push_back(leRow(in.leSeen[i], (int)i));
        }
    }
    for (const ClDevice& s : in.clSeen) {
        if (!s.audio || savedClassic(in, s.addr)) {
            continue;
        }
        Row r;
        r.kind    = Kind::Classic;
        r.inRange = true;
        r.audio   = true;
        r.addr    = s.addr;
        r.name    = s.name.empty() ? s.addr : s.name;
        r.rssi    = s.rssi;
        if (s.addr == in.clAddr) {
            markLinked(r, in, false);
        }
        found.push_back(std::move(r));
    }
    std::vector<bool> taken(found.size(), false);
    for (int audio = 1; audio >= 0; audio--) {
        for (;;) {
            int best = -1;
            for (size_t i = 0; i < found.size(); i++) {
                if (!taken[i] && (int)found[i].audio == audio && (best < 0 || found[i].rssi > found[best].rssi)) {
                    best = (int)i;
                }
            }
            if (best < 0) {
                break;
            }
            taken[best] = true;
            rows.push_back(std::move(found[best]));
        }
    }
    return rows;
}

size_t savedCount(const std::vector<Row>& rows)
{
    size_t n = 0;
    for (const Row& r : rows) {
        n += r.saved ? 1 : 0;
    }
    return n;
}

Plan choose(const Row& row, const Inputs& in)
{
    Plan p;
    if (row.connected) {
        p.step = Plan::Step::AskDisconnect;
        return p;
    }
    if (row.connecting) {
        return p;
    }
    p.step = Plan::Step::Connect;
    if (row.kind == Kind::Classic) {
        // Paging a Classic device while an LE connection exists locks the coprocessor up (trial of 2026-11-11).
        // A previous Classic connection is closed by the Classic host itself.
        p.dropLe = in.leConnected || in.leConnecting;
    } else {
        p.dropClassic = in.clConnected || in.clConnecting;
    }
    return p;
}

}  // namespace btlist
