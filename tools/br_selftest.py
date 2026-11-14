#!/usr/bin/env python3
"""Read the Soft-BR bench self-test of the ESP32-C6 guard-test image through the P4 and name what works.

    python tools/br_selftest.py HOST [--watch S] [--poll S]
    python tools/br_selftest.py HOST --box

The self-test image (c6_firmware: `sh build.sh --guard-test`, CONFIG_CYBERDECK_BR_SELFTEST) first opens lone RX
windows on BLE advertising channel 37, one per RX recipe of the adapter, then runs a 10.24 s GIAC inquiry every
16 s by itself. It writes its results and counters to the CIS trace (vendor HCI 0xFC30 subcommand 10, kinds
0xB0..0xBF, see c6_firmware/main/br_c6_core.c). This tool polls a P4 firmware that serves that trace as
GET /api/c6/cis/trace?from=N and prints every new record, what the probe windows received per recipe, the health
of the C6 and a verdict naming the first stage that did not work. The C6 keeps only the last 32 trace entries, so
the tool must run while the test image runs (it rolls back by itself after its trial time: 7 minutes). A restart
of the C6 in the middle of the trial is followed: the counters of the runs are added up.

HOST (or env LE_AUDIO_HOST) and the bearer token (--token or env LE_AUDIO_OTA_TOKEN) are the same as for
tools/c6_ota.py. The token is never printed. Nothing is written to the device.

Verdict levels, in the order the stages depend on each other:
  NOT_RUNNING     no self-test records: wrong image, Bluetooth off on the P4, or the crash fuse disabled Soft-BR
  ENGINE_REFUSED  the engine did not accept HCI_Inquiry
  SCHED_REJECTS   the BLE scheduler refused every raw slot (r_ble_lll_sched_insert)
  SLOTS_NOT_RUN   slots were queued but none executed (all skipped or pre-empted)
  RX_NEVER_RETURNS  TX slots complete, but no RX slot is ever reported back, so the engine stalls
  NO_ANSWER       TX and RX slots run, but no sync word was ever matched
  SYNC_ONLY       a device answered (sync word matched), but no FHS packet decoded
  INQUIRY_WORKS   at least one device was found (address and class of device decoded from its FHS)
  CONNECTION_WORKS  the device found was paged and a baseband connection came up (Connection Complete, status 0)

Exit codes: 0 = INQUIRY_WORKS or CONNECTION_WORKS, 2 = any other verdict, 1 = the P4 did not answer.

--box reads the trace once and prints the black box of the C6 instead: how it started and, if a crash is on record
in its flash, where the chip was (panic reason, pc, return addresses from the stack, the last characters the ROM
printed - a failed assertion of the Bluetooth controller names its line and function there). Every image from 1.5.2
on writes these records when Soft-BR starts, a regular one too. Exit codes: 0 = start record read, 2 = none in the
trace, 1 = the P4 did not answer.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

KIND_ENGINE, KIND_RADIO, KIND_RESULT, KIND_CAPTURE, KIND_STARTED = 0xB0, 0xB1, 0xB2, 0xB3, 0xB4
KIND_STUCK, KIND_PROBE, KIND_COLLECT = 0xB5, 0xB6, 0xB7
KIND_PROBE_RESULT, KIND_HEALTH, KIND_PREVIOUS, KIND_BOOT = 0xB8, 0xB9, 0xBA, 0xBB
KIND_CRASH, KIND_CRASH_MORE, KIND_CRASH_REASON, KIND_CAPTURE_TIME = 0xBC, 0xBD, 0xBE, 0xBF
# panic_exception_t of ESP-IDF 5.5 (esp_private/panic_internal.h).
PANIC_EXCEPTIONS = {0: "debug exception", 1: "interrupt watchdog", 2: "task watchdog", 3: "abort", 4: "fault"}
NO_PANIC_RECORD = 0xFF
# br_c6_rx_recipe_t (c6_firmware/main/br_c6.h): how the adapter fills in an RX schedule item.
RECIPES = {0: "stock", 1: "window, short item", 2: "window", 3: "word 7 only"}
# BR_AT_* (same header): where the LL task was inside the adapter.
WHERE = {0: "outside the adapter", 1: "in the adapter", 2: "in r_ble_lll_sched_insert",
         3: "in r_ble_lll_sched_delete_by_sm_num_and_type", 4: "in r_ble_phy_disable",
         5: "in the engine's completion handler"}
# esp_reset_reason_t of ESP-IDF 5.5.
RESET_REASONS = {0: "unknown", 1: "power on or reset pin", 2: "external pin", 3: "software", 4: "panic",
                 5: "interrupt watchdog", 6: "task watchdog", 7: "other watchdog", 8: "deep sleep", 9: "brownout",
                 10: "SDIO", 11: "USB", 12: "JTAG", 13: "eFuse", 14: "power glitch", 15: "CPU lockup"}
ADV_TYPES = {0: "ADV_IND", 1: "ADV_DIRECT_IND", 2: "ADV_NONCONN_IND", 3: "SCAN_REQ", 4: "SCAN_RSP",
             5: "CONNECT_IND", 6: "ADV_SCAN_IND"}
PROBE_CHANNEL = 37  # the probes listen on 2402 MHz with the advertising access address
KIND_WIFI, KIND_WIFI_SEEN = 0xC0, 0xC1  # Wi-Fi tap of the same image (c6_firmware/main/wifi_tap.c)
KIND_LE_HOST = 0xC2  # the host's LE scan / connect commands, which the image keeps apart from Soft-BR work
KIND_HCI_EVENT, KIND_ST_COMMAND, KIND_PAGE_PROGRESS, KIND_CIPHER_TIME = 0xC3, 0xC4, 0xC5, 0xC6
KIND_PACKET_TIMING = 0xC7
KIND_DATA_PROBE = 0xC8
KIND_CRASH_IMAGE, KIND_CRASH_STACK, KIND_CRASH_ROM_TAIL = 0xC9, 0xCA, 0xCB
KIND_ABORT_TEST = 0xCC  # BR_ST_ABORT_TEST: pages given up half way
KIND_POP_HELD = 0xCD  # executed Soft-BR items kept from the controller's recycle pass (any image)
DATA_PROBE_FRAMES = {0: "one 3-slot packet of 164 bytes", 1: "one 1-slot packet of 23 bytes",
                     2: "one 1-slot packet of 25 bytes", 3: "one 1-slot packet of 27 bytes"}
E0_SAMPLE_START = 0xE06F9994  # 94 99 6f e0: the key stream of the specification's fourth E0 sample set begins so
ENGINE_STATES = {0: "idle", 1: "inquiry", 2: "page", 3: "page response", 4: "new connection", 5: "connected"}
HCI_EVENTS = {0x01: "Inquiry Complete", 0x03: "Connection Complete", 0x05: "Disconnection Complete",
              0x07: "Remote Name Request Complete", 0x0E: "Command Complete", 0x0F: "Command Status",
              0x13: "Number Of Completed Packets", 0xFF: "vendor event"}
HCI_STATUS = {0x00: "success", 0x02: "unknown connection", 0x04: "page timeout", 0x08: "connection timeout",
              0x0B: "connection already exists", 0x0C: "command disallowed", 0x12: "invalid parameters",
              0x13: "remote user ended the connection", 0x16: "ended by the local host", 0x22: "LMP response timeout",
              0x3E: "connection failed to be established"}
ST_COMMANDS = {1: "inquiry cancel", 2: "create connection", 3: "disconnect", 4: "nothing: it listens for ID packets"}
LE_COMMANDS = {0x200C: "LE Set Scan Enable", 0x200D: "LE Create Connection", 0x2042: "LE Set Extended Scan Enable",
               0x2043: "LE Extended Create Connection"}
STUCK_STEPS = {0: "seen", 1: "scheduler delete", 2: "radio stop"}
AUTH_ALGS = {0: "open", 1: "shared key", 2: "FT", 3: "SAE"}
# IEEE 802.11 status codes that matter when a station cannot log in.
WIFI_STATUS = {0: "success", 1: "unspecified failure", 13: "algorithm not supported", 14: "wrong sequence number",
               15: "challenge failure", 16: "timeout", 17: "access point full", 30: "try again later",
               31: "management frame protection policy", 37: "request declined", 40: "invalid element",
               43: "invalid AKMP", 45: "invalid RSN capabilities", 53: "invalid PMKID",
               76: "anti-clogging token required", 77: "finite cyclic group not supported",
               123: "unknown password identifier", 126: "SAE hash-to-element", 127: "SAE-PK"}
WATCH_DEFAULT_S = 600.0
POLL_DEFAULT_S = 4.0


def _s8(v: int) -> int:
    v &= 0xFF
    return v - 256 if v > 127 else v


def ble_whiten(data: bytes, channel: int) -> bytes:
    """BLE data whitening (x^7 + x^4 + 1, seeded with the channel index); applying it twice gives the input."""
    lfsr = int(f"{channel & 0xFF:08b}"[::-1], 2) | 2  # the register one step early: bit-reversed channel, then 1
    out = bytearray()
    for byte in data:
        for bit in range(8):
            if lfsr & 0x80:
                lfsr ^= 0x11
                byte ^= 1 << bit
            lfsr = (lfsr << 1) & 0xFF
        out.append(byte)
    return bytes(out)


def sync_word(lap: int) -> int:
    """The 64-bit sync word of an access code for a LAP (Core Specification Vol 2 Part B 6.3.3), first transmitted bit
    lowest: 34 parity bits of the (64,30) code, the LAP, the 6-bit Barker extension."""
    pn, poly = 0x83848D96BBCC54FC, 0x0000000585713DA9
    lap &= 0xFFFFFF
    info = ((0x13 if lap & 0x800000 else 0x2C) << 24 | lap) ^ (pn >> 34)
    rem = info << 34
    for bit in range(63, 33, -1):
        if rem >> bit & 1:
            rem ^= poly << (bit - 34)
    return (info << 34 | rem & 0x3FFFFFFFF) ^ pn


def adv_header(data: bytes) -> tuple[int, int] | None:
    """(PDU type, length) when the first two bytes are a legal legacy advertising channel header."""
    if len(data) < 2:
        return None
    kind, length = data[0] & 0x0F, data[1]
    return (kind, length) if kind in ADV_TYPES and 6 <= length <= 37 else None


def probe_reading(data: bytes) -> str:
    """What the eight bytes after the access address of a probe window are. The adapter switches the hardware
    whitening off, so a real advertising packet arrives whitened; both readings are tried."""
    if not any(data):
        return "nothing received"
    for label, plain in (("after de-whitening", ble_whiten(data, PROBE_CHANNEL)), ("as received", data)):
        h = adv_header(plain)
        if h:
            return (f"BLE advertising packet {label}: {ADV_TYPES[h[0]]}, {h[1]} payload bytes "
                    f"({plain.hex(' ')})")
    return f"bytes received, not a BLE advertising header ({data.hex(' ')})"


def _text(words: list[int]) -> str:
    """Characters packed four to a little-endian word, up to the first NUL."""
    raw = b"".join((w & 0xFFFFFFFF).to_bytes(4, "little") for w in words)
    return raw.split(b"\0", 1)[0].decode("ascii", "replace")


def decode(entry: dict) -> dict | None:
    """One element of the trace "entries" list -> a Soft-BR self-test record, None for any other trace kind."""
    v = entry.get("v")
    if not isinstance(v, list) or len(v) < 4:
        return None
    kind, code, cis, acl = entry.get("kind_id"), entry.get("code", 0), entry.get("cis", 0), entry.get("acl", 0)
    if kind == KIND_ENGINE:
        return {"what": "engine", "state": code, "results": cis, "round": acl, "slots_tx": v[0], "slots_rx": v[1],
                "rx_sync_ok": v[2] & 0xFFFF, "slots_skipped": v[2] >> 16, "hec_ok": v[3] & 0xFF,
                "hec_err": (v[3] >> 8) & 0xFF, "crc_ok": (v[3] >> 16) & 0xFF, "crc_err": (v[3] >> 24) & 0xFF}
    if kind == KIND_RADIO:
        return {"what": "radio", "insert_fail": cis, "skipped": acl, "insert_ok": v[0], "tx_done": v[1],
                "rx_done": v[2], "rx_captured": v[3]}
    if kind == KIND_RESULT:
        raw = cis.to_bytes(2, "big") + (v[0] & 0xFFFFFFFF).to_bytes(4, "big")
        return {"what": "result", "rssi": _s8(code), "addr": ":".join(f"{b:02X}" for b in raw), "cod": v[1],
                "round": acl}
    if kind == KIND_CAPTURE:
        return {"what": "capture", "rssi": _s8(code), "len": cis & 0xFF, "hdr": cis >> 8, "chan": acl,
                "raw": b"".join((w & 0xFFFFFFFF).to_bytes(4, "little") for w in v[:4])}
    if kind == KIND_STARTED:
        if code == 2:  # the host sent its first Soft-BR command: the self-test starts no more inquiries
            return {"what": "host", "round": cis}
        return {"what": "started", "accepted": bool(code), "round": cis, "recipe": v[0],
                "probe_hits": [(v[1] >> (8 * r)) & 0xFF for r in range(4)], "id_ends_with_sync": bool(v[2])}
    if kind == KIND_COLLECT:
        return {"what": "collect", "pairs_lost": cis, "retired": acl, "rx_collected": v[0], "rx_overrun": v[1],
                "rx_linked": v[2], "slot_linked": v[3]}
    if kind == KIND_STUCK:
        return {"what": "stuck", "step": code, "slot": cis & 0x0F, "is_tx": bool(cis & 0x10),
                "hw_current": bool(cis & 0x20), "probe": bool(cis & 0x40), "busy_after": bool(cis & 0x80),
                "deleted": cis >> 8, "late_ms": acl, "sch0": v[0], "sch_flags": v[1], "hw_cur": v[2],
                "hw_state": v[3]}
    if kind == KIND_PROBE:
        return {"what": "probe", "probe": code, "queued": bool(cis), "chan": acl, "access_addr": v[0],
                "dur_us": v[1], "recipe": v[2]}
    if kind == KIND_PROBE_RESULT:
        return {"what": "probe_result", "probe": code, "recipe": cis & 0x0F, "held": bool(cis & 0x10),
                "skipped": bool(cis & 0x20), "status": v[0], "stamp": v[1],
                "data": b"".join((w & 0xFFFFFFFF).to_bytes(4, "little") for w in v[2:4])}
    if kind == KIND_HEALTH:
        return {"what": "health", "stamp_only": code, "service_runs": cis, "rx_waits": acl, "heap_free": v[0],
                "heap_min": v[1], "ll_us": v[2], "esp_us": v[3]}
    if kind == KIND_PREVIOUS:
        return {"what": "previous", "where": code, "ll_us": v[0], "esp_us": v[1], "service_runs": v[2],
                "tx_done": v[3]}
    if kind == KIND_BOOT:
        return {"what": "boot", "reset": code, "live": bool(cis), "crashes": acl, "rom_chars": v[1]}
    if kind == KIND_LE_HOST:
        return {"what": "le_host", "opcode": cis, "scanning": bool(code & 1), "initiating": bool(code & 2),
                "passed": v[0], "refused": v[1]}
    if kind == KIND_HCI_EVENT:
        raw = b"".join((w & 0xFFFFFFFF).to_bytes(4, "little") for w in v[:4])
        return {"what": "hci_event", "event": code, "plen": cis, "data": raw[:min(cis, 16)]}
    if kind == KIND_ST_COMMAND:
        return {"what": "st_command", "command": code, "accepted": bool(cis), "handle": acl, "psrm": v[0] & 0xFF,
                "clock_offset": v[0] >> 16, "id_limit": bool(acl & 1), "id_ends_with_sync": bool(acl & 2),
                "device": acl >> 8,
                "sync_word": (v[2] & 0xFFFFFFFF) << 32 | (v[1] & 0xFFFFFFFF), "hop_address": v[3]}
    if kind == KIND_DATA_PROBE:
        return {"what": "data_probe", "variant": code & 0x0F, "device": code >> 4, "control": cis == 0,
                "frame_len": acl, "slots_tx": v[0] & 0xFFFF, "resent": v[0] >> 16, "heard_sync": v[1] & 0xFFFF,
                "heard_hec": v[1] >> 16, "acked": v[2] & 0xFFFF, "refused": v[2] >> 16,
                "frames_delivered": v[3] & 0xFFFF, "frames_received": v[3] >> 16}
    if kind == KIND_PACKET_TIMING and code == 1:
        return {"what": "long_pairs", "asked": cis, "taken": acl, "tx_done": v[0], "rx_done": v[1], "skipped": v[2],
                "refused": v[3]}
    if kind == KIND_PACKET_TIMING:
        return {"what": "build_times", "late_pairs": v[0], "longest_us": v[1], "allowance_us": v[2],
                "adapter_refused": v[3]}
    if kind == KIND_CIPHER_TIME:
        return {"what": "cipher_time", "short_us": v[0], "long_us": v[1], "matches_sample": v[2] == E0_SAMPLE_START}
    if kind == KIND_PAGE_PROGRESS:
        return {"what": "page_progress", "id_answers": v[0], "fhs_tx": v[1], "fhs_acks": v[2], "polls_tx": v[3]}
    if kind == KIND_CRASH:
        return {"what": "crash", "exception": code, "reset": cis & 0xFF, "where": cis >> 8, "crashes": acl,
                "pc": v[0], "ra": v[1], "cause": v[2], "tval": v[3]}
    if kind == KIND_CRASH_MORE:
        return {"what": "crash_more", "tx_done": acl, "sp": v[0], "task": _text(v[1:3]), "last_esp_us": v[3]}
    if kind == KIND_CRASH_REASON:
        return {"what": "crash_reason", "part": code, "text": _text(v[:4])}
    if kind == KIND_CRASH_IMAGE:
        return {"what": "crash_image", "img": (v[0] & 0xFFFFFFFF).to_bytes(4, "little").hex(), "rom_chars": v[1]}
    if kind == KIND_CRASH_STACK:
        return {"what": "crash_stack", "part": code, "code": [w & 0xFFFFFFFF for w in v[:4] if w]}
    if kind == KIND_CRASH_ROM_TAIL:
        return {"what": "crash_rom_tail", "part": code, "text": _text(v[:4])}
    if kind == KIND_POP_HELD:
        return {"what": "pop_held", "count": v[0]}
    if kind == KIND_ABORT_TEST:
        return {"what": "abort_test", "pages": v[0], "aborts": v[1], "refused": v[2]}
    if kind == KIND_CAPTURE_TIME:
        late = v[0] & 0xFFFFFFFF
        return {"what": "capture_time", "chan": acl, "late_us": late - (1 << 32) if late & 0x80000000 else late}
    if kind == KIND_WIFI:
        bssid = bytes([cis >> 8, cis & 0xFF, acl >> 8, acl & 0xFF, (v[3] >> 16) & 0xFF, (v[3] >> 24) & 0xFF])
        body = b"".join((w & 0xFFFFFFFF).to_bytes(4, "little") for w in v[:2]) + (v[2] & 0xFFFF).to_bytes(2, "little")
        return {"what": "wifi", "subtype": code, "bssid": ":".join(f"{b:02x}" for b in bssid), "rssi": _s8(v[3]),
                "chan": (v[3] >> 8) & 0xFF, "len": (v[2] >> 16) & 0xFFFF, "body": body}
    if kind == KIND_WIFI_SEEN:
        return {"what": "wifi_seen", "mgmt": v[0], "matched": v[1], "dropped": v[2]}
    return None


ENGINE_COUNTERS = ("slots_tx", "slots_rx", "rx_sync_ok", "slots_skipped", "hec_ok", "hec_err", "crc_ok", "crc_err")
RADIO_COUNTERS = ("insert_ok", "insert_fail", "tx_done", "rx_done", "rx_captured", "skipped")


class Summary:
    """Running state of one observation: the latest counters win, devices are keyed by address."""

    def __init__(self) -> None:
        self.next_index = 0       # first trace index not seen yet (the P4 serves absolute indexes)
        self.last: tuple | None = None  # (index, C6 time) of the last entry read: it identifies the run
        self.runs = 1             # the C6 starts counted so far
        self.rounds_started = 0
        self.rounds_refused = 0
        self.engine: dict = {}
        self.radio: dict = {}
        self._finished: dict[str, int] = {}  # counters of the runs that ended, added up
        self.captures = 0
        self.devices: dict[str, dict] = {}
        self.host_drives = False  # the host took Soft-BR over: what follows are its own commands
        self.collect: dict = {}
        self.probes: dict[int, dict] = {}  # recipe -> windows, of those with bytes, of those advertising packets
        self._health: dict | None = None
        self.clock_stalls = 0     # health records in which the controller clock ran at under half the real pace
        self.heap_first: int | None = None
        self.heap_last: int | None = None
        self.heap_lowest: int | None = None
        self.crashes = 0          # Soft-BR crashes the image has on record
        self.connections = 0      # Connection Complete events with status 0
        self.failed_connections: dict[int, int] = {}  # status -> Connection Complete events with it

    @property
    def fetch_from(self) -> int:
        """The index to ask the P4 for: the last entry read comes back with the new ones and proves the run."""
        return self.last[0] if self.last else 0

    def same_run(self, entries: list[dict]) -> bool:
        """False when the page no longer holds the last entry read: the C6 started again and counts from zero."""
        return self.last is None or any((e.get("i"), e.get("t_us")) == self.last for e in entries)

    def restart(self) -> None:
        """A new run of the C6: its trace starts from zero, the counters of the run that ended are kept."""
        for d, keys in ((self.engine, ENGINE_COUNTERS), (self.radio, RADIO_COUNTERS)):
            for k in keys:
                self._finished[k] = self._finished.get(k, 0) + d.get(k, 0)
        self.engine, self.radio, self.collect = {}, {}, {}
        self.next_index, self.last, self._health = 0, None, None
        self.runs += 1

    def _sum(self, current: dict, keys: tuple) -> dict:
        if not current and not any(self._finished.get(k) for k in keys):
            return {}
        return {**current, **{k: self._finished.get(k, 0) + current.get(k, 0) for k in keys}}

    def engine_sum(self) -> dict:
        return self._sum(self.engine, ENGINE_COUNTERS)

    def radio_sum(self) -> dict:
        return self._sum(self.radio, RADIO_COUNTERS)

    def feed(self, entries: list[dict]) -> list[dict]:
        """Takes a trace page, skips what was seen before, returns the new decoded self-test records."""
        fresh = []
        for e in entries:
            i = e.get("i", self.next_index)
            if i < self.next_index:
                continue
            self.next_index = i + 1
            self.last = (i, e.get("t_us"))
            d = decode(e)
            if d is None:
                continue
            fresh.append(d)
            if d["what"] == "started":
                if d["accepted"]:
                    self.rounds_started += 1
                else:
                    self.rounds_refused += 1
            elif d["what"] == "engine":
                self.engine = d
            elif d["what"] == "radio":
                self.radio = d
            elif d["what"] == "capture":
                self.captures += 1
            elif d["what"] == "host":
                self.host_drives = True
            elif d["what"] == "collect":
                self.collect = d
            elif d["what"] == "result":
                self.devices[d["addr"]] = d
            elif d["what"] == "probe_result":
                p = self.probes.setdefault(d["recipe"], {"windows": 0, "bytes": 0, "adv": 0})
                p["windows"] += 1
                p["bytes"] += any(d["data"])
                p["adv"] += "BLE advertising packet" in probe_reading(d["data"])
            elif d["what"] == "health":
                self._feed_health(d)
            elif d["what"] == "boot":
                self.crashes = max(self.crashes, d["crashes"])
            elif d["what"] == "hci_event" and d["event"] == 0x03 and d["data"]:
                status = d["data"][0]
                if status == 0:
                    self.connections += 1
                else:
                    self.failed_connections[status] = self.failed_connections.get(status, 0) + 1
        return fresh

    def _feed_health(self, d: dict) -> None:
        prev, self._health = self._health, d
        self.heap_first = d["heap_free"] if self.heap_first is None else self.heap_first
        self.heap_last = d["heap_free"]
        self.heap_lowest = d["heap_min"] if self.heap_lowest is None else min(self.heap_lowest, d["heap_min"])
        if prev is None:
            return
        d["d_ll_us"] = (d["ll_us"] - prev["ll_us"]) & 0xFFFFFFFF
        d["d_esp_us"] = (d["esp_us"] - prev["esp_us"]) & 0xFFFFFFFF
        d["stalled"] = d["d_esp_us"] >= 500000 and d["d_ll_us"] < d["d_esp_us"] // 2
        self.clock_stalls += d["stalled"]


def verdict(s: Summary) -> tuple[str, str]:
    """(level, explanation): the first stage of the chain that did not work, or INQUIRY_WORKS."""
    r = s.radio_sum()
    e = s.engine_sum()
    if s.devices:
        found = ", ".join(f"{a} (class 0x{d['cod']:06X}, {d['rssi']} dBm)" for a, d in sorted(s.devices.items()))
        if s.connections:
            return "CONNECTION_WORKS", (f"{s.connections} baseband connection(s) came up after paging; found "
                                        f"{len(s.devices)} device(s): {found}")
        failed = "; ".join(f"{n} attempt(s) ended with status 0x{st:02X} ({HCI_STATUS.get(st, '?')})"
                           for st, n in sorted(s.failed_connections.items()))
        return "INQUIRY_WORKS", (f"found {len(s.devices)} device(s): {found}"
                                 + (f"; no baseband connection: {failed}" if failed else ""))
    if s.rounds_started == 0 and s.rounds_refused == 0 and not r and not e:
        return "NOT_RUNNING", ("no Soft-BR self-test records in the trace - wrong C6 image, Bluetooth off on the "
                               "P4, or Soft-BR disabled by its crash fuse")
    if s.rounds_started == 0 and s.rounds_refused > 0:
        return "ENGINE_REFUSED", f"the engine refused HCI_Inquiry {s.rounds_refused} time(s)"
    if r.get("insert_ok", 0) == 0:
        return "SCHED_REJECTS", (f"the BLE scheduler accepted no raw slot ({r.get('insert_fail', 0)} refused) - "
                                 "the schedule-item layout or timing is wrong for this controller")
    if r.get("tx_done", 0) == 0 and r.get("rx_done", 0) == 0:
        return "SLOTS_NOT_RUN", (f"{r['insert_ok']} slots queued, none executed ({r.get('skipped', 0)} skipped) - "
                                 "the radio never ran a Soft-BR slot")
    if r.get("tx_done", 0) > 0 and r.get("rx_done", 0) == 0:
        return "RX_NEVER_RETURNS", (f"{r['tx_done']} TX slot(s) completed, no RX slot ever came back (skipped "
                                    f"{r.get('skipped', 0)}) - the engine waits for the first RX result forever; "
                                    "the raw RX schedule item is not ended or not recycled by the controller")
    # Only the engine's own count tells answers apart: the radio counter also holds the probe windows' packets.
    if e.get("rx_sync_ok", 0) == 0:
        return "NO_ANSWER", (f"{r.get('tx_done', 0)} TX and {r.get('rx_done', 0)} RX slots ran, no sync word matched - "
                             "no discoverable Classic device nearby, or it does not understand our ID packets, or "
                             "the correlator does not match its FHS")
    return "SYNC_ONLY", (f"sync word matched {e['rx_sync_ok']} time(s) but no FHS decoded "
                         f"(HEC ok/err {e.get('hec_ok', 0)}/{e.get('hec_err', 0)}, CRC ok/err "
                         f"{e.get('crc_ok', 0)}/{e.get('crc_err', 0)}) - a device answers our ID "
                         "packets; the receive bit pipe needs work")


def probe_summary(s: Summary) -> str:
    """One line per RX recipe: how many probe windows received bytes. Empty when the image ran no probes."""
    return "\n".join(
        f"PROBES: recipe {r} ({RECIPES.get(r, '?')}): {p['windows']} windows, {p['bytes']} with bytes"
        + (f" ({p['adv']} BLE advertising)" if p["bytes"] else "")
        for r, p in sorted(s.probes.items()))


def health_summary(s: Summary) -> str:
    """Heap and controller clock over the observation. Empty when the image sent no health records."""
    if s.heap_first is None:
        return ""
    return (f"HEALTH: {s.runs} run(s) of the C6, free heap {s.heap_first} -> {s.heap_last} B (lowest "
            f"{s.heap_lowest}), controller clock stalled in {s.clock_stalls} record(s), Soft-BR crashes on record "
            f"{s.crashes}")


def describe(d: dict) -> str:
    w = d["what"]
    if w == "started":
        hits = ", ".join(f"{RECIPES.get(r, r)} {h}" for r, h in enumerate(d["probe_hits"]))
        ids = "ending with the sync word" if d["id_ends_with_sync"] else "with 24 bits after the sync word"
        return (f"inquiry round {d['round']} {'started' if d['accepted'] else 'REFUSED by the engine'} with RX "
                f"recipe {d['recipe']} ({RECIPES.get(d['recipe'], '?')}), ID packets {ids}; probe windows with "
                f"bytes: {hits}")
    if w == "probe_result":
        flags = (" RADIO STOPPED" if d["held"] else "") + (" skipped" if d["skipped"] else "")
        return (f"probe {d['probe']} recipe {d['recipe']} ({RECIPES.get(d['recipe'], '?')}){flags}: status "
                f"0x{d['status']:08X} stamp 0x{d['stamp']:08X} - {probe_reading(d['data'])}")
    if w == "health":
        clock = ""
        if "d_esp_us" in d:
            clock = f", controller clock +{d['d_ll_us'] // 1000} ms in {d['d_esp_us'] // 1000} ms"
            clock += " - CONTROLLER CLOCK STALLED" if d["stalled"] else ""
        stamps = f", {d['stamp_only']} RX slots with a time stamp but no bytes" if d["stamp_only"] else ""
        return (f"health  free heap {d['heap_free']} B (lowest {d['heap_min']}), adapter passes "
                f"{d['service_runs']} ({d['rx_waits']} waiting for an RX slot){clock}{stamps}")
    if w == "previous":
        return (f"PREVIOUS RUN ended with the LL task {WHERE.get(d['where'], d['where'])}: last adapter pass at "
                f"{d['esp_us'] / 1e6:.3f} s of its uptime (controller clock {d['ll_us'] / 1e6:.3f} s), "
                f"{d['service_runs']} passes, {d['tx_done']} TX slots done")
    if w == "hci_event":
        name = HCI_EVENTS.get(d["event"], f"event 0x{d['event']:02X}")
        b = d["data"]
        if d["event"] == 0x03 and len(b) >= 3:
            more = f"status 0x{b[0]:02X} ({HCI_STATUS.get(b[0], '?')}), handle 0x{int.from_bytes(b[1:3], 'little'):04X}"
        elif d["event"] == 0x05 and len(b) >= 4:
            more = (f"status 0x{b[0]:02X}, handle 0x{int.from_bytes(b[1:3], 'little'):04X}, reason 0x{b[3]:02X} "
                    f"({HCI_STATUS.get(b[3], '?')})")
        elif d["event"] == 0x0F and len(b) >= 4:
            more = (f"status 0x{b[0]:02X} ({HCI_STATUS.get(b[0], '?')}) for command "
                    f"0x{int.from_bytes(b[2:4], 'little'):04X}")
        elif d["event"] == 0x0E and len(b) >= 4:
            more = f"command 0x{int.from_bytes(b[1:3], 'little'):04X}, status 0x{b[3]:02X} ({HCI_STATUS.get(b[3], '?')})"
        elif d["event"] == 0x01 and b:
            more = f"status 0x{b[0]:02X}"
        else:
            more = f"{d['plen']} parameter bytes: {b.hex(' ')}"
        return f"HCI     {name}: {more}"
    if w == "st_command":
        what = ST_COMMANDS.get(d["command"], d["command"])
        more = ""
        if d["command"] == 4:
            lap = d["hop_address"] & 0xFFFFFF
            ok = sync_word(lap) == d["sync_word"]
            more = (f" of device {d['device']} (access code {'matches' if ok else 'DOES NOT MATCH'} LAP {lap:06X}; an ID "
                    f"packet shows as bytes {(d['sync_word'] >> 32) & 0xFFFF:04x} read low byte first)")
        elif d["command"] == 2:
            lap = d["hop_address"] & 0xFFFFFF
            code = (f"access code matches LAP {lap:06X}" if sync_word(lap) == d["sync_word"]
                    else f"ACCESS CODE DOES NOT MATCH LAP {lap:06X}")
            more = (f" to device {d['device']} (page scan repetition mode {d['psrm']}, clock offset "
                    f"0x{d['clock_offset']:04X}, ID answers {'with' if d['id_limit'] else 'without'} the length limit, "
                    f"ID packets {'ending with the sync word' if d['id_ends_with_sync'] else 'with 24 bits after it'}; "
                    f"{code}, hop address 0x{d['hop_address']:07X})")
        elif d["command"] == 3:
            more = f" (handle 0x{d['handle']:04X})"
        return f"self-test sends {what}{more}: {'accepted' if d['accepted'] else 'REFUSED by the engine'}"
    if w == "data_probe":
        frame = ("the 20-byte control frame in one 1-slot packet" if d["control"]
                 else DATA_PROBE_FRAMES.get(d["variant"], f"variant {d['variant']}"))
        return (f"DATA    device {d['device']}, {frame}: {d['frames_delivered']} frame(s) delivered, "
                f"{d['acked']} packet(s) acknowledged, {d['refused']} refused, {d['resent']} sent again; in "
                f"{d['slots_tx']} TX slots the device was heard {d['heard_sync']} time(s), "
                f"{d['heard_hec']} with a good header; {d['frames_received']} frame(s) came back")
    if w == "long_pairs":
        return (f"LONG    {d['asked']} pair(s) with a 3-slot TX item asked for, {d['taken']} taken by the adapter: "
                f"{d['tx_done']} TX done, {d['rx_done']} RX done, {d['skipped']} skipped, {d['refused']} refused; "
                "the chip is still running")
    if w == "build_times":
        return (f"BUILD   longest {d['longest_us']} us from choosing a slot to handing the pair over, allowance now "
                f"{d['allowance_us']} us; {d['late_pairs']} pair(s) ready too late and not handed over, "
                f"{d['adapter_refused']} item(s) refused by the adapter as too late")
    if w == "cipher_time":
        return (f"CIPHER  E0 key stream on this chip: {d['short_us']} us for a 30-byte packet, {d['long_us']} us for "
                f"a 340-byte packet; "
                + ("its first bytes match the specification's sample data" if d["matches_sample"]
                   else "ITS FIRST BYTES DO NOT MATCH the specification's sample data"))
    if w == "page_progress":
        return (f"PAGE    handshakes so far: {d['id_answers']} ID answers accepted, {d['fhs_tx']} FHS sent, "
                f"{d['fhs_acks']} FHS acknowledged, {d['polls_tx']} first POLLs sent")
    if w == "le_host":
        state = [n for n, on in (("scanning", d["scanning"]), ("connection attempt pending", d["initiating"])) if on]
        return (f"LE host  last command {LE_COMMANDS.get(d['opcode'], hex(d['opcode']))}: {d['passed']} let "
                f"through, {d['refused']} refused while Soft-BR worked ({', '.join(state) or 'idle'} now)")
    if w == "crash":
        head = (f"CRASH   on record (number {d['crashes']}, found by a start with reset reason {d['reset']}, "
                f"{RESET_REASONS.get(d['reset'], '?')}); the LL task was {WHERE.get(d['where'], 'unknown')}")
        if d["exception"] == NO_PANIC_RECORD:
            return head + "; no panic record (a watchdog or brownout reset the chip without the panic handler)"
        kind = PANIC_EXCEPTIONS.get(d["exception"] & 0x7F, f"exception {d['exception'] & 0x7F}")
        return (head + f"; {kind}: pc 0x{d['pc']:08X} ra 0x{d['ra']:08X} mcause 0x{d['cause']:08X} "
                f"mtval 0x{d['tval']:08X}")
    if w == "crash_more":
        return (f"CRASH   in task '{d['task']}', sp 0x{d['sp']:08X}; last adapter pass at "
                f"{d['last_esp_us'] / 1e6:.3f} s of that run, {d['tx_done']} TX slots done")
    if w == "crash_reason":
        return f"CRASH   reason, part {d['part']}: {d['text']!r}"
    if w == "crash_image":
        return (f"CRASH   found by a start of image {d['img']} (the image that crashed, unless the firmware guard "
                f"went back to the previous one); the ROM had printed {d['rom_chars']} characters in that run")
    if w == "crash_stack":
        return (f"CRASH   code addresses on the stack (the calls that led to the panic are among them), part "
                f"{d['part']}: "
                + " ".join(f"0x{a:08X}" for a in d["code"]))
    if w == "crash_rom_tail":
        return f"CRASH   last ROM output, part {d['part']}: {d['text']!r}"
    if w == "pop_held":
        return (f"GUARD   {d['count']} executed Soft-BR item(s) held back from the controller's recycle pass "
                "while the baseband still pointed at them (each pass would have taken the spare-block swap, "
                "which asserts when the spare is not one of the adapter's blocks)")
    if w == "abort_test":
        return (f"ABORT   {d['pages']} page(s) started, {d['aborts']} given up half way, {d['refused']} refused "
                "by the engine; the chip is still running")
    if w == "capture_time":
        return f"capture arrived {d['late_us']:+d} us from the slot boundary asked for (channel {d['chan']})"
    if w == "boot":
        return (f"start   reset reason {d['reset']} ({RESET_REASONS.get(d['reset'], '?')}), Soft-BR "
                f"{'was' if d['live'] else 'was not'} running at the reset, crashes on record {d['crashes']}; "
                + (f"ROM output kept ({d['rom_chars']} characters so far)" if d["rom_chars"]
                   else "ROM output not kept"))
    if w == "engine":
        return (f"engine  state {d['state']} ({ENGINE_STATES.get(d['state'], '?')}) round {d['round']}: slots tx "
                f"{d['slots_tx']} rx {d['slots_rx']} skipped "
                f"{d['slots_skipped']}, sync ok {d['rx_sync_ok']}, HEC {d['hec_ok']}/{d['hec_err']}, CRC "
                f"{d['crc_ok']}/{d['crc_err']}, results {d['results']}")
    if w == "host":
        return f"the host drives Soft-BR from here (after self-test round {d['round']}): no more self-test inquiries"
    if w == "collect":
        return (f"collect RX slots collected {d['rx_collected']} (stopped past their end {d['rx_overrun']}), slots "
                f"retired {d['retired']}, pairs the engine gave up {d['pairs_lost']}; still in the controller's "
                f"queue: {d['rx_linked']} looks at ended RX slots, {d['slot_linked']} free slots passed over")
    if w == "radio":
        return (f"radio   insert ok {d['insert_ok']} fail {d['insert_fail']}, tx done {d['tx_done']}, rx done "
                f"{d['rx_done']}, captured {d['rx_captured']}, skipped {d['skipped']}")
    if w == "stuck":
        return (f"STUCK   {'TX' if d['is_tx'] else 'RX'} slot {d['slot']}{' (probe)' if d['probe'] else ''} "
                f"{d['late_ms']} ms past its end, step: {STUCK_STEPS.get(d['step'], d['step'])}, deleted "
                f"{d['deleted']}, {'still busy' if d['busy_after'] else 'came back'}; baseband item "
                f"{'ours' if d['hw_current'] else 'other'} (cur 0x{d['hw_cur']:08X} state 0x{d['hw_state']:08X}), "
                f"sch0 0x{d['sch0']:08X} flags 0x{d['sch_flags']:08X}")
    if w == "wifi":
        b = d["body"]
        u16 = [int.from_bytes(b[i:i + 2], "little") for i in range(0, 10, 2)]
        head = f"wifi    {d['bssid']} ({d['rssi']} dBm, channel {d['chan']}, {d['len']} B): "
        if d["subtype"] == 0x0B:
            return (head + f"authentication {AUTH_ALGS.get(u16[0], u16[0])} seq {u16[1]}, status {u16[2]} "
                    f"({WIFI_STATUS.get(u16[2], '?')}), then {b[6:].hex(' ')}")
        if d["subtype"] in (0x0A, 0x0C):
            return head + f"{'deauthentication' if d['subtype'] == 0x0C else 'disassociation'}, reason {u16[0]}"
        if d["subtype"] in (0x01, 0x03):
            return head + f"association response, status {u16[1]} ({WIFI_STATUS.get(u16[1], '?')})"
        return head + f"management subtype {d['subtype']}: {b.hex(' ')}"
    if w == "wifi_seen":
        return (f"wifi    tap: {d['mgmt']} management frames heard, {d['matched']} for this station, "
                f"{d['dropped']} not kept")
    if w == "probe":
        return (f"probe {d['probe']}: lone RX {d['dur_us']} us on channel {d['chan']} "
                f"(access address 0x{d['access_addr']:08X}, recipe {d['recipe']}) "
                f"{'queued' if d['queued'] else 'REFUSED'}")
    if w == "capture":
        return (f"capture channel {d['chan']} rssi {d['rssi']} dBm len {d['len']} hdr 0x{d['hdr']:02X}: "
                f"{d['raw'].hex(' ')}")
    return f"RESULT  {d['addr']} class 0x{d['cod']:06X} rssi {d['rssi']} dBm (round {d['round']})"


BOX_RECORDS = ("boot", "previous", "crash", "crash_more", "crash_image", "crash_reason", "crash_stack",
               "crash_rom_tail", "pop_held")


def box_report(entries: list[dict] | None) -> tuple[int, list[str]]:
    """(exit code, lines) of --box: how the C6 started and the crash it has on record, from one trace page.

    Every image from 1.5.2 on writes these records when Soft-BR starts, a regular one too. The trace keeps the last
    32 entries, so read it before LE Audio is set up; the record itself stays in the C6 and is written again at
    its next start."""
    if entries is None:
        return 1, ["BOX: the P4 did not answer GET /api/c6/cis/trace"]
    records = [d for d in map(decode, entries) if d and d["what"] in BOX_RECORDS]
    lines = [describe(d) for d in records]
    if not any(d["what"] == "boot" for d in records):
        return 2, lines + ["BOX: no start record in the trace - a C6 image older than 1.5.2, Bluetooth off on the "
                           "P4, or the 32 entries were overwritten since the start"]
    crash = next((d for d in records if d["what"] == "crash"), None)
    if crash is None:
        return 0, lines + ["BOX: no crash on record"]
    if crash["exception"] == NO_PANIC_RECORD:
        return 0, lines + ["BOX: crash on record, without a panic record (a watchdog or brownout reset)"]

    def parts(what: str) -> list[dict]:
        return sorted((d for d in records if d["what"] == what), key=lambda d: d["part"])

    def text(what: str) -> str:
        return "".join(d["text"] for d in parts(what)).encode("unicode_escape").decode("ascii")

    addresses = [crash["pc"], crash["ra"]] + [a for d in parts("crash_stack") for a in d["code"]]
    return 0, lines + ["BOX: crash on record - the addresses belong to the ELF of the image that crashed",
                       f"BOX: reason: {text('crash_reason')}",
                       f"BOX: last ROM output: {text('crash_rom_tail')}",
                       "BOX: addresses: " + " ".join(f"0x{a:08X}" for a in addresses)]


def fetch(host: str, token: str, index: int, timeout: float = 10) -> list[dict] | None:
    req = urllib.request.Request(f"http://{host}/api/c6/cis/trace?from={index}",
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            entries = json.load(r).get("entries")
            return entries if isinstance(entries, list) else None
    except (urllib.error.URLError, OSError, ValueError):
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("host", nargs="?", default=os.environ.get("LE_AUDIO_HOST", ""),
                    help="P4 address (env LE_AUDIO_HOST)")
    ap.add_argument("--token", default=os.environ.get("LE_AUDIO_OTA_TOKEN", ""),
                    help="bearer token (env LE_AUDIO_OTA_TOKEN)")
    ap.add_argument("--watch", type=float, default=WATCH_DEFAULT_S, metavar="S",
                    help="observation time in seconds (default: %(default)s)")
    ap.add_argument("--poll", type=float, default=POLL_DEFAULT_S, metavar="S",
                    help="seconds between trace reads (default: %(default)s; the C6 keeps 32 entries)")
    ap.add_argument("--box", action="store_true",
                    help="read the trace once, print how the C6 started and the crash it has on record, and exit "
                         "(any image from 1.5.2 on, a regular one too)")
    args = ap.parse_args(argv)
    if not args.host.strip():
        ap.error("host is required (argument or env LE_AUDIO_HOST)")
    if not args.token.strip():
        ap.error("token is required (--token or env LE_AUDIO_OTA_TOKEN)")
    if args.box:
        code, lines = box_report(fetch(args.host.strip(), args.token.strip(), 0))
        print("\n".join(lines))
        return code

    s = Summary()
    answered = False
    silent_since = time.monotonic()
    t0 = time.monotonic()
    while time.monotonic() - t0 < args.watch:
        entries = fetch(args.host.strip(), args.token.strip(), s.fetch_from)
        if entries is not None and not s.same_run(entries):
            s.restart()
            print(f"[{time.monotonic() - t0:5.0f} s] THE C6 STARTED AGAIN (run {s.runs}): reading its trace "
                  "from the beginning", flush=True)
            entries = fetch(args.host.strip(), args.token.strip(), 0)
        if entries is None:
            # The inquiry holds the shared radio with the highest priority, so Wi-Fi reads fail now and then.
            if time.monotonic() - silent_since > 30:
                print(f"[{time.monotonic() - t0:5.0f} s] no answer from the P4 for 30 s", flush=True)
                silent_since = time.monotonic()
        else:
            answered = True
            silent_since = time.monotonic()
            for d in s.feed(entries):
                print(f"[{time.monotonic() - t0:5.0f} s] {describe(d)}", flush=True)
        time.sleep(args.poll)

    if not answered:
        print("VERDICT: the P4 never answered GET /api/c6/cis/trace")
        return 1
    for line in (probe_summary(s), health_summary(s)):
        if line:
            print(line)
    level, text = verdict(s)
    print(f"VERDICT: {level} - {text}")
    return 0 if level in ("INQUIRY_WORKS", "CONNECTION_WORKS") else 2


if __name__ == "__main__":
    sys.exit(main())
