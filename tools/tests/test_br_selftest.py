"""Tests for the pure helpers in tools/br_selftest.py (no network)."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import br_selftest  # noqa: E402


def entry(kind, code=0, cis=0, acl=0, v=(0, 0, 0, 0), i=0):
    """One element of GET /api/c6/cis/trace "entries" as the P4 serves it."""
    return {"i": i, "t_us": 1000 * i, "kind": "?", "kind_id": kind, "code": code, "cis": cis, "acl": acl,
            "v": list(v)}


class Decode(unittest.TestCase):
    def test_other_kinds_are_ignored(self):
        self.assertIsNone(br_selftest.decode(entry(1)))
        self.assertIsNone(br_selftest.decode(entry(0xAF)))
        self.assertIsNone(br_selftest.decode({"kind_id": 0xB0}))  # malformed: no values

    def test_engine_counters(self):
        d = br_selftest.decode(entry(0xB0, code=2, cis=3, acl=7,
                                     v=(1000, 990, 12 | (5 << 16), 4 | (1 << 8) | (2 << 16) | (9 << 24))))
        self.assertEqual(d, {"what": "engine", "state": 2, "results": 3, "round": 7, "slots_tx": 1000,
                             "slots_rx": 990, "rx_sync_ok": 12, "slots_skipped": 5, "hec_ok": 4, "hec_err": 1,
                             "crc_ok": 2, "crc_err": 9})

    def test_radio_counters(self):
        d = br_selftest.decode(entry(0xB1, cis=2, acl=40, v=(800, 400, 390, 6)))
        self.assertEqual(d, {"what": "radio", "insert_fail": 2, "skipped": 40, "insert_ok": 800, "tx_done": 400,
                             "rx_done": 390, "rx_captured": 6})

    def test_inquiry_result_address_and_signed_rssi(self):
        d = br_selftest.decode(entry(0xB2, code=0xC4, cis=0x0011, acl=3, v=(0x22334455, 0x240404, 0, 0)))
        self.assertEqual(d, {"what": "result", "rssi": -60, "addr": "00:11:22:33:44:55", "cod": 0x240404,
                             "round": 3})

    def test_rx_capture_bytes_in_air_order(self):
        d = br_selftest.decode(entry(0xB3, code=0xD8, cis=0x2C | (0xE2 << 8), acl=39,
                                     v=(0x04030201, 0x08070605, 0x0C0B0A09, 0x100F0E0D)))
        self.assertEqual(d["what"], "capture")
        self.assertEqual((d["rssi"], d["len"], d["hdr"], d["chan"]), (-40, 0x2C, 0xE2, 39))
        self.assertEqual(d["raw"], bytes(range(1, 17)))

    def test_stuck_slot_report(self):
        # RX slot 1, still busy 2 s after its end; the scheduler delete (step 1) removed 1 item and the slot came back.
        d = br_selftest.decode(entry(0xB5, code=1, cis=0x01 | (1 << 5) | (1 << 8), acl=2000,
                                     v=(0x00100000, 0x02000500, 0x000A1234, 0x80000000)))
        self.assertEqual(d, {"what": "stuck", "step": 1, "slot": 1, "is_tx": False, "hw_current": True,
                             "probe": False, "busy_after": False, "deleted": 1, "late_ms": 2000,
                             "sch0": 0x00100000, "sch_flags": 0x02000500, "hw_cur": 0x000A1234,
                             "hw_state": 0x80000000})
        d = br_selftest.decode(entry(0xB5, code=2, cis=0x03 | (1 << 4) | (1 << 6) | (1 << 7), acl=4000))
        self.assertEqual((d["step"], d["slot"], d["is_tx"], d["probe"], d["busy_after"], d["deleted"]),
                         (2, 3, True, True, True, 0))

    def test_probe_started(self):
        d = br_selftest.decode(entry(0xB6, code=1, cis=1, acl=0, v=(0x8E89BED6, 20000, 2, 0)))
        self.assertEqual(d, {"what": "probe", "probe": 1, "queued": True, "chan": 0, "access_addr": 0x8E89BED6,
                             "dur_us": 20000, "recipe": 2})

    def test_probe_result_keeps_the_raw_words(self):
        d = br_selftest.decode(entry(0xB8, code=7, cis=2 | 0x10, v=(0xB9000003, 0x12345678, 0x04030201, 0x08070605)))
        self.assertEqual(d, {"what": "probe_result", "probe": 7, "recipe": 2, "held": True, "skipped": False,
                             "status": 0xB9000003, "stamp": 0x12345678, "data": bytes(range(1, 9))})
        self.assertTrue(br_selftest.decode(entry(0xB8, code=8, cis=0x20))["skipped"])

    def test_health_record(self):
        d = br_selftest.decode(entry(0xB9, code=7, cis=800, acl=30, v=(150000, 120000, 5000000, 7000000)))
        self.assertEqual(d, {"what": "health", "stamp_only": 7, "service_runs": 800, "rx_waits": 30,
                             "heap_free": 150000, "heap_min": 120000, "ll_us": 5000000, "esp_us": 7000000})
        self.assertIn("7 RX slots with a time stamp but no bytes", br_selftest.describe(d))

    def test_previous_run_and_start_records(self):
        d = br_selftest.decode(entry(0xBA, code=3, v=(111, 222, 333, 444)))
        self.assertEqual(d, {"what": "previous", "where": 3, "ll_us": 111, "esp_us": 222, "service_runs": 333,
                             "tx_done": 444})
        d = br_selftest.decode(entry(0xBB, code=4, cis=1, acl=2))
        self.assertEqual(d, {"what": "boot", "reset": 4, "live": True, "crashes": 2, "rom_chars": 0})
        self.assertIn("ROM output not kept", br_selftest.describe(d))
        d = br_selftest.decode(entry(0xBB, code=1, v=(0, 20, 0, 0)))
        self.assertIn("ROM output kept (20 characters so far)", br_selftest.describe(d))

    def test_wifi_tap_authentication_frame(self):
        # SAE commit answer from the access point: algorithm 3, sequence 1, status 76 (anti-clogging token required).
        d = br_selftest.decode(entry(0xC0, code=0x0B, cis=0x0211, acl=0x2233,
                                     v=(0x00010003, 0x0013004C, 0x00660000 | 0xBBAA,
                                        0xC8 | (4 << 8) | (0x44 << 16) | (0x55 << 24))))
        self.assertEqual(d, {"what": "wifi", "subtype": 0x0B, "bssid": "02:11:22:33:44:55", "rssi": -56, "chan": 4,
                             "len": 0x66, "body": bytes.fromhex("0300 0100 4c00 1300 aabb")})
        text = br_selftest.describe(d)
        self.assertIn("authentication", text)
        self.assertIn("SAE", text)
        self.assertIn("status 76", text)

    def test_wifi_tap_deauthentication_reason(self):
        d = br_selftest.decode(entry(0xC0, code=0x0C, cis=0x0211, acl=0x2233, v=(0x0002, 0, 26 << 16, 0xD0 | (4 << 8))))
        self.assertIn("deauthentication, reason 2", br_selftest.describe(d))

    def test_wifi_tap_counters(self):
        d = br_selftest.decode(entry(0xC1, v=(1500, 4, 1, 0)))
        self.assertEqual(d, {"what": "wifi_seen", "mgmt": 1500, "matched": 4, "dropped": 1})

    def test_crash_record_from_nvs(self):
        d = br_selftest.decode(entry(0xBC, code=4, cis=4 | (2 << 8), acl=1,
                                     v=(0x42012345, 0x4201AAAA, 0x00000005, 0x00000010)))
        self.assertEqual(d, {"what": "crash", "exception": 4, "reset": 4, "where": 2, "crashes": 1,
                             "pc": 0x42012345, "ra": 0x4201AAAA, "cause": 5, "tval": 0x10})
        text = br_selftest.describe(d)
        self.assertIn("pc 0x42012345", text)
        self.assertIn("in r_ble_lll_sched_insert", text)
        self.assertIn("fault", text)
        # A watchdog reset leaves no panic record: only the reset reason and the LL task's place are known.
        text = br_selftest.describe(br_selftest.decode(entry(0xBC, code=0xFF, cis=7 | (5 << 8), acl=2)))
        self.assertIn("no panic record", text)
        self.assertNotIn("pc 0x", text)

    def test_crash_task_and_reason_text(self):
        name = int.from_bytes(b"btCo", "little"), int.from_bytes(b"ntrl", "little")
        d = br_selftest.decode(entry(0xBD, acl=1700, v=(0x4081FFF0, name[0], name[1], 61500000)))
        self.assertEqual(d, {"what": "crash_more", "tx_done": 1700, "sp": 0x4081FFF0, "task": "btContrl",
                             "last_esp_us": 61500000})
        words = [int.from_bytes(b"assert failed: x"[i:i + 4], "little") for i in range(0, 16, 4)]
        d = br_selftest.decode(entry(0xBE, code=1, v=words))
        self.assertEqual(d, {"what": "crash_reason", "part": 1, "text": "assert failed: x"})
        d = br_selftest.decode(entry(0xBE, code=2, v=(int.from_bytes(b"ab\0\0", "little"), 0, 0, 0)))
        self.assertEqual(d["text"], "ab")

    def test_crash_image_stack_and_rom_output(self):
        # The image is named by the first bytes of its ELF hash, in the order the hash is printed.
        d = br_selftest.decode(entry(0xC9, v=(int.from_bytes(bytes.fromhex("24c746cb"), "little"), 3100, 0, 0)))
        self.assertEqual(d, {"what": "crash_image", "img": "24c746cb", "rom_chars": 3100})
        self.assertIn("image 24c746cb", br_selftest.describe(d))
        # Return addresses, nearest first; the list ends at the first zero word.
        d = br_selftest.decode(entry(0xCA, code=1, v=(0x4080E622, 0x42001234, 0, 0)))
        self.assertEqual(d, {"what": "crash_stack", "part": 1, "code": [0x4080E622, 0x42001234]})
        self.assertIn("0x4080E622 0x42001234", br_selftest.describe(d))
        # The controller's own assertion line, which the panic reason does not carry.
        words = [int.from_bytes(b"BLE assert: line"[i:i + 4], "little") for i in range(0, 16, 4)]
        d = br_selftest.decode(entry(0xCB, code=0, v=words))
        self.assertEqual(d, {"what": "crash_rom_tail", "part": 0, "text": "BLE assert: line"})
        self.assertIn("'BLE assert: line'", br_selftest.describe(d))

    def test_items_held_back_from_the_recycle_pass(self):
        d = br_selftest.decode(entry(0xCD, v=(3, 0, 0, 0)))
        self.assertEqual(d, {"what": "pop_held", "count": 3})
        self.assertIn("3 executed Soft-BR item(s) held back", br_selftest.describe(d))
        # --box shows it next to the start record: it says the guard in the adapter had work to do.
        code, lines = br_selftest.box_report([entry(0xBB, code=1, v=(0, 20, 0, 0)), entry(0xCD, v=(3, 0, 0, 0))])
        self.assertEqual(code, 0)
        self.assertTrue(any("held back" in ln for ln in lines))
        self.assertEqual(lines[-1], "BOX: no crash on record")

    def test_pages_given_up_half_way(self):
        d = br_selftest.decode(entry(0xCC, v=(41, 40, 1, 0)))
        self.assertEqual(d, {"what": "abort_test", "pages": 41, "aborts": 40, "refused": 1})
        self.assertIn("41 page(s) started, 40 given up half way, 1 refused", br_selftest.describe(d))

    def test_capture_arrival_time_is_signed(self):
        self.assertEqual(br_selftest.decode(entry(0xBF, acl=44, v=(37, 0, 0, 0))),
                         {"what": "capture_time", "chan": 44, "late_us": 37})
        self.assertEqual(br_selftest.decode(entry(0xBF, acl=44, v=(0xFFFFFFB0, 0, 0, 0)))["late_us"], -80)

    def test_le_commands_of_the_host(self):
        d = br_selftest.decode(entry(0xC2, code=2, cis=0x2043, v=(3, 1, 0, 0)))
        self.assertEqual(d, {"what": "le_host", "opcode": 0x2043, "scanning": False, "initiating": True,
                             "passed": 3, "refused": 1})
        text = br_selftest.describe(d)
        self.assertIn("LE Extended Create Connection", text)
        self.assertIn("3 let through, 1 refused", text)

    def test_hci_event_of_the_engine(self):
        # Connection Complete: status 0, handle 0x0B00, address, ACL link, no encryption.
        params = bytes([0x00, 0x00, 0x0B, 1, 2, 3, 4, 5, 6, 0x01, 0x00])
        words = [int.from_bytes(params.ljust(16, b"\0")[i:i + 4], "little") for i in range(0, 16, 4)]
        d = br_selftest.decode(entry(0xC3, code=0x03, cis=len(params), v=words))
        self.assertEqual(d, {"what": "hci_event", "event": 0x03, "plen": 11, "data": params})
        text = br_selftest.describe(d)
        self.assertIn("Connection Complete", text)
        self.assertIn("status 0x00", text)
        self.assertIn("handle 0x0B00", text)
        failed = br_selftest.decode(entry(0xC3, code=0x03, cis=11, v=(0x04, 0, 0, 0)))
        self.assertIn("status 0x04 (page timeout)", br_selftest.describe(failed))

    def test_selftest_command(self):
        d = br_selftest.decode(entry(0xC4, code=2, cis=1, acl=1 | (2 << 8),
                                     v=(1 | (0x1234 << 16), 0x331A3AE2, 0x4E7A2CCE, 0x09E8B33)))
        self.assertEqual(d, {"what": "st_command", "command": 2, "accepted": True, "handle": 1 | (2 << 8),
                             "psrm": 1, "clock_offset": 0x1234, "id_limit": True, "id_ends_with_sync": False,
                             "device": 2, "sync_word": 0x4E7A2CCE331A3AE2, "hop_address": 0x09E8B33})
        new = br_selftest.decode(entry(0xC4, code=2, cis=1, acl=2, v=(1, 0x331A3AE2, 0x4E7A2CCE, 0x09E8B33)))
        self.assertIn("ID packets ending with the sync word", br_selftest.describe(new))
        text = br_selftest.describe(d)
        self.assertIn("create connection to device 2", text)
        self.assertIn("ID answers with the length limit", text)
        # The access code is checked against the specification's algorithm for the LAP in the hop address.
        self.assertIn("access code matches LAP 9E8B33", text)
        wrong = br_selftest.decode(entry(0xC4, code=2, cis=1, acl=0, v=(1, 0x331A3AE3, 0x4E7A2CCE, 0x09E8B33)))
        self.assertIn("ID answers without the length limit", br_selftest.describe(wrong))
        self.assertIn("ACCESS CODE DOES NOT MATCH LAP 9E8B33", br_selftest.describe(wrong))

    def test_packet_build_times_and_late_pairs(self):
        d = br_selftest.decode(entry(0xC7, v=(2, 1480, 1850, 1)))
        self.assertEqual(d, {"what": "build_times", "late_pairs": 2, "longest_us": 1480, "allowance_us": 1850,
                             "adapter_refused": 1})
        text = br_selftest.describe(d)
        self.assertIn("longest 1480 us", text)
        self.assertIn("allowance now 1850 us", text)
        self.assertIn("2 pair(s) ready too late and not handed over", text)
        self.assertIn("1 item(s) refused by the adapter", text)

    def test_data_probe_on_a_self_test_connection(self):
        d = br_selftest.decode(entry(0xC8, code=0x10, cis=1, acl=164,
                                     v=(800 | (399 << 16), 2 | (1 << 16), 0, 0)))
        self.assertEqual(d["device"], 1)
        self.assertEqual(d["variant"], 0)
        self.assertFalse(d["control"])
        self.assertEqual((d["slots_tx"], d["resent"], d["heard_sync"], d["heard_hec"]), (800, 399, 2, 1))
        text = br_selftest.describe(d)
        self.assertIn("device 1, one 3-slot packet of 164 bytes: 0 frame(s) delivered", text)
        self.assertIn("399 sent again", text)
        control = br_selftest.decode(entry(0xC8, code=0x03, cis=0, acl=20, v=(40, 40 | (40 << 16), 1, 1)))
        self.assertIn("device 0, the 20-byte control frame in one 1-slot packet: 1 frame(s) delivered",
                      br_selftest.describe(control))
        full = br_selftest.decode(entry(0xC8, code=0x03, cis=1, acl=27, v=(40, 40 | (40 << 16), 0, 0)))
        self.assertIn("device 0, one 1-slot packet of 27 bytes", br_selftest.describe(full))

    def test_long_pair_probe(self):
        d = br_selftest.decode(entry(0xC7, code=1, cis=3, acl=3, v=(3, 3, 0, 0)))
        self.assertEqual(d, {"what": "long_pairs", "asked": 3, "taken": 3, "tx_done": 3, "rx_done": 3, "skipped": 0,
                             "refused": 0})
        self.assertIn("3 pair(s) with a 3-slot TX item asked for, 3 taken", br_selftest.describe(d))

    def test_cipher_time_on_the_chip(self):
        d = br_selftest.decode(entry(0xC6, v=(140, 900, 0xE06F9994, 0)))
        self.assertEqual(d, {"what": "cipher_time", "short_us": 140, "long_us": 900, "matches_sample": True})
        self.assertIn("140 us for a 30-byte packet, 900 us for a 340-byte packet", br_selftest.describe(d))
        self.assertIn("match the specification's sample data", br_selftest.describe(d))
        wrong = br_selftest.decode(entry(0xC6, v=(140, 900, 0x12345678, 0)))
        self.assertIn("DO NOT MATCH", br_selftest.describe(wrong))

    def test_page_handshake_counters(self):
        d = br_selftest.decode(entry(0xC5, v=(5, 12, 1, 3)))
        self.assertEqual(d, {"what": "page_progress", "id_answers": 5, "fhs_tx": 12, "fhs_acks": 1, "polls_tx": 3})
        text = br_selftest.describe(d)
        self.assertIn("5 ID answers accepted, 12 FHS sent, 1 FHS acknowledged, 3 first POLLs sent", text)

    def test_listening_for_id_packets_names_the_bytes_to_look_for(self):
        d = br_selftest.decode(entry(0xC4, code=4, cis=1, acl=0, v=(0, 0x331A3AE2, 0x4E7A2CCE, 0x09E8B33)))
        text = br_selftest.describe(d)
        self.assertIn("listens for ID packets of device 0", text)
        self.assertIn("access code matches LAP 9E8B33", text)
        self.assertIn("2cce", text)  # sync word bits 32..47: the two bytes after the access address

    def test_access_code_of_the_specification(self):
        # Core Specification Vol 2 Part G, access code sample data (printed there with the last sent bit first).
        for lap, printed in ((0x000000, 0x7E7041E34000000D), (0xFFFFFF, 0xE758B5227FFFFFF2),
                             (0x9E8B33, 0x475C58CC73345E72), (0x9E8B34, 0x28ED3C34CB345E72)):
            sent = br_selftest.sync_word(lap)
            self.assertEqual(int(f"{sent:064b}"[::-1], 2), printed, f"LAP {lap:06X}")

    def test_inquiry_started(self):
        d = br_selftest.decode(entry(0xB4, code=1, cis=5, v=(2, 0x00050300, 1, 0)))
        self.assertEqual(d, {"what": "started", "accepted": True, "round": 5, "recipe": 2,
                             "probe_hits": [0, 3, 5, 0], "id_ends_with_sync": True})
        self.assertIn("ID packets ending with the sync word", br_selftest.describe(d))
        old = br_selftest.decode(entry(0xB4, code=1, cis=6, v=(0, 0, 0, 0)))
        self.assertIn("ID packets with 24 bits after the sync word", br_selftest.describe(old))
        self.assertFalse(br_selftest.decode(entry(0xB4, code=0, cis=5))["accepted"])

    def test_host_took_over_is_not_an_inquiry_round(self):
        self.assertEqual(br_selftest.decode(entry(0xB4, code=2, cis=5)), {"what": "host", "round": 5})
        s = br_selftest.Summary()
        s.feed([entry(0xB4, code=2, cis=5)])
        self.assertEqual((s.rounds_started, s.rounds_refused, s.host_drives), (0, 0, True))

    def test_rx_collection_counters(self):
        d = br_selftest.decode(entry(0xB7, cis=3, acl=1, v=(500, 2, 7, 4)))
        self.assertEqual(d, {"what": "collect", "pairs_lost": 3, "retired": 1, "rx_collected": 500,
                             "rx_overrun": 2, "rx_linked": 7, "slot_linked": 4})
        self.assertIn("collected 500", br_selftest.describe(d))
        self.assertIn("still in the controller's queue: 7 looks at ended RX slots, 4 free slots passed over",
                      br_selftest.describe(d))


def words(text: bytes, n: int = 16):
    """Characters as the image packs them into trace values: four to a little-endian word, zero padded."""
    text = text.ljust(n, b"\0")
    return [int.from_bytes(text[i:i + 4], "little") for i in range(0, n, 4)]


class BlackBox(unittest.TestCase):
    """--box: one read of the trace says how the C6 started and what its last crash left, on any image."""

    def test_the_p4_did_not_answer(self):
        code, lines = br_selftest.box_report(None)
        self.assertEqual(code, 1)
        self.assertIn("did not answer", lines[-1])

    def test_no_start_record_in_the_page(self):
        code, lines = br_selftest.box_report([entry(1), entry(5)])
        self.assertEqual(code, 2)
        self.assertIn("no start record", lines[-1])

    def test_start_without_a_crash_on_record(self):
        code, lines = br_selftest.box_report([entry(0xBB, code=1, v=(0, 20, 0, 0))])
        self.assertEqual(code, 0)
        self.assertIn("reset reason 1", lines[0])
        self.assertEqual(lines[-1], "BOX: no crash on record")

    def test_crash_on_record_is_put_together_from_its_parts(self):
        reason = b"assert failed: osi_assert_wrapper bt.c:579 (0)"
        tail = b"BLE assert: line 1234 in function box_test, param: 0xa, 0xb"
        page = [entry(0xBB, code=1, acl=1, v=(0, 20, 0, 0)),
                entry(0xBC, code=3, cis=4 | (1 << 8), acl=1, v=(0x4080E622, 0x4080E61E, 0, 0)),
                entry(0xBD, acl=7, v=(0x4081FFF0, *words(b"ble_ll_t", 8), 347000000)),
                entry(0xC9, v=(int.from_bytes(bytes.fromhex("4c5eec7f"), "little"), 77, 0, 0)),
                *[entry(0xBE, code=p, v=words(reason[16 * p:16 * p + 16])) for p in range(3)],
                entry(0xCA, code=0, v=(0x4080E622, 0x42001234, 0x4200ABCD, 0x40001000)),
                entry(0xCA, code=1, v=(0x42005678, 0, 0, 0)),
                *[entry(0xCB, code=p, v=words(tail[16 * p:16 * p + 16])) for p in range(4)],
                entry(0xB9, v=(1, 2, 3, 4))]  # a record of another kind does not belong to the report
        code, lines = br_selftest.box_report(page)
        self.assertEqual(code, 0)
        text = "\n".join(lines)
        self.assertIn("pc 0x4080E622", text)
        self.assertIn("in task 'ble_ll_t'", text)
        self.assertIn("image 4c5eec7f", text)
        self.assertNotIn("health", text)
        self.assertIn("BOX: crash on record", lines[-4])
        self.assertEqual(lines[-3], "BOX: reason: assert failed: osi_assert_wrapper bt.c:579 (0)")
        self.assertEqual(lines[-2], "BOX: last ROM output: BLE assert: line 1234 in function box_test, param: 0xa, 0xb")
        self.assertEqual(lines[-1], "BOX: addresses: 0x4080E622 0x4080E61E 0x4080E622 0x42001234 0x4200ABCD "
                                    "0x40001000 0x42005678")

    def test_reset_that_left_no_panic_record(self):
        page = [entry(0xBB, code=5, cis=1, acl=1), entry(0xBC, code=0xFF, cis=5 | (2 << 8), acl=1),
                entry(0xBD, acl=0, v=(0, 0, 0, 1000)), entry(0xC9, v=(1, 0, 0, 0))]
        code, lines = br_selftest.box_report(page)
        self.assertEqual(code, 0)
        self.assertEqual(lines[-1], "BOX: crash on record, without a panic record (a watchdog or brownout reset)")


class Verdict(unittest.TestCase):
    """The verdict names the first stage that did not work, so the next step is unambiguous."""

    def feed(self, *entries):
        s = br_selftest.Summary()
        for n, e in enumerate(entries):
            e["i"] = n
            s.feed([e])
        return s

    def radio(self, insert_ok=0, insert_fail=0, tx_done=0, rx_done=0, rx_captured=0, skipped=0):
        return entry(0xB1, cis=insert_fail, acl=skipped, v=(insert_ok, tx_done, rx_done, rx_captured))

    def test_no_selftest_entries(self):
        self.assertEqual(br_selftest.verdict(br_selftest.Summary())[0], "NOT_RUNNING")
        self.assertEqual(br_selftest.verdict(self.feed(entry(1), entry(5)))[0], "NOT_RUNNING")

    def test_inquiry_refused_by_engine(self):
        self.assertEqual(br_selftest.verdict(self.feed(entry(0xB4, code=0, cis=1)))[0], "ENGINE_REFUSED")

    def test_scheduler_rejects_raw_slots(self):
        s = self.feed(entry(0xB4, code=1, cis=1), self.radio(insert_ok=0, insert_fail=50))
        self.assertEqual(br_selftest.verdict(s)[0], "SCHED_REJECTS")

    def test_slots_never_executed(self):
        s = self.feed(entry(0xB4, code=1, cis=1), self.radio(insert_ok=500, skipped=500))
        self.assertEqual(br_selftest.verdict(s)[0], "SLOTS_NOT_RUN")

    def test_rx_slots_never_return(self):
        # Tab5, 2026-11-10: the first TX slot completed, its RX slot never came back and the engine stalled.
        s = self.feed(entry(0xB4, code=1, cis=1), self.radio(insert_ok=2, tx_done=1, rx_done=0))
        level, text = br_selftest.verdict(s)
        self.assertEqual(level, "RX_NEVER_RETURNS")
        self.assertIn("1 TX", text)

    def test_radio_runs_but_hears_nothing(self):
        s = self.feed(entry(0xB4, code=1, cis=1), self.radio(insert_ok=800, tx_done=400, rx_done=400))
        self.assertEqual(br_selftest.verdict(s)[0], "NO_ANSWER")

    def test_sync_word_matched_but_fhs_not_decoded(self):
        s = self.feed(entry(0xB4, code=1, cis=1),
                      self.radio(insert_ok=800, tx_done=400, rx_done=400, rx_captured=3),
                      entry(0xB0, code=1, acl=1, v=(400, 400, 3, 0)),
                      entry(0xB3, code=0xD0, cis=0x2C, acl=10))
        self.assertEqual(br_selftest.verdict(s)[0], "SYNC_ONLY")

    def test_packets_of_the_probe_windows_are_not_answers(self):
        # Tab5, 2026-11-10, fourth run: 96 probe windows received advertising packets, the inquiry heard nothing.
        s = self.feed(entry(0xB4, code=1, cis=1),
                      self.radio(insert_ok=1696, tx_done=800, rx_done=895, rx_captured=96),
                      entry(0xB0, code=1, acl=1, v=(800, 799, 0, 0)),
                      entry(0xB3, code=0xD0, cis=0xC7, acl=0))
        self.assertEqual(br_selftest.verdict(s)[0], "NO_ANSWER")

    def test_device_found(self):
        s = self.feed(entry(0xB4, code=1, cis=1),
                      self.radio(insert_ok=800, tx_done=400, rx_done=400, rx_captured=3),
                      entry(0xB2, code=0xC4, cis=0x0011, acl=1, v=(0x22334455, 0x240404, 0, 0)),
                      entry(0xB2, code=0xC0, cis=0x0011, acl=2, v=(0x22334455, 0x240404, 0, 0)))
        level, text = br_selftest.verdict(s)
        self.assertEqual(level, "INQUIRY_WORKS")
        self.assertIn("00:11:22:33:44:55", text)
        self.assertEqual(len(s.devices), 1)  # the same address in two rounds is one device

    def test_baseband_connection(self):
        ok = entry(0xC3, code=0x03, cis=11, v=(0x000B0000, 0, 0, 0))
        s = self.feed(entry(0xB4, code=1, cis=1),
                      self.radio(insert_ok=800, tx_done=400, rx_done=400, rx_captured=3),
                      entry(0xB2, code=0xC4, cis=0x0011, acl=1, v=(0x22334455, 0x240404, 0, 0)), ok)
        level, text = br_selftest.verdict(s)
        self.assertEqual(level, "CONNECTION_WORKS")
        self.assertIn("1 baseband connection", text)

    def test_page_that_fails_stays_at_inquiry_works(self):
        s = self.feed(entry(0xB4, code=1, cis=1),
                      self.radio(insert_ok=800, tx_done=400, rx_done=400, rx_captured=3),
                      entry(0xB2, code=0xC4, cis=0x0011, acl=1, v=(0x22334455, 0x240404, 0, 0)),
                      entry(0xC3, code=0x03, cis=11, v=(0x04, 0, 0, 0)))
        level, text = br_selftest.verdict(s)
        self.assertEqual(level, "INQUIRY_WORKS")
        self.assertIn("no baseband connection: 1 attempt(s) ended with status 0x04 (page timeout)", text)

    def test_latest_counters_win_and_old_entries_are_not_fed_twice(self):
        s = br_selftest.Summary()
        first = [dict(entry(0xB4, code=1, cis=1), i=0), dict(self.radio(insert_ok=10, tx_done=5, rx_done=5), i=1)]
        s.feed(first)
        s.feed(first + [dict(self.radio(insert_ok=90, tx_done=45, rx_done=45, rx_captured=1), i=2)])
        self.assertEqual(s.next_index, 3)
        self.assertEqual(s.radio["insert_ok"], 90)
        self.assertEqual(s.rounds_started, 1)


def adv_bytes_on_air(channel=37):
    """ADV_IND, random address, 37 payload bytes: the first eight bytes after the access address, whitened."""
    return br_selftest.ble_whiten(bytes([0x40, 0x25, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6]), channel)


def probe_result(probe, recipe, data=bytes(8), i=0):
    return entry(0xB8, code=probe, cis=recipe, i=i,
                 v=(0xB9000000, 0, int.from_bytes(data[:4], "little"), int.from_bytes(data[4:8], "little")))


class Whitening(unittest.TestCase):
    def test_channel_37_sequence(self):
        # The whitening sequence of advertising channel 37 as radios without BLE whitening have to apply it.
        self.assertEqual(br_selftest.ble_whiten(bytes(8), 37), bytes.fromhex("8dd257a13da766b0"))

    def test_matches_the_shift_register_of_the_specification(self):
        def spec(data, channel):  # Core Specification Vol 6 Part B 3.2: x^7 + x^4 + 1, position 0 = 1
            reg = [1] + [(channel >> (5 - n)) & 1 for n in range(6)]
            out = bytearray()
            for byte in data:
                v = 0
                for bit in range(8):
                    w = reg[6]
                    v |= (((byte >> bit) & 1) ^ w) << bit
                    reg = [w, reg[0], reg[1], reg[2], reg[3] ^ w, reg[4], reg[5]]
                out.append(v)
            return bytes(out)

        data = bytes(range(0x30, 0x50))
        for channel in (0, 11, 37, 38, 39):
            self.assertEqual(br_selftest.ble_whiten(data, channel), spec(data, channel))

    def test_is_its_own_inverse(self):
        data = bytes(range(40))
        self.assertEqual(br_selftest.ble_whiten(br_selftest.ble_whiten(data, 38), 38), data)


class Probes(unittest.TestCase):
    def test_reading_of_the_bytes_after_the_access_address(self):
        self.assertEqual(br_selftest.probe_reading(bytes(8)), "nothing received")
        self.assertIn("BLE advertising packet", br_selftest.probe_reading(adv_bytes_on_air()))
        self.assertIn("ADV_IND", br_selftest.probe_reading(adv_bytes_on_air()))
        # 0x0F is no advertising packet type and 0xFF no legal length, whitened or not.
        odd = br_selftest.ble_whiten(bytes([0x0F, 0xFF, 1, 2, 3, 4, 5, 6]), 37)
        self.assertIn("not a BLE advertising header", br_selftest.probe_reading(odd))

    def test_windows_are_counted_per_recipe(self):
        s = br_selftest.Summary()
        s.feed([probe_result(1, 0, i=0), probe_result(2, 1, adv_bytes_on_air(), i=1), probe_result(3, 1, i=2),
                probe_result(4, 0, i=3)])
        self.assertEqual(s.probes[0], {"windows": 2, "bytes": 0, "adv": 0})
        self.assertEqual(s.probes[1], {"windows": 2, "bytes": 1, "adv": 1})
        text = br_selftest.probe_summary(s)
        self.assertIn("recipe 0 (stock): 2 windows, 0 with bytes", text)
        self.assertIn("recipe 1 (window, short item): 2 windows, 1 with bytes (1 BLE advertising)", text)

    def test_no_probe_no_summary(self):
        self.assertEqual(br_selftest.probe_summary(br_selftest.Summary()), "")


class Restart(unittest.TestCase):
    """The trace indexes start again from zero when the C6 (and with it the P4) restarts in the middle of a trial."""

    def radio(self, i, tx_done):
        return entry(0xB1, v=(2 * tx_done, tx_done, tx_done, 0), i=i)

    def test_the_last_entry_read_tells_the_runs_apart(self):
        s = br_selftest.Summary()
        self.assertEqual(s.fetch_from, 0)
        self.assertTrue(s.same_run([]))  # nothing read yet: nothing to compare
        page = [self.radio(0, 10), self.radio(1, 20)]
        s.feed(page)
        self.assertEqual(s.fetch_from, 1)  # the last entry read is asked for again: it proves the run
        self.assertTrue(s.same_run(page[1:] + [self.radio(2, 30)]))
        self.assertFalse(s.same_run([]))  # the new run has not got that far yet
        self.assertFalse(s.same_run([dict(self.radio(1, 5), t_us=77)]))  # same index, another moment

    def test_counters_of_finished_runs_are_kept(self):
        # Tab5, 2026-11-10: the C6 stopped answering twice at 6490 TX slots; the image started a third time.
        s = br_selftest.Summary()
        s.feed([dict(entry(0xB4, code=1, cis=1), i=0), self.radio(1, 6490)])
        s.restart()
        self.assertEqual((s.runs, s.next_index, s.fetch_from), (2, 0, 0))
        self.assertEqual(s.radio, {})
        self.assertEqual(s.radio_sum()["tx_done"], 6490)
        s.feed([self.radio(0, 100)])
        self.assertEqual(s.radio_sum()["tx_done"], 6590)
        self.assertEqual(br_selftest.verdict(s)[0], "NO_ANSWER")  # not NOT_RUNNING: the first run did run


class Health(unittest.TestCase):
    def health(self, i, ll_ms, esp_ms, heap=100000, heap_min=90000):
        return entry(0xB9, cis=10, acl=1, v=(heap, heap_min, ll_ms * 1000, esp_ms * 1000), i=i)

    def test_controller_clock_that_stops_is_counted(self):
        s = br_selftest.Summary()
        fresh = s.feed([self.health(0, 1000, 5000), self.health(1, 3000, 7000), self.health(2, 3100, 9000)])
        self.assertEqual((fresh[1]["d_ll_us"], fresh[1]["d_esp_us"]), (2000000, 2000000))
        self.assertEqual(s.clock_stalls, 1)
        self.assertIn("CONTROLLER CLOCK", br_selftest.describe(fresh[2]))
        self.assertNotIn("CONTROLLER CLOCK", br_selftest.describe(fresh[1]))

    def test_lowest_heap_is_kept(self):
        s = br_selftest.Summary()
        s.feed([self.health(0, 0, 0, heap=100000, heap_min=90000), self.health(1, 2000, 2000, heap=40000, heap_min=30000)])
        self.assertEqual((s.heap_first, s.heap_last, s.heap_lowest), (100000, 40000, 30000))
        self.assertIn("free heap 100000 -> 40000 B (lowest 30000)", br_selftest.health_summary(s))

    def test_clock_difference_wraps_at_32_bits(self):
        s = br_selftest.Summary()
        e0 = entry(0xB9, v=(1, 1, 0xFFFFFF00, 0xFFFFFE00), i=0)
        e1 = entry(0xB9, v=(1, 1, 0x00000100, 0x00000000), i=1)
        fresh = s.feed([e0, e1])
        self.assertEqual((fresh[1]["d_ll_us"], fresh[1]["d_esp_us"]), (0x200, 0x200))


if __name__ == "__main__":
    unittest.main()
