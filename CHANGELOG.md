# Changelog

## [0.2.0] - 2026-11-14

Bluetooth Classic next to LE Audio. Classic is experimental: one speaker, a few days.

### Added
- Bluetooth Classic basic-rate link layer for the ESP32-C6 (`br_ll/`, "Soft-BR"): inquiry, page, connection, ARQ,
  AFH, E0 encryption, 1- and 3-slot packets sent and received with the BLE radio through the stock controller's
  scheduler, so Wi-Fi and BLE keep their turns. Unit tests on the Core specification's sample data and a
  discrete-event simulator with eight link conditions.
- ESP32-C6 firmware 1.5.4: the Classic adapter (`c6_firmware/main/br_c6_*`) next to the CIS adapter, vendor HCI
  commands 0xFC31, a guard that refuses LE scans and LE connection attempts while the Classic engine works, a crash
  fuse for the Classic layer that forgives after three minutes without a crash.
- A black box in the ESP32-C6 firmware: after a crash of the chip the next start keeps in flash the panic reason,
  the task, code addresses from the stack and the last characters the ROM printed (the closed Bluetooth controller
  names a failed assertion of its own only there), and every start writes that record to the trace the host
  already reads. `python tools/br_selftest.py HOST --box` prints it.
- ESP32-P4 Bluetooth Classic host as an ESP-IDF component (`p4_bt_classic/`): LMP with Secure Simple Pairing and
  legacy PIN pairing, L2CAP, SDP, AVDTP source, AVRCP, an SBC encoder, a bitpool that follows the link load, up to
  four remembered devices, diagnostics (`bt_classic_get_diag`). Host tests and a compile check.
- `le_audio_forget()`: erases the key of one LE device (both earbuds of a connected set).
- Tab5 demo: one device list for LE Audio and Classic with the remembered devices on top (`main/devices.cpp`,
  `main/bt_list_model.cpp` with a host test); the sound goes to whichever device is connected.

### Changed
- Tab5 demo: the device list is always on screen; tap connects or switches, tap on the connected device
  disconnects, hold forgets. The boot stages are one line.
- The LE Audio host ignores the ACL handle and the credit returns of the Classic connection.

### Fixed
- Classic link layer: a packet size is given up only after a confirming round, and a lowered size comes back
  after two seconds. Before, the tested speaker's pauses of about 50 ms were taken for a refusal of 3-slot packets
  and the stream stayed on 1-slot packets, too slow for the sound, until the connection ended.

- Classic adapter of the C6: an executed Soft-BR schedule item that the baseband still points at is no longer
  handed to the controller's recycle pass, which would copy it into a spare block of its own and keep the
  original (hook `r_ble_lll_sched_pop_executed_sch`). That copy was the assertion `r_ble_lll_mmgmt_block_copy`
  line 912 and, when it went through, a broken scheduler queue: the C6 restarted at a connection attempt or hung
  in a scan, after the host's background reconnect of LE earbuds. The adapter takes such an RX slot back
  without waiting for the controller. Stopping the engine no longer deletes its items from the controller's
  queue either.

### Known limitations
- One audio device at a time: the application has to disconnect the LE device before it uses a Classic one (the
  demo does). A Classic page while an LE connection is up has not been tried on C6 firmware 1.5.4.
- Tab5 demo: switching between devices while one is connected, forgetting a device and saving a new pairing have
  not been verified on hardware in the demo itself (forgetting works in the firmware this project was extracted
  from, with the same host components).
- Basic rate only (no EDR), SBC only, source only; not a qualified BR/EDR implementation.

## [0.1.0] - 2026-11-06

First public version.

### Added
- ESP32-C6 CIS link layer on the stock BLE controller (2 CIS in 1 CIG, NSE 2, FT 4, CCM), HCI ISO data path.
- CIS engine (`cis_ll/`) with host unit tests and a discrete-event simulator (drift, host jitter, NSE 2 gates).
- ESP32-C6 firmware 1.4.85 (`c6_firmware/`): esp_hosted slave + CIS adapter, build-time hooks checked in the linked
  ELF, `fw_guard` (trial after OTA, self-confirm, automatic rollback), crash fuse, hang trace, vendor diagnostics.
  `fw_guard` confirms an image for a Wi-Fi host only with working Wi-Fi, and for a BLE-only host with HCI traffic
  delivered in both directions within the 60 s window.
- ESP32-P4 LE Audio host as an ESP-IDF component (`p4_le_audio/`): HCI/ATT/SMP over esp_hosted SDIO, reconnect from
  a saved bond with encryption, PACS/ASCS/BAP unicast client, CSIP set member join (RSI/SIRK), dual LC3 (liblc3),
  ISO credits with lost-NOCP recovery (500 ms) and an SDU deadline queue (25 ms), stream thread holding full CPU
  speed, background manager (reconnect, join before the stream, auto start), scan and connect of the device the
  user picks, CIS statistics from the C6, Media Control (gestures), and the C6 firmware update over SDIO
  (`le_audio_c6_install`). Host tests of the pure models, including the P4 <-> C6 HCI contract through the real CIS
  engine and the C6 image header check.
- Patched esp_hosted 1.4.0 host component: raw HCI channel that carries ISO packets, transport bring-up without
  Wi-Fi, TX buffer ownership fix in the RPC path, longer OTA end timeout.
- `p4_le_audio/test/compile_check`: the smallest firmware that uses the API, built in CI.
- M5Stack Tab5 demo (`examples/tab5_player/`): MP3 files from the SD card to both earbuds, touch UI, device list
  for pairing, bonds in NVS, a copy of the log on the SD card, and the C6 firmware embedded in the app and installed
  with `le_audio_c6_install` after a tap. For it, `components/` also carries the patched fatfs (exFAT, 16 kB SD
  transfers) and the Tab5 display stack. Built in CI.
- Documentation: integration guide, architecture, C6 link layer, flashing and recovery, measurements; notes for AI
  coding agents (`AGENTS.md`).
- Tools: `c6_ota.py` (C6 update through a P4 network endpoint), `privacy_scan.py`, `fetch_deps.sh`. CI workflow.

### Verified on hardware (M5Stack Tab5, Galaxy Buds3 Pro)
- Stereo playback with both earbuds, reconnect from saved keys, the second earbud joining before the stream,
  pairing never-paired earbuds picked from a device list, earbud gestures.
- 15 minutes of stereo at home with 0.016 % / 0.07 % SDUs lost on air; a crowded train without audible dropouts.
- C6 firmware 1.4.85 installed from the P4 with `le_audio_c6_install` in the Tab5 demo (over 1.4.84, and over
  itself); `fw_guard` confirmed it with a Wi-Fi host and with the BLE-only demo (13 minutes of stereo past the 600 s
  trial limit, no rollback).

### Known issues
- The second earbud's CIS sometimes drops with 0x08 a few seconds after the stream starts (in a series right after
  connecting); the host re-joins it. Under investigation.
- Installing over the M5Stack factory C6 firmware is not tested yet.
