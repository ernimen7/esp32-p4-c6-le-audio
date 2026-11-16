# Using LE Audio and Bluetooth Classic in your own ESP32-P4 firmware

This guide adds LE Audio to an existing ESP-IDF project on an ESP32-P4 + ESP32-C6 board; section 6 adds Bluetooth
Classic (A2DP source, experimental) next to it.
[`p4_le_audio/test/compile_check`](../p4_le_audio/test/compile_check) is the smallest firmware that follows it, and
the Tab5 demo [`examples/tab5_player`](../examples/tab5_player) a complete one (UI, bonds in NVS, device list, C6
installer). Both are built in CI, so they always match the API.

## 1. What to take from this repository

| Path | Why |
|---|---|
| `p4_le_audio/` | The LE Audio host: BAP unicast client, CSIP, LC3, ISO over HCI, C6 firmware update. C API in `include/le_audio.h`. |
| `components/espressif__esp_hosted/` | esp_hosted 1.4.0 host with the patches the host needs: a raw HCI channel that carries ISO packets, transport bring-up without Wi-Fi, a longer OTA end timeout ([PATCHES.md](../components/espressif__esp_hosted/PATCHES.md)). The stock component does not work. |
| `third_party/liblc3` | Fetched by `sh tools/fetch_deps.sh` (liblc3 v1.1.3). Elsewhere: set `LIBLC3_DIR`. |
| `c6_firmware/` or `esp32c6-firmware-*.zip` from Releases | The ESP32-C6 firmware with the CIS link layer (and, from 1.5.0, the Classic one). Without it `le_audio_init()` returns `ESP_ERR_NOT_SUPPORTED`. |
| `p4_bt_classic/` (optional) | The Bluetooth Classic host: LMP, L2CAP, SDP, AVDTP source, AVRCP, SBC encoder. C API in `include/bt_classic.h`. See section 6. |

Add the two components to your project (`EXTRA_COMPONENT_DIRS` or copy them into `components/`), list
`p4_le_audio` in the `REQUIRES` / `PRIV_REQUIRES` of the component that uses it, and add `espressif/esp_wifi_remote`
0.8.5 to your `idf_component.yml` (esp_hosted registers its Wi-Fi channel with it even in a BLE-only firmware).

## 2. Configuration

Start from [`p4_le_audio/test/compile_check/sdkconfig.defaults`](../p4_le_audio/test/compile_check/sdkconfig.defaults)
and keep at least:

- PSRAM enabled (`CONFIG_SPIRAM=y`, `CONFIG_SPIRAM_ALLOW_NOINIT_SEG_EXTERNAL_MEMORY=y`): host state and thread
  stacks live in PSRAM.
- The esp_hosted host on SDIO with the slave target ESP32-C6 (`CONFIG_SLAVE_IDF_TARGET_ESP32C6=y`,
  `CONFIG_ESP_HOSTED_SDIO_HOST_INTERFACE=y`) and **your board's** SDIO pins, bus width, clock and C6 reset GPIO.
  The values in the file are the M5Stack Tab5 wiring.
- `CONFIG_FREERTOS_HZ=1000`.

Power and enable the ESP32-C6 the way your board needs it before the transport comes up (on the Tab5 an IO
expander switches the C6 supply, `WLAN_PWR_EN`).

## 3. Bring-up order

```c
// 1. Transport to the C6. A firmware that uses Wi-Fi gets it from esp_wifi_init(); a BLE-only firmware must
//    bring it up itself (patched esp_hosted, esp_hosted_cyberdeck.h):
ESP_ERROR_CHECK(esp_hosted_cyberdeck_connect(30000));

// 2. Bond storage: keys "bt.bond" (list of bonds) and "bt.irk" (our IRK), both secrets. The callbacks run on
//    threads with PSRAM stacks and must not touch flash: load the values from NVS into RAM before le_audio_init,
//    serve them from RAM, and write changes back from a task with an internal stack.
le_audio_config_t cfg = LE_AUDIO_CONFIG_DEFAULT();
cfg.kv = my_bond_store;          // set == NULL: read-only, new pairings stay in RAM
cfg.allow_pairing = true;        // false: only saved earbuds are used
cfg.device_name = "My device";

// 3. Host start. ESP_ERR_NOT_SUPPORTED: the C6 runs a firmware without CIS (step 5).
esp_err_t err = le_audio_init(&cfg);

// 4. Earbuds: saved ones reconnect in the background (auto_connect); new ones are picked by the user.
le_audio_device_t found[12];
int n = le_audio_scan(found, 12, 6);
le_audio_connect_device(&found[user_choice]);   // pairs a new device, connects a saved one with its key

// 5. Audio: interleaved stereo int16 at 48 kHz from your own task. The call blocks while the queue is full, so
//    the stream paces your decoder.
le_audio_write_pcm(pcm, frames, 200);
```

Calls other than `le_audio_write_pcm`, `le_audio_set_volume`, `le_audio_get_status` and
`le_audio_take_media_command` can block for seconds: call them from a task, never from an ISR or the UI thread.
Earbud gestures arrive through `le_audio_take_media_command`; report your player state with
`le_audio_set_media_state`. Do not pair the first device a scan returns on your own: it may be someone else's.

## 4. Installing the C6 firmware from your firmware (OTA)

The C6 is reachable only over SDIO, so your P4 firmware sends the image. Link the image into your app and let the
user start the install:

```cmake
# your component's CMakeLists.txt
target_add_binary_data(${COMPONENT_TARGET} "path/to/network_adapter.bin" BINARY)
```

```c
extern const uint8_t c6_img_start[] asm("_binary_network_adapter_bin_start");
extern const uint8_t c6_img_end[]   asm("_binary_network_adapter_bin_end");

char carried[33];
le_audio_c6_image_version(c6_img_start, c6_img_end - c6_img_start, carried, sizeof(carried));
// compare with le_audio_status_t.coprocessor_fw; ask the user; then:
le_audio_stop();
if (le_audio_c6_install(c6_img_start, c6_img_end - c6_img_start, my_progress, NULL) == ESP_OK) {
    vTaskDelay(pdMS_TO_TICKS(8000));   // the C6 restarts ~5 s after verifying the image
    esp_restart();                     // the SDIO link does not survive the C6 restart
}
```

`le_audio_c6_install` needs only the transport, not `le_audio_init`, so it also works when the C6 still runs a
firmware without LE Audio. Never install automatically at boot: the user may run another C6 firmware on purpose.
A firmware with a network endpoint can instead stream an uploaded image through the same esp_hosted RPCs and use
`python tools/c6_ota.py <device-ip> --bin network_adapter.bin`.

After the install the image runs on trial on the C6 (`fw_guard`). It confirms itself after 60 s if SDIO and BLE
work and the P4 talks to it: with working Wi-Fi if your firmware turned Wi-Fi on, with HCI traffic delivered in
both directions if it did not. Otherwise it rolls back by itself (3 crashes, 10 boots, 600 s, RTC watchdog). While
an image is on trial the C6 refuses another OTA (`ESP_ERR_INVALID_STATE`).

## 5. Pitfalls we hit

- **Light sleep and DFS:** the stream thread holds the CPU at full speed and blocks light sleep while it streams
  (`esp_pm` locks inside the component). If you add your own power management, do not release them.
- **SD card on the same SDMMC controller as the C6:** a slow or failing card stalls SDIO; the deadline queue rides
  out about 70 ms. Use a good card and large reads.
- **Second earbud:** join it before the stream starts (the API does this). Joining against a running CIG often
  fails (0x3E); see the known limitations in the [README](../README.md#known-limitations).
- **Legacy I2C driver:** components that pull in the legacy I2C driver next to `i2c_master` abort at start; on the
  Tab5 this was `esp_codec_dev` (`CONFIG_CODEC_I2C_BACKWARD_COMPATIBLE` off).

## 6. Bluetooth Classic next to LE Audio (experimental)

`p4_bt_classic` plays to a Bluetooth Classic speaker or headphones (A2DP source, SBC) through the same C6 and the
same transport. It needs C6 firmware 1.5.4 or newer (earlier 1.5.x images could restart the C6 at a Classic
command after LE connection activity); the Tab5 demo uses both hosts and is the reference
([`examples/tab5_player/main/devices.cpp`](../examples/tab5_player/main/devices.cpp)).

```c
// After the transport is up (and after le_audio_init, if you use both hosts: they share the HCI channel, each
// takes its own packets).
bt_classic_config_t cfg = BT_CLASSIC_CONFIG_DEFAULT();
cfg.device_name = "My device";
cfg.kv = my_classic_store;       // one key, "bt.classic_bond": up to four remembered devices with their link keys
                                 // (a secret). Same rule as the LE store: serve it from RAM, write NVS elsewhere.
bt_classic_init(&cfg);
if (!bt_classic_c6_supported()) { /* C6 firmware without Classic, or its crash fuse is open (see below) */ }

bt_classic_device_t found[16];
int n = bt_classic_scan(found, 16, 6500, true);    // 6.5 s inquiry, then the names of the audio devices
bt_classic_connect_device(&found[user_choice]);    // pairs a new device; a remembered one uses its key
// later: bt_classic_connect_bonded() connects the remembered device that was used last
bt_classic_start();                                // AVDTP START

// From your audio task. timeout_ms > 0 waits for room, so a file decoder is paced by the stream;
// timeout_ms <= 0 never waits, for a producer with its own clock. Any sample rate, mono or stereo.
bt_classic_write_pcm(pcm, frames, 44100, 2, 100);
```

Rules that are yours to keep:

- **One Bluetooth device at a time.** Before any Classic call that uses the radio (`bt_classic_scan`,
  `bt_classic_connect_*`) disconnect the LE device (`le_audio_disconnect`) and wait for it; do not start an LE
  scan or connection while a Classic one runs. The C6 answers an LE scan or connection attempt with Command
  Disallowed while its Classic engine works, but it does not refuse a Classic command while an LE connection
  exists, and that combination has not been tried on 1.5.4. Run both hosts' radio calls from one worker, as the
  demo does.
- `bt_classic_scan`, `bt_classic_connect_*`, `bt_classic_start` and `bt_classic_disconnect` block for seconds
  (a page that nobody answers takes about 17 s): call them from a task.
- The speaker's buttons arrive through `bt_classic_take_media_command`; the volume is `bt_classic_set_volume`
  (0..255, the scale of `le_audio_set_volume`).

When the sound stutters, read `bt_classic_get_diag`: `tx_size_level` (0 = 3-slot packets; a link that stays at 1
is too slow for the stream), `size_strikes`, `tx_flushes`, `bitpool`, `link_busy_pct`, `media_lost`. The bitpool
follows the link load by itself (`bt_classic_set_link_limits`).

### When a Classic device does not connect

`bt_classic_connect_*` tell three failures apart: `ESP_ERR_TIMEOUT` (no answer to the page, or the setup did not
finish in its 12 s), `ESP_ERR_NOT_ALLOWED` (the device answered and refused the audio channel - headphones do that
while another phone or computer holds them; tell the user to disconnect them there) and `ESP_FAIL` (pairing or
authentication failed, or the link was lost).

For everything else the host keeps the conversation of the current or the last link:
`bt_classic_lmp_trace_text()` (the last 64 LMP messages: direction, a tick of about half a second, the first five
bytes, the length) and `bt_classic_l2cap_trace_text()` (the last 64 L2CAP frames of signalling, SDP, AVDTP and
AVRCP: direction, tick, channel, up to 24 payload bytes, the length; media packets are left out). Read them after
the failed call and put them in your log or on a diagnostic page; the demo logs them
([`examples/tab5_player/main/devices.cpp`](../examples/tab5_player/main/devices.cpp), `logClassicFailure`). The
last message the device answered, or the result it refused with, is usually the whole diagnosis: the three fixes
of 0.2.1 were a refused `LMP_io_capability_req`, an SDP request for 32 bytes that got 68, and an L2CAP connection
response "no resources". A buffer of 1.5 kB holds the LMP text and one of 4.4 kB the L2CAP text. Neither holds a
device address; the first characters of the device's name can show.

**Crash fuse and black box of the C6.** Two crashes of the C6 while its Classic layer works switch that layer off
until the next start (LE Audio and Wi-Fi go on; `bt_classic_c6_supported()` then returns false), and the record is
forgotten after three minutes without a crash. After any crash the C6 keeps what its panic left - reason, task,
code addresses from the stack and the last characters its ROM printed, where the closed Bluetooth controller names
a failed assertion of its own - in flash, and writes it at every start into the trace that vendor command
0xFC30 sub-command 0x0A returns (records 0xBB, 0xBC to 0xBE, 0xC9 to 0xCB; formats in
`c6_firmware/main/br_c6_core.c`). A firmware that serves that trace as JSON (`GET /api/c6/cis/trace?from=N`, the
way the firmware this project was extracted from does) can be read with
`python tools/br_selftest.py HOST --box`. If your device restarts when a Classic call starts, that record is the
first thing to read and to attach to a bug report.

What it is not: basic rate only (no EDR), SBC only, source only, one device, and tested with one speaker and one
pair of headphones - see the
known limitations in the [README](../README.md#known-limitations).
