# tab5_player - MP3 player for the M5Stack Tab5 with LE Audio and Bluetooth Classic

Demo application for the **M5Stack Tab5** (ESP32-P4 + ESP32-C6). It plays every `*.mp3` under `/sd/music`
(recursive, sorted, in a loop) to the Bluetooth audio device you pick from one list:

- **LE Audio earbuds** - BAP unicast, CSIP, two CIS, LC3 stereo at 48 kHz ([`p4_le_audio`](../../p4_le_audio));
- **Bluetooth Classic speakers and headphones** (experimental) - A2DP source with SBC at 44.1 kHz and AVRCP, through
  the Soft-BR link layer in the C6 firmware ([`p4_bt_classic`](../../p4_bt_classic)).

One audio device plays at a time; the sound goes to whichever is connected.

## Requirements

- The ESP32-C6 firmware of this project (`c6_firmware/`, 1.5.4 or newer for Classic). The player carries
  `c6_firmware/build/network_adapter.bin` inside `tab5_player.bin`: if the C6 runs something else, the boot line
  says so and **C6 firmware -> Install** updates it over SDIO in about 30 s. A firmware that does not work goes
  back to the previous one by itself (`fw_guard`).
- LE Audio earbuds or a Bluetooth Classic speaker or headphones.
- A microSD card (FAT32 or exFAT) with MP3 files under `/music`.

## The screen

- **Devices** (left): remembered devices on top - the connected one first, then those seen in the last scan - and
  the devices found nearby below, audio devices first, LE Audio and Classic together.
  - Tap a device: connect it. If another one is connected, it is disconnected first.
  - Tap the connected device: disconnect (after a question).
  - Hold a remembered device: forget it (its pairing key is erased, after a question).
  - A new device has to be in pairing mode; other BLE devices are listed in grey and cannot be chosen.
- **Scan**: an LE scan of 6 s, then a Classic inquiry of 6.5 s. With a Classic device connected there is no scan
  (it would end the connection); with earbuds connected only the LE scan runs.
- **Disconnect**, **Play / Pause**, **Next**, **Vol -**, **Vol +**: one volume for both kinds of device. A Classic
  stream is suspended after 5 s of pause and started again when the music continues.
- **C6 firmware**: the version on the C6 and the one in the player; installs after you confirm.
- The right side shows where the sound goes and the counters of that link (bitpool and lost packets for Classic,
  per-earbud state and loss for LE Audio).

At start the player connects a remembered device by itself: earbuds if they answer, otherwise the Classic device
used last.

## Why one manager for both

The two hosts do not know each other, and the radio serves one audio device at a time: paging a Classic device
while an LE connection exists locks the ESP32-C6 up. All Bluetooth actions of the player therefore go through one
worker task ([`main/devices.cpp`](main/devices.cpp)) that disconnects the other kind first. The order of the list is
a pure function with a host test ([`main/bt_list_model.cpp`](main/bt_list_model.cpp),
`sh examples/tab5_player/test/host/run.sh`). Use the same pattern in your own application.

## Build

```sh
sh c6_firmware/build.sh                     # c6_firmware/build/network_adapter.bin, must end with RESULT: PASS
sh examples/tab5_player/build.sh            # examples/tab5_player/build/tab5_player.bin
```

## Flash over USB (never done automatically)

```sh
cd examples/tab5_player/build
python -m esptool --chip esp32p4 -p <PORT> -b 460800 --before default_reset --after hard_reset write_flash "@flash_args"
```

This flashes the ESP32-P4 only; the ESP32-C6 is updated only when you tap **C6 firmware -> Install**.

Bonds are kept in NVS in the layout of the firmware this project was extracted from (namespace `sec`: `bt.bond`,
`bt.irk`, `bt.cbond`), plus the names of the LE devices the player connected (namespace `tab5player`).
`CONFIG_TAB5_PLAYER_SAVE_BONDS=n` makes the store read-only: new pairings then last until the next reset.
