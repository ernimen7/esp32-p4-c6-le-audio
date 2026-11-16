---
name: Device test report
about: Report how LE Audio earbuds, or a Bluetooth Classic speaker or headphones, work with this project
labels: earbud-report
---

**Device**: (earbuds, speaker or headphones: brand, model, firmware version if you know it)
**Board**: (M5Stack Tab5 / other P4 + C6 board)
**Firmware**: P4 build id and C6 version (`/api/status` -> bt.coprocessor_fw)

- [ ] Both earbuds connect (stereo, 2 CIS)
- [ ] Audio plays without dropouts for 5 minutes
- [ ] Earbuds reconnect automatically after taking them out of the case

For a Bluetooth Classic speaker or headphones instead:

- [ ] It pairs and plays
- [ ] It connects again with the saved pairing
- [ ] Audio plays without dropouts for 5 minutes

**If a Classic device does not connect**: the lines `Classic LMP trace:` and `Classic L2CAP trace:` that the Tab5
demo writes to its log (`tab5_player.log` on the SD card) after the failed attempt, or the output of
`bt_classic_lmp_trace_text()` and `bt_classic_l2cap_trace_text()` from your own firmware. They hold no addresses;
the first characters of the device's name can show. Say whether another phone or computer was connected to the
device at the time.

**Measurement** (optional, see docs/measurements.md): SDU air loss per CIS, dropouts, environment (home / crowded).

**Log excerpt** around any problem (remove addresses and keys):
