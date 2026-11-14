#!/bin/sh
# Builds the ESP32-C6 firmware (esp_hosted slave + LE Audio CIS link layer) in the pinned ESP-IDF container.
# Nothing is flashed.
# Usage: sh c6_firmware/build.sh               -> c6_firmware/build/network_adapter.bin
#        sh c6_firmware/build.sh --guard-test  -> c6_firmware/build_guardtest/network_adapter.bin (fw_guard test
#           image: never confirms itself, version 1.4.49, separate sdkconfig)
#        sh c6_firmware/build.sh --guard-test-wpa2 -> c6_firmware/build_guardtest_wpa2/ (the same without WPA3:
#           the station joins a WPA2/WPA3 access point with WPA2 and cannot join a WPA3-only one)
# Mounts the whole repository, because main/CMakeLists.txt compiles the CIS engine from its single source, cis_ll/.
# Order: host tests (fw_guard, CIS engine), idf.py build, hook verification in the linked ELF.
# The ESP-IDF image is pinned by digest (a tag can be re-pushed, a digest cannot).
set -e
IDF_IMAGE="espressif/idf:v5.5.5@sha256:a9231d0697ab8f7517cc072e93b7c83e04907bfbfba80b6440d7dbbf90665cf2"
VARIANT="${1:-}"
case "$VARIANT" in ""|--guard-test|--guard-test-wpa2) ;; *) echo "usage: sh $0 [--guard-test|--guard-test-wpa2]"; exit 2 ;; esac
FW="$(cd "$(dirname "$0")/.." && pwd)"
# Git Bash on Windows: host path as C:/..., container paths without MSYS conversion.
case "$(uname -s)" in MINGW*|MSYS*) FW="$(cd "$FW" && pwd -W)"; export MSYS_NO_PATHCONV=1 ;; esac
# BR_ST_EXTRA_PEER=aa:bb:cc:dd:ee:ff in the environment: the bench self-test also pages that device (it need not be
# discoverable). The address goes into the image only, never into the repository.
# BR_ST_PASSIVE=1 in the environment: the test image runs no self-test of its own - it waits for the host like a
# regular image, and keeps what the test image adds for finding a crash (the panic record and the trace).
# BR_ST_CRASH_TEST=1 in the environment: the test image stops itself once, a minute after its start, the way a
# failed assertion of the Bluetooth controller does - to see on the chip what the black box keeps of it.
# BR_ST_ABORT_TEST=1 in the environment: the test image starts a page every two seconds and gives the previous one
# up (BR_VS_ABORT_ALL), the way a host's name requests stop the engine in mid-flight; the device paged is
# BR_ST_EXTRA_PEER, else an address nobody has.
# BR_ST_TRIAL_SECS=900 in the environment: the test image is rolled back after that many seconds instead of 420
# (for a sound trial, where a person has to pair and listen; 420 to 1800).
docker run --rm -e VARIANT="$VARIANT" -e BR_ST_EXTRA_PEER -e BR_ST_TRIAL_SECS -e BR_ST_PASSIVE -e BR_ST_CRASH_TEST -e BR_ST_ABORT_TEST -v "$FW:/fw" -w /fw/c6_firmware "$IDF_IMAGE" bash -c '
	set -e
	. /opt/esp/idf/export.sh >/dev/null 2>&1
	sh test/run_host_tests.sh
	sh ../cis_ll/test/run.sh
	sh ../br_ll/test/run.sh
	sh ../br_ll/sim/run.sh
	if [ "$VARIANT" = "--guard-test" ] || [ "$VARIANT" = "--guard-test-wpa2" ]; then
		B=build_guardtest
		DEFS="sdkconfig.defaults;sdkconfig.guardtest"
		if [ "$VARIANT" = "--guard-test-wpa2" ]; then
			B=build_guardtest_wpa2
			DEFS="$DEFS;sdkconfig.wpa2"
		fi
		idf.py -B "$B" -D IDF_TARGET=esp32c6 -D SDKCONFIG="$B/sdkconfig" -D "SDKCONFIG_DEFAULTS=$DEFS" \
			-D "BR_ST_EXTRA_PEER=$BR_ST_EXTRA_PEER" -D "BR_ST_TRIAL_SECS=$BR_ST_TRIAL_SECS" \
			-D "BR_ST_PASSIVE=$BR_ST_PASSIVE" -D "BR_ST_CRASH_TEST=$BR_ST_CRASH_TEST" \
			-D "BR_ST_ABORT_TEST=$BR_ST_ABORT_TEST" build
		grep -q "^CONFIG_CYBERDECK_FW_GUARD_TEST=y" "$B/sdkconfig" || { echo "missing CYBERDECK_FW_GUARD_TEST"; exit 1; }
		if [ "$VARIANT" = "--guard-test-wpa2" ]; then
			grep -q "^# CONFIG_ESP_WIFI_ENABLE_WPA3_SAE is not set" "$B/sdkconfig" || { echo "WPA3 is still on"; exit 1; }
		fi
	else
		B=build
		[ -f sdkconfig ] || idf.py set-target esp32c6 >/dev/null
		grep -q "^CONFIG_CYBERDECK_FW_GUARD_TEST=y" sdkconfig && { echo "sdkconfig contains the test image"; exit 1; }
		idf.py build
	fi
	python3 cmake/verify_hooks.py --elf "$B/network_adapter.elf" --map "$B/network_adapter.map" \
		--hooks cmake/ble_hooks.txt \
		--orig-lib "$IDF_PATH/components/bt/controller/lib_esp32c6/esp32c6-bt-lib/esp32c6/libble_app.a"
'
