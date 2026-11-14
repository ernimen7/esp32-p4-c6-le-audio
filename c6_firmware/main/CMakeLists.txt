if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/common")
    set(common_dir "${CMAKE_CURRENT_SOURCE_DIR}/common")
else()
    set(common_dir "../../common")
endif()

set(COMPONENT_SRCS "slave_control.c" "${common_dir}/proto/esp_hosted_rpc.pb-c.c" "protocomm_pserial.c" "app_main.c" "slave_bt.c" "mempool.c" "stats.c"  "mempool_ll.c" "fw_guard.c" "fw_guard_policy.c")
set(COMPONENT_ADD_INCLUDEDIRS "." "${common_dir}" "${common_dir}/log" "${common_dir}/proto" "${common_dir}/rpc" "${common_dir}/transport")

# Select BT UART code based on IDF Target
if(CONFIG_IDF_TARGET_ESP32)
    list(APPEND COMPONENT_SRCS slave_bt_uart_esp32.c)
elseif(CONFIG_IDF_TARGET_ESP32C3 OR CONFIG_IDF_TARGET_ESP32S3)
    list(APPEND COMPONENT_SRCS slave_bt_uart_esp32c3_s3.c)
else()
    list(APPEND COMPONENT_SRCS slave_bt_uart_esp32xx.c)
endif()

if(CONFIG_ESP_SDIO_HOST_INTERFACE)
    list(APPEND COMPONENT_SRCS sdio_slave_api.c)
elseif(CONFIG_ESP_SPI_HOST_INTERFACE)
    list(APPEND COMPONENT_SRCS spi_slave_api.c)
elseif(CONFIG_ESP_SPI_HD_MODE)
    list(APPEND COMPONENT_SRCS spi_hd_slave_api.c)
else(CONFIG_ESP_UART_HOST_INTERFACE)
    list(APPEND COMPONENT_SRCS uart_slave_api.c)
endif()

# CIS engine (<repo>/cis_ll) and Soft-BR Classic engine (<repo>/br_ll) + C6 adapters.
set(cis_ll_dir "${CMAKE_CURRENT_SOURCE_DIR}/../../cis_ll")
set(br_ll_dir  "${CMAKE_CURRENT_SOURCE_DIR}/../../br_ll")
if(CONFIG_BT_ENABLED AND CONFIG_IDF_TARGET_ESP32C6)
    list(APPEND COMPONENT_SRCS
        "${cis_ll_dir}/cis_engine.c" "${cis_ll_dir}/cis_proto.c" "${cis_ll_dir}/cis_crypto.c"
        "cis_c6_core.c" "cis_c6_radio.c" "cis_c6_llcp.c" "cis_c6_crash.c" "cis_c6_hang.c"
        "${br_ll_dir}/br_proto.c" "${br_ll_dir}/br_hop.c" "${br_ll_dir}/br_air.c"
        "${br_ll_dir}/br_crypto.c" "${br_ll_dir}/br_engine.c"
        "br_c6_core.c" "br_c6_radio.c" "br_c6_crash.c")
    list(APPEND COMPONENT_ADD_INCLUDEDIRS "${cis_ll_dir}" "${br_ll_dir}")
    # The Soft-BR engine builds and ciphers every packet between two radio slots, in the link layer task, and how
    # long that takes decides how many packets a second the link carries. The firmware as a whole is built for
    # debugging (-Og); with that the cipher took 660 us for 340 bytes on the chip (radio run 25). These five
    # files, which the host tests cover, are built for speed; the last -O on the command line is the one used.
    set_source_files_properties(
        "${br_ll_dir}/br_proto.c" "${br_ll_dir}/br_hop.c" "${br_ll_dir}/br_air.c"
        "${br_ll_dir}/br_crypto.c" "${br_ll_dir}/br_engine.c"
        PROPERTIES COMPILE_OPTIONS "-O2")
endif()

if(CONFIG_CYBERDECK_WIFI_TAP)
    list(APPEND COMPONENT_SRCS "wifi_tap.c")
endif()

register_component()

# br_c6_core.c notes where a panic happened before the stock handler restarts the chip (trace 0xBC..0xBE, 0xC9..0xCB).
if(CONFIG_BT_ENABLED AND CONFIG_IDF_TARGET_ESP32C6)
    target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=esp_panic_handler")
endif()

# Bench self-test image: it never confirms itself, so the trial time is only the wait for the rollback. 420 s is
# enough for a radio run. A sound trial needs longer (build.sh passes BR_ST_TRIAL_SECS when it is set in the
# environment): the player takes two of those seven minutes to install, and in sound trial 9 the rest ran out
# before the speaker was connected.
if(CONFIG_CYBERDECK_BR_SELFTEST)
    if(BR_ST_TRIAL_SECS MATCHES "^[0-9]+$" AND BR_ST_TRIAL_SECS GREATER_EQUAL 420 AND BR_ST_TRIAL_SECS LESS_EQUAL 1800)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE FW_GUARD_TRIAL_SECS=${BR_ST_TRIAL_SECS}u)
    elseif(BR_ST_TRIAL_SECS)
        message(FATAL_ERROR "BR_ST_TRIAL_SECS=${BR_ST_TRIAL_SECS}: a number of seconds from 420 to 1800")
    else()
        target_compile_definitions(${COMPONENT_LIB} PRIVATE FW_GUARD_TRIAL_SECS=420u)
    endif()
    # One more device for the self-test to page (build.sh passes BR_ST_EXTRA_PEER=aa:bb:cc:dd:ee:ff when it is set
    # in the environment): the six address bytes, least significant first, as the macro BR_ST_EXTRA_PEER.
    if(BR_ST_EXTRA_PEER)
        string(REPLACE ":" ";" br_st_peer "${BR_ST_EXTRA_PEER}")
        list(REVERSE br_st_peer)
        list(TRANSFORM br_st_peer PREPEND "0x")
        list(JOIN br_st_peer "," br_st_peer)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE "BR_ST_EXTRA_PEER=${br_st_peer}")
    endif()
    # No self-test of its own (build.sh passes BR_ST_PASSIVE=1 when it is set in the environment): for a crash
    # that only a host command brings about, the radio must not have worked before that command.
    if(BR_ST_PASSIVE)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE BR_ST_PASSIVE=1)
    endif()
    # The black box tried on the chip (build.sh passes BR_ST_CRASH_TEST=1 when it is set in the environment): the
    # image stops itself once, a minute after its start, the way a failed assertion of the controller does.
    if(BR_ST_CRASH_TEST)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE BR_ST_CRASH_TEST=1)
    endif()
    # Pages given up half way, one every two seconds (build.sh passes BR_ST_ABORT_TEST=1 when it is set in the
    # environment): what a host's name requests do, without a host.
    if(BR_ST_ABORT_TEST)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE BR_ST_ABORT_TEST=1)
    endif()
endif()

# Add directory of protocomm_priv.h to include paths
idf_component_get_property(protocomm_dir protocomm COMPONENT_DIR)
target_include_directories(${COMPONENT_LIB} PRIVATE "${protocomm_dir}/src/common")
