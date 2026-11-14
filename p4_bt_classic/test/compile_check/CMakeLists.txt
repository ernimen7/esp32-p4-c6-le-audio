cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/../.."
    "${CMAKE_CURRENT_LIST_DIR}/../../../components/espressif__esp_hosted"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(bt_classic_compile_check)
