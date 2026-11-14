/*
 * ESP32-P4 compile & link check for `p4_bt_classic`.
 */
#include "bt_classic.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

void app_main(void)
{
    bt_classic_config_t cfg = BT_CLASSIC_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(bt_classic_init(&cfg));

    bt_classic_status_t st;
    bt_classic_get_status(&st);
    ESP_LOGI("compile_check", "bt_classic_init OK (c6_soft_br_ready=%d)", (int)st.c6_soft_br_ready);

    if (bt_classic_c6_supported()) {
        bt_classic_device_t devs[8];
        int n = bt_classic_scan(devs, 8, 5120, false);
        ESP_LOGI("compile_check", "Scanned %d Classic devices", n);
    }

    int16_t silence[256] = {0};
    (void)bt_classic_write_pcm(silence, 128, 48000, 2, 0);
    (void)bt_classic_take_media_command();

    bt_classic_saved_t saved[4];
    const int remembered = bt_classic_saved(saved, 4);
    bt_classic_diag_t diag;
    bt_classic_get_diag(&diag);
    ESP_LOGI("compile_check", "%d remembered device(s), bitpool %u", remembered, (unsigned)diag.bitpool);
    if (remembered > 0) {
        (void)bt_classic_forget(saved[0].addr);
    }

    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
