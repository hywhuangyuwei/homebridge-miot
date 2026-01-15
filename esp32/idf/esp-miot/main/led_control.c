#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "led_strip.h"
#include "led_control.h"

#define BLINK_GPIO 48
#define LED_STRIP_LEN 1
#define LED_STRIP_RMT_RES_HZ (10 * 1000 * 1000)

static const char *TAG = "led_ctrl";
static led_strip_handle_t led_strip;
static TaskHandle_t s_led_task_handle = NULL; // 用于保存任务句柄

/* HSV 转 RGB 辅助函数 (保持不变) */
static void hsv2rgb(uint32_t h, uint32_t s, uint32_t v, uint32_t *r, uint32_t *g, uint32_t *b)
{
    h %= 360;
    uint32_t rgb_max = v * 2.55f;
    uint32_t rgb_min = rgb_max * (100 - s) / 100.0f;
    uint32_t i = h / 60;
    uint32_t diff = h % 60;
    uint32_t rgb_adj = (rgb_max - rgb_min) * diff / 60;

    switch (i)
    {
    case 0:
        *r = rgb_max;
        *g = rgb_min + rgb_adj;
        *b = rgb_min;
        break;
    case 1:
        *r = rgb_max - rgb_adj;
        *g = rgb_max;
        *b = rgb_min;
        break;
    case 2:
        *r = rgb_min;
        *g = rgb_max;
        *b = rgb_min + rgb_adj;
        break;
    case 3:
        *r = rgb_min;
        *g = rgb_max - rgb_adj;
        *b = rgb_max;
        break;
    case 4:
        *r = rgb_min + rgb_adj;
        *g = rgb_min;
        *b = rgb_max;
        break;
    default:
        *r = rgb_max;
        *g = rgb_min;
        *b = rgb_max - rgb_adj;
        break;
    }
}

/* 执行闪烁蓝灯三下的逻辑 */
static void blink_blue_sequence(void)
{
    ESP_LOGI(TAG, "Blinking Blue!");
    for (int i = 0; i < 3; i++)
    {
        // 亮蓝灯 (R=0, G=0, B=255)
        led_strip_set_pixel(led_strip, 0, 0, 0, 255);
        led_strip_refresh(led_strip);
        vTaskDelay(pdMS_TO_TICKS(50)); // 亮 50ms

        // 灭灯
        led_strip_clear(led_strip);
        vTaskDelay(pdMS_TO_TICKS(50)); // 灭 50ms
    }
}

/* 主 LED 任务 */
static void rainbow_task(void *pvParameters)
{
    uint32_t hue = 0;
    uint32_t r, g, b;

    while (1)
    {
        // 1. 检查是否有通知 (ulTaskNotifyTake)
        // 参数1: pdTRUE 表示读取后清零通知值
        // 参数2: 0 表示不等待（非阻塞），如果有信号立即返回 > 0，没有则返回 0
        if (ulTaskNotifyTake(pdTRUE, 0) > 0)
        {
            // 如果收到信号，暂停彩虹，插入闪烁逻辑
            blink_blue_sequence();
        }

        // 2. 正常显示彩虹
        hsv2rgb(hue, 100, 20, &r, &g, &b);
        led_strip_set_pixel(led_strip, 0, r, g, b);
        led_strip_refresh(led_strip);

        hue++;
        if (hue >= 360)
            hue = 0;

        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

/* 外部调用的触发函数 */
void trigger_blue_blink(void)
{
    if (s_led_task_handle != NULL)
    {
        // 发送通知给 LED 任务，使其从彩虹中中断去闪烁
        xTaskNotifyGive(s_led_task_handle);
    }
}

void start_rainbow_led(void)
{
    ESP_LOGI(TAG, "Initializing LED strip");

    led_strip_config_t strip_config = {
        .strip_gpio_num = BLINK_GPIO,
        .max_leds = LED_STRIP_LEN,
    };
    led_strip_rmt_config_t rmt_config = {
        .resolution_hz = LED_STRIP_RMT_RES_HZ,
        .flags.with_dma = false,
    };
    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_config, &rmt_config, &led_strip));
    led_strip_clear(led_strip);

    // 创建任务并保存句柄
    xTaskCreate(rainbow_task, "rainbow_task", 2048, NULL, 5, &s_led_task_handle);
}
