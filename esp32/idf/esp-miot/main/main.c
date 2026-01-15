#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "led_control.h"
#include "miot.h"
#include "secrets.h"

/* --- 配置区域 --- */
#define MAX_RETRY 10                        // (可选) 最大重连次数，本例中设为无限重连逻辑

/* FreeRTOS event group signal */
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static const char *TAG = "example_server";

/* --------------------------------------------------------------------------
   HTTP Server 部分
   -------------------------------------------------------------------------- */

/* GET /ping 处理函数 */
static esp_err_t ping_get_handler(httpd_req_t *req)
{
  // 1. 触发 LED 闪烁 (异步，不会阻塞 HTTP 响应)
  trigger_blue_blink();
  miot_send_action_once();

  // 2. 发送响应
  const char *resp_str = "pong";
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  ESP_LOGI(TAG, "Received /ping -> Blinking Blue LED -> Responding pong");

  return ESP_OK;
}

/* URI 处理结构体配置 */
static const httpd_uri_t ping_uri = {
    .uri = "/ping",
    .method = HTTP_GET,
    .handler = ping_get_handler,
    .user_ctx = NULL};

/* 启动 Web Server */
static httpd_handle_t start_webserver(void)
{
  httpd_handle_t server = NULL;
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();

  // 可以在这里修改端口等配置，默认是 80
  // config.server_port = 8080;

  ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);

  if (httpd_start(&server, &config) == ESP_OK)
  {
    // 注册 URI Handler
    ESP_LOGI(TAG, "Registering URI handlers");
    httpd_register_uri_handler(server, &ping_uri);
    return server;
  }

  ESP_LOGI(TAG, "Error starting server!");
  return NULL;
}

/* 停止 Web Server (用于断网时释放资源) */
static void stop_webserver(httpd_handle_t server)
{
  if (server)
  {
    httpd_stop(server);
  }
}

/* --------------------------------------------------------------------------
   Wi-Fi 连接与事件处理部分
   -------------------------------------------------------------------------- */

static httpd_handle_t server_handle = NULL;

static void event_handler(void *arg, esp_event_base_t event_base,
                          int32_t event_id, void *event_data)
{
  // Wi-Fi 启动 -> 开始连接
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
  {
    esp_wifi_connect();
  }
  // Wi-Fi 断开 -> 自动重连
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
  {
    ESP_LOGI(TAG, "Wi-Fi disconnected, retrying to connect...");
    esp_wifi_connect();

    // 如果断网了，可以选择停止 Server (可选)
    if (server_handle)
    {
      stop_webserver(server_handle);
      server_handle = NULL;
    }
  }
  // 获取到 IP -> 标记连接成功 & 启动 Server
  else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
  {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));

    // 通知主任务 WiFi 已连接
    xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);

    // 获取 IP 后启动 Server
    if (server_handle == NULL)
    {
      server_handle = start_webserver();
    }
  }
}

void wifi_init_sta(void)
{
  s_wifi_event_group = xEventGroupCreate();

  // 初始化网络接口
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  esp_netif_create_default_wifi_sta();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  // 注册事件处理
  ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                      ESP_EVENT_ANY_ID,
                                                      &event_handler,
                                                      NULL,
                                                      NULL));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                      IP_EVENT_STA_GOT_IP,
                                                      &event_handler,
                                                      NULL,
                                                      NULL));

  // 配置 WiFi 账号密码
  wifi_config_t wifi_config = {
      .sta = {
          .ssid = EXAMPLE_ESP_WIFI_SSID,
          .password = EXAMPLE_ESP_WIFI_PASS,
          // 增强兼容性配置
          .threshold.authmode = WIFI_AUTH_WPA2_PSK,
          .sae_pwe_h2e = WPA3_SAE_PWE_BOTH,
      },
  };

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
  ESP_ERROR_CHECK(esp_wifi_start());

  ESP_LOGI(TAG, "wifi_init_sta finished.");
}

/* --------------------------------------------------------------------------
   主函数
   -------------------------------------------------------------------------- */
void app_main(void)
{
  // 1. 初始化 NVS (WiFi 驱动需要)
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
  {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  start_rainbow_led();
  ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");

  // 2. 初始化并连接 WiFi
  wifi_init_sta();

  // 3. 这里可以选择等待连接成功，也可以让 server 在 event_handler 里面异步启动
  // 本例已经在 event_handler 的 GOT_IP 事件中启动了 Server，所以这里只需要让主任务不退出即可

  // 简单阻塞等待，防止主任务退出（虽然 app_main 退出也不会杀掉 FreeRTOS 任务，但通常为了逻辑清晰会保留）
  while (1)
  {
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
