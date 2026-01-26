# esp_miot (Arduino)

这是把 `esp32/idf/esp-miot/main` 的 ESP-IDF 小工程，等价迁移到 Arduino(ESP32) 的版本。

## 功能

- 连接 WiFi（STA）
- 本机 HTTP 服务：`GET /ping` 返回 `pong`
- 收到 `/ping`：
  - WS2812 彩虹灯效暂停，蓝色闪烁 3 次
  - 通过 UDP 向米家设备发送一次 `action`（AES-128-CBC + MD5 校验），逻辑与原 `miot.c` 保持一致

## 目录

- `esp_miot.ino`：主程序
- `constants.h`：所有常量/配置集中在这里（WiFi、IP、Token、GPIO、时序等）
- `led_control.*`：WS2812 彩虹 + 蓝闪（非阻塞）
- `miot.*`：MiOT UDP action 发送

## 依赖

- Arduino IDE 或 PlatformIO
- ESP32 Arduino Core
- Arduino Library：`Adafruit NeoPixel`

## 配置

编辑 `constants.h`：

- `WIFI_SSID` / `WIFI_PASS`
- `MIOT_TARGET_IP` / `MIOT_TARGET_PORT`
- `MIOT_DEVICE_TOKEN_HEX`
- `LED_PIN`（WS2812 数据脚）

## 使用

- 用 Arduino IDE 打开 `ino/esp_miot/esp_miot.ino`
- 安装 `Adafruit NeoPixel`
- 选择 ESP32 对应开发板与端口并烧录

请求：

```bash
curl http://<ESP32_IP>/ping
```

返回 `pong` 即成功。
