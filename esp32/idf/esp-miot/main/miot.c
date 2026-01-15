#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include "mbedtls/aes.h"
#include "mbedtls/md5.h"

#include "secrets.h"

// 功能定义 (SIID, AIID) 和 参数 JSON
#define ACTION_SIID 2
#define ACTION_AIID 1
#define ACTION_PARAMS "[]" // 必须是 JSON 数组字符串

// ============================================================================
// 内部常量与宏
// ============================================================================
static const char *TAG = "mi_action";

#define MIOT_MAGIC 0x2131
#define HEADER_SIZE 32
#define BUFFER_SIZE 1024
#define TIMEOUT_MS 1000

// ============================================================================
// 辅助函数
// ============================================================================

// 将 Hex 字符转换为数值
static uint8_t hex_char_to_byte(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F')
    return 10 + (c - 'A');
  return 0;
}

// 解析 32 字节 hex 字符串到 16 字节数组
static void parse_token_string(const char *hex_str, uint8_t *out_bytes)
{
  for (int i = 0; i < 16; i++)
  {
    out_bytes[i] = (hex_char_to_byte(hex_str[i * 2]) << 4) |
                   hex_char_to_byte(hex_str[i * 2 + 1]);
  }
}

// 写入大端 uint16
static void write_be_u16(uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t)((v >> 8) & 0xFF);
  p[1] = (uint8_t)(v & 0xFF);
}

// 写入大端 uint32
static void write_be_u32(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)((v >> 24) & 0xFF);
  p[1] = (uint8_t)((v >> 16) & 0xFF);
  p[2] = (uint8_t)((v >> 8) & 0xFF);
  p[3] = (uint8_t)(v & 0xFF);
}

// 读取大端 uint32
static uint32_t read_be_u32(const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// MD5 封装
static void calc_md5(const uint8_t *data, size_t len, uint8_t *output)
{
  mbedtls_md5_context ctx;
  mbedtls_md5_init(&ctx);
  mbedtls_md5_starts(&ctx);
  mbedtls_md5_update(&ctx, data, len);
  mbedtls_md5_finish(&ctx, output);
  mbedtls_md5_free(&ctx);
}

// AES-128-CBC 加密 (带 PKCS7 Padding)
// 返回加密后的长度，数据直接写入 out_buf
static int encrypt_payload(const uint8_t *key, const uint8_t *iv,
                           const uint8_t *plain, size_t plain_len,
                           uint8_t *out_buf)
{

  // 1. 计算 Padding
  size_t block_size = 16;
  size_t padding_len = block_size - (plain_len % block_size);
  size_t padded_len = plain_len + padding_len;

  // 复制明文并添加 padding
  // 注意：这里假设 out_buf 足够大 (padded_len)
  memcpy(out_buf, plain, plain_len);
  for (size_t i = plain_len; i < padded_len; i++)
  {
    out_buf[i] = (uint8_t)padding_len;
  }

  // 2. 加密
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);

  if (mbedtls_aes_setkey_enc(&ctx, key, 128) != 0)
  {
    ESP_LOGE(TAG, "AES setkey failed");
    mbedtls_aes_free(&ctx);
    return -1;
  }

  uint8_t iv_temp[16];
  memcpy(iv_temp, iv, 16); // IV 会被修改，所以需要拷贝一份

  int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, padded_len, iv_temp, out_buf, out_buf);
  mbedtls_aes_free(&ctx);

  if (ret != 0)
  {
    ESP_LOGE(TAG, "AES encrypt failed");
    return -1;
  }

  return (int)padded_len;
}

// ============================================================================
// 核心逻辑函数
// ============================================================================

/**
 * 核心功能：执行一次完整的米家协议 UDP 发包流程
 * 步骤：
 * 1. 发送握手包 (Handshake) 获取 Device ID 和 Stamp
 * 2. 计算加密 Key 和 IV
 * 3. 构造 JSON 负载并加密
 * 4. 构造最终包头并计算 checksum
 * 5. 发送 Action 包
 */
esp_err_t miot_send_action_once(void)
{
  int sock = -1;
  struct sockaddr_in dest_addr;
  uint8_t buffer[BUFFER_SIZE];
  uint8_t token[16];

  // 0. 准备 Token
  parse_token_string(DEVICE_TOKEN_HEX, token);

  // 设置目标地址
  dest_addr.sin_addr.s_addr = inet_addr(TARGET_IP);
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(TARGET_PORT);

  // 创建 UDP Socket
  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock < 0)
  {
    ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
    return ESP_FAIL;
  }

  // 设置超时
  struct timeval timeout;
  timeout.tv_sec = TIMEOUT_MS / 1000;
  timeout.tv_usec = (TIMEOUT_MS % 1000) * 1000;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  // ========================================================================
  // 1. 握手阶段 (Handshake)
  // ========================================================================
  ESP_LOGI(TAG, "Sending handshake to %s...", TARGET_IP);

  memset(buffer, 0xff, HEADER_SIZE);
  write_be_u16(buffer, MIOT_MAGIC);
  write_be_u16(buffer + 2, HEADER_SIZE);
  // 后面全是 0xFF

  int err = sendto(sock, buffer, HEADER_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
  if (err < 0)
  {
    ESP_LOGE(TAG, "Handshake send failed: errno %d", errno);
    close(sock);
    return ESP_FAIL;
  }

  // 接收握手响应
  struct sockaddr_in source_addr;
  socklen_t socklen = sizeof(source_addr);
  int len = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&source_addr, &socklen);

  // 记录接收到的时刻（用于校准时间戳）
  int64_t t0_us = esp_timer_get_time();

  if (len < HEADER_SIZE)
  {
    ESP_LOGE(TAG, "Handshake recv failed or too short");
    close(sock);
    return ESP_FAIL;
  }

  uint32_t device_id = read_be_u32(buffer + 8);
  uint32_t device_stamp = read_be_u32(buffer + 12);
  ESP_LOGI(TAG, "Handshake OK. DID: %lu, Stamp: %lu", (unsigned long)device_id, (unsigned long)device_stamp);

  // ========================================================================
  // 2. 准备加密上下文
  // ========================================================================

  uint8_t token_key[16];
  uint8_t token_iv[16];

  // token_key = md5(token)
  calc_md5(token, 16, token_key);

  // token_iv = md5(token_key + token)
  uint8_t temp_buf[32];
  memcpy(temp_buf, token_key, 16);
  memcpy(temp_buf + 16, token, 16);
  calc_md5(temp_buf, 32, token_iv);

  // ========================================================================
  // 3. 构建负载 (Payload)
  // ========================================================================

  char json_payload[256];
  int json_len = snprintf(json_payload, sizeof(json_payload),
                          "{\"method\":\"action\",\"params\":{\"siid\":%d,\"aiid\":%d,\"in\":%s},\"id\":1}",
                          ACTION_SIID, ACTION_AIID, ACTION_PARAMS);

  if (json_len >= sizeof(json_payload))
  {
    ESP_LOGE(TAG, "JSON payload too long");
    close(sock);
    return ESP_FAIL;
  }

  // 加密负载
  // buffer 偏移 32 字节开始放加密后的数据，头部留给 header
  uint8_t *encrypted_ptr = buffer + HEADER_SIZE;
  int encrypted_len = encrypt_payload(token_key, token_iv,
                                      (uint8_t *)json_payload, json_len,
                                      encrypted_ptr);

  if (encrypted_len < 0)
  {
    close(sock);
    return ESP_FAIL;
  }

  // ========================================================================
  // 4. 构建最终包头
  // ========================================================================

  // 计算当前的时间戳偏移
  int64_t now_us = esp_timer_get_time();
  uint32_t elapsed_sec = (uint32_t)((now_us - t0_us) / 1000000);
  uint32_t current_stamp = device_stamp + elapsed_sec;

  // 填充头部
  write_be_u16(buffer, MIOT_MAGIC);
  write_be_u16(buffer + 2, HEADER_SIZE + encrypted_len);
  write_be_u32(buffer + 4, 0); // Unknown/Length placeholder
  write_be_u32(buffer + 8, device_id);
  write_be_u32(buffer + 12, current_stamp);

  // 计算 Checksum = md5(header[0:16] + token + encrypted_payload)
  // 我们需要将 header(16) + token(16) + encrypted_payload 拼在一起算 MD5
  // 为了节省内存，我们利用 mbedtls 分段 update 的特性，不需要申请大 buffer 拼接

  mbedtls_md5_context ctx;
  uint8_t checksum[16];

  mbedtls_md5_init(&ctx);
  mbedtls_md5_starts(&ctx);
  mbedtls_md5_update(&ctx, buffer, 16);                   // Header 前 16 字节
  mbedtls_md5_update(&ctx, token, 16);                    // Token
  mbedtls_md5_update(&ctx, encrypted_ptr, encrypted_len); // 加密后的负载
  mbedtls_md5_finish(&ctx, checksum);
  mbedtls_md5_free(&ctx);

  // 将 checksum 填入头部的后 16 字节
  memcpy(buffer + 16, checksum, 16);

  // ========================================================================
  // 5. 发送 Action 包
  // ========================================================================

  int total_len = HEADER_SIZE + encrypted_len;
  ESP_LOGI(TAG, "Sending action packet (len: %d)...", total_len);

  err = sendto(sock, buffer, total_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

  close(sock);

  if (err < 0)
  {
    ESP_LOGE(TAG, "Action send failed");
    return ESP_FAIL;
  }

  ESP_LOGI(TAG, "Action sent successfully.");
  return ESP_OK;
}

// ============================================================================
// 如果需要测试，可以在 app_main 中调用
// ============================================================================
/*
void app_main(void)
{
    // 确保 Wi-Fi 已连接...
    // wifi_init_sta();

    // 调用发包函数
    miot_send_action_once();
}
*/
