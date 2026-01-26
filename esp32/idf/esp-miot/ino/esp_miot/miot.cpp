#include "miot.h"

#include <WiFi.h>
#include <WiFiUdp.h>

#include "esp_timer.h"

#include <mbedtls/aes.h>
#include <mbedtls/md5.h>

#include "constants.h"

static uint8_t hex_char_to_nibble(char c)
{
  if (c >= '0' && c <= '9')
    return (uint8_t)(c - '0');
  if (c >= 'a' && c <= 'f')
    return (uint8_t)(10 + (c - 'a'));
  if (c >= 'A' && c <= 'F')
    return (uint8_t)(10 + (c - 'A'));
  return 0;
}

static void parse_token_string_16(const char *hex_str_32, uint8_t out_16[16])
{
  for (int i = 0; i < 16; i++)
  {
    out_16[i] = (uint8_t)((hex_char_to_nibble(hex_str_32[i * 2]) << 4) |
                          hex_char_to_nibble(hex_str_32[i * 2 + 1]));
  }
}

static void write_be_u16(uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t)((v >> 8) & 0xFF);
  p[1] = (uint8_t)(v & 0xFF);
}

static void write_be_u32(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)((v >> 24) & 0xFF);
  p[1] = (uint8_t)((v >> 16) & 0xFF);
  p[2] = (uint8_t)((v >> 8) & 0xFF);
  p[3] = (uint8_t)(v & 0xFF);
}

static uint32_t read_be_u32(const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void calc_md5(const uint8_t *data, size_t len, uint8_t out16[16])
{
  mbedtls_md5_context ctx;
  mbedtls_md5_init(&ctx);
  mbedtls_md5_starts(&ctx);
  mbedtls_md5_update(&ctx, data, len);
  mbedtls_md5_finish(&ctx, out16);
  mbedtls_md5_free(&ctx);
}

static int encrypt_payload_aes128_cbc_pkcs7(const uint8_t key[16], const uint8_t iv[16],
                                            const uint8_t *plain, size_t plain_len,
                                            uint8_t *inout_buf, size_t inout_capacity)
{
  const size_t block_size = 16;
  const size_t padding_len = block_size - (plain_len % block_size);
  const size_t padded_len = plain_len + padding_len;

  if (padded_len > inout_capacity)
  {
    return -1;
  }

  memcpy(inout_buf, plain, plain_len);
  for (size_t i = plain_len; i < padded_len; i++)
  {
    inout_buf[i] = (uint8_t)padding_len;
  }

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  if (mbedtls_aes_setkey_enc(&ctx, key, 128) != 0)
  {
    mbedtls_aes_free(&ctx);
    return -1;
  }

  uint8_t iv_tmp[16];
  memcpy(iv_tmp, iv, 16);

  const int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, padded_len, iv_tmp, inout_buf, inout_buf);
  mbedtls_aes_free(&ctx);

  if (ret != 0)
  {
    return -1;
  }

  return (int)padded_len;
}

static bool udp_recv_with_timeout(WiFiUDP &udp, uint8_t *buf, size_t buf_cap, int *out_len, uint32_t timeout_ms)
{
  const uint32_t start = millis();
  while ((uint32_t)(millis() - start) < timeout_ms)
  {
    const int packet_len = udp.parsePacket();
    if (packet_len > 0)
    {
      const int len = udp.read(buf, (int)min(buf_cap, (size_t)packet_len));
      *out_len = len;
      return true;
    }
    delay(1);
  }
  return false;
}

bool miot_send_action_once()
{
  if (WiFi.status() != WL_CONNECTED)
  {
    return false;
  }

  WiFiUDP udp;
  if (!udp.begin(MIOT_LOCAL_UDP_PORT))
  {
    return false;
  }

  uint8_t buffer[MIOT_BUFFER_SIZE];
  uint8_t token[16];
  parse_token_string_16(MIOT_DEVICE_TOKEN_HEX, token);

  IPAddress dest_ip;
  if (!dest_ip.fromString(MIOT_TARGET_IP))
  {
    udp.stop();
    return false;
  }

  // =========================
  // 1) Handshake
  // =========================
  memset(buffer, 0xFF, MIOT_HEADER_SIZE);
  write_be_u16(buffer, MIOT_MAGIC);
  write_be_u16(buffer + 2, MIOT_HEADER_SIZE);

  udp.beginPacket(dest_ip, MIOT_TARGET_PORT);
  udp.write(buffer, MIOT_HEADER_SIZE);
  if (!udp.endPacket())
  {
    udp.stop();
    return false;
  }

  int recv_len = 0;
  if (!udp_recv_with_timeout(udp, buffer, sizeof(buffer), &recv_len, MIOT_TIMEOUT_MS))
  {
    udp.stop();
    return false;
  }

  const uint64_t t0_us = (uint64_t)esp_timer_get_time(); // ESP32 Arduino provides this

  if (recv_len < (int)MIOT_HEADER_SIZE)
  {
    udp.stop();
    return false;
  }

  const uint32_t device_id = read_be_u32(buffer + 8);
  const uint32_t device_stamp = read_be_u32(buffer + 12);

  // =========================
  // 2) Prepare key/iv
  // =========================
  uint8_t token_key[16];
  uint8_t token_iv[16];
  calc_md5(token, 16, token_key);

  uint8_t tmp[32];
  memcpy(tmp, token_key, 16);
  memcpy(tmp + 16, token, 16);
  calc_md5(tmp, 32, token_iv);

  // =========================
  // 3) Build & encrypt payload
  // =========================
  char json_payload[256];
  const int json_len = snprintf(json_payload, sizeof(json_payload),
                                "{\"method\":\"action\",\"params\":{\"siid\":%d,\"aiid\":%d,\"in\":%s},\"id\":1}",
                                MIOT_ACTION_SIID, MIOT_ACTION_AIID, MIOT_ACTION_PARAMS_JSON);

  if (json_len <= 0 || json_len >= (int)sizeof(json_payload))
  {
    udp.stop();
    return false;
  }

  uint8_t *encrypted_ptr = buffer + MIOT_HEADER_SIZE;
  const size_t encrypted_cap = sizeof(buffer) - MIOT_HEADER_SIZE;

  const int encrypted_len = encrypt_payload_aes128_cbc_pkcs7(token_key, token_iv,
                                                             (const uint8_t *)json_payload, (size_t)json_len,
                                                             encrypted_ptr, encrypted_cap);
  if (encrypted_len < 0)
  {
    udp.stop();
    return false;
  }

  // =========================
  // 4) Final header + checksum
  // =========================
  const uint64_t now_us = (uint64_t)esp_timer_get_time();
  const uint32_t elapsed_sec = (uint32_t)((now_us - t0_us) / 1000000ULL);
  const uint32_t current_stamp = device_stamp + elapsed_sec;

  write_be_u16(buffer, MIOT_MAGIC);
  write_be_u16(buffer + 2, (uint16_t)(MIOT_HEADER_SIZE + encrypted_len));
  write_be_u32(buffer + 4, 0);
  write_be_u32(buffer + 8, device_id);
  write_be_u32(buffer + 12, current_stamp);

  // checksum = md5(header[0:16] + token + encrypted_payload)
  mbedtls_md5_context ctx;
  uint8_t checksum[16];
  mbedtls_md5_init(&ctx);
  mbedtls_md5_starts(&ctx);
  mbedtls_md5_update(&ctx, buffer, 16);
  mbedtls_md5_update(&ctx, token, 16);
  mbedtls_md5_update(&ctx, encrypted_ptr, (size_t)encrypted_len);
  mbedtls_md5_finish(&ctx, checksum);
  mbedtls_md5_free(&ctx);

  memcpy(buffer + 16, checksum, 16);

  // =========================
  // 5) Send action packet
  // =========================
  const int total_len = (int)MIOT_HEADER_SIZE + encrypted_len;

  udp.beginPacket(dest_ip, MIOT_TARGET_PORT);
  udp.write(buffer, total_len);
  const bool ok = udp.endPacket();

  udp.stop();
  return ok;
}
