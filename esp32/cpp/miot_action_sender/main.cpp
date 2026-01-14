#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(MIOT_USE_COMMONCRYPTO)
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#elif defined(MIOT_USE_MBEDTLS)
#include <mbedtls/aes.h>
#include <mbedtls/md5.h>
#else
#error "Select crypto backend: MIOT_USE_COMMONCRYPTO (macOS) or MIOT_USE_MBEDTLS (embedded/Linux)"
#endif

namespace
{

  constexpr uint16_t kMagic = 0x2131;
  constexpr uint16_t kHeaderSize = 32;
  constexpr uint16_t kPort = 54321;

  static void die(const std::string &msg)
  {
    std::cerr << msg << "\n";
    std::exit(2);
  }

  static bool is_hex_char(char c)
  {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  }

  static uint8_t hex_nibble(char c)
  {
    if (c >= '0' && c <= '9')
      return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f')
      return static_cast<uint8_t>(10 + (c - 'a'));
    if (c >= 'A' && c <= 'F')
      return static_cast<uint8_t>(10 + (c - 'A'));
    throw std::runtime_error("invalid hex");
  }

  static std::vector<uint8_t> hex_to_bytes(std::string_view hex)
  {
    if (hex.size() % 2 != 0)
      throw std::runtime_error("hex length must be even");
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
      if (!is_hex_char(hex[i]) || !is_hex_char(hex[i + 1]))
        throw std::runtime_error("invalid hex");
      out.push_back(static_cast<uint8_t>((hex_nibble(hex[i]) << 4) | hex_nibble(hex[i + 1])));
    }
    return out;
  }

  static std::array<uint8_t, 16> md5_16(const uint8_t *data, size_t len)
  {
    std::array<uint8_t, 16> out{};
#if defined(MIOT_USE_COMMONCRYPTO)
    CC_MD5(data, static_cast<CC_LONG>(len), out.data());
#elif defined(MIOT_USE_MBEDTLS)
    mbedtls_md5_ret(data, len, out.data());
#endif
    return out;
  }

  static std::vector<uint8_t> pkcs7_pad(const std::vector<uint8_t> &in, size_t block_size = 16)
  {
    size_t pad = block_size - (in.size() % block_size);
    if (pad == 0)
      pad = block_size;
    std::vector<uint8_t> out = in;
    out.insert(out.end(), pad, static_cast<uint8_t>(pad));
    return out;
  }

  static std::vector<uint8_t> aes128_cbc_encrypt(
      const std::array<uint8_t, 16> &key,
      const std::array<uint8_t, 16> &iv,
      const std::vector<uint8_t> &plaintext)
  {
    auto padded = pkcs7_pad(plaintext, 16);
    std::vector<uint8_t> out(padded.size());

#if defined(MIOT_USE_COMMONCRYPTO)
    CCCryptorRef cryptor = nullptr;
    CCCryptorStatus st = CCCryptorCreate(
        kCCEncrypt, kCCAlgorithmAES, 0 /* no padding */,
        key.data(), key.size(), iv.data(), &cryptor);
    if (st != kCCSuccess || !cryptor)
      throw std::runtime_error("CCCryptorCreate failed");

    size_t moved1 = 0;
    st = CCCryptorUpdate(cryptor, padded.data(), padded.size(), out.data(), out.size(), &moved1);
    if (st != kCCSuccess)
    {
      CCCryptorRelease(cryptor);
      throw std::runtime_error("CCCryptorUpdate failed");
    }

    size_t moved2 = 0;
    st = CCCryptorFinal(cryptor, out.data() + moved1, out.size() - moved1, &moved2);
    CCCryptorRelease(cryptor);
    if (st != kCCSuccess)
      throw std::runtime_error("CCCryptorFinal failed");

    out.resize(moved1 + moved2);
    return out;

#elif defined(MIOT_USE_MBEDTLS)
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_enc(&ctx, key.data(), 128) != 0)
    {
      mbedtls_aes_free(&ctx);
      throw std::runtime_error("mbedtls_aes_setkey_enc failed");
    }

    std::array<uint8_t, 16> iv_mut = iv;
    if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, padded.size(), iv_mut.data(), padded.data(), out.data()) != 0)
    {
      mbedtls_aes_free(&ctx);
      throw std::runtime_error("mbedtls_aes_crypt_cbc failed");
    }
    mbedtls_aes_free(&ctx);
    return out;
#endif
  }

  static void write_be_u16(uint8_t *p, uint16_t v)
  {
    p[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[1] = static_cast<uint8_t>(v & 0xFF);
  }

  static void write_be_u32(uint8_t *p, uint32_t v)
  {
    p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(v & 0xFF);
  }

  static uint32_t read_be_u32(const uint8_t *p)
  {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
  }

  struct HandshakeResult
  {
    uint32_t did;
    uint32_t stamp;
    std::chrono::steady_clock::time_point t0;
  };

  static HandshakeResult handshake_udp(const std::string &ip, int timeout_ms = 3000)
  {
    std::array<uint8_t, kHeaderSize> msg{};
    write_be_u16(msg.data() + 0, kMagic);
    write_be_u16(msg.data() + 2, kHeaderSize);
    std::memset(msg.data() + 4, 0xFF, kHeaderSize - 4);

    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
      throw std::runtime_error("socket() failed");

    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1)
    {
      ::close(fd);
      throw std::runtime_error("invalid ip");
    }

    ssize_t sent = ::sendto(fd, msg.data(), msg.size(), 0, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    if (sent != static_cast<ssize_t>(msg.size()))
    {
      ::close(fd);
      throw std::runtime_error("sendto(handshake) failed");
    }

    std::array<uint8_t, 2048> buf{};
    sockaddr_in from{};
    socklen_t fromlen = sizeof(from);
    ssize_t n = ::recvfrom(fd, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr *>(&from), &fromlen);
    auto t0 = std::chrono::steady_clock::now();
    ::close(fd);
    if (n < 16)
      throw std::runtime_error("handshake recv too short");

    uint32_t did = read_be_u32(buf.data() + 8);
    uint32_t stamp = read_be_u32(buf.data() + 12);
    return HandshakeResult{did, stamp, t0};
  }

  static std::vector<uint8_t> build_encrypted_packet(
      const std::vector<uint8_t> &token,
      const HandshakeResult &hs,
      uint32_t siid,
      uint32_t aiid,
      const std::string &in_json_array)
  {

    // token_key = md5(token)
    auto token_key = md5_16(token.data(), token.size());

    // token_iv = md5(token_key + token)
    std::vector<uint8_t> key_plus_token;
    key_plus_token.insert(key_plus_token.end(), token_key.begin(), token_key.end());
    key_plus_token.insert(key_plus_token.end(), token.begin(), token.end());
    auto token_iv = md5_16(key_plus_token.data(), key_plus_token.size());

    // Minimal JSON without a JSON library; `in` is raw JSON array string.
    std::string payload =
        std::string("{\"method\":\"action\",\"params\":{\"siid\":") + std::to_string(siid) +
        ",\"aiid\":" + std::to_string(aiid) +
        ",\"in\":" + in_json_array +
        "},\"id\":1}";

    std::vector<uint8_t> payload_bytes(payload.begin(), payload.end());
    auto encrypted = aes128_cbc_encrypt(token_key, token_iv, payload_bytes);

    uint32_t stamp = hs.stamp;
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - hs.t0).count();
    if (elapsed > 0)
      stamp = static_cast<uint32_t>(stamp + static_cast<uint32_t>(elapsed));

    std::array<uint8_t, kHeaderSize> header{};
    write_be_u16(header.data() + 0, kMagic);
    write_be_u16(header.data() + 2, static_cast<uint16_t>(kHeaderSize + encrypted.size()));
    write_be_u32(header.data() + 4, 0);
    write_be_u32(header.data() + 8, hs.did);
    write_be_u32(header.data() + 12, stamp);

    // checksum = md5(header[0:16] + token + encrypted)
    std::vector<uint8_t> checksum_input;
    checksum_input.insert(checksum_input.end(), header.begin(), header.begin() + 16);
    checksum_input.insert(checksum_input.end(), token.begin(), token.end());
    checksum_input.insert(checksum_input.end(), encrypted.begin(), encrypted.end());
    auto checksum = md5_16(checksum_input.data(), checksum_input.size());
    std::memcpy(header.data() + 16, checksum.data(), 16);

    std::vector<uint8_t> pkt;
    pkt.insert(pkt.end(), header.begin(), header.end());
    pkt.insert(pkt.end(), encrypted.begin(), encrypted.end());
    return pkt;
  }

  static void send_udp_packet(const std::string &ip, const std::vector<uint8_t> &pkt)
  {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
      throw std::runtime_error("socket() failed");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1)
    {
      ::close(fd);
      throw std::runtime_error("invalid ip");
    }

    ssize_t sent = ::sendto(fd, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    ::close(fd);
    if (sent != static_cast<ssize_t>(pkt.size()))
      throw std::runtime_error("sendto(action) failed");
  }

  struct Args
  {
    std::string ip;
    std::string token_hex;
    uint32_t siid = 0;
    uint32_t aiid = 0;
    std::string in_json = "[]";
  };

  static std::optional<std::string_view> get_opt(int &i, int argc, char **argv)
  {
    if (i + 1 >= argc)
      return std::nullopt;
    return std::string_view(argv[++i]);
  }

  static Args parse_args(int argc, char **argv)
  {
    Args a;
    for (int i = 1; i < argc; i++)
    {
      std::string_view k(argv[i]);
      if (k == "--ip")
      {
        auto v = get_opt(i, argc, argv);
        if (!v)
          die("missing --ip value");
        a.ip = std::string(*v);
      }
      else if (k == "--token")
      {
        auto v = get_opt(i, argc, argv);
        if (!v)
          die("missing --token value");
        a.token_hex = std::string(*v);
      }
      else if (k == "--siid")
      {
        auto v = get_opt(i, argc, argv);
        if (!v)
          die("missing --siid value");
        a.siid = static_cast<uint32_t>(std::stoul(std::string(*v)));
      }
      else if (k == "--aiid")
      {
        auto v = get_opt(i, argc, argv);
        if (!v)
          die("missing --aiid value");
        a.aiid = static_cast<uint32_t>(std::stoul(std::string(*v)));
      }
      else if (k == "--in")
      {
        auto v = get_opt(i, argc, argv);
        if (!v)
          die("missing --in value");
        a.in_json = std::string(*v);
      }
      else if (k == "-h" || k == "--help")
      {
        std::cout
            << "Usage: miot_action_sender --ip <ip> --token <32-hex> --siid <n> --aiid <n> --in '[]'\n";
        std::exit(0);
      }
      else
      {
        die(std::string("unknown arg: ") + std::string(k));
      }
    }

    if (a.ip.empty())
      die("--ip is required");
    if (a.token_hex.size() != 32)
      die("--token must be 32 hex chars");
    if (a.in_json.empty() || a.in_json.front() != '[')
      die("--in must be a raw JSON array string, e.g. '[]'");
    if (a.siid == 0 || a.aiid == 0)
      die("--siid/--aiid must be non-zero");
    return a;
  }

} // namespace

int main(int argc, char **argv)
{
  try
  {
    Args args = parse_args(argc, argv);
    auto token = hex_to_bytes(args.token_hex);

    auto hs = handshake_udp(args.ip);
    auto pkt = build_encrypted_packet(token, hs, args.siid, args.aiid, args.in_json);
    send_udp_packet(args.ip, pkt);
    return 0;
  }
  catch (const std::exception &e)
  {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
