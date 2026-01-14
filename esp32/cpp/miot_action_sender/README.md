# miot_action_sender (C++)

Minimal C++ sender for miIO/MIoT `action` packets:

- UDP handshake (32 bytes) to obtain `did` + `stamp`
- AES-128-CBC encrypt JSON payload
- Build miIO header + MD5 checksum
- Send one UDP packet to `IP:54321`

This tool **does not receive or parse responses**.

## Build (macOS)

Uses Apple CommonCrypto by default.

```sh
cd cpp/miot_action_sender
cmake -S . -B build
cmake --build build
```

## Run

`--in` is a *raw JSON array string* (so we don't need a JSON library).

```sh
./cpp/miot_action_sender/build/miot_action_sender \
  --ip 192.168.31.141 \
  --token 0fbb6905b3149362f4bc9cc357c8ea21 \
  --siid 2 --aiid 1 \
  --in '[]'
```

## Embedded notes (C++)

- Prefer `mbedTLS` (common in MCU SDKs) for AES/MD5.
- This implementation avoids RTC: it uses a monotonic timer after handshake to increment `stamp` by elapsed seconds.

To build with mbedTLS in a toolchain environment:

```sh
cmake -S . -B build -DMIOT_USE_MBEDTLS=ON
cmake --build build
```

You may need to provide include/lib search paths via your toolchain file.
