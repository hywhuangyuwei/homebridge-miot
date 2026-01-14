"""Minimal Python script to send one miIO `action` packet.

Edit the constants at the top (IP/TOKEN/ACTION_ID/IN_PARAMS), then run:

    python3 algo_min.py

What it does (same packet shape as homebridge-miot / miIO):
  1) UDP handshake (32 bytes) to obtain deviceId (did) and server stamp
  2) Send encrypted miIO request: method='action', params={siid, aiid, in: [...]}

Notes:
  - Requires an AES-128-CBC implementation (pycryptodome preferred).
  - No trace/debug/log printing; it only sends packets.
"""

import hashlib
import json
import socket
import struct
import time

PORT = 54321
HEADER_SIZE = 32

# --- Configure these constants ---
IP = "192.168.31.141"
TOKEN_HEX = "0fbb6905b3149362f4bc9cc357c8ea21"  # 32 hex chars
ACTION_ID = "2.1"  # "<siid>.<aiid>"
IN_PARAMS: list = []  # must be a JSON-like list


def _md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad]) * pad


def _aes128_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    # Prefer pycryptodome; fall back to cryptography if available.
    try:
        from Crypto.Cipher import AES  # type: ignore

        return AES.new(key, AES.MODE_CBC, iv).encrypt(_pkcs7_pad(plaintext))
    except Exception:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore

            encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            return encryptor.update(_pkcs7_pad(plaintext)) + encryptor.finalize()
        except Exception:
            raise SystemExit(1)


def _handshake(ip: str, timeout: float = 3.0) -> tuple[int, int, int]:
    # 0x2131 + length=0x0020 + 28 bytes of 0xff
    msg = bytes.fromhex("21310020" + "ff" * 28)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(msg, (ip, PORT))
    data, _ = s.recvfrom(2048)
    s.close()

    stamp_time_ms = int(time.time() * 1000)
    did = struct.unpack(">I", data[8:12])[0]
    stamp = struct.unpack(">I", data[12:16])[0]
    return did, stamp, stamp_time_ms


def _build_encrypted_packet(
    token_hex: str,
    did: int,
    base_stamp: int,
    base_stamp_time_ms: int,
    payload_obj: dict,
) -> bytes:
    token = bytes.fromhex(token_hex)
    token_key = _md5(token)
    token_iv = _md5(token_key + token)

    payload = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
    encrypted = _aes128_cbc_encrypt(token_key, token_iv, payload)

    now_ms = int(time.time() * 1000)
    seconds_passed = max(0, (now_ms - base_stamp_time_ms) // 1000)
    stamp = int(base_stamp) + int(seconds_passed)

    header = bytearray(HEADER_SIZE)
    struct.pack_into(">H", header, 0, 0x2131)
    struct.pack_into(">H", header, 2, HEADER_SIZE + len(encrypted))
    struct.pack_into(">I", header, 4, 0)
    struct.pack_into(">I", header, 8, int(did))
    struct.pack_into(">I", header, 12, int(stamp))

    checksum = _md5(bytes(header[:16]) + token + encrypted)
    header[16:32] = checksum

    return bytes(header) + encrypted


def _send_action(
    ip: str, token_hex: str, siid: int, aiid: int, in_params: list
) -> None:
    did, base_stamp, base_stamp_time_ms = _handshake(ip)

    request = {
        "method": "action",
        "params": {"siid": int(siid), "aiid": int(aiid), "in": in_params},
        "id": 1,
    }
    pkt = _build_encrypted_packet(
        token_hex, did, base_stamp, base_stamp_time_ms, request
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(pkt, (ip, PORT))
    s.close()


def _parse_action_id(action_id: str) -> tuple[int, int]:
    siid_s, aiid_s = action_id.split(".", 1)
    return int(siid_s), int(aiid_s)


def main() -> None:
    siid, aiid = _parse_action_id(ACTION_ID)
    _send_action(IP, TOKEN_HEX, siid, aiid, IN_PARAMS)


if __name__ == "__main__":
    main()
