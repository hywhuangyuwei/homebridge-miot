"""Minimal Python reproduction of: `action <IP> <siid.aiid>`

This script sends *the same kind of packets* as `homebridge-miot`:
  1) Handshake UDP packet
    2) Encrypted miIO request packet: method=action, params={siid, aiid, in: []}

Every section below is annotated with its corresponding implementation location in:
  `lib/protocol/MiioProtocol.js`
"""

import hashlib
import json
import os
import socket
import struct
import time

PORT = 54321  # MiioProtocol.js: const PORT = 54321;


TRACE_PREFIX = "MIOT_TRACE"


def _trace_enabled() -> bool:
    return os.getenv("MIOT_TRACE") == "1"


def _trace_escape(val: object) -> str:
    if val is None:
        s = ""
    elif isinstance(val, (bytes, bytearray, memoryview)):
        s = bytes(val).hex()
    else:
        s = str(val)
    return (
        s.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _trace(addr: str, step: str, pairs: list[tuple[str, object]]) -> None:
    if not _trace_enabled():
        return
    parts = [
        f"{TRACE_PREFIX}",
        f"addr={_trace_escape(addr)}",
        f"step={_trace_escape(step)}",
    ]
    for k, v in pairs:
        parts.append(f"{k}={_trace_escape(v)}")
    print("|".join(parts))


def _parse_int(value: str) -> int:
    s = value.strip()
    if not s:
        raise ValueError("empty")
    if s.lower().startswith("0x"):
        return int(s, 16)
    if any(c in "abcdefABCDEF" for c in s):
        return int(s, 16)
    return int(s, 10)


def _env_int(name: str) -> int | None:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return None
    return _parse_int(v)


# Header layout (MiioProtocol.js: _encryptMessage / _decryptMessage)
HEADER_SIZE = 32
OFF_MAGIC = 0
OFF_LEN = 2
OFF_UNKNOWN = 4
OFF_DID = 8
OFF_STAMP = 12
OFF_CHECKSUM = 16


# --- Utils (MiioProtocol.js mirrors these operations inline) ---
def _md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad]) * pad


def _aes128_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    # MiioProtocol.js: crypto.createCipheriv('aes-128-cbc', device._tokenKey, device._tokenIV)
    try:
        from Crypto.Cipher import AES  # pycryptodome
    except Exception as e:  # pragma: no cover
        # Fallback to `cryptography` if available.
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except Exception:  # pragma: no cover
            raise SystemExit(
                "Missing AES dependency. Install one of:\n"
                "  python3 -m pip install pycryptodome\n"
                "  python3 -m pip install cryptography\n"
                f"Import error: {e}"
            )

        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return encryptor.update(_pkcs7_pad(plaintext)) + encryptor.finalize()

    return AES.new(key, AES.MODE_CBC, iv).encrypt(_pkcs7_pad(plaintext))


def _decode_header(pkt: bytes) -> dict:
    if len(pkt) < HEADER_SIZE:
        raise ValueError(f"packet too short: {len(pkt)}")
    magic = struct.unpack(">H", pkt[OFF_MAGIC : OFF_MAGIC + 2])[0]
    length = struct.unpack(">H", pkt[OFF_LEN : OFF_LEN + 2])[0]
    unknown = struct.unpack(">I", pkt[OFF_UNKNOWN : OFF_UNKNOWN + 4])[0]
    did = struct.unpack(">I", pkt[OFF_DID : OFF_DID + 4])[0]
    stamp = struct.unpack(">I", pkt[OFF_STAMP : OFF_STAMP + 4])[0]
    checksum = pkt[OFF_CHECKSUM : OFF_CHECKSUM + 16]
    return {
        "magic": magic,
        "length": length,
        "unknown": unknown,
        "did": did,
        "stamp": stamp,
        "checksum_hex": checksum.hex(),
    }


def _compute_stamp(
    base_stamp: int, base_stamp_time_ms: int, now_ms: int | None = None
) -> int:
    # MiioProtocol.js:
    #   secondsPassed = floor((Date.now() - device._serverStampTime) / 1000)
    #   stamp = device._serverStamp + secondsPassed
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    seconds_passed = max(0, (now_ms - base_stamp_time_ms) // 1000)
    return int(base_stamp) + int(seconds_passed)


# --- 1) Handshake (MiioProtocol.js: handshake() -> _handshake() -> _socketSend()) ---
def handshake(ip: str, timeout: float = 3.0) -> tuple[int, int, int]:
    # MiioProtocol.js: _handshake() uses this exact 32-byte buffer:
    #   Buffer.from('21310020' + 'ff'*28, 'hex')
    msg = bytes.fromhex("21310020" + "ff" * 28)

    _trace(ip, "handshake_send", [("port", PORT), ("len", len(msg)), ("hex", msg)])

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(msg, (ip, PORT))

    # Device replies with a 32-byte header.
    # MiioProtocol.js: _decryptMessage() reads:
    #   deviceId = msg.readUInt32BE(8)
    #   stamp    = msg.readUInt32BE(12)
    data, _ = s.recvfrom(2048)
    s.close()

    stamp_time_ms = int(time.time() * 1000)

    did = struct.unpack(">I", data[8:12])[0]
    stamp = struct.unpack(">I", data[12:16])[0]

    try:
        hdr = _decode_header(data)
        _trace(
            ip,
            "handshake_recv",
            [
                ("len", len(data)),
                ("magic", hdr["magic"]),
                ("magic_hex", f"{hdr['magic']:04x}"),
                ("length", hdr["length"]),
                ("unknown", hdr["unknown"]),
                ("did", hdr["did"]),
                ("did_hex", f"{hdr['did']:08x}"),
                ("stamp", hdr["stamp"]),
                ("stamp_hex", f"{hdr['stamp']:08x}"),
                ("checksum_hex", hdr["checksum_hex"]),
                ("header_hex", data[:HEADER_SIZE]),
            ],
        )
    except Exception:
        _trace(ip, "handshake_recv", [("len", len(data)), ("hex", data)])

    return did, stamp, stamp_time_ms


# --- 2) Build encrypted request packet (MiioProtocol.js: _encryptMessage()) ---
def build_request_packet(
    token_hex: str,
    did: int,
    base_stamp: int,
    base_stamp_time_ms: int,
    payload_obj: dict,
    trace_addr: str = "-",
    now_ms_override: int | None = None,
) -> bytes:
    # MiioProtocol.js: setDevice() derives _token, _tokenKey, _tokenIV:
    #   _token    = Buffer.from(token, 'hex')
    #   _tokenKey = md5(_token)
    #   _tokenIV  = md5(_tokenKey + _token)
    token = bytes.fromhex(token_hex)
    token_key = _md5(token)
    token_iv = _md5(token_key + token)

    _trace(
        trace_addr,
        "token_derive",
        [("token", token), ("token_key", token_key), ("token_iv", token_iv)],
    )

    # MiioProtocol.js: _encryptMessage() encrypts JSON bytes
    payload_str = json.dumps(payload_obj, separators=(",", ":"))
    payload = payload_str.encode("utf-8")
    _trace(
        trace_addr,
        "plaintext_json",
        [("utf8", payload_str), ("len", len(payload)), ("hex", payload)],
    )
    encrypted = _aes128_cbc_encrypt(token_key, token_iv, payload)
    _trace(
        trace_addr,
        "encrypt_aes128_cbc",
        [("len", len(encrypted)), ("hex", encrypted)],
    )

    # MiioProtocol.js: header layout (32 bytes)
    # 0..1   magic 0x2131
    # 2..3   length
    # 4..7   unknown (0)
    # 8..11  deviceId
    # 12..15 stamp
    # 16..31 checksum (MD5)
    now_ms = now_ms_override if now_ms_override is not None else int(time.time() * 1000)
    seconds_passed = max(0, (now_ms - base_stamp_time_ms) // 1000)
    stamp = int(base_stamp) + int(seconds_passed)
    _trace(
        trace_addr,
        "stamp_compute",
        [
            ("base_stamp", int(base_stamp)),
            ("base_stamp_hex", f"{int(base_stamp):08x}"),
            ("base_time_ms", int(base_stamp_time_ms)),
            ("now_ms", int(now_ms)),
            ("seconds_passed", int(seconds_passed)),
            ("stamp", int(stamp)),
            ("stamp_hex", f"{int(stamp):08x}"),
        ],
    )

    header = bytearray(HEADER_SIZE)
    struct.pack_into(">H", header, OFF_MAGIC, 0x2131)
    struct.pack_into(">H", header, OFF_LEN, HEADER_SIZE + len(encrypted))
    struct.pack_into(">I", header, OFF_UNKNOWN, 0)
    struct.pack_into(">I", header, OFF_DID, int(did))
    struct.pack_into(">I", header, OFF_STAMP, int(stamp))

    _trace(
        trace_addr,
        "header_before_checksum",
        [
            ("magic_hex", "2131"),
            ("length", HEADER_SIZE + len(encrypted)),
            ("unknown", 0),
            ("did", int(did)),
            ("did_hex", f"{int(did):08x}"),
            ("stamp", int(stamp)),
            ("stamp_hex", f"{int(stamp):08x}"),
            ("header16_hex", bytes(header[:16])),
        ],
    )

    # MiioProtocol.js: checksum digest = md5(header[0:16] + token + encrypted)
    checksum = _md5(bytes(header[:16]) + token + encrypted)
    header[OFF_CHECKSUM : OFF_CHECKSUM + 16] = checksum
    _trace(
        trace_addr,
        "checksum_md5",
        [("md5", checksum), ("header32_hex", bytes(header))],
    )

    pkt = bytes(header) + encrypted
    _trace(trace_addr, "packet", [("len", len(pkt)), ("hex", pkt)])
    return pkt


# --- 3) Send `get-prop <IP> 2.1` (MiioProtocol.js: send() -> _send() -> _socketSend()) ---
def send_get_prop(ip: str, token_hex: str, siid: int = 2, piid: int = 1) -> bytes:
    # For 1:1 comparison with Node output, you can reuse the exact base values:
    #   MIOT_DID / MIOT_BASE_STAMP / MIOT_BASE_STAMP_TIME_MS / MIOT_NOW_MS
    env_did = _env_int("MIOT_DID")
    env_stamp = _env_int("MIOT_BASE_STAMP")
    env_stamp_time_ms = _env_int("MIOT_BASE_STAMP_TIME_MS")
    env_now_ms = _env_int("MIOT_NOW_MS")

    did_source = "handshake"
    if env_did is not None and env_stamp is not None and env_stamp_time_ms is not None:
        did, stamp, stamp_time_ms = int(env_did), int(env_stamp), int(env_stamp_time_ms)
        did_source = "env"
    else:
        # Handshake to obtain (did, stamp)
        did, stamp, stamp_time_ms = handshake(ip)

    _trace(
        ip,
        "handshake_values",
        [
            ("did", int(did)),
            ("did_hex", f"{int(did):08x}"),
            ("base_stamp", int(stamp)),
            ("base_stamp_hex", f"{int(stamp):08x}"),
            ("base_time_ms", int(stamp_time_ms)),
            ("source", did_source),
        ],
    )

    # MiioProtocol.js: request object contains {id, method, params}
    # Match JS `send()` behavior more closely:
    # request starts as {method, params}, then `id` is assigned later.
    request = {
        "method": "get_properties",
        "params": [{"siid": siid, "piid": piid}],
        "id": 1,
    }
    pkt = build_request_packet(
        token_hex,
        did,
        stamp,
        stamp_time_ms,
        request,
        trace_addr=ip,
        now_ms_override=env_now_ms,
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(pkt, (ip, PORT))
    s.close()
    return pkt


def send_action(
    ip: str,
    token_hex: str,
    siid: int,
    aiid: int,
    in_params: list | None = None,
) -> bytes:
    if in_params is None:
        in_params = []

    env_did = _env_int("MIOT_DID")
    env_stamp = _env_int("MIOT_BASE_STAMP")
    env_stamp_time_ms = _env_int("MIOT_BASE_STAMP_TIME_MS")
    env_now_ms = _env_int("MIOT_NOW_MS")

    did_source = "handshake"
    if env_did is not None and env_stamp is not None and env_stamp_time_ms is not None:
        did, stamp, stamp_time_ms = int(env_did), int(env_stamp), int(env_stamp_time_ms)
        did_source = "env"
    else:
        did, stamp, stamp_time_ms = handshake(ip)

    _trace(
        ip,
        "handshake_values",
        [
            ("did", int(did)),
            ("did_hex", f"{int(did):08x}"),
            ("base_stamp", int(stamp)),
            ("base_stamp_hex", f"{int(stamp):08x}"),
            ("base_time_ms", int(stamp_time_ms)),
            ("source", did_source),
        ],
    )

    # Match cli/commands/action.js:
    #   method='action', params={siid, aiid, in: []}
    action_request = {
        "siid": int(siid),
        "aiid": int(aiid),
        "in": in_params,
    }

    request = {
        "method": "action",
        "params": action_request,
        "id": 1,
    }

    pkt = build_request_packet(
        token_hex,
        did,
        stamp,
        stamp_time_ms,
        request,
        trace_addr=ip,
        now_ms_override=env_now_ms,
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(pkt, (ip, PORT))
    s.close()
    return pkt


if __name__ == "__main__":
    # Keep it minimal: configure via env vars or edit defaults.
    ip = os.getenv("MIOT_IP", "192.168.31.141")
    token = os.getenv("MIOT_TOKEN", "")
    if not token:
        raise SystemExit(
            "Set MIOT_TOKEN to your 32-hex token, e.g. MIOT_TOKEN=... python3 action.py"
        )

    # Action id format: "<siid>.<aiid>" (e.g. "2.1")
    action_id = os.getenv("MIOT_ACTION_ID", "2.1")
    if "." not in action_id:
        raise SystemExit("MIOT_ACTION_ID must be like '2.1'")
    siid_s, aiid_s = action_id.split(".", 1)
    siid = int(siid_s)
    aiid = int(aiid_s)

    in_json = os.getenv("MIOT_IN", "[]")
    try:
        in_params = json.loads(in_json)
    except Exception as e:
        raise SystemExit(f"Invalid MIOT_IN JSON: {e}")
    if not isinstance(in_params, list):
        raise SystemExit("MIOT_IN must be a JSON list, e.g. '[]'")

    pkt = send_action(ip, token, siid, aiid, in_params)
    print(f"sent {len(pkt)} bytes to {ip}:{PORT}")
    print(pkt.hex())

    if os.getenv("MIOT_DEBUG_HEADER") == "1":
        print(_decode_header(pkt))
