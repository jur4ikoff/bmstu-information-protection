"""Учебная комплексная криптосистема: RSA-OAEP, AES-256-CTR и ЭЦП RSA.

Модуль не требует сторонних пакетов. Форматы файлов являются форматом этой
работы и не предназначены для совместимости с OpenSSL или другими утилитами.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SHA256_SIZE = 32
PBKDF2_ITERATIONS = 310_000
OAEP_LABEL = b"lab-03 RSA session key"
_DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _i2osp(value: int, length: int) -> bytes:
    if value < 0 or value >= 256**length:
        raise ValueError("integer does not fit into requested length")
    return value.to_bytes(length, "big")


def _os2ip(value: bytes) -> int:
    return int.from_bytes(value, "big")


def _mgf1(seed: bytes, length: int) -> bytes:
    result = bytearray()
    for counter in range(math.ceil(length / SHA256_SIZE)):
        result.extend(hashlib.sha256(seed + _i2osp(counter, 4)).digest())
    return bytes(result[:length])


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def is_probable_prime(candidate: int, rounds: int = 40) -> bool:
    """Проверка простоты Миллера--Рабина с криптографически случайными базами."""
    if candidate < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if candidate in small_primes:
        return True
    if any(candidate % p == 0 for p in small_primes):
        return False
    odd_part, exponent = candidate - 1, 0
    while odd_part % 2 == 0:
        exponent += 1
        odd_part //= 2
    for _ in range(rounds):
        base = secrets.randbelow(candidate - 3) + 2
        value = pow(base, odd_part, candidate)
        if value in (1, candidate - 1):
            continue
        for _ in range(exponent - 1):
            value = pow(value, 2, candidate)
            if value == candidate - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        value = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(value):
            return value


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int = 65537

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def to_dict(self) -> dict[str, str]:
        return {"n": str(self.n), "e": str(self.e)}

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "PublicKey":
        return cls(n=int(data["n"]), e=int(data["e"]))


@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int
    e: int = 65537
    p: int | None = None
    q: int | None = None

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(self.n, self.e)

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def to_dict(self) -> dict[str, str]:
        return {
            "n": str(self.n),
            "e": str(self.e),
            "d": str(self.d),
            "p": str(self.p) if self.p else "",
            "q": str(self.q) if self.q else "",
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "PrivateKey":
        return cls(
            int(data["n"]),
            int(data["d"]),
            int(data["e"]),
            int(data["p"]) if data.get("p") else None,
            int(data["q"]) if data.get("q") else None,
        )


def generate_key_pair(bits: int = 2048) -> tuple[PublicKey, PrivateKey]:
    """Генерирует RSA-ключи. 1024 бита оставлены только для быстрых тестов."""
    if bits < 1024 or bits % 2:
        raise ValueError(
            "RSA modulus length must be an even number of at least 1024 bits"
        )
    e = 65537
    while True:
        p, q = _generate_prime(bits // 2), _generate_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            n = p * q
            return PublicKey(n, e), PrivateKey(n, pow(e, -1, phi), e, p, q)


# AES-256 implementation ----------------------------------------------------
def _gmul(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        left = ((left << 1) ^ (0x11B if left & 0x80 else 0)) & 0xFF
        right >>= 1
    return result


def _rot8(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _aes_sbox(value: int) -> int:
    inverse = 0 if value == 0 else _gf_power(value, 254)
    return (
        inverse
        ^ _rot8(inverse, 1)
        ^ _rot8(inverse, 2)
        ^ _rot8(inverse, 3)
        ^ _rot8(inverse, 4)
        ^ 0x63
    )


def _gf_power(value: int, power: int) -> int:
    result = 1
    while power:
        if power & 1:
            result = _gmul(result, value)
        value = _gmul(value, value)
        power >>= 1
    return result


_SBOX = tuple(_aes_sbox(i) for i in range(256))


def _expand_aes256_key(key: bytes) -> list[bytes]:
    if len(key) != 32:
        raise ValueError("AES-256 key must contain 32 bytes")
    words = [list(key[index : index + 4]) for index in range(0, 32, 4)]
    rcon = 1
    for index in range(8, 60):
        word = words[index - 1].copy()
        if index % 8 == 0:
            word = [_SBOX[item] for item in word[1:] + word[:1]]
            word[0] ^= rcon
            rcon = _gmul(rcon, 2)
        elif index % 8 == 4:
            word = [_SBOX[item] for item in word]
        words.append([a ^ b for a, b in zip(words[index - 8], word)])
    return [bytes(sum(words[offset : offset + 4], [])) for offset in range(0, 60, 4)]


def _aes_block(block: bytes, round_keys: list[bytes]) -> bytes:
    if len(block) != 16:
        raise ValueError("AES operates on 16-byte blocks")
    state = [value ^ round_keys[0][index] for index, value in enumerate(block)]

    def substitute() -> None:
        for index, value in enumerate(state):
            state[index] = _SBOX[value]

    def shift_rows() -> None:
        saved = state.copy()
        for row in range(4):
            for column in range(4):
                state[4 * column + row] = saved[4 * ((column + row) % 4) + row]

    def mix_columns() -> None:
        for column in range(4):
            offset = 4 * column
            a, b, c, d = state[offset : offset + 4]
            state[offset : offset + 4] = [
                _gmul(a, 2) ^ _gmul(b, 3) ^ c ^ d,
                a ^ _gmul(b, 2) ^ _gmul(c, 3) ^ d,
                a ^ b ^ _gmul(c, 2) ^ _gmul(d, 3),
                _gmul(a, 3) ^ b ^ c ^ _gmul(d, 2),
            ]

    for round_number in range(1, 14):
        substitute()
        shift_rows()
        mix_columns()
        state = [
            value ^ round_keys[round_number][index] for index, value in enumerate(state)
        ]
    substitute()
    shift_rows()
    return bytes(value ^ round_keys[14][index] for index, value in enumerate(state))


def aes256_ctr(data: bytes, key: bytes, initial_counter: bytes) -> bytes:
    """AES-256 in CTR mode; encryption and decryption are the same operation."""
    if len(initial_counter) != 16:
        raise ValueError("CTR counter must contain 16 bytes")
    round_keys = _expand_aes256_key(key)
    counter = int.from_bytes(initial_counter, "big")
    output = bytearray()
    for offset in range(0, len(data), 16):
        stream = _aes_block(counter.to_bytes(16, "big"), round_keys)
        output.extend(_xor(data[offset : offset + 16], stream))
        counter = (counter + 1) % (1 << 128)
    return bytes(output)


# RSA and serialisation ------------------------------------------------------
def rsa_oaep_encrypt(
    message: bytes, public_key: PublicKey, label: bytes = OAEP_LABEL
) -> bytes:
    key_size = public_key.size_bytes
    if len(message) > key_size - 2 * SHA256_SIZE - 2:
        raise ValueError("message is too long for this RSA-OAEP key")
    label_hash = hashlib.sha256(label).digest()
    padding = b"\x00" * (key_size - len(message) - 2 * SHA256_SIZE - 2)
    db = label_hash + padding + b"\x01" + message
    seed = secrets.token_bytes(SHA256_SIZE)
    masked_db = _xor(db, _mgf1(seed, key_size - SHA256_SIZE - 1))
    masked_seed = _xor(seed, _mgf1(masked_db, SHA256_SIZE))
    encoded = b"\x00" + masked_seed + masked_db
    return _i2osp(pow(_os2ip(encoded), public_key.e, public_key.n), key_size)


def rsa_oaep_decrypt(
    ciphertext: bytes, private_key: PrivateKey, label: bytes = OAEP_LABEL
) -> bytes:
    key_size = private_key.size_bytes
    if len(ciphertext) != key_size or _os2ip(ciphertext) >= private_key.n:
        raise ValueError("invalid RSA-OAEP ciphertext")
    encoded = _i2osp(pow(_os2ip(ciphertext), private_key.d, private_key.n), key_size)
    masked_seed, masked_db = encoded[1 : 1 + SHA256_SIZE], encoded[1 + SHA256_SIZE :]
    seed = _xor(masked_seed, _mgf1(masked_db, SHA256_SIZE))
    db = _xor(masked_db, _mgf1(seed, key_size - SHA256_SIZE - 1))
    valid = encoded[0] == 0 and hmac.compare_digest(
        db[:SHA256_SIZE], hashlib.sha256(label).digest()
    )
    separator = db.find(b"\x01", SHA256_SIZE)
    valid = valid and separator >= SHA256_SIZE and not any(db[SHA256_SIZE:separator])
    if not valid:
        raise ValueError("invalid RSA-OAEP ciphertext or label")
    return db[separator + 1 :]


def sign(data: bytes, private_key: PrivateKey) -> bytes:
    """Создаёт RSA PKCS#1 v1.5 подпись SHA-256."""
    digest_info = _DIGEST_INFO_SHA256 + hashlib.sha256(data).digest()
    padding_length = private_key.size_bytes - len(digest_info) - 3
    if padding_length < 8:
        raise ValueError("RSA key is too short for SHA-256 signature")
    encoded = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    return _i2osp(
        pow(_os2ip(encoded), private_key.d, private_key.n), private_key.size_bytes
    )


def verify(data: bytes, signature: bytes, public_key: PublicKey) -> bool:
    if len(signature) != public_key.size_bytes or _os2ip(signature) >= public_key.n:
        return False
    digest_info = _DIGEST_INFO_SHA256 + hashlib.sha256(data).digest()
    padding_length = public_key.size_bytes - len(digest_info) - 3
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    recovered = _i2osp(
        pow(_os2ip(signature), public_key.e, public_key.n), public_key.size_bytes
    )
    return hmac.compare_digest(recovered, expected)


def _authenticated_encrypt(
    data: bytes, key: bytes, context: bytes
) -> tuple[bytes, bytes, bytes]:
    nonce = secrets.token_bytes(16)
    ciphertext = aes256_ctr(data, key, nonce)
    tag = hmac.new(
        hashlib.sha256(b"mac" + key).digest(),
        context + nonce + ciphertext,
        hashlib.sha256,
    ).digest()
    return nonce, ciphertext, tag


def _authenticated_decrypt(
    nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes, context: bytes
) -> bytes:
    expected = hmac.new(
        hashlib.sha256(b"mac" + key).digest(),
        context + nonce + ciphertext,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError(
            "authentication tag is invalid: data was changed or password is wrong"
        )
    return aes256_ctr(ciphertext, key, nonce)


def _dump(path: str | Path, magic: str, values: dict[str, Any]) -> None:
    Path(path).write_text(
        json.dumps({"format": magic, **values}, sort_keys=True), encoding="utf-8"
    )


def _load(path: str | Path, magic: str) -> dict[str, Any]:
    try:
        result = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("file is not a valid cryptosystem container") from exc
    if result.get("format") != magic:
        raise ValueError(f"expected {magic} container")
    return result


def save_public_key(path: str | Path, public_key: PublicKey) -> None:
    _dump(path, "lab03-public-v1", public_key.to_dict())


def load_public_key(path: str | Path) -> PublicKey:
    return PublicKey.from_dict(_load(path, "lab03-public-v1"))


def save_private_key(path: str | Path, private_key: PrivateKey, password: str) -> None:
    if not password:
        raise ValueError("master password cannot be empty")
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, 32
    )
    plaintext = json.dumps(private_key.to_dict(), sort_keys=True).encode("utf-8")
    nonce, ciphertext, tag = _authenticated_encrypt(plaintext, key, b"lab03-private-v1")
    _dump(
        path,
        "lab03-private-v1",
        {
            "iterations": PBKDF2_ITERATIONS,
            "salt": _b64(salt),
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
            "tag": _b64(tag),
        },
    )


def load_private_key(path: str | Path, password: str) -> PrivateKey:
    values = _load(path, "lab03-private-v1")
    try:
        salt, nonce, ciphertext, tag = (
            _unb64(values[name]) for name in ("salt", "nonce", "ciphertext", "tag")
        )
        iterations = int(values["iterations"])
        key = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations, 32
        )
        plaintext = _authenticated_decrypt(
            nonce, ciphertext, tag, key, b"lab03-private-v1"
        )
        return PrivateKey.from_dict(json.loads(plaintext.decode("utf-8")))
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ValueError(
            "unable to decrypt private key: wrong password or damaged file"
        ) from exc


def encrypt_file(
    source: str | Path, destination: str | Path, public_key: PublicKey
) -> None:
    session_key = secrets.token_bytes(32)
    plaintext = Path(source).read_bytes()
    nonce, ciphertext, tag = _authenticated_encrypt(
        plaintext, session_key, b"lab03-file-v1"
    )
    _dump(
        destination,
        "lab03-envelope-v1",
        {
            "encrypted_key": _b64(rsa_oaep_encrypt(session_key, public_key)),
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
            "tag": _b64(tag),
        },
    )


def decrypt_file(
    source: str | Path, destination: str | Path, private_key: PrivateKey
) -> None:
    values = _load(source, "lab03-envelope-v1")
    try:
        session_key = rsa_oaep_decrypt(_unb64(values["encrypted_key"]), private_key)
        plaintext = _authenticated_decrypt(
            _unb64(values["nonce"]),
            _unb64(values["ciphertext"]),
            _unb64(values["tag"]),
            session_key,
            b"lab03-file-v1",
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "unable to decrypt file: incorrect key or damaged envelope"
        ) from exc
    Path(destination).write_bytes(plaintext)


def sign_file(
    source: str | Path, signature_path: str | Path, private_key: PrivateKey
) -> None:
    _dump(
        signature_path,
        "lab03-signature-v1",
        {"signature": _b64(sign(Path(source).read_bytes(), private_key))},
    )


def verify_file(
    source: str | Path, signature_path: str | Path, public_key: PublicKey
) -> bool:
    try:
        signature = _unb64(_load(signature_path, "lab03-signature-v1")["signature"])
    except (KeyError, TypeError, ValueError):
        return False
    return verify(Path(source).read_bytes(), signature, public_key)
