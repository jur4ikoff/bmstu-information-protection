"""Streaming RSA-OAEP + AES-256-GCM implementation for laboratory work 5."""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import os
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"HYB1"
NONCE_SIZE, TAG_SIZE, AES256_KEY_SIZE = 12, 16, 32
SHA256_SIZE, PBKDF2_ITERATIONS, BUFFER_SIZE = 32, 310_000, 64 * 1024


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _i2osp(value: int, size: int) -> bytes:
    if not 0 <= value < 1 << (size * 8):
        raise ValueError("integer does not fit requested size")
    return value.to_bytes(size, "big")


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if not b:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - a // b * y


def mod_inverse(a: int, n: int) -> int:
    g, x, _ = _egcd(a, n)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % n


def mod_pow(a: int, exponent: int, n: int) -> int:
    if exponent < 0 or n <= 0:
        raise ValueError("invalid exponent or modulus")
    result, a = 1 % n, a % n
    while exponent:
        if exponent & 1:
            result = result * a % n
        a, exponent = a * a % n, exponent >> 1
    return result


def _prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small:
        return True
    if any(n % p == 0 for p in small):
        return False
    d, s = n - 1, 0
    while not d & 1:
        d, s = d >> 1, s + 1
    for _ in range(rounds):
        x = mod_pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        value = secrets.randbits(bits) | 1 | (1 << (bits - 1))
        if _prime(value):
            return value


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int = 65537

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int
    e: int
    p: int
    q: int

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(self.n, self.e)

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


def generate_key_pair(bits: int = 2048) -> tuple[PublicKey, PrivateKey]:
    """A 1024-bit key is permitted here only for fast unit tests; CLI requires 2048."""
    if bits < 1024 or bits % 2:
        raise ValueError("RSA size must be even and at least 1024 bits")
    while True:
        p, q = _generate_prime(bits // 2), _generate_prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and math.gcd(65537, phi) == 1:
            n = p * q
            d = mod_inverse(65537, phi)
            return PublicKey(n), PrivateKey(n, d, 65537, p, q)


def _rsa_private(c: int, key: PrivateKey) -> int:
    if not 0 <= c < key.n:
        raise ValueError("invalid RSA ciphertext")
    mp = mod_pow(c, key.d % (key.p - 1), key.p)
    mq = mod_pow(c, key.d % (key.q - 1), key.q)
    return mq + key.q * ((mp - mq) * mod_inverse(key.q, key.p) % key.p)


def _mgf1(seed: bytes, length: int) -> bytes:
    return b"".join(
        hashlib.sha256(seed + _i2osp(i, 4)).digest()
        for i in range(math.ceil(length / SHA256_SIZE))
    )[:length]


def rsa_oaep_encrypt(message: bytes, key: PublicKey) -> bytes:
    size = key.size_bytes
    if len(message) > size - 2 * SHA256_SIZE - 2:
        raise ValueError("message is too long for RSA-OAEP")
    db = (
        hashlib.sha256(b"").digest()
        + b"\0" * (size - len(message) - 2 * SHA256_SIZE - 2)
        + b"\1"
        + message
    )
    seed = secrets.token_bytes(SHA256_SIZE)
    masked_db = _xor(db, _mgf1(seed, len(db)))
    encoded = b"\0" + _xor(seed, _mgf1(masked_db, SHA256_SIZE)) + masked_db
    return _i2osp(mod_pow(int.from_bytes(encoded, "big"), key.e, key.n), size)


def rsa_oaep_decrypt(ciphertext: bytes, key: PrivateKey) -> bytes:
    size = key.size_bytes
    if len(ciphertext) != size or int.from_bytes(ciphertext, "big") >= key.n:
        raise ValueError("invalid RSA-OAEP encrypted session key")
    encoded = _i2osp(_rsa_private(int.from_bytes(ciphertext, "big"), key), size)
    seed = _xor(encoded[1:33], _mgf1(encoded[33:], SHA256_SIZE))
    db = _xor(encoded[33:], _mgf1(seed, size - 33))
    separator = db.find(b"\1", SHA256_SIZE)
    if (
        encoded[0]
        or not hmac.compare_digest(db[:32], hashlib.sha256(b"").digest())
        or separator < 32
        or any(db[32:separator])
    ):
        raise ValueError("invalid RSA-OAEP encrypted session key")
    return db[separator + 1 :]


# AES, with FIPS-197 state layout (four column-major columns).
def _gmul(a: int, b: int) -> int:
    value = 0
    for _ in range(8):
        if b & 1:
            value ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return value


def _gfpow(a: int, exponent: int) -> int:
    value = 1
    while exponent:
        if exponent & 1:
            value = _gmul(value, a)
        a, exponent = _gmul(a, a), exponent >> 1
    return value


def _sbox_byte(a: int) -> int:
    a = 0 if a == 0 else _gfpow(a, 254)
    return (
        a
        ^ ((a << 1 | a >> 7) & 255)
        ^ ((a << 2 | a >> 6) & 255)
        ^ ((a << 3 | a >> 5) & 255)
        ^ ((a << 4 | a >> 4) & 255)
        ^ 0x63
    )


_SBOX = tuple(_sbox_byte(i) for i in range(256))
_INV_SBOX = tuple(_SBOX.index(i) for i in range(256))


def _expand_aes_key(key: bytes) -> list[bytes]:
    """KeyExpansion for AES-128, AES-192 and AES-256."""
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    nk, nr = len(key) // 4, len(key) // 4 + 6
    words = [list(key[i : i + 4]) for i in range(0, len(key), 4)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = words[i - 1].copy()
        if i % nk == 0:
            temp = [_SBOX[x] for x in temp[1:] + temp[:1]]
            temp[0], rcon = temp[0] ^ rcon, _gmul(rcon, 2)
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[x] for x in temp]
        words.append([a ^ b for a, b in zip(words[i - nk], temp)])
    return [bytes(sum(words[i : i + 4], [])) for i in range(0, len(words), 4)]


def _shift_rows(state: list[int], inverse: bool = False) -> list[int]:
    result = state.copy()
    for row in range(4):
        for col in range(4):
            result[4 * col + row] = state[
                4 * ((col - row if inverse else col + row) % 4) + row
            ]
    return result


def _mix_columns(state: list[int], inverse: bool = False) -> list[int]:
    result = state.copy()
    c = (14, 11, 13, 9) if inverse else (2, 3, 1, 1)
    for col in range(4):
        a, b, d, e = state[4 * col : 4 * col + 4]
        result[4 * col : 4 * col + 4] = [
            _gmul(a, c[0]) ^ _gmul(b, c[1]) ^ _gmul(d, c[2]) ^ _gmul(e, c[3]),
            _gmul(a, c[3]) ^ _gmul(b, c[0]) ^ _gmul(d, c[1]) ^ _gmul(e, c[2]),
            _gmul(a, c[2]) ^ _gmul(b, c[3]) ^ _gmul(d, c[0]) ^ _gmul(e, c[1]),
            _gmul(a, c[1]) ^ _gmul(b, c[2]) ^ _gmul(d, c[3]) ^ _gmul(e, c[0]),
        ]
    return result


def _aes_encrypt_block(block: bytes, keys: list[bytes]) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    state = list(_xor(block, keys[0]))
    for round_key in keys[1:-1]:
        state = [_SBOX[x] for x in state]
        state = _mix_columns(_shift_rows(state))
        state = list(_xor(bytes(state), round_key))
    state = _shift_rows([_SBOX[x] for x in state])
    return _xor(bytes(state), keys[-1])


def _aes_decrypt_block(block: bytes, keys: list[bytes]) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    state = list(_xor(block, keys[-1]))
    for round_key in reversed(keys[1:-1]):
        state = [_INV_SBOX[x] for x in _shift_rows(state, True)]
        state = _mix_columns(list(_xor(bytes(state), round_key)), True)
    state = [_INV_SBOX[x] for x in _shift_rows(state, True)]
    return _xor(bytes(state), keys[0])


def aes128_encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    return _aes_encrypt_block(block, _expand_aes_key(key))


def aes128_decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    return _aes_decrypt_block(block, _expand_aes_key(key))


def _inc32(counter: bytes) -> bytes:
    return counter[:12] + (
        (int.from_bytes(counter[12:], "big") + 1) & 0xFFFFFFFF
    ).to_bytes(4, "big")


def _gf128mul(a: bytes, b: bytes) -> bytes:
    x, y, result = int.from_bytes(a, "big"), int.from_bytes(b, "big"), 0
    for bit in range(128):
        if (x >> (127 - bit)) & 1:
            result ^= y
        y = (y >> 1) ^ (0xE1000000000000000000000000000000 if y & 1 else 0)
    return result.to_bytes(16, "big")


class _GHash:
    def __init__(self, subkey: bytes):
        self.subkey, self.value, self.pending = subkey, bytes(16), b""

    def update(self, data: bytes) -> None:
        data = self.pending + data
        full = len(data) // 16 * 16
        for i in range(0, full, 16):
            self.value = _gf128mul(_xor(self.value, data[i : i + 16]), self.subkey)
        self.pending = data[full:]

    def finish(self, length: int) -> bytes:
        if self.pending:
            self.value = _gf128mul(
                _xor(self.value, self.pending.ljust(16, b"\0")), self.subkey
            )
        return _gf128mul(
            _xor(self.value, (length * 8).to_bytes(16, "big")), self.subkey
        )


def _gcm_context(key: bytes, nonce: bytes) -> tuple[list[bytes], bytes, bytes]:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("AES-256-GCM needs a 32-byte key and 12-byte nonce")
    keys = _expand_aes_key(key)
    return keys, _aes_encrypt_block(bytes(16), keys), nonce + b"\0\0\0\1"


def _gcm_transform(
    data: bytes, keys: list[bytes], counter: bytes
) -> tuple[bytes, bytes]:
    output = bytearray()
    for i in range(0, len(data), 16):
        counter = _inc32(counter)
        output.extend(_xor(data[i : i + 16], _aes_encrypt_block(counter, keys)))
    return bytes(output), counter


def _gcm_tag(subkey: bytes, ciphertext: bytes) -> bytes:
    ghash = _GHash(subkey)
    ghash.update(ciphertext)
    return ghash.finish(len(ciphertext))


def _pem(label: str, content: bytes) -> bytes:
    encoded = base64.b64encode(content).decode("ascii")
    return (
        f"-----BEGIN {label}-----\n"
        + "\n".join(encoded[i : i + 64] for i in range(0, len(encoded), 64))
        + f"\n-----END {label}-----\n"
    ).encode("ascii")


def _unpem(raw: bytes, label: str) -> bytes:
    try:
        lines = raw.decode("ascii").strip().splitlines()
        if (
            lines[0] != f"-----BEGIN {label}-----"
            or lines[-1] != f"-----END {label}-----"
        ):
            raise ValueError
        return base64.b64decode("".join(lines[1:-1]), validate=True)
    except (UnicodeDecodeError, IndexError, ValueError) as error:
        raise ValueError("invalid PEM") from error


def _der_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    encoded = _i2osp(length, (length.bit_length() + 7) // 8)
    return bytes([0x80 | len(encoded)]) + encoded


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _der_integer(value: int) -> bytes:
    raw = _i2osp(value, max(1, (value.bit_length() + 7) // 8))
    return _der(2, (b"\0" if raw[0] & 0x80 else b"") + raw)


def _sequence(*parts: bytes) -> bytes:
    return _der(0x30, b"".join(parts))


def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise ValueError("truncated DER")
    lead = data[pos]
    if not lead & 128:
        return lead, pos + 1
    count = lead & 127
    if count == 0 or pos + count >= len(data):
        raise ValueError("invalid DER length")
    return int.from_bytes(data[pos + 1 : pos + 1 + count], "big"), pos + 1 + count


def _read_der(data: bytes, pos: int, tag: int) -> tuple[bytes, int]:
    if pos >= len(data) or data[pos] != tag:
        raise ValueError("unexpected DER tag")
    length, start = _read_length(data, pos + 1)
    if start + length > len(data):
        raise ValueError("truncated DER")
    return data[start : start + length], start + length


def _read_int(data: bytes, pos: int) -> tuple[int, int]:
    raw, pos = _read_der(data, pos, 2)
    if not raw or raw[0] & 128:
        raise ValueError("invalid DER integer")
    return int.from_bytes(raw, "big"), pos


def _public_der(key: PublicKey) -> bytes:
    return _sequence(_der_integer(key.n), _der_integer(key.e))


def _private_der(key: PrivateKey) -> bytes:
    return _sequence(
        *(
            _der_integer(x)
            for x in (
                0,
                key.n,
                key.e,
                key.d,
                key.p,
                key.q,
                key.d % (key.p - 1),
                key.d % (key.q - 1),
                mod_inverse(key.q, key.p),
            )
        )
    )


def _parse_public(data: bytes) -> PublicKey:
    body, end = _read_der(data, 0, 0x30)
    n, pos = _read_int(body, 0)
    e, pos = _read_int(body, pos)
    if end != len(data) or pos != len(body) or n.bit_length() < 1024 or not 1 < e < n:
        raise ValueError("invalid RSA public key")
    return PublicKey(n, e)


def _parse_private(data: bytes) -> PrivateKey:
    body, end = _read_der(data, 0, 0x30)
    pos, values = 0, []
    while pos < len(body):
        value, pos = _read_int(body, pos)
        values.append(value)
    if end != len(data) or len(values) != 9 or values[0] != 0:
        raise ValueError("invalid RSA private key")
    _, n, e, d, p, q, dp, dq, qi = values
    if n != p * q or dp != d % (p - 1) or dq != d % (q - 1) or qi != mod_inverse(q, p):
        raise ValueError("invalid RSA private key")
    return PrivateKey(n, d, e, p, q)


def save_public_key(path: str | Path, key: PublicKey) -> None:
    Path(path).write_bytes(_pem("RSA PUBLIC KEY", _public_der(key)))


def load_public_key(path: str | Path) -> PublicKey:
    try:
        return _parse_public(_unpem(Path(path).read_bytes(), "RSA PUBLIC KEY"))
    except (OSError, ValueError) as error:
        raise ValueError("cannot read RSA public PEM key") from error


def save_private_key(path: str | Path, key: PrivateKey, password: str) -> None:
    if not password:
        raise ValueError("password for private key cannot be empty")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PBKDF2_ITERATIONS, 32
    )
    keys, subkey, counter = _gcm_context(derived, nonce)
    plaintext = _private_der(key)
    ciphertext, _ = _gcm_transform(plaintext, keys, counter)
    tag = _xor(_aes_encrypt_block(counter, keys), _gcm_tag(subkey, ciphertext))
    blob = (
        b"L5PK" + PBKDF2_ITERATIONS.to_bytes(4, "big") + salt + nonce + ciphertext + tag
    )
    Path(path).write_bytes(_pem("ENCRYPTED RSA PRIVATE KEY", blob))


def load_private_key(path: str | Path, password: str) -> PrivateKey:
    try:
        blob = _unpem(Path(path).read_bytes(), "ENCRYPTED RSA PRIVATE KEY")
        if len(blob) < 52 or blob[:4] != b"L5PK":
            raise ValueError("invalid encrypted private PEM")
        iterations = int.from_bytes(blob[4:8], "big")
        salt, nonce, ciphertext, tag = blob[8:24], blob[24:36], blob[36:-16], blob[-16:]
        if not password or not 100_000 <= iterations <= 2_000_000:
            raise ValueError("wrong password or damaged private PEM")
        derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, 32)
        keys, subkey, counter = _gcm_context(derived, nonce)
        expected = _xor(_aes_encrypt_block(counter, keys), _gcm_tag(subkey, ciphertext))
        if not hmac.compare_digest(tag, expected):
            raise ValueError("wrong password or damaged private PEM")
        plaintext, _ = _gcm_transform(ciphertext, keys, counter)
        return _parse_private(plaintext)
    except (OSError, ValueError) as error:
        raise ValueError(
            "cannot decrypt private PEM: wrong password or damaged file"
        ) from error


def _temporary(destination: str | Path):
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    return tempfile.NamedTemporaryFile(
        "wb", dir=target.parent, prefix=f".{target.name}.", delete=False
    )


def encrypt_file(source: str | Path, destination: str | Path, key: PublicKey) -> None:
    """Write HYB1 container while reading source in BUFFER_SIZE chunks."""
    session_key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    wrapped = rsa_oaep_encrypt(session_key, key)
    keys, subkey, counter = _gcm_context(session_key, nonce)
    ghash, total = _GHash(subkey), 0
    output = _temporary(destination)
    name = output.name
    try:
        with Path(source).open("rb") as input_file, output:
            output.write(MAGIC + len(wrapped).to_bytes(2, "big") + wrapped + nonce)
            while chunk := input_file.read(BUFFER_SIZE):
                ciphertext, counter = _gcm_transform(chunk, keys, counter)
                output.write(ciphertext)
                ghash.update(ciphertext)
                total += len(ciphertext)
            output.write(
                _xor(_aes_encrypt_block(nonce + b"\0\0\0\1", keys), ghash.finish(total))
            )
        os.replace(name, destination)
    except Exception:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        raise


def decrypt_file(source: str | Path, destination: str | Path, key: PrivateKey) -> None:
    """Only replaces destination after the GCM tag has been authenticated."""
    source_path = Path(source)
    try:
        size = source_path.stat().st_size
        with source_path.open("rb") as input_file:
            header = input_file.read(6)
            if len(header) != 6 or header[:4] != MAGIC:
                raise ValueError("invalid encrypted-file signature (expected HYB1)")
            wrapped_size = int.from_bytes(header[4:], "big")
            if wrapped_size != key.size_bytes:
                raise ValueError("encrypted file belongs to a different RSA key size")
            wrapped, nonce = input_file.read(wrapped_size), input_file.read(12)
            if len(wrapped) != wrapped_size or len(nonce) != 12:
                raise ValueError("encrypted file header is truncated")
            ciphertext_size = size - 6 - wrapped_size - 12 - 16
            if ciphertext_size < 0:
                raise ValueError("encrypted file is truncated")
            session_key = rsa_oaep_decrypt(wrapped, key)
            if len(session_key) != 32:
                raise ValueError("invalid decrypted AES session key")
            keys, subkey, counter = _gcm_context(session_key, nonce)
            ghash, processed = _GHash(subkey), 0
            output = _temporary(destination)
            name = output.name
            try:
                with output:
                    while processed < ciphertext_size:
                        chunk = input_file.read(
                            min(BUFFER_SIZE, ciphertext_size - processed)
                        )
                        if not chunk:
                            raise ValueError("encrypted file is truncated")
                        plaintext, counter = _gcm_transform(chunk, keys, counter)
                        output.write(plaintext)
                        ghash.update(chunk)
                        processed += len(chunk)
                    tag = input_file.read(16)
                    if len(tag) != 16 or input_file.read(1):
                        raise ValueError("encrypted file has invalid length")
                    expected = _xor(
                        _aes_encrypt_block(nonce + b"\0\0\0\1", keys),
                        ghash.finish(processed),
                    )
                    if not hmac.compare_digest(tag, expected):
                        raise ValueError(
                            "authentication failed: wrong key or damaged file"
                        )
                os.replace(name, destination)
            except Exception:
                try:
                    os.unlink(name)
                except FileNotFoundError:
                    pass
                raise
    except OSError as error:
        raise ValueError(f"cannot process encrypted file: {error}") from error


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        while chunk := file.read(BUFFER_SIZE):
            digest.update(chunk)
    return digest.hexdigest()
