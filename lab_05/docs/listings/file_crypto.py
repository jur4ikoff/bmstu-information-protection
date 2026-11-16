# Листинг из lab_05/src/hybrid_crypto.py

def _pkcs7_pad(data: bytes) -> bytes:
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding]) * padding


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("invalid PKCS#7 padding")
    padding = data[-1]
    if not 1 <= padding <= BLOCK_SIZE or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-padding]


def _cbc_encrypt(data: bytes, keys: list[bytes], previous: bytes) -> tuple[bytes, bytes]:
    if len(data) % BLOCK_SIZE or len(previous) != BLOCK_SIZE:
        raise ValueError("CBC needs whole blocks and a 16-byte IV")
    output = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        previous = _aes_encrypt_block(_xor(data[i:i + BLOCK_SIZE], previous), keys)
        output.extend(previous)
    return bytes(output), previous


def _cbc_decrypt(data: bytes, keys: list[bytes], previous: bytes) -> tuple[bytes, bytes]:
    if len(data) % BLOCK_SIZE or len(previous) != BLOCK_SIZE:
        raise ValueError("CBC needs whole blocks and a 16-byte IV")
    output = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        output.extend(_xor(_aes_decrypt_block(block, keys), previous))
        previous = block
    return bytes(output), previous


def encrypt_file(source: str | Path, destination: str | Path, key: PublicKey) -> None:
    """HYB1: RSA(AES key || HMAC key), IV, CBC ciphertext, Encrypt-then-MAC."""
    _require_variant_key(key)
    aes_key, mac_key = secrets.token_bytes(AES256_KEY_SIZE), secrets.token_bytes(HMAC_KEY_SIZE)
    iv = secrets.token_bytes(IV_SIZE)
    wrapped = rsa_oaep_encrypt(aes_key + mac_key, key)
    header = MAGIC + len(wrapped).to_bytes(2, "big") + wrapped + iv
    mac = hmac.new(mac_key, header, hashlib.sha256)
    keys, previous, pending = _expand_aes_key(aes_key), iv, b""
    # Открываем источник до создания временного файла.
    with Path(source).open("rb") as input_file:
        output = _temporary(destination)
        name = output.name
        try:
            with output:
                output.write(header)
                while chunk := input_file.read(BUFFER_SIZE):
                    pending += chunk
                    full = len(pending) // BLOCK_SIZE * BLOCK_SIZE
                    ciphertext, previous = _cbc_encrypt(pending[:full], keys, previous)
                    pending = pending[full:]
                    output.write(ciphertext)
                    mac.update(ciphertext)
                ciphertext, _ = _cbc_encrypt(_pkcs7_pad(pending), keys, previous)
                output.write(ciphertext)
                mac.update(ciphertext)
                output.write(mac.digest())
            os.replace(name, destination)
        except Exception:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass
            raise


def decrypt_file(source: str | Path, destination: str | Path, key: PrivateKey) -> None:
    """Authenticate a bounded-memory snapshot before CBC decryption and unpadding."""
    _require_variant_key(key)
    try:
        with Path(source).open("rb") as input_file:
            size = os.fstat(input_file.fileno()).st_size
            prefix = input_file.read(6)
            if len(prefix) != 6 or prefix[:4] != MAGIC:
                raise ValueError("invalid encrypted-file signature (expected HYB1)")
            wrapped_size = int.from_bytes(prefix[4:], "big")
            if wrapped_size != key.size_bytes:
                raise ValueError("invalid encrypted session material length")
            wrapped, iv = input_file.read(wrapped_size), input_file.read(IV_SIZE)
            if len(wrapped) != wrapped_size or len(iv) != IV_SIZE:
                raise ValueError("encrypted file header is truncated")
            ciphertext_size = size - 6 - wrapped_size - IV_SIZE - TAG_SIZE
            if ciphertext_size < BLOCK_SIZE or ciphertext_size % BLOCK_SIZE:
                raise ValueError("invalid CBC ciphertext length")
            material = rsa_oaep_decrypt(wrapped, key)
            if len(material) != AES256_KEY_SIZE + HMAC_KEY_SIZE:
                raise ValueError("invalid AES/HMAC session material (variant 3 required)")
            aes_key, mac_key = material[:AES256_KEY_SIZE], material[AES256_KEY_SIZE:]
            mac = hmac.new(mac_key, prefix + wrapped + iv, hashlib.sha256)
            # Снимок исключает изменение шифртекста между проверкой и расшифровкой.
            with tempfile.TemporaryFile("w+b") as authenticated:
                remaining = ciphertext_size
                while remaining:
                    chunk = input_file.read(min(BUFFER_SIZE, remaining))
                    if not chunk:
                        raise ValueError("encrypted file is truncated")
                    authenticated.write(chunk)
                    mac.update(chunk)
                    remaining -= len(chunk)
                tag = input_file.read(TAG_SIZE)
                if len(tag) != TAG_SIZE or input_file.read(1):
                    raise ValueError("encrypted file has invalid length")
                if not hmac.compare_digest(tag, mac.digest()):
                    raise ValueError("authentication failed: wrong key or damaged file")
                authenticated.seek(0)
                keys, previous = _expand_aes_key(aes_key), iv
                output = _temporary(destination)
                name = output.name
                try:
                    with output:
                        remaining = ciphertext_size
                        chunk_size = max(BLOCK_SIZE, BUFFER_SIZE // BLOCK_SIZE * BLOCK_SIZE)
                        while remaining:
                            chunk = authenticated.read(min(chunk_size, remaining))
                            plaintext, previous = _cbc_decrypt(chunk, keys, previous)
                            remaining -= len(chunk)
                            output.write(_pkcs7_unpad(plaintext) if not remaining else plaintext)
                    os.replace(name, destination)
                except Exception:
                    try:
                        os.unlink(name)
                    except FileNotFoundError:
                        pass
                    raise
    except OSError as error:
        raise ValueError(f"cannot process encrypted file: {error}") from error
