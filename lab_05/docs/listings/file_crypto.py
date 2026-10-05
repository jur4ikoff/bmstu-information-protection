def encrypt_file(source: str | Path, destination: str | Path, key: PublicKey) -> None:
    """Запись HYB1-контейнера при чтении файла фиксированными блоками."""
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
            output.write(_xor(_aes_encrypt_block(nonce + b"\0\0\0\1", keys), ghash.finish(total)))
        os.replace(name, destination)
    except Exception:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        raise


def decrypt_file(source: str | Path, destination: str | Path, key: PrivateKey) -> None:
    """Публикует результат только после успешной проверки тега GCM."""
    source_path = Path(source)
    with source_path.open("rb") as input_file:
        size = source_path.stat().st_size
        header = input_file.read(6)
        if len(header) != 6 or header[:4] != MAGIC:
            raise ValueError("invalid encrypted-file signature (expected HYB1)")
        wrapped_size = int.from_bytes(header[4:], "big")
        if wrapped_size != key.size_bytes:
            raise ValueError("encrypted file belongs to a different RSA key size")
        wrapped, nonce = input_file.read(wrapped_size), input_file.read(12)
        ciphertext_size = size - 6 - wrapped_size - 12 - 16
        session_key = rsa_oaep_decrypt(wrapped, key)
        keys, subkey, counter = _gcm_context(session_key, nonce)
        ghash, processed = _GHash(subkey), 0
        output = _temporary(destination)
        name = output.name
        try:
            with output:
                while processed < ciphertext_size:
                    chunk = input_file.read(min(BUFFER_SIZE, ciphertext_size - processed))
                    plaintext, counter = _gcm_transform(chunk, keys, counter)
                    output.write(plaintext)
                    ghash.update(chunk)
                    processed += len(chunk)
                tag = input_file.read(16)
                expected = _xor(_aes_encrypt_block(nonce + b"\0\0\0\1", keys), ghash.finish(processed))
                if not hmac.compare_digest(tag, expected):
                    raise ValueError("authentication failed: wrong key or damaged file")
            os.replace(name, destination)
        except Exception:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass
            raise
