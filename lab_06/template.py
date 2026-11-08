"""Лабораторная работа 6. Хеш-функции и имитовставка."""
import hashlib
import hmac
import os
import secrets
import zlib

VARIANT = 0  # Укажите вариант от 1 до 20 или введите его при запуске.


def variant(n: int) -> dict:
    if not 1 <= n <= 20:
        raise ValueError('Номер варианта должен быть от 1 до 20')
    i = (n - 1) % 5
    key_len = [8, 12, 16, 20, 24][i]
    return {
        'M': f'user=student{n:02d}&role=user'.encode(),
        'K': hashlib.sha256(f'lab6-key-{n}'.encode()).digest()[:key_len],
        't_bits': [96, 112, 128, 160, 192][i],
        'collision_bits': [24, 28, 32, 36, 40][i],
        'digest': ['sha256', 'sha512', 'sha3_256', 'blake2b', 'sha384'][i],
    }


def hamming(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError('Длины строк должны совпадать')
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def avalanche_results(msg: bytes, trials: int = 256) -> list:
    if not msg or trials < 256:
        raise ValueError('Требуются непустое сообщение и не менее 256 испытаний')
    original = hashlib.sha256(msg).digest()
    results = []
    for i in range(max(trials, len(msg) * 8)):
        changed = bytearray(msg)
        bit = i % (len(msg) * 8)
        changed[bit // 8] ^= 1 << (bit % 8)
        results.append(hamming(original, hashlib.sha256(changed).digest()))
    return results


def avalanche(msg: bytes, trials: int = 256) -> float:
    results = avalanche_results(msg, trials)
    return sum(results) / len(results)


def crc_is_linear() -> bool:
    for _ in range(100):
        a, b, c = (secrets.token_bytes(32) for _ in range(3))
        combined = bytes(x ^ y ^ z for x, y, z in zip(a, b, c))
        if zlib.crc32(combined) != zlib.crc32(a) ^ zlib.crc32(b) ^ zlib.crc32(c):
            return False
    return True


def truncated(msg: bytes, bits: int) -> bytes:
    if not 1 <= bits <= 256:
        raise ValueError('Длина усечения должна быть от 1 до 256 бит')
    result = bytearray(hashlib.sha256(msg).digest()[:(bits + 7) // 8])
    if bits % 8:
        result[-1] &= 0xff << (8 - bits % 8)
    return bytes(result)


def birthday_collision(bits: int):
    seen = {}
    attempts = 0
    while True:
        msg = secrets.token_bytes(16)
        digest = truncated(msg, bits)
        attempts += 1
        previous = seen.get(digest)
        if previous is not None and previous != msg:
            return previous, msg, digest, attempts
        seen[digest] = msg


def naive_mac(key: bytes, msg: bytes, digest: str = 'sha256') -> str:
    return hashlib.new(digest, key + msg).hexdigest()


def hmac_mac(key: bytes, msg: bytes, digest: str = 'sha256', bits: int = 256) -> str:
    return hmac.new(key, msg, digest).digest()[:bits // 8].hex()


def hmac_verify(key: bytes, msg: bytes, tag: str, digest: str = 'sha256', bits: int = 256) -> bool:
    return hmac.compare_digest(hmac_mac(key, msg, digest, bits), tag)


def manual_hmac(key: bytes, msg: bytes, digest: str = 'sha256', bits: int = 256) -> str:
    block_size = hashlib.new(digest).block_size
    if len(key) > block_size:
        key = hashlib.new(digest, key).digest()
    key = key.ljust(block_size, b'\0')
    inner = bytes(x ^ 0x36 for x in key)
    outer = bytes(x ^ 0x5c for x in key)
    inner_hash = hashlib.new(digest, inner + msg).digest()
    return hashlib.new(digest, outer + inner_hash).digest()[:bits // 8].hex()


def tampered_demo(key: bytes, msg: bytes, digest: str = 'sha256', bits: int = 256) -> bool:
    if b'role=user' not in msg:
        raise ValueError('В сообщении отсутствует role=user')
    tag = hmac_mac(key, msg, digest, bits)
    changed = msg.replace(b'role=user', b'role=admin')
    print('Изменённое сообщение с новым тегом:', hmac_verify(key, changed, hmac_mac(key, changed, digest, bits), digest, bits))
    return hmac_verify(key, changed, tag, digest, bits)


def store_password(password: str) -> dict:
    salt = secrets.token_bytes(16)
    iterations = 100_000
    return {'salt': salt, 'hash': hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations), 'iterations': iterations}


def check_password(password: str, record: dict) -> bool:
    result = hashlib.pbkdf2_hmac('sha256', password.encode(), record['salt'], record['iterations'])
    return hmac.compare_digest(result, record['hash'])


if __name__ == '__main__':
    try:
        number = VARIANT or int(input('Номер варианта (1–20): '))
        v = variant(number)
    except ValueError as exc:
        print('Ошибка:', exc)
        raise SystemExit(1)
    msg, key = v['M'], v['K']
    digest, bits = v['digest'], v['t_bits']
    print('Вариант:', number, '| M:', msg.decode(), '| K:', key.hex())
    print('SHA-256:', hashlib.sha256(msg).hexdigest())
    results = avalanche_results(msg)
    print(f'Лавинный эффект: {len(results)} испытаний, среднее {sum(results)/len(results):.2f}')
    print('Гистограмма (изменившихся бит: количество):')
    for value in sorted(set(results)):
        print(f'{value}: {"#" * results.count(value)} ({results.count(value)})')
    print('Равенство CRC для строк одинаковой длины:', crc_is_linear())
    attempts = []
    for i in range(5):
        a, b, value, count = birthday_collision(v['collision_bits'])
        attempts.append(count)
        print(f'Коллизия {i+1}: {count} попыток, M1={a.hex()}, M2={b.hex()}, хеш={value.hex()}')
    print(f'Среднее: {sum(attempts)/5:.1f}; оценка: {2**(v["collision_bits"]/2):.1f}')
    tag = hmac_mac(key, msg, digest, bits)
    print('Наивный MAC:', naive_mac(key, msg, digest))
    print(f'HMAC ({digest}, {bits} бит):', tag)
    print('Ручной HMAC совпадает:', hmac.compare_digest(tag, manual_hmac(key, msg, digest, bits)))
    print('Подмена со старым тегом прошла:', tampered_demo(key, msg, digest, bits))
    first, second = store_password('example-password'), store_password('example-password')
    for i, record in enumerate((first, second), 1):
        print(f'Запись {i}: соль={record["salt"].hex()}, хеш={record["hash"].hex()}, итерации={record["iterations"]}')
    print('Записи различаются:', first != second)
    start = os.times().elapsed
    valid = check_password('example-password', first)
    elapsed = os.times().elapsed - start
    print(f'Пароль верен: {valid}, время проверки: {elapsed:.3f} с')
    print(f'Оценка перебора 10 млн паролей: {elapsed * 10_000_000 / 86400:.2f} суток')
