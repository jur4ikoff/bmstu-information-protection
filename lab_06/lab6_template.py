"""Лабораторная работа № 6. Хеш-функции и имитовставка.
ШАБЛОН. Заполните места, помеченные  # TODO.
Разрешены модули стандартной библиотеки: hashlib, hmac, secrets, os, zlib.

Номер варианта узнайте у преподавателя и впишите ниже.
"""
import hashlib
import hmac
import os
import secrets
import zlib

VARIANT = 0  # TODO: впишите номер своего варианта


def variant(n: int) -> dict:
    key_len = [8, 12, 16, 20, 24][(n - 1) % 5]
    key = hashlib.sha256(f"lab6-key-{n}".encode()).digest()[:key_len]
    return {
        "M": f"user=student{n:02d}&role=user".encode(),
        "K": key,
        "t_bits": [96, 112, 128, 160, 192][(n - 1) % 5],
    }


# --- Задание 2. Лавинный эффект -------------------------------------------
def hamming(a: bytes, b: bytes) -> int:
    """Число различающихся бит в двух байтовых строках одинаковой длины."""
    # TODO
    raise NotImplementedError


def avalanche(msg: bytes, trials: int = 256) -> float:
    """Среднее число изменившихся бит хеша при инверсии одного бита сообщения."""
    # TODO: по очереди инвертируйте биты msg, сравнивайте SHA-256 с исходным
    raise NotImplementedError


# --- Задание 3. Линейность CRC --------------------------------------------
def crc_is_linear() -> bool:
    """Проверьте на случайных строках: CRC(a^b^c) == CRC(a)^CRC(b)^CRC(c)."""
    # TODO
    raise NotImplementedError


# --- Задание 4. Коллизия усечённого хеша ----------------------------------
def truncated(msg: bytes, bits: int) -> bytes:
    """Первые bits бит от SHA-256(msg)."""
    # TODO
    raise NotImplementedError


def birthday_collision(bits: int):
    """Верните (M1, M2, общий_хеш, число_попыток) для усечённого до bits хеша."""
    # TODO: генерируйте случайные сообщения, храните увиденные хеши в словаре
    raise NotImplementedError


# --- Задание 5. Имитовставка ----------------------------------------------
def naive_mac(key: bytes, msg: bytes) -> str:
    """hash(key || msg) — небезопасный вариант, нужен только для сравнения."""
    # TODO
    raise NotImplementedError


def hmac_mac(key: bytes, msg: bytes) -> str:
    """HMAC-SHA256, hex."""
    # TODO
    raise NotImplementedError


def hmac_verify(key: bytes, msg: bytes, tag: str) -> bool:
    """Проверка тега. Используйте hmac.compare_digest."""
    # TODO
    raise NotImplementedError


# --- Задание 6. Контроль целостности --------------------------------------
def tampered_demo(key: bytes, msg: bytes) -> bool:
    """Защитите msg тегом, подмените role=user на role=admin, проверьте тег.
    Функция должна вернуть False (подделка не прошла)."""
    # TODO
    raise NotImplementedError


# --- Задание 7. Хранение пароля -------------------------------------------
def store_password(password: str) -> dict:
    """Верните запись {salt, hash, iterations} с PBKDF2-HMAC-SHA256."""
    # TODO
    raise NotImplementedError


def check_password(password: str, record: dict) -> bool:
    # TODO
    raise NotImplementedError


if __name__ == "__main__":
    v = variant(VARIANT)
    print("Вариант", VARIANT, "| M =", v["M"].decode(), "| ключ", len(v["K"]), "байт")
    # Раскомментируйте по мере выполнения заданий:
    # print("Лавина:", avalanche(v["M"]))
    # print("CRC линейна:", crc_is_linear())
    # print("Коллизия:", birthday_collision(min(v["t_bits"] // 4, 40)))
    # print("HMAC:", hmac_mac(v["K"], v["M"]))
    # print("Подделка прошла проверку:", tampered_demo(v["K"], v["M"]))
