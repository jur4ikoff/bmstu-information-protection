"""CLI for laboratory work 5."""

from __future__ import annotations

import argparse
import getpass
import sys
import time

from hybrid_crypto import (
    decrypt_file,
    encrypt_file,
    generate_key_pair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
    sha256_file,
)


def _password(value: str | None, confirm: bool = False) -> str:
    password = (
        value if value is not None else getpass.getpass("Пароль закрытого ключа: ")
    )
    if confirm:
        repeated = value if value is not None else getpass.getpass("Повторите пароль: ")
        if password != repeated:
            raise ValueError("пароли не совпадают")
    return password


def _file_arguments(parser: argparse.ArgumentParser, private: bool = False) -> None:
    parser.add_argument("--key", required=True, help="PEM-файл ключа")
    parser.add_argument("--in", dest="source", required=True, help="входной файл")
    parser.add_argument(
        "--out", dest="destination", required=True, help="выходной файл"
    )
    if private:
        parser.add_argument(
            "--password", help="пароль; без него будет интерактивный запрос"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ЛР №5: RSA-OAEP-SHA256 + AES-256-GCM")
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="создать RSA-ключи в PEM")
    keygen.add_argument(
        "--bits", type=int, default=2048, help="размер модуля RSA, минимум 2048"
    )
    keygen.add_argument("--public", "--pub", dest="public", required=True)
    keygen.add_argument("--private", "--priv", dest="private", required=True)
    keygen.add_argument(
        "--password", help="пароль; без него будет интерактивный запрос"
    )
    _file_arguments(commands.add_parser("encrypt", help="зашифровать файл"))
    _file_arguments(
        commands.add_parser("decrypt", help="расшифровать и проверить GCM-тег"),
        private=True,
    )
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    try:
        if arguments.command == "keygen":
            if arguments.bits < 2048 or arguments.bits % 2:
                raise ValueError("RSA-модуль должен быть чётным и не менее 2048 бит")
            started = time.perf_counter()
            public, private = generate_key_pair(arguments.bits)
            save_public_key(arguments.public, public)
            save_private_key(
                arguments.private, private, _password(arguments.password, confirm=True)
            )
            print(f"Ключи сохранены за {time.perf_counter() - started:.2f} с.")
        elif arguments.command == "encrypt":
            encrypt_file(
                arguments.source, arguments.destination, load_public_key(arguments.key)
            )
            print("Файл зашифрован: HYB1 / RSA-OAEP / AES-256-GCM.")
        else:
            decrypt_file(
                arguments.source,
                arguments.destination,
                load_private_key(arguments.key, _password(arguments.password)),
            )
            print(f"Файл расшифрован; SHA-256: {sha256_file(arguments.destination)}")
        return 0
    except (OSError, ValueError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
