"""
Пример:
python3 src/main.py keygen public.json private.json
python3 src/main.py encrypt public.json input.bin encrypted.json
python3 src/main.py decrypt private.json encrypted.json output.bin
"""

from __future__ import annotations

import argparse
import getpass

from rsa_crypto import (decrypt_file, encrypt_file, generate_key_pair, load_private_key,
                        load_public_key, save_private_key, save_public_key, sign_file,
                        verify_file)


def _password(confirm: bool = False) -> str:
    password = getpass.getpass("Мастер-пароль: ")
    if confirm and password != getpass.getpass("Повторите мастер-пароль: "):
        raise ValueError("пароли не совпадают")
    return password


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ЛР №3: RSA, AES и электронная подпись")
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="создать RSA-ключи")
    keygen.add_argument("public_key")
    keygen.add_argument("private_key")
    keygen.add_argument("--bits", type=int, default=2048, help="размер RSA, по умолчанию 2048")
    for name in ("encrypt", "decrypt", "sign", "verify"):
        item = commands.add_parser(name)
        item.add_argument("key")
        item.add_argument("source")
        item.add_argument("destination")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "keygen":
        public, private = generate_key_pair(args.bits)
        save_public_key(args.public_key, public)
        save_private_key(args.private_key, private, _password(confirm=True))
        print("Ключи созданы.")
    elif args.command == "encrypt":
        encrypt_file(args.source, args.destination, load_public_key(args.key))
        print("Файл зашифрован.")
    elif args.command == "decrypt":
        decrypt_file(args.source, args.destination, load_private_key(args.key, _password()))
        print("Файл расшифрован.")
    elif args.command == "sign":
        sign_file(args.source, args.destination, load_private_key(args.key, _password()))
        print("Подпись создана.")
    else:
        valid = verify_file(args.source, args.destination, load_public_key(args.key))
        print("Подпись корректна." if valid else "Подпись некорректна.")
        return 0 if valid else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
