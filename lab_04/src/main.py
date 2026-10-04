"""CLI для лабораторной работы №4.

python3 src/main.py genkeys --bits 2048 --pub public.key --priv private.key
python3 src/main.py encrypt --key public.key --in input.bin --out input.rsa
python3 src/main.py decrypt --key private.key --in input.rsa --out recovered.bin
"""

from __future__ import annotations
import argparse, getpass, json, sys, time
from pathlib import Path
from rsa_crypto import *


def _password(confirm=False):
    value = getpass.getpass("Мастер-пароль: ")
    if confirm and value != getpass.getpass("Повторите мастер-пароль: "):
        raise ValueError("пароли не совпадают")
    return value


def _file(p, private=False):
    p.add_argument("--key", required=True)
    p.add_argument("--in", dest="source", required=True)
    p.add_argument("--out", dest="destination", required=True)


def build_parser():
    p = argparse.ArgumentParser(
        description="ЛР №4: RSA, КТО, подпись и гибридная схема"
    )
    s = p.add_subparsers(dest="command", required=True)
    x = s.add_parser("genkeys", aliases=["keygen"])
    x.add_argument(
        "--bits", type=int, default=3072, help="длина модуля; для варианта 15 — 3072"
    )
    x.add_argument("--pub", required=True)
    x.add_argument("--priv", required=True)
    for name, priv in (
        ("encrypt", False),
        ("decrypt", True),
        ("hybrid-encrypt", False),
        ("hybrid-decrypt", True),
        ("sign", True),
        ("verify", False),
    ):
        _file(s.add_parser(name), priv)
    x = s.add_parser("encrypt-int")
    x.add_argument("--key", required=True)
    x.add_argument("message", type=int)
    x = s.add_parser("decrypt-int")
    x.add_argument("--key", required=True)
    x.add_argument("ciphertext", type=int)
    x = s.add_parser("encrypt-text")
    x.add_argument("--key", required=True)
    x.add_argument("text")
    x.add_argument("--out", required=True)
    x = s.add_parser("decrypt-text")
    x.add_argument("--key", required=True)
    x.add_argument("--in", dest="source", required=True)
    x.add_argument("--out")
    x = s.add_parser("crt-time")
    x.add_argument("--key", required=True)
    x.add_argument("ciphertext", type=int)
    x.add_argument("--repetitions", type=int, default=3)
    x = s.add_parser(
        "benchmark", help="замеры для файла (по умолчанию: 1024, 2048, 3072 бит)"
    )
    x.add_argument("--in", dest="source", required=True)
    x.add_argument("--bits", type=int, nargs="+", default=[1024, 2048, 3072])
    x.add_argument("--out")
    x = s.add_parser("weaknesses")
    x.add_argument("--key", required=True)
    s.add_parser("variant15", help="проверить расчёт p=83, q=19, e=13, M=222")
    return p


def main():
    a = build_parser().parse_args()
    try:
        if a.command in ("genkeys", "keygen"):
            t = time.perf_counter()
            pub, priv = generate_key_pair(a.bits)
            save_public_key(a.pub, pub)
            save_private_key(a.priv, priv, _password(True))
            print(f"Ключи созданы за {time.perf_counter()-t:.3f} с.")
        elif a.command == "encrypt":
            encrypt_blocks(a.source, a.destination, load_public_key(a.key))
            print("Файл зашифрован учебным RSA.")
        elif a.command == "decrypt":
            decrypt_blocks(
                a.source, a.destination, load_private_key(a.key, _password())
            )
            print("Файл расшифрован.")
        elif a.command == "hybrid-encrypt":
            encrypt_file(a.source, a.destination, load_public_key(a.key))
            print("Гибридный контейнер создан.")
        elif a.command == "hybrid-decrypt":
            decrypt_file(a.source, a.destination, load_private_key(a.key, _password()))
            print("Гибридный контейнер расшифрован.")
        elif a.command == "sign":
            sign_file(a.source, a.destination, load_private_key(a.key, _password()))
            print("Подпись создана.")
        elif a.command == "verify":
            ok = verify_file(a.source, a.destination, load_public_key(a.key))
            print("Подпись корректна." if ok else "Подпись некорректна.")
            return 0 if ok else 1
        elif a.command == "encrypt-int":
            print(encrypt_integer(a.message, load_public_key(a.key)))
        elif a.command == "decrypt-int":
            print(decrypt_integer(a.ciphertext, load_private_key(a.key, _password())))
        elif a.command == "encrypt-text":
            Path(a.out).write_text(
                encrypt_text(a.text, load_public_key(a.key)), encoding="utf-8"
            )
            print("Текст зашифрован.")
        elif a.command == "decrypt-text":
            text = decrypt_text(
                Path(a.source).read_text(encoding="utf-8"),
                load_private_key(a.key, _password()),
            )
            if a.out:
                Path(a.out).write_text(text, encoding="utf-8")
            else:
                print(text)
        elif a.command == "crt-time":
            normal, crt = rsa_decrypt_timing(
                a.ciphertext, load_private_key(a.key, _password()), a.repetitions
            )
            print(
                json.dumps(
                    {
                        "ordinary_seconds": normal,
                        "crt_seconds": crt,
                        "speedup": normal / crt if crt else None,
                    }
                )
            )
        elif a.command == "benchmark":
            result = benchmark_file(a.source, tuple(a.bits))
            rendered = json.dumps(result, ensure_ascii=False, indent=2)
            if a.out:
                Path(a.out).write_text(rendered + "\n", encoding="utf-8")
            print(rendered)
        elif a.command == "variant15":
            print(json.dumps(solve_variant_15(), ensure_ascii=False, indent=2))
        else:
            print(
                json.dumps(
                    demonstrate_textbook_weaknesses(load_public_key(a.key)), indent=2
                )
            )
        return 0
    except (OSError, ValueError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
