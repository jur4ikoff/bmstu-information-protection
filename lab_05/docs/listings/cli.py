# Листинг из lab_05/src/main.py

def main() -> int:
    arguments = build_parser().parse_args()
    try:
        if arguments.command == "keygen":
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
            print("Файл зашифрован: вариант 3 / HYB1 / RSA-2048-OAEP / AES-256-CBC / HMAC-SHA256.")
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
