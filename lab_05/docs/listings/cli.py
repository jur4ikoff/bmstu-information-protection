def main() -> int:
    arguments = build_parser().parse_args()
    try:
        if arguments.command == "keygen":
            if arguments.bits < 2048 or arguments.bits % 2:
                raise ValueError("RSA-модуль должен быть чётным и не менее 2048 бит")
            public, private = generate_key_pair(arguments.bits)
            save_public_key(arguments.public, public)
            save_private_key(arguments.private, private, _password(arguments.password, confirm=True))
            print("Ключи сохранены.")
        elif arguments.command == "encrypt":
            encrypt_file(arguments.source, arguments.destination, load_public_key(arguments.key))
            print("Файл зашифрован: HYB1 / RSA-OAEP / AES-256-GCM.")
        else:
            private = load_private_key(arguments.key, _password(arguments.password))
            decrypt_file(arguments.source, arguments.destination, private)
            print(f"Файл расшифрован; SHA-256: {sha256_file(arguments.destination)}")
        return 0
    except (OSError, ValueError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 2
