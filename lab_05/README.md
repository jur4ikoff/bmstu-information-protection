# Лабораторная работа №5 — гибридное шифрование файлов

Реализована потоковая схема RSA-OAEP-SHA-256 + AES-256-GCM без сторонних
пакетов. Сеансовый ключ и nonce создаются через `secrets`; закрытый RSA-ключ
сохраняется в защищённом паролем PEM. AES-128 реализован вручную, включая
обратные преобразования, и проверяется вектором FIPS 197 C.1.

```bash
# Пароль можно опустить: тогда он будет запрошен интерактивно.
python3 src/main.py keygen --public public.pem --private private.pem --password 'пароль'
python3 src/main.py encrypt --key public.pem --in input.rar --out input.rar.enc
python3 src/main.py decrypt --key private.pem --in input.rar.enc --out restored.rar --password 'пароль'

# Проверка идентичности исходного и расшифрованного файлов
shasum -a 256 input.rar restored.rar
```

Формат `.enc`: `HYB1 | L (2 байта, big-endian) | RSA-OAEP(сеансовый ключ) |
nonce (12 байт) | ciphertext | GCM tag (16 байт)`. При неверном ключе или
пароле, а также повреждённом контейнере, выходной файл не создаётся либо не
заменяется.

```bash
python3 -m unittest discover -s tests -v
```
