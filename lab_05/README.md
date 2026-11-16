# Лабораторная работа №5 — вариант 3

Реализована потоковая схема **RSA-2048-OAEP-SHA256 + AES-256-CBC +
HMAC-SHA256 (Encrypt-then-MAC)** без сторонних Python-пакетов.

Два независимых сеансовых ключа по 32 байта (AES и HMAC) и IV 16 байт
создаются через `secrets`. RSA-OAEP шифрует конкатенацию двух ключей.
AES-CBC использует дополнение PKCS#7, включая полный блок дополнения
для пустого файла или файла, кратного 16 байтам.

Команды запускаются из `lab_05`:

```bash
# Если --password опущен, пароль запрашивается интерактивно.
python3 src/main.py keygen --public public.pem --private private.pem
python3 src/main.py encrypt --key public.pem --in data/sample.txt --out sample.txt.enc
python3 src/main.py decrypt --key private.pem --in sample.txt.enc --out restored.txt
shasum -a 256 data/sample.txt restored.txt

python3 src/main.py encrypt --key public.pem --in data/sample.rar --out sample.rar.enc
python3 src/main.py decrypt --key private.pem --in sample.rar.enc --out restored.rar
shasum -a 256 data/sample.rar restored.rar
```

`--bits` допускает только 2048. Загружаемые ключи также проверяются на
точную длину модуля 2048 бит. В `data` находятся текст и настоящий RAR-архив
для проверки; внешние архиваторы не нужны для работы самой программы.

Формат `.enc`:

```text
HYB1 | L (2 байта, big-endian) | RSA-OAEP(K_AES || K_HMAC) |
IV (16 байт) | AES-256-CBC ciphertext + PKCS#7 | HMAC-SHA256 (32 байта)
```

Для RSA-2048 `L = 256`. При исходном размере `N` длина шифртекста равна
`C = 16 * (N // 16 + 1)`, всего контейнер занимает `6 + L + 16 + C + 32` байт.
HMAC защищает все байты перед тегом, включая заголовок, RSA-шифртекст и IV.
Проверка через `hmac.compare_digest` выполняется **до расшифрования CBC**.
Аутентифицированный шифртекст хранится во временном файле, затем
расшифровывается из этого снимка. RAM ограничена размером буфера (64 КиБ)
и служебными данными, временное дисковое пространство растёт с размером файла.

При неверном ключе, пароле, HMAC или дополнении выходной файл не создаётся,
а существующий сохраняется. Успешный результат публикуется через `os.replace`.
Старые контейнеры AES-GCM предыдущей реализации несовместимы с вариантом 3.

Закрытый RSA-ключ сохраняется в PEM-оболочке проекта `L5PK`, защищённой
паролем через PBKDF2-HMAC-SHA256 (310 000 итераций, соль 16 байт) и AES-256-GCM.
Это отдельный механизм защиты файла ключа; содержимое пользовательских файлов
шифруется CBC согласно варианту. Оболочка читается функцией `load_private_key`
этого проекта, а не стандартным загрузчиком PKCS#8.

AES-128 и AES-256 реализованы вручную, включая обратные преобразования.
Проверки: FIPS 197 C.1 для AES-128, NIST SP 800-38A F.2.5/F.2.6 для AES-256-CBC,
границы блоков, пустые файлы, подмена всех полей, отклонение до расшифрования,
сохранение существующего результата, защита закрытого ключа.

```bash
python3 -m unittest discover -s tests -v
```

Результаты запуска: [docs/results.txt](docs/results.txt).
Отчёт: [docs/report.pdf](docs/report.pdf).
Сборка отчёта из корня репозитория:

```bash
typst compile --no-pdf-tags --root lab_05 lab_05/docs/report.typ
```
