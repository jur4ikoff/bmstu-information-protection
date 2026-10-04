# Лабораторная работа №3

Самодостаточная реализация комплексной криптосистемы на Python 3.11+ без
сторонних зависимостей. Исходный код расположен в `src/`.

- Генерация RSA-ключей с вероятностной проверкой Миллера--Рабина.
- Гибридное шифрование файлов: случайный AES-256 ключ инкапсулируется
  посредством RSA-OAEP (SHA-256); данные шифруются AES-256-CTR и защищаются
  HMAC-SHA-256 от изменения.
- Создание и проверка ЭЦП RSA PKCS#1 v1.5 над SHA-256.
- Защищённое сохранение закрытого ключа: PBKDF2-HMAC-SHA256 с солью и
  310 000 итераций, затем AES-256-CTR + HMAC-SHA-256.
- Автоматические тесты пустого, однобайтного и большого файла.

## Использование

Из корня проекта:

```bash
python3 src/main.py keygen public.json private.json
python3 src/main.py encrypt public.json input.bin encrypted.json
python3 src/main.py decrypt private.json encrypted.json restored.bin
python3 src/main.py sign private.json input.bin input.sig
python3 src/main.py verify public.json input.bin input.sig
```

При создании, расшифровании закрытого ключа и подписи программа запросит
мастер-пароль без отображения на экране. По умолчанию создаётся RSA-ключ 2048
бит; `--bits 1024` оставлен только для ускорения экспериментов и тестов.

Проверка:

```bash
python3 -m unittest discover -s tests -v
```
