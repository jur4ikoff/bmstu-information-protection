# Лабораторная работа №4 — RSA

Реализация алгоритма RSA на Python без готовых криптографических библиотек.
Работа выполнена для варианта 15: `p = 83`, `q = 19`, `e = 13`, `M = 222`,
длина ключа 3072 бита, тип демонстрационного файла — `.docx`.

## Возможности

- тест Миллера--Рабина и генерация простых чисел;
- расширенный алгоритм Евклида, обратный элемент и собственное быстрое
  возведение в степень по модулю;
- генерация и хранение RSA-ключей; закрытый ключ защищён мастер-паролем;
- шифрование и расшифрование целых чисел и UTF-8 текста;
- поблочное шифрование произвольных бинарных файлов учебным RSA;
- контроль длины, ключа-получателя и SHA-256 целостности файлового контейнера;
- расшифрование с китайской теоремой об остатках;
- подпись SHA-256/RSA;
- гибридное шифрование AES-256-CTR + RSA-OAEP + HMAC-SHA-256;
- измерение времени и демонстрация слабостей учебного RSA.

> Учебный поблочный RSA детерминирован и не должен применяться для защиты
> реальных данных. Для практического сценария используйте команды
> `hybrid-encrypt` и `hybrid-decrypt`.

## Требования

- Python 3.10 или новее;
- для сборки отчёта — [Typst](https://typst.app/).

Сторонние Python-пакеты не требуются.

## Быстрый старт

Из корня репозитория создайте ключи. По умолчанию используется требуемый для
варианта 15 размер 3072 бита.

```bash
python3 src/main.py genkeys --pub public.key --priv private.key
```

Зашифруйте и расшифруйте Word-документ учебной поблочной схемой RSA:

```bash
python3 src/main.py encrypt --key public.key --in source.docx --out source.rsa
python3 src/main.py decrypt --key private.key --in source.rsa --out restored.docx
cmp source.docx restored.docx
```

## Команды

```bash
# Проверка ручного расчёта варианта 15.
python3 src/main.py variant15

# Целые числа.
python3 src/main.py encrypt-int --key public.key 222
python3 src/main.py decrypt-int --key private.key 129

# Текст UTF-8.
python3 src/main.py encrypt-text --key public.key "Привет, RSA" --out text.rsa.json
python3 src/main.py decrypt-text --key private.key --in text.rsa.json

# Электронная подпись.
python3 src/main.py sign --key private.key --in source.docx --out source.sig
python3 src/main.py verify --key public.key --in source.docx --out source.sig

# Практический гибридный режим.
python3 src/main.py hybrid-encrypt --key public.key --in source.docx --out source.hybrid
python3 src/main.py hybrid-decrypt --key private.key --in source.hybrid --out restored.docx

# Сравнение обычного расшифрования и КТО.
python3 src/main.py crt-time --key private.key 129

# Замеры на файле для 1024, 2048 и 3072 бит.
python3 src/main.py benchmark --in source.docx --out benchmark.json

# Демонстрация детерминированности и мультипликативности учебного RSA.
python3 src/main.py weaknesses --key public.key
```

Полный список параметров доступен через `python3 src/main.py --help`.

## Формат учебного RSA-контейнера

Файл, создаваемый командой `encrypt`, начинается с заголовка `RSA-L4`. Он
содержит размер блока, исходную длину файла, SHA-256 отпечаток открытого ключа
и SHA-256 исходных данных. Затем располагаются RSA-блоки: при модуле длиной
`k` байт один блок открытого текста имеет `k - 1` байт, шифртекста — `k` байт.

Такой формат сохраняет ведущие нулевые байты, корректно восстанавливает
последний неполный блок и отклоняет контейнер, зашифрованный для другого ключа
или повреждённый при передаче.

## Тестирование

```bash
python3 -m unittest discover -s tests -v
```

Тесты проверяют AES-контрольный вектор, защиту закрытого ключа паролем,
гибридное шифрование и подписи для пустого, однобайтного и большого файлов,
а также реакцию на изменение данных.

## Отчёт

Исходник отчёта находится в [`docs/report.typ`](docs/report.typ), готовый PDF
— в [`docs/report.pdf`](docs/report.pdf). Для пересборки:

```bash
cd docs
typst compile --no-pdf-tags --root .. report.typ report.pdf
```
