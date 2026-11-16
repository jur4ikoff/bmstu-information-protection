"""Командный интерфейс лабораторной работы №7."""

import argparse
import csv
import json
from html import escape
from pathlib import Path
import random

from vigenere import (ALPHABETS, analyze, decrypt, encrypt, letter_indices,
                      shortest_period, statistics)

ROOT = Path(__file__).resolve().parent


def read_text(path: Path) -> str:
    # Не преобразуем CRLF: нешифруемые символы сохраняются точно.
    with path.open(encoding='utf-8', newline='') as stream:
        return stream.read()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as stream:
        stream.write(text)


def write_json(path: Path, value: dict) -> None:
    write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def chart(path: Path, title: str, labels: list[str], series: dict[str, list[float]],
          bars: bool = False) -> None:
    """Статический SVG, открываемый браузером; частоты показываются в процентах."""
    width, height = max(1100, len(labels) * 22), 560
    left, top, bottom, right = 65, 90, 110, 30
    plot_w, plot_h = width - left - right, height - top - bottom
    maximum = max((v for values in series.values() for v in values), default=0) * 1.1 or 1
    colors = ['#2563eb', '#e25822', '#009b72']
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
           '<rect width="100%" height="100%" fill="white"/>',
           '<g font-family="sans-serif" font-size="13">',
           f'<text x="{left}" y="28" font-size="20">{escape(title)}</text>']
    for tick in range(6):
        value = maximum * tick / 5
        y = top + plot_h * (1 - value / maximum)
        svg.extend([f'<path d="M {left} {y} H {width-right}" stroke="#ddd"/>',
                    f'<text x="{left-8}" y="{y+4}" text-anchor="end">{100*value:.1f}%</text>'])
    cell = plot_w / max(1, len(labels))
    for i, label in enumerate(labels):
        x = left + (i + 0.5) * cell
        svg.append(f'<text transform="translate({x},{top+plot_h+18}) rotate(60)">{escape(label)}</text>')
    for number, (name, values) in enumerate(series.items()):
        color = colors[number % len(colors)]
        svg.append(f'<text x="{left+number*290}" y="60" fill="{color}">{escape(name)}</text>')
        points = []
        for i, value in enumerate(values):
            x = left + (i + 0.5) * cell
            y = top + plot_h * (1 - value / maximum)
            if bars:
                bar_w = cell * 0.8 / len(series)
                bx = left + (i + 0.1) * cell + number * bar_w
                svg.append(f'<rect x="{bx}" y="{y}" width="{bar_w}" height="{top+plot_h-y}" fill="{color}"/>')
            else:
                points.append(f'{x},{y}')
        if not bars:
            svg.append(f'<polyline points="{" ".join(points)}" fill="none" stroke="{color}" stroke-width="2"/>')
    svg.append('</g></svg>')
    write_text(path, '\n'.join(svg))


def save_analysis(text: str, language: str, output: Path, max_length: int = 40,
                  key_length: int | None = None, known_plaintext: str | None = None,
                  known_key: str | None = None) -> dict:
    result = analyze(text, language, max_length, key_length)
    plain = result.pop('plaintext')
    write_text(output / 'decrypted.txt', plain)
    if known_plaintext is not None:
        matches = sum(a == b for a, b in zip(plain, known_plaintext))
        result['plaintext_accuracy'] = matches / max(len(plain), len(known_plaintext), 1)
        expected = letter_indices(known_plaintext, language)
        actual = letter_indices(plain, language)
        result['letter_accuracy'] = sum(a == b for a, b in zip(expected, actual)) / max(len(expected), len(actual), 1)
        result['plaintext_exact'] = plain == known_plaintext
    if known_key is not None:
        canonical = shortest_period(known_key.upper())
        result['known_key'] = known_key
        result['key_exact'] = result['key'] == canonical
        result['key_accuracy'] = sum(a == b for a, b in zip(result['key'], canonical)) / max(len(result['key']), len(canonical))
    write_json(output / 'analysis.json', result)
    with (output / 'key_lengths.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(result['candidates'][0]))
        writer.writeheader()
        writer.writerows(result['candidates'])
    print(f'Ключ: {result["key"]}; длина: {result["key_length"]}')
    print(f'НОД расстояний: {result["kasiski"]["distance_gcd"]}; '
          f'повторяющихся n-грамм: {result["kasiski"]["repeated_ngrams"]}')
    print(f'Повторное шифрование совпало: {result["reencryption_matches"]}')
    print(result['selection_reason'])
    if known_plaintext is not None:
        print(f'Точность текста: {result["plaintext_accuracy"]:.2%}')
    print(result['note'])
    print(f'Результаты: {output}')
    return result


def prepare_text(size: int, language: str) -> str:
    """Учебный корпус из перемешанных абзацев; собственный текст можно передать CLI."""
    sample = ROOT / 'data' / ('sample_en.txt' if language == 'en' else 'sample_ru.txt')
    paragraphs = [p for p in read_text(sample).split('\n\n') if p.strip()]
    rng = random.Random(15)
    chunks, total = [], 0
    while total < size:
        batch = paragraphs.copy()
        rng.shuffle(batch)
        chunk = '\n\n'.join(batch) + '\n\n'
        chunks.append(chunk)
        total += len(chunk)
    return ''.join(chunks)[:size]


def experiment(args: argparse.Namespace) -> None:
    if args.size < 100_000:
        raise ValueError('По условию нужен текст не менее 100 000 символов')
    text = read_text(args.input) if args.input else prepare_text(args.size, args.language)
    if len(text) < 100_000:
        raise ValueError('Исходный файл должен содержать не менее 100 000 символов')
    if not 3 <= len(args.short_key) <= 5 or len(args.long_key) < 15:
        raise ValueError('Короткий ключ: 3–5 букв; длинный ключ: не менее 15 букв')
    if len(shortest_period(args.long_key.upper())) < 15:
        raise ValueError('Длинный ключ должен иметь минимальный период не менее 15')
    if not letter_indices(text, args.language):
        raise ValueError('Текст не содержит букв выбранного алфавита')
    texts = {'original': text,
             'short': encrypt(text, args.short_key, args.language),
             'long': encrypt(text, args.long_key, args.language)}
    labels = {'original': 'Исходный текст', 'short': 'Короткий ключ', 'long': 'Длинный ключ'}
    summaries = {}
    for name, value in texts.items():
        write_text(args.output / f'{name}.txt', value)
        summaries[name] = statistics(value, args.language)
        freqs = summaries[name]['letter_frequencies']
        chart(args.output / f'letters_{name}.svg', labels[name], list(freqs), {labels[name]: list(freqs.values())}, bars=True)
    alphabet = ALPHABETS[args.language]
    comparison = {labels[name]: list(stat['letter_frequencies'].values()) for name, stat in summaries.items()}
    chart(args.output / 'letters_comparison.svg', 'Сравнение частот букв', list(alphabet), comparison, bars=True)
    chart(args.output / 'letters_distribution.svg', 'Распределение частот букв', list(alphabet), comparison)
    symbols = sorted(set().union(*(stat['symbol_counts'] for stat in summaries.values())))
    symbol_labels = [{' ': 'пробел', '\n': '\\n', '\r': '\\r', '\t': '\\t'}.get(c, c) for c in symbols]
    chart(args.output / 'symbols_distribution.svg', 'Частоты всех символов (с учётом регистра)', symbol_labels,
          {labels[name]: [stat['symbol_counts'].get(c, 0) / len(text) for c in symbols] for name, stat in summaries.items()})
    write_json(args.output / 'statistics.json', summaries)
    with (args.output / 'frequencies.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['letter', 'original', 'short', 'long'])
        for letter in alphabet:
            writer.writerow([letter, *(summaries[name]['letter_frequencies'][letter] for name in texts)])
    attacks = {}
    for name, key in [('short', args.short_key), ('long', args.long_key)]:
        print(f'\nКриптоанализ: {labels[name]}')
        attacks[name] = save_analysis(texts[name], args.language, args.output / f'attack_{name}',
                                      max_length=max(40, len(key)), known_plaintext=text, known_key=key)
    summary = [f'Символов: {len(text)}; алфавит: {args.language}',
               f'Короткий ключ: {args.short_key}; длинный ключ: {args.long_key}']
    for name, stat in summaries.items():
        summary.append(f'{labels[name]}: букв={stat["letters"]}, IC={stat["ic"]:.6f}, '
                       f'энтропия={stat["entropy_bits_per_letter"]:.6f} бит/букву')
    for name, result in attacks.items():
        summary.append(f'{labels[name]}: найден ключ {result["key"]}, '
                       f'точность ключа={result["key_accuracy"]:.2%}, текста={result["plaintext_accuracy"]:.2%}')
    summary.append('Выбор длины: Казиски формирует гипотезы; IC показывает периоды, '
                   'χ² восстанавливает сдвиги; правдоподобие со штрафом за длину различает период и его кратные.')
    summary.append('Длина ключа не гарантирует равномерность: важны частоты его сдвигов и исходный текст.')
    if not args.input:
        summary.append('Учебный корпус составлен из повторяющихся перемешанных абзацев; '
                       'повторы могут облегчать Казиски. Для независимого исследования передайте --input.')
    write_text(args.output / 'summary.txt', '\n'.join(summary) + '\n')
    print('\n' + '\n'.join(summary))


def main() -> None:
    parser = argparse.ArgumentParser(description='Лабораторная №7: Виженер и криптоанализ')
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('encrypt', 'decrypt', 'analyze', 'experiment'):
        sub = commands.add_parser(command)
        sub.add_argument('--language', choices=ALPHABETS, default='ru', help='ru: без Ё; ru33: с Ё; en: английский')
        sub.add_argument('--input', type=Path, required=command in ('encrypt', 'decrypt'))
        sub.add_argument('--output', type=Path, required=command in ('encrypt', 'decrypt'),
                         default=ROOT / 'results' / command)
        if command in ('encrypt', 'decrypt'):
            sub.add_argument('--key', required=True)
        elif command == 'analyze':
            sub.add_argument('--max-key-length', type=int, default=40)
            sub.add_argument('--key-length', type=int)
            sub.add_argument('--known-plaintext', type=Path)
            sub.add_argument('--known-key')
        else:
            sub.add_argument('--size', type=int, default=100_000)
            sub.add_argument('--short-key')
            sub.add_argument('--long-key')
    args = parser.parse_args()
    try:
        if args.command in ('encrypt', 'decrypt'):
            value = read_text(args.input)
            function = encrypt if args.command == 'encrypt' else decrypt
            write_text(args.output, function(value, args.key, args.language))
        elif args.command == 'analyze':
            path = args.input or ROOT / 'data' / 'teacher_ciphertext.txt'
            save_analysis(read_text(path), args.language, args.output, args.max_key_length,
                          args.key_length, read_text(args.known_plaintext) if args.known_plaintext else None,
                          args.known_key)
        else:
            args.short_key = args.short_key or ('KEY' if args.language == 'en' else 'КЛЮЧ')
            args.long_key = args.long_key or ('INFORMATIONSECURITY' if args.language == 'en' else 'ИНФОРМАЦИОННАЯЗАЩИТА')
            experiment(args)
    except (ValueError, OSError) as exc:
        parser.exit(1, f'Ошибка: {exc}\n')


if __name__ == '__main__':
    main()
