"""Проверка сохранённых результатов и подготовка данных отчёта (из любого каталога)."""
from pathlib import Path
from collections import Counter
import ast
import json
import math
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from vigenere import analyze, encrypt, decrypt, statistics, letter_indices, reference_frequencies, ALPHABETS


def read(path):
    with Path(path).open(encoding='utf-8', newline='') as stream:
        return stream.read()


def load(path):
    return json.loads(read(path))


def fmt(value, digits=6):
    return f'{value:.{digits}f}'.replace('.', ',')


rows, accuracy = [], []
for directory, language, keys in [
    ('experiment', 'ru', ('КЛЮЧ', 'ИНФОРМАЦИОННАЯЗАЩИТА')),
    ('experiment_en', 'en', ('KEY', 'INFORMATIONSECURITY')),
]:
    folder = ROOT / 'results' / directory
    saved = load(folder / 'statistics.json')
    original = read(folder / 'original.txt')
    assert len(original) >= 100_000
    for name, label in [('original', 'Исходный'), ('short', 'Короткий ключ'), ('long', 'Длинный ключ')]:
        text = read(folder / f'{name}.txt')
        actual = statistics(text, language)
        assert actual == saved[name], (directory, name)
        rows.append([language, label, str(actual['characters']), str(actual['letters']),
                     fmt(actual['ic']), fmt(actual['entropy_bits_per_letter'])])
    for name, key in zip(('short', 'long'), keys):
        cipher = read(folder / f'{name}.txt')
        result = load(folder / f'attack_{name}' / 'analysis.json')
        assert encrypt(original, key, language) == cipher
        restored = read(folder / f'attack_{name}' / 'decrypted.txt')
        assert restored == original == decrypt(cipher, result['key'], language)
        assert result['key'] == key and result['key_exact'] and result['plaintext_exact']
        for a, b in zip(original, cipher):
            if a not in ALPHABETS[language] + ALPHABETS[language].lower():
                assert a == b
        accuracy.append([language, key, str(len(key)), result['key'], '100 %', '100 %'])

cipher = read(ROOT / 'data/teacher_ciphertext.txt')
teacher = analyze(cipher)
assert teacher['key'] == 'СЕКРЕТЫ'
plain = read(ROOT / 'results/analyze/decrypted.txt')
assert plain == teacher['plaintext']
stored = load(ROOT / 'results/analyze/analysis.json')
normalized = json.loads(json.dumps({k: v for k, v in teacher.items() if k != 'plaintext'}))
assert stored == normalized
assert encrypt(plain, teacher['key']) == cipher

candidates = teacher['candidates']
selected = {1, 2, 3, 4, 5, 6, 7, 8, 14, 21, 28, 35, 40}
def candidate_row(c):
    return [str(c['length']), str(c['kasiski_votes']), fmt(c['mean_ic']), fmt(c['criterion'], 2)]

votes = sorted(teacher['kasiski']['factor_votes'].items(), key=lambda item: (-item[1], item[0]))[:10]
first = teacher['kasiski']['examples'][0]
group_rows = [[str(g['position']), str(g['size']), str(g['shift']), g['letter'], fmt(g['chi_square'], 3)] for g in teacher['groups']]
reference = reference_frequencies('ru')
values = letter_indices(plain)[0::7]
counts = Counter(values)
most_frequent = sorted(range(32), key=lambda i: -reference[i])[:8]
frequency_rows = [[ALPHABETS['ru'][i], fmt(100 * reference[i], 3), fmt(100 * counts[i] / len(values), 3)] for i in most_frequent]

s = read(ROOT / 'vigenere.py')
functions = {node.name: ast.get_source_segment(s, node) for node in ast.parse(s).body if isinstance(node, ast.FunctionDef)}
original_ru = read(ROOT / 'results/experiment/original.txt')
original_en = read(ROOT / 'results/experiment_en/original.txt')

report = {
    'statistics': rows, 'accuracy': accuracy,
    'teacher_letters': teacher['letters'], 'teacher_characters': len(cipher),
    'teacher_ic': fmt(teacher['overall_ic']), 'reference_ic': fmt(teacher['reference_ic']),
    'ic_threshold': fmt(teacher['ic_threshold']),
    'repeated_ngrams': teacher['kasiski']['repeated_ngrams'],
    'votes': [[str(k), str(v)] for k, v in votes],
    'repeat': {'ngram': first['ngram'], 'positions': ', '.join(map(str, first['positions'])),
               'distances': ', '.join(map(str, first['distances'])),
               'gcd': math.gcd(*first['distances'])},
    'candidate_rows': [candidate_row(c) for c in candidates if c['length'] in selected],
    'all_candidates': [candidate_row(c) for c in candidates],
    'groups': group_rows, 'group_frequencies': frequency_rows,
    'sources': {name: functions[name] for name in ('transform', 'kasiski', 'index_of_coincidence', 'mean_group_ic', 'recover_key', 'analyze')},
    'ru_fragment': original_ru[:220], 'en_fragment': original_en[:220],
    'cipher_short_fragment': read(ROOT / 'results/experiment/short.txt')[:220],
    'cipher_long_fragment': read(ROOT / 'results/experiment/long.txt')[:220],
    'other_ru': len(original_ru) - len(letter_indices(original_ru)),
    'other_en': len(original_en) - len(letter_indices(original_en, 'en')),
}
(ROOT / 'docs/report-data.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
summary = read(ROOT / 'results/experiment/summary.txt') + '\n' + read(ROOT / 'results/experiment_en/summary.txt')
summary += '\nКриптограмма преподавателя: 3192 буквы; ключ СЕКРЕТЫ; период 7.\n'
summary += f'Повторов n-грамм: {teacher["kasiski"]["repeated_ngrams"]}; общий НОД: 1; голосов за 7: 994.\n'
summary += 'Средний IC групп при L=7: 0.056447; повторное шифрование совпадает: True.\n'
(ROOT / 'docs/results.txt').write_text(summary, encoding='utf-8')
print('Сверены статистика, четыре криптограммы и их расшифровки, позиции нешифруемых символов и криптограмма преподавателя.')
