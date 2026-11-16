"""Виженер и статистический криптоанализ. Только стандартная библиотека."""

from collections import Counter, defaultdict
from functools import reduce
from math import gcd, log


ALPHABETS = {
    'ru': 'АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ',  # Без Ё: Ё сохраняется.
    'ru33': 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ',
    'en': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
}

# Относительные частоты букв языка; перед использованием нормируются.
RU_WEIGHTS = dict(zip(
    ALPHABETS['ru33'],
    (8.01, 1.59, 4.54, 1.70, 2.98, 8.45, 0.04, 0.94, 1.65, 7.35,
     1.21, 3.49, 4.40, 3.21, 6.70, 10.97, 2.81, 4.73, 5.47, 6.26,
     2.62, 0.26, 0.97, 0.48, 1.44, 0.73, 0.36, 0.04, 1.90, 1.74,
     0.32, 0.64, 2.01),
))
EN_WEIGHTS = dict(zip(
    ALPHABETS['en'],
    (8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
     0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
     6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074),
))


def alphabet_for(language: str) -> str:
    try:
        return ALPHABETS[language]
    except KeyError:
        raise ValueError('Алфавит должен быть ru, ru33 или en') from None


def reference_frequencies(language: str) -> list[float]:
    alphabet = alphabet_for(language)
    weights = EN_WEIGHTS if language == 'en' else RU_WEIGHTS
    total = sum(weights[c] for c in alphabet)
    return [weights[c] / total for c in alphabet]


def letter_indices(text: str, language: str = 'ru') -> list[int]:
    alphabet = alphabet_for(language)
    indices = {c: i for i, upper in enumerate(alphabet) for c in (upper, upper.lower())}
    return [indices[c] for c in text if c in indices]


def transform(text: str, key: str, language: str = 'ru', decrypt: bool = False) -> str:
    """Ключ продвигается только на буквах выбранного алфавита."""
    alphabet = alphabet_for(language)
    indices = {c: i for i, upper in enumerate(alphabet) for c in (upper, upper.lower())}
    if not key or any(c not in indices for c in key):
        raise ValueError('Ключ должен содержать только буквы выбранного алфавита')
    shifts = [indices[c] for c in key]
    result = []
    position = 0
    direction = -1 if decrypt else 1
    for char in text:
        index = indices.get(char)
        if index is None:
            result.append(char)
            continue
        changed = alphabet[(index + direction * shifts[position % len(shifts)]) % len(alphabet)]
        result.append(changed.lower() if char.islower() else changed)
        position += 1
    return ''.join(result)


def encrypt(text: str, key: str, language: str = 'ru') -> str:
    return transform(text, key, language)


def decrypt(text: str, key: str, language: str = 'ru') -> str:
    return transform(text, key, language, decrypt=True)


def index_of_coincidence(values: list[int]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    return sum(count * (count - 1) for count in Counter(values).values()) / (n * (n - 1))


def mean_group_ic(values: list[int], length: int) -> float:
    if length < 1:
        raise ValueError('Длина ключа должна быть положительной')
    return sum(index_of_coincidence(values[i::length]) for i in range(length)) / length


def kasiski(text: str, language: str = 'ru', max_length: int = 40,
            min_ngram: int = 3, max_ngram: int = 5) -> dict:
    """Расстояния между соседними повторами; позиции считаются по буквам.

    Для длинных текстов соседние повторы позволяют избежать квадратичного
    числа пар. НОД этих расстояний совпадает с НОД всех попарных расстояний.
    """
    alphabet = alphabet_for(language)
    if max_length < 1 or not 3 <= min_ngram <= max_ngram:
        raise ValueError('Нужны max_length >= 1 и 3 <= min_ngram <= max_ngram')
    letters = ''.join(alphabet[i] for i in letter_indices(text, language))
    distances = Counter()
    repeats = []
    for size in range(min_ngram, max_ngram + 1):
        positions = defaultdict(list)
        for i in range(len(letters) - size + 1):
            positions[letters[i:i + size]].append(i)
        for gram, locations in positions.items():
            if len(locations) < 2:
                continue
            gaps = [b - a for a, b in zip(locations, locations[1:])]
            distances.update(gaps)
            repeats.append({'ngram': gram, 'positions': locations, 'distances': gaps})
    votes = Counter()
    for distance, count in distances.items():
        for divisor in range(2, min(max_length, distance) + 1):
            if distance % divisor == 0:
                votes[divisor] += count
    common = reduce(gcd, distances, 0)
    return {
        'distance_gcd': common,
        'gcd_hypotheses': [d for d in range(2, max_length + 1) if common and common % d == 0],
        'factor_votes': dict(sorted(votes.items())),
        'distance_counts': dict(sorted(distances.items())),
        'repeated_ngrams': len(repeats),
        'examples': sorted(repeats, key=lambda r: (-len(r['ngram']), -len(r['positions']), r['ngram']))[:20],
    }


def recover_key(text: str, length: int, language: str = 'ru') -> tuple[str, list[dict]]:
    alphabet = alphabet_for(language)
    values = letter_indices(text, language)
    if not 1 <= length <= len(values):
        raise ValueError('Длина ключа должна быть от 1 до числа букв криптограммы')
    reference = reference_frequencies(language)
    key, groups = [], []
    for position in range(length):
        group = values[position::length]
        counts = Counter(group)
        n = len(group)
        scores = []
        for shift in range(len(alphabet)):
            score = sum(
                (counts[(letter + shift) % len(alphabet)] - n * expected) ** 2 / (n * expected)
                for letter, expected in enumerate(reference)
            )
            scores.append(score)
        shift = min(range(len(alphabet)), key=scores.__getitem__)
        key.append(alphabet[shift])
        groups.append({'position': position + 1, 'size': n, 'shift': shift,
                       'letter': alphabet[shift], 'chi_square': scores[shift],
                       'all_shift_scores': scores})
    return ''.join(key), groups


def shortest_period(key: str) -> str:
    for length in range(1, len(key) + 1):
        if len(key) % length == 0 and key == key[:length] * (len(key) // length):
            return key[:length]
    return key


def analyze(text: str, language: str = 'ru', max_length: int = 40,
            key_length: int | None = None) -> dict:
    """Казиски + IC + χ². Вероятностная оценка штрафует лишние позиции ключа."""
    values = letter_indices(text, language)
    if len(values) < 2:
        raise ValueError('Для анализа нужны хотя бы две буквы выбранного алфавита')
    if max_length < 1:
        raise ValueError('Максимальная длина ключа должна быть положительной')
    limit = min(max_length, max(1, len(values) // 2))
    if key_length is not None and not 1 <= key_length <= len(values):
        raise ValueError('Заданная длина ключа превышает число букв или неположительна')
    evidence = kasiski(text, language, max_length=max(limit, key_length or 1))
    reference = reference_frequencies(language)
    alphabet = alphabet_for(language)
    candidates = []
    lengths = sorted(set(range(1, limit + 1)) | ({key_length} if key_length else set()))
    for length in lengths:
        key, groups = recover_key(text, length, language)
        shifts = [alphabet.index(c) for c in key]
        plain_counts = Counter((value - shifts[i % length]) % len(alphabet)
                               for i, value in enumerate(values))
        log_likelihood = sum(count * log(reference[letter]) for letter, count in plain_counts.items())
        # Штраф за длину помогает выбрать L вместо кратных 2L, 3L.
        criterion = -2 * log_likelihood + length * log(len(values))
        candidates.append({'length': length, 'mean_ic': mean_group_ic(values, length),
                           'kasiski_votes': evidence['factor_votes'].get(length, 0),
                           'key': key, 'chi_square': sum(g['chi_square'] for g in groups),
                           'criterion': criterion})
    # IC отбирает периоды с выраженной неоднородностью внутри групп.
    # В отличие от выбора максимального IC это не предпочитает большие кратные L.
    random_ic = 1 / len(alphabet)
    peak_ic = max(c['mean_ic'] for c in candidates)
    ic_threshold = random_ic + max(0, peak_ic - random_ic) * 0.5
    plausible = [c for c in candidates if c['mean_ic'] >= ic_threshold] or candidates
    best = (next(c for c in candidates if c['length'] == key_length) if key_length
            else min(plausible, key=lambda c: c['criterion']))
    key = shortest_period(best['key'])
    _, groups = recover_key(text, len(key), language)
    plaintext = decrypt(text, key, language)
    return {'language': language, 'alphabet': alphabet, 'letters': len(values),
            'overall_ic': index_of_coincidence(values), 'random_ic': 1 / len(alphabet),
            'reference_ic': sum(p * p for p in reference),
            'kasiski': evidence, 'candidates': candidates, 'ic_threshold': ic_threshold,
            'selection_reason': (f'Средний IC выбранного периода: {best["mean_ic"]:.6f}; '
                                 f'голосов Казиски: {best["kasiski_votes"]}. '
                                 'После проверки IC выбрано лучшее правдоподобие со штрафом за длину.'
                                 if key_length is None else 'Длина задана пользователем.'),
            'key': key,
            'key_length': len(key), 'groups': groups, 'plaintext': plaintext,
            'reencryption_matches': encrypt(plaintext, key, language) == text,
            'note': 'Повторное шифрование проверяет обратимость, но само по себе не доказывает верность ключа.'}


def statistics(text: str, language: str = 'ru') -> dict:
    alphabet = alphabet_for(language)
    values = letter_indices(text, language)
    counts = Counter(values)
    n = len(values)
    frequencies = [counts[i] / n if n else 0.0 for i in range(len(alphabet))]
    return {'characters': len(text), 'letters': n, 'ic': index_of_coincidence(values),
            'entropy_bits_per_letter': -sum(p * log(p, 2) for p in frequencies if p),
            'letter_counts': {c: counts[i] for i, c in enumerate(alphabet)},
            'letter_frequencies': dict(zip(alphabet, frequencies)),
            'symbol_counts': dict(sorted(Counter(text).items()))}
