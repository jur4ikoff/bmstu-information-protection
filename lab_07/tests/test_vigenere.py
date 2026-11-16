import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vigenere import (ALPHABETS, analyze, decrypt, encrypt, index_of_coincidence,
                      kasiski, letter_indices, recover_key, reference_frequencies)
from main import prepare_text, read_text, ROOT


class VigenereTests(unittest.TestCase):
    def test_known_vector(self):
        self.assertEqual(encrypt('ATTACKATDAWN', 'LEMON', 'en'), 'LXFOPVEFRNHR')
        self.assertEqual(decrypt('Lxfopv ef rnhr!', 'LEMON', 'en'), 'Attack at dawn!')

    def test_nonletters_do_not_advance_key(self):
        self.assertEqual(encrypt('A-1 A\nA', 'BC', 'en'), 'B-1 C\nB')

    def test_round_trip_and_preserved_characters(self):
        text = 'АаБб Ёё, Яя! Hello, 123\r\n\tßıſ🙂'
        for language, key in [('ru', 'КЛЮЧ'), ('ru33', 'ЁЖИК'), ('en', 'SECRET')]:
            encrypted = encrypt(text, key, language)
            self.assertEqual(len(encrypted), len(text))
            self.assertEqual(decrypt(encrypted, key, language), text)
            for before, after in zip(text, encrypted):
                if before not in ALPHABETS[language] + ALPHABETS[language].lower():
                    self.assertEqual(before, after)
        self.assertEqual(encrypt('Ёё', 'КЛЮЧ', 'ru'), 'Ёё')
        self.assertNotEqual(encrypt('Ёё', 'ЁЖ', 'ru33'), 'Ёё')

    def test_invalid_inputs(self):
        for key in ('', 'KEY!', 'ключ'):
            with self.assertRaises(ValueError):
                encrypt('text', key, 'en')
        for text in ('', '123!'):
            with self.assertRaises(ValueError):
                analyze(text)
        with self.assertRaises(ValueError):
            analyze('ABC', 'en', key_length=4)
        with self.assertRaises(ValueError):
            analyze('ABC', 'en', max_length=0)
        self.assertEqual(encrypt('', 'KEY', 'en'), '')

    def test_ic_and_frequencies(self):
        self.assertEqual(index_of_coincidence([0, 0, 0]), 1.0)
        self.assertEqual(index_of_coincidence([0, 1, 2]), 0.0)
        self.assertEqual(index_of_coincidence([]), 0.0)
        for language in ALPHABETS:
            self.assertAlmostEqual(sum(reference_frequencies(language)), 1.0)

    def test_kasiski_uses_letter_positions(self):
        result = kasiski('ABC---ABC ABC', 'en', max_length=9, max_ngram=3)
        self.assertEqual(result['distance_gcd'], 3)
        # ABC даёт два расстояния, BCA и CAB — ещё по одному.
        self.assertEqual(result['factor_votes'][3], 4)
        self.assertEqual(result['examples'][0]['positions'], [0, 3, 6])

    def test_teacher_ciphertext(self):
        cipher = read_text(ROOT / 'data' / 'teacher_ciphertext.txt')
        result = analyze(cipher)
        self.assertEqual(result['key'], 'СЕКРЕТЫ')
        self.assertTrue(result['plaintext'].startswith('СОВРЕМЕННЫЕИНФОРМАЦИОННЫЕСИСТЕМЫ'))
        self.assertTrue(result['reencryption_matches'])

    def test_recovery_in_both_languages(self):
        for language, key in [('ru', 'КЛЮЧ'), ('ru', 'ИНФОРМАЦИОННАЯЗАЩИТА'),
                              ('ru33', 'ЁЖИК'), ('en', 'LEMON'),
                              ('en', 'INFORMATIONSECURITY')]:
            with self.subTest(language=language, key=key):
                text = prepare_text(20_000, language)
                cipher = encrypt(text, key, language)
                recovered, _ = recover_key(cipher, len(key), language)
                self.assertEqual(recovered, key)
                result = analyze(cipher, language, max_length=40)
                self.assertEqual(result['key'], key)
                self.assertEqual(result['plaintext'], text)
                self.assertEqual(len(letter_indices(cipher, language)), len(letter_indices(text, language)))

    def test_repeated_key_reduces_to_fundamental_period(self):
        text = prepare_text(10_000, 'en')
        result = analyze(encrypt(text, 'KEYKEY', 'en'), 'en', key_length=6)
        self.assertEqual(result['key'], 'KEY')


if __name__ == '__main__':
    unittest.main()
