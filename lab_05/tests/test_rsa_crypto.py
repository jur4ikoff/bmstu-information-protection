import hashlib
import tempfile
import unittest
import hmac
from unittest.mock import patch
from pathlib import Path

from src import hybrid_crypto


class HybridCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public, cls.private = hybrid_crypto.generate_key_pair(2048)

    def test_variant3_rsa_size(self):
        self.assertEqual(self.public.n.bit_length(), 2048)
        with self.assertRaises(ValueError):
            hybrid_crypto.generate_key_pair(1024)

    def test_aes256_cbc_nist_vector(self):
        # NIST SP 800-38A, F.2.5/F.2.6; без PKCS#7 для проверки режима.
        key = bytes.fromhex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')
        iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plain = bytes.fromhex(
            '6bc1bee22e409f96e93d7e117393172a'
            'ae2d8a571e03ac9c9eb76fac45af8e51'
            '30c81c46a35ce411e5fbc1191a0a52ef'
            'f69f2445df4f9b17ad2b417be66c3710')
        expected = bytes.fromhex(
            'f58c4c04d6e5f1ba779eabfb5f7bfbd6'
            '9cfc4e967edb808d679f777bc6702c7d'
            '39f23369a9d9bacfa530e26304231461'
            'b2eb05e2c39be9fcda6c19078c6a9d1b')
        keys = hybrid_crypto._expand_aes_key(key)
        actual, _ = hybrid_crypto._cbc_encrypt(plain, keys, iv)
        self.assertEqual(actual, expected)
        restored, _ = hybrid_crypto._cbc_decrypt(expected, keys, iv)
        self.assertEqual(restored, plain)

    def test_boundary_lengths_and_unaligned_buffers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, encrypted, restored = (root / name for name in ('source', 'encrypted', 'restored'))
            for size in (0, 1, 15, 16, 17, 31, 32, 33, 61, 62, 63, 100):
                with self.subTest(size=size), patch.object(hybrid_crypto, 'BUFFER_SIZE', 31):
                    data = bytes(range(size))
                    source.write_bytes(data)
                    hybrid_crypto.encrypt_file(source, encrypted, self.public)
                    hybrid_crypto.decrypt_file(encrypted, restored, self.private)
                    self.assertEqual(restored.read_bytes(), data)
                    self.assertEqual(encrypted.stat().st_size, 6 + 256 + 16 + (size // 16 + 1) * 16 + 32)

    def test_session_material_and_encrypt_then_mac(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, encrypted = root / 'source', root / 'encrypted'
            source.write_bytes(b'example')
            hybrid_crypto.encrypt_file(source, encrypted, self.public)
            content = encrypted.read_bytes()
            material = hybrid_crypto.rsa_oaep_decrypt(content[6:262], self.private)
            self.assertEqual(len(material), 64)
            self.assertNotEqual(material[:32], material[32:])
            self.assertEqual(content[-32:], hmac.digest(material[32:], content[:-32], 'sha256'))
            hybrid_crypto.encrypt_file(source, encrypted, self.public)
            self.assertNotEqual(encrypted.read_bytes(), content)

    def test_all_container_fields_authenticated_before_decryption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, encrypted, restored = (root / name for name in ('source', 'encrypted', 'restored'))
            source.write_bytes(b'confidential data' * 3)
            hybrid_crypto.encrypt_file(source, encrypted, self.public)
            original = encrypted.read_bytes()
            for offset in (0, 4, 6, 262, 278, len(original) - 1):
                with self.subTest(offset=offset):
                    changed = bytearray(original)
                    changed[offset] ^= 1
                    encrypted.write_bytes(changed)
                    restored.write_bytes(b'existing file')
                    with patch.object(hybrid_crypto, '_cbc_decrypt') as decrypt:
                        with self.assertRaises(ValueError):
                            hybrid_crypto.decrypt_file(encrypted, restored, self.private)
                        decrypt.assert_not_called()
                    self.assertEqual(restored.read_bytes(), b'existing file')
            for changed in (b'', original[:100], original[:-1], original + b'X'):
                encrypted.write_bytes(changed)
                with self.assertRaises(ValueError):
                    hybrid_crypto.decrypt_file(encrypted, restored, self.private)
                self.assertEqual(restored.read_bytes(), b'existing file')
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['encrypted', 'restored', 'source'])

    def test_authenticated_invalid_padding_preserves_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, encrypted, restored = (root / name for name in ('source', 'encrypted', 'restored'))
            source.write_bytes(b'example')
            hybrid_crypto.encrypt_file(source, encrypted, self.public)
            content = encrypted.read_bytes()
            material = hybrid_crypto.rsa_oaep_decrypt(content[6:262], self.private)
            # Держатель ключа формирует корректный MAC над некорректным дополнением.
            cipher, _ = hybrid_crypto._cbc_encrypt(bytes(16), hybrid_crypto._expand_aes_key(material[:32]), content[262:278])
            body = content[:278] + cipher
            encrypted.write_bytes(body + hmac.digest(material[32:], body, 'sha256'))
            restored.write_bytes(b'existing')
            with self.assertRaisesRegex(ValueError, 'PKCS#7'):
                hybrid_crypto.decrypt_file(encrypted, restored, self.private)
            self.assertEqual(restored.read_bytes(), b'existing')

    def test_pkcs7_rejects_invalid_padding(self):
        for data in (b'', bytes(16), b'A' * 15, b'A' * 15 + b'\x11', b'A' * 14 + b'\x01\x02'):
            with self.assertRaises(ValueError):
                hybrid_crypto._pkcs7_unpad(data)

    def test_missing_source_leaves_no_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(OSError):
                hybrid_crypto.encrypt_file(root / 'missing', root / 'output', self.public)
            self.assertEqual(list(root.iterdir()), [])

    def test_aes128_fips197_c1_and_inverse(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(hybrid_crypto.aes128_encrypt_block(plaintext, key), ciphertext)
        self.assertEqual(hybrid_crypto.aes128_decrypt_block(ciphertext, key), plaintext)

    def test_aes256_gcm_nist_vector(self):
        # NIST SP 800-38D, AES-256-GCM: zero key, IV and one zero block.
        keys, subkey, counter = hybrid_crypto._gcm_context(bytes(32), bytes(12))
        ciphertext, _ = hybrid_crypto._gcm_transform(bytes(16), keys, counter)
        tag = hybrid_crypto._xor(
            hybrid_crypto._aes_encrypt_block(counter, keys),
            hybrid_crypto._gcm_tag(subkey, ciphertext),
        )
        self.assertEqual(ciphertext.hex(), "cea7403d4d606b6e074ec5d3baf39d18")
        self.assertEqual(tag.hex(), "d0d1c8a799996bf0265b98b5d48ab919")

    def test_password_protected_pem(self):
        with tempfile.TemporaryDirectory() as directory:
            pem = Path(directory) / "private.pem"
            hybrid_crypto.save_private_key(pem, self.private, "correct password")
            self.assertIn(b"BEGIN ENCRYPTED RSA PRIVATE KEY", pem.read_bytes())
            self.assertEqual(
                hybrid_crypto.load_private_key(pem, "correct password"), self.private
            )
            with self.assertRaisesRegex(ValueError, "wrong password"):
                hybrid_crypto.load_private_key(pem, "bad password")

    def test_hyb1_stream_round_trip_and_sha256(self):
        # More than two chunks and a final non-block-aligned fragment.
        source_data = bytes(range(256)) * 5 + b"partial AES block"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, encrypted, restored = (
                root / "source.rar",
                root / "source.enc",
                root / "restored.rar",
            )
            source.write_bytes(source_data)
            with patch.object(hybrid_crypto, "BUFFER_SIZE", 512):
                hybrid_crypto.encrypt_file(source, encrypted, self.public)
            content = encrypted.read_bytes()
            self.assertEqual(content[:4], b"HYB1")
            self.assertEqual(
                int.from_bytes(content[4:6], "big"), self.public.size_bytes
            )
            self.assertEqual(
                len(content), 6 + self.public.size_bytes + 16 + (len(source_data) // 16 + 1) * 16 + 32
            )
            with patch.object(hybrid_crypto, "BUFFER_SIZE", 512):
                hybrid_crypto.decrypt_file(encrypted, restored, self.private)
            self.assertEqual(
                hashlib.sha256(restored.read_bytes()).digest(),
                hashlib.sha256(source_data).digest(),
            )

    def test_tampering_leaves_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, encrypted, output = (
                root / "plain.txt",
                root / "plain.enc",
                root / "restored.txt",
            )
            source.write_bytes(b"confidential data")
            hybrid_crypto.encrypt_file(source, encrypted, self.public)
            damaged = bytearray(encrypted.read_bytes())
            damaged[-33] ^= 1
            encrypted.write_bytes(damaged)
            with self.assertRaisesRegex(ValueError, "authentication failed"):
                hybrid_crypto.decrypt_file(encrypted, output, self.private)
            self.assertFalse(output.exists())

    def test_wrong_key_leaves_no_output(self):
        _, wrong_private = hybrid_crypto.generate_key_pair(2048)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, encrypted, output = (
                root / "plain",
                root / "plain.enc",
                root / "restored",
            )
            source.write_bytes(b"data")
            hybrid_crypto.encrypt_file(source, encrypted, self.public)
            with self.assertRaises(ValueError):
                hybrid_crypto.decrypt_file(encrypted, output, wrong_private)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
