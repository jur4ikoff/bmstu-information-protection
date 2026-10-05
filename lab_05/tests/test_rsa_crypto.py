import hashlib
import tempfile
import unittest
from pathlib import Path

from src import hybrid_crypto


class HybridCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public, cls.private = hybrid_crypto.generate_key_pair(1024)

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
        source_data = bytes(range(256)) * 600 + b"partial AES block"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, encrypted, restored = (
                root / "source.rar",
                root / "source.enc",
                root / "restored.rar",
            )
            source.write_bytes(source_data)
            hybrid_crypto.encrypt_file(source, encrypted, self.public)
            content = encrypted.read_bytes()
            self.assertEqual(content[:4], b"HYB1")
            self.assertEqual(
                int.from_bytes(content[4:6], "big"), self.public.size_bytes
            )
            self.assertEqual(
                len(content), 6 + self.public.size_bytes + 12 + len(source_data) + 16
            )
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
            damaged[-17] ^= 1
            encrypted.write_bytes(damaged)
            with self.assertRaisesRegex(ValueError, "authentication failed"):
                hybrid_crypto.decrypt_file(encrypted, output, self.private)
            self.assertFalse(output.exists())

    def test_wrong_key_leaves_no_output(self):
        _, wrong_private = hybrid_crypto.generate_key_pair(1024)
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
