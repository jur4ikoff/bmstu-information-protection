import tempfile
import unittest
from pathlib import Path

from src import rsa_crypto


class CryptoSystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 1024 bits are sufficient for tests and preserve OAEP-SHA-256 capacity.
        cls.public, cls.private = rsa_crypto.generate_key_pair(1024)

    def test_aes256_known_answer(self):
        key = bytes.fromhex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        )
        block = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected = bytes.fromhex("f3eed1bdb5d2a03c064b5a7e3db181f8")
        self.assertEqual(
            rsa_crypto._aes_block(block, rsa_crypto._expand_aes256_key(key)), expected
        )

    def test_key_protection_and_wrong_password(self):
        with tempfile.TemporaryDirectory() as directory:
            protected = Path(directory) / "private.json"
            rsa_crypto.save_private_key(
                protected, self.private, "correct horse battery staple"
            )
            self.assertEqual(
                rsa_crypto.load_private_key(protected, "correct horse battery staple"),
                self.private,
            )
            with self.assertRaises(ValueError):
                rsa_crypto.load_private_key(protected, "wrong password")

    def test_boundary_file_sizes_sign_encrypt_decrypt(self):
        # Пустой, однобайтный и существенно превышающий блок RSA файл.
        samples = (b"", b"X", bytes(range(256)) * 20)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for number, sample in enumerate(samples):
                original = root / f"input-{number}.bin"
                envelope = root / f"encrypted-{number}.json"
                recovered = root / f"output-{number}.bin"
                signature = root / f"input-{number}.sig"
                original.write_bytes(sample)
                rsa_crypto.encrypt_file(original, envelope, self.public)
                rsa_crypto.decrypt_file(envelope, recovered, self.private)
                self.assertEqual(recovered.read_bytes(), sample)
                rsa_crypto.sign_file(original, signature, self.private)
                self.assertTrue(
                    rsa_crypto.verify_file(original, signature, self.public)
                )

    def test_tampered_ciphertext_and_signature_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data, envelope, signature = (
                root / "data",
                root / "envelope",
                root / "signature",
            )
            data.write_bytes(b"original")
            rsa_crypto.encrypt_file(data, envelope, self.public)
            content = envelope.read_text(encoding="utf-8")
            envelope.write_text(
                content.replace("ciphertext", "ciphertexx", 1), encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                rsa_crypto.decrypt_file(envelope, root / "output", self.private)
            rsa_crypto.sign_file(data, signature, self.private)
            data.write_bytes(b"changed")
            self.assertFalse(rsa_crypto.verify_file(data, signature, self.public))


if __name__ == "__main__":
    unittest.main()
