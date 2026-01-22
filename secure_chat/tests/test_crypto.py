import unittest
import os
from cryptography.hazmat.primitives import serialization
from core.security import SecurityManager

class TestSecurityManager(unittest.TestCase):
    def setUp(self):
        self.sm = SecurityManager()
        # Load server keys for signature tests
        with open("certs/server_key.pem", "rb") as f:
            self.server_priv_key = serialization.load_pem_private_key(
                f.read(), password=None
            )
        with open("certs/server_cert.pem", "rb") as f:
            self.server_cert_bytes = f.read()

    def test_ecdh_exchange(self):
        """Test that two parties arrive at the same shared secret."""
        # Alice (Client)
        priv_a, pub_a_bytes = self.sm.generate_ecdh_keys()
        
        # Bob (Server)
        priv_b, pub_b_bytes = self.sm.generate_ecdh_keys()

        # Exchange
        secret_a = self.sm.compute_shared_secret(priv_a, pub_b_bytes)
        secret_b = self.sm.compute_shared_secret(priv_b, pub_a_bytes)

        self.assertEqual(secret_a, secret_b)
        self.assertEqual(len(secret_a), 32) # SHA-256 size usually, but ECDH P-256 output is 32 bytes

    def test_hkdf_derivation(self):
        """Test key derivation produces correct length and different keys."""
        secret = os.urandom(32)
        salt = os.urandom(16)

        key_c2s, key_s2c = self.sm.derive_keys(secret, salt)

        self.assertEqual(len(key_c2s), 16) # AES-128
        self.assertEqual(len(key_s2c), 16)
        self.assertNotEqual(key_c2s, key_s2c)

    def test_rsa_signature(self):
        """Test RSA signing and verification."""
        data = b"pk_S_bytes" + b"client_id" + b"random_salt"
        
        # Sign
        signature = self.sm.sign_handshake(self.server_priv_key, data)
        
        # Verify (Should succeed)
        is_valid = self.sm.verify_handshake(self.server_cert_bytes, signature, data)
        self.assertTrue(is_valid)

        # Verify tampered data (Should fail)
        is_valid_tampered = self.sm.verify_handshake(self.server_cert_bytes, signature, data + b"hack")
        self.assertFalse(is_valid_tampered)

    def test_aes_gcm(self):
        """Test AES-GCM Encryption and Decryption."""
        key = os.urandom(16)
        nonce = os.urandom(12)
        plaintext = b"Hello, World!"
        aad = b"header_info"

        # Encrypt
        ciphertext_tag = self.sm.encrypt_with_nonce(key, nonce, plaintext, aad)
        
        # Payload size = plaintext + 16 bytes tag
        self.assertEqual(len(ciphertext_tag), len(plaintext) + 16)

        # Decrypt
        decrypted = self.sm.decrypt(key, nonce, ciphertext_tag, aad)
        self.assertEqual(decrypted, plaintext)

    def test_aes_gcm_tamper(self):
        """Test AES-GCM decryption fails with tampered ciphertext or AAD."""
        key = os.urandom(16)
        nonce = os.urandom(12)
        plaintext = b"Secret Message"
        aad = b"header"

        ciphertext_tag = self.sm.encrypt_with_nonce(key, nonce, plaintext, aad)

        # 1. Tamper Ciphertext
        tampered_cipher = bytearray(ciphertext_tag)
        tampered_cipher[0] ^= 0xFF # Flip bits
        with self.assertRaises(Exception):
            self.sm.decrypt(key, nonce, bytes(tampered_cipher), aad)

        # 2. Wrong AAD
        with self.assertRaises(Exception):
            self.sm.decrypt(key, nonce, ciphertext_tag, b"wrong_header")

if __name__ == '__main__':
    unittest.main()
