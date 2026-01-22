from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import os

class SecurityManager:
    def __init__(self):
        self.backend = default_backend()
        self.curve = ec.SECP256R1()

    def generate_ecdh_keys(self):
        """Generates an ephemeral ECDH key pair."""
        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, public_key_bytes

    def compute_shared_secret(self, private_key, peer_public_key_bytes):
        """Computes ECDH shared secret Z."""
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_bytes,
            backend=self.backend
        )
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_secret

    def derive_keys(self, shared_secret, salt):
        """
        Derives session keys using HKDF-SHA256 (TLS 1.3 style).
        Returns (key_c2s, key_s2c).
        """
        if not salt:
            salt = os.urandom(16) # Should be provided by server usually

        # HKDF Extract & Expand done together or separate. 
        # Using standard HKDF implementation which does Extract then Expand.
        # But we need two separate keys with different info labels.
        # So first we can get a pseudo-random key (PRK) if we want, or just derive twice from the master secret.
        # The prompt says: HKDF-Extract: PRK = HMAC(salt, Z), then Expand.
        # The cryptography library HKDF class does Extract+Expand in `derive`.
        # To do Extract then Expand separately is possible but we can also just run HKDF twice on the common Z 
        # but that is not strictly TLS 1.3 style (TLS 1.3 derives a handshake secret then application traffic secrets).
        # We will follow the prompt:
        # PRK = HMAC(salt, Z) -> logic is inside HKDF(algorithm, length, salt, info)
        
        # 1. Derive Key Client-to-Server
        hkdf_c2s = HKDF(
            algorithm=hashes.SHA256(),
            length=16, # AES-128
            salt=salt,
            info=b"c2s",
            backend=self.backend
        )
        key_c2s = hkdf_c2s.derive(shared_secret)

        # 2. Derive Key Server-to-Client
        hkdf_s2c = HKDF(
            algorithm=hashes.SHA256(),
            length=16, # AES-128
            salt=salt,
            info=b"s2c",
            backend=self.backend
        )
        key_s2c = hkdf_s2c.derive(shared_secret)

        return key_c2s, key_s2c

    def sign_handshake(self, rsa_private_key, data):
        """
        Signs data using RSA-SHA256.
        Data = pk_S || client_id || salt
        """
        signature = rsa_private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_handshake(self, cert_bytes, signature, data):
        """
        Verifies RSA-SHA256 signature using the server's certificate.
        """
        cert = x509.load_pem_x509_certificate(cert_bytes, self.backend)
        public_key = cert.public_key()
        
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Verification Failed: {e}")
            return False

    def encrypt(self, key, plaintext, aad):
        """
        Encrypts plaintext using AES-128-GCM.
        Returns nonce + ciphertext + tag.
        Actually, GCM generates tag automatically.
        We will return ciphertext + tag. Nonce should be handled outside or appended.
        The prompts says structure: [nonce] [headers] [ciphertext+tag].
        For GCM, the nonce is input.
        """
        # We need a nonce. GCM needs 12 bytes nonce.
        # IMPORTANT: The Nonce is usually passed IN because it's part of the header.
        # So we should probably assume the nonce is derived or passed in.
        # Wait, the prompt structure says: [nonce] + [IDs] + [seq] + [ciphertext+tag]
        # And "AAD: sender_id | recipient_id | seq_no"
        # The encrypt function needs to know the nonce being used.
        # Let's check prompt requirement: "Nonce: deve ser único por mensagem e por direção."
        # Usually we pass nonce as argument to encrypt.
        pass

    def encrypt_with_nonce(self, key, nonce, plaintext, aad):
        """
        Encrypts using AES-GCM with specific nonce.
        """
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext + encryptor.tag

    def decrypt(self, key, nonce, ciphertext_with_tag, aad):
        """
        Decrypts using AES-GCM.
        Input ciphertext_with_tag is what we received (payload).
        """
        # GCM tag is usually last 16 bytes
        tag = ciphertext_with_tag[-16:]
        ciphertext = ciphertext_with_tag[:-16]

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()
