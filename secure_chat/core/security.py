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
        """Gera um par de chaves ECDH efemeras."""
        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, public_key_bytes

    def compute_shared_secret(self, private_key, peer_public_key_bytes):
        """Calcula o segredo compartilhado ECDH (Z)."""
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_bytes,
            backend=self.backend
        )
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_secret

    def derive_keys(self, shared_secret, salt):
        """
        Deriva chaves de sessao usando HKDF-SHA256 (estilo TLS 1.3).
        Retorna (key_c2s, key_s2c).
        """
        if not salt:
            salt = os.urandom(16) # Deve ser fornecido pelo servidor geralmente

        # 1. Derivar Chave Cliente-para-Servidor
        hkdf_c2s = HKDF(
            algorithm=hashes.SHA256(),
            length=16, # AES-128
            salt=salt,
            info=b"c2s",
            backend=self.backend
        )
        key_c2s = hkdf_c2s.derive(shared_secret)

        # 2. Derivar Chave Servidor-para-Cliente
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
        Assina dados usando RSA-SHA256.
        Dados = pk_S || client_id || salt
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
        Verifica a assinatura RSA-SHA256 usando o certificado do servidor.
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
            print(f"Verificacao Falhou: {e}")
            return False

    def encrypt_with_nonce(self, key, nonce, plaintext, aad):
        """
        Cifra usando AES-GCM com nonce especifico.
        """
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext + encryptor.tag

    def decrypt(self, key, nonce, ciphertext_with_tag, aad):
        """
        Decifra usando AES-GCM.
        Entrada ciphertext_with_tag e' o que recebemos (payload).
        """
        # Tag GCM geralmente sao os ultimos 16 bytes
        tag = ciphertext_with_tag[-16:]
        ciphertext = ciphertext_with_tag[:-16]

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()
