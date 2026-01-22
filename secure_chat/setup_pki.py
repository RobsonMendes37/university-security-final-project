import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

# Configuração
CERT_DIR = "certs"
KEY_FILE = os.path.join(CERT_DIR, "server_key.pem")
CERT_FILE = os.path.join(CERT_DIR, "server_cert.pem")

def generate_pki():
    print(f"[*] Gerando infraestrutura PKI em '{CERT_DIR}'...")

    # Garante que o diretório existe
    if not os.path.exists(CERT_DIR):
        print(f"[*] Criando diretório {CERT_DIR}...")
        os.makedirs(CERT_DIR)

    # 1. Gerar Chave Privada RSA (2048 bits)
    print("[*] Gerando Chave Privada RSA de 2048 bits...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Salvar Chave Privada
    with open(KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[+] Chave Privada salva em {KEY_FILE}")

    # 2. Gerar Certificado Autoassinado
    print("[*] Gerando Certificado X.509 Autoassinado...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"RS"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Porto Alegre"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Projeto de Seguranca da Universidade"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Valido por 1 ano
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    # Salvar Certificado
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Certificado salvo em {CERT_FILE}")
    print("[SUCESSO] Fase 1 Completa: PKI inicializada.")

if __name__ == "__main__":
    generate_pki()
