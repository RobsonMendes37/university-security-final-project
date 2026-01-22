import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

# Configuration
CERT_DIR = "certs"
KEY_FILE = os.path.join(CERT_DIR, "server_key.pem")
CERT_FILE = os.path.join(CERT_DIR, "server_cert.pem")

def generate_pki():
    print(f"[*] Generating PKI infrastructure in '{CERT_DIR}'...")

    # Ensure directory exists
    if not os.path.exists(CERT_DIR):
        print(f"[*] Creating directory {CERT_DIR}...")
        os.makedirs(CERT_DIR)

    # 1. Generate RSA Private Key (2048 bits)
    print("[*] Generating 2048-bit RSA Private Key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save Private Key
    with open(KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[+] Private Key saved to {KEY_FILE}")

    # 2. Generate Self-Signed Certificate
    print("[*] Generating Self-Signed X.509 Certificate...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"RS"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Porto Alegre"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University Security Project"),
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
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Valid for 1 year
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    # Save Certificate
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Certificate saved to {CERT_FILE}")
    print("[SUCCESS] Phase 1 Complete: PKI initialized.")

if __name__ == "__main__":
    generate_pki()
