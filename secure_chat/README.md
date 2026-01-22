# Secure Multi-Client Messaging Application

## 🎯 Overview
This project implements a secure messaging application with a central server, guaranteeing:
*   **Confidentiality**: AES-128-GCM Encryption.
*   **Integrity**: GCM Authentication Tags.
*   **Authenticity**: RSA Signatures & Certificates.
*   **Forward Secrecy**: ECDHE (Elliptic Curve Diffie-Hellman Ephemeral).
*   **Anti-Replay**: Monotonically increasing sequence numbers with server-side validation.

## 📂 Structure
*   `secure_chat/certs/`: Stores Server RSA Key and Certificate.
*   `secure_chat/core/security.py`: Cryptographic primitives (ECDHE, HKDF, AES-GCM).
*   `secure_chat/core/protocol.py`: Network packet structure definition.
*   `secure_chat/server.py`: Central server handling multiple clients.
*   `secure_chat/client.py`: Client CLI.
*   `secure_chat/setup_pki.py`: Initialization script.
*   `secure_chat/tests/`: Unit tests and attack simulations.

## 🚀 How to Run

### 1. Prerequisites
Install dependencies:
```bash
pip install cryptography
```

### 2. Initialization (Phase 1)
Generate the Server's Identity (RSA Key + Self-Signed Certificate):
```bash
cd secure_chat
python3 setup_pki.py
```
*Creates `certs/server_key.pem` and `certs/server_cert.pem`.*

### 3. Start Server
```bash
python3 server.py
```
*Server listens on 0.0.0.0:8000.*

### 4. Start Clients
Open new terminals for each client:
```bash
# Client A (Alice)
python3 client.py Alice
```
```bash
# Client B (Bob)
python3 client.py Bob
```

### 5. Send Messages
In Alice's terminal:
```text
@Bob Hello Bob, this is a secure message!
```

## 🛡️ Security Verification
To verify **Anti-Replay** protection:
1. Ensure Server is running.
2. Run the attack script:
```bash
python3 tests/attack_replay.py
```
**Expected Output**: The script will send a valid packet, verify it works, then resend it. The script should report `[SUCCESS] Connection Reset` or server disconnection.

## 🧪 Unit Tests
Run the cryptographic core tests:
```bash
python3 -m unittest tests/test_crypto.py
```
