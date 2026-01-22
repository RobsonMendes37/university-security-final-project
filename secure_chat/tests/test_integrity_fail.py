import socket
import struct
import os
import sys
import time

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.security import SecurityManager
from core.protocol import pack_packet, unpack_header, get_aad, HEADER_SIZE

HOST = '127.0.0.1'
PORT = 8000
SERVER_ID = b'SERVER'

def run_tampering_attack():
    print("[*] Starting Integrity (Tampering) Attack Simulation...")
    client_id = b'TAMPERER'
    sm = SecurityManager()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
        
        # --- HANDSHAKE ---
        print("[*] Performing Handshake...")
        sk_c, pk_c_bytes = sm.generate_ecdh_keys()
        
        # Send Hello
        packet = pack_packet(os.urandom(12), client_id, SERVER_ID, 0, pk_c_bytes)
        sock.sendall(packet)
        
        # Recv Hello
        header_data = sock.recv(HEADER_SIZE)
        if not header_data: raise Exception("Conn Closed")
        _, _, _, _, payload_len = unpack_header(header_data)
        
        response_payload = b''
        while len(response_payload) < payload_len:
            response_payload += sock.recv(payload_len - len(response_payload))
            
        # Parse Salt/Key to be able to send encrypted data
        # We need to parse to get salt to derive keys
        # We also need to verify signature locally if we wanted to be a real client,
        # but here we just want keys.
        # However, if we want to be correct:
        offset = 0
        pk_s_len = struct.unpack("!I", response_payload[offset:offset+4])[0]
        offset += 4
        pk_s_bytes = response_payload[offset:offset+pk_s_len]
        offset += pk_s_len
        
        cert_len = struct.unpack("!I", response_payload[offset:offset+4])[0]
        offset += 4
        offset += cert_len # skip cert
        
        sig_len = struct.unpack("!I", response_payload[offset:offset+4])[0]
        offset += 4
        offset += sig_len # skip sig
        
        salt = response_payload[offset:offset+16]
        
        shared_secret = sm.compute_shared_secret(sk_c, pk_s_bytes)
        key_c2s, key_s2c = sm.derive_keys(shared_secret, salt)
        
        print("[+] Handshake Done.")
        
        # --- ATTACK ---
        print("[*] Generating Valid Packet...")
        seq = 1
        nonce = os.urandom(12)
        plaintext = b"Message to be tampered"
        recipient = b"VICTIM"
        
        dummy_header = pack_packet(nonce, client_id, recipient, seq, b'')
        aad = get_aad(dummy_header[:HEADER_SIZE])
        ciphertext = sm.encrypt_with_nonce(key_c2s, nonce, plaintext, aad)
        
        # TAMPERING
        print("[*] Tampering with ciphertext (flipping last bit)...")
        # Ciphertext is bytes (immutable), convert to bytearray
        tampered_cipher = bytearray(ciphertext)
        tampered_cipher[-1] ^= 0x01 # Flip last bit
        
        tampered_packet = pack_packet(nonce, client_id, recipient, seq, bytes(tampered_cipher))
        
        print("[*] Sending Tampered Packet (Should be rejected)...")
        sock.sendall(tampered_packet)
        
        # Check response
        sock.settimeout(2)
        try:
            data = sock.recv(1024)
            if not data:
                print("[SUCCESS] Server closed connection (EOF). Tampering Detected!")
            else:
                print("[?] Server sent data back. Check logs.")
        except socket.timeout:
             print("[?] Socket timeout. Server might have silently dropped it or kept alive.")
        except ConnectionResetError:
             print("[SUCCESS] Connection Reset by Server. Tampering Detected!")

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    run_tampering_attack()
