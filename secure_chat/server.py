import socket
import threading
import struct
import os
import time
from cryptography.hazmat.primitives import serialization
from core.security import SecurityManager
from core.protocol import pack_packet, unpack_header, get_aad, HEADER_SIZE

# Configuration
HOST = '0.0.0.0'
PORT = 8000
CERT_DIR = "certs"
SERVER_KEY_PATH = os.path.join(CERT_DIR, "server_key.pem")
SERVER_CERT_PATH = os.path.join(CERT_DIR, "server_cert.pem")
SERVER_ID = b'SERVER'

class SecureServer:
    def __init__(self):
        self.sm = SecurityManager()
        self.sessions = {} # {client_id: {conn, keys, counters, salt}}
        self.lock = threading.Lock()
        
        # Load PKI
        print("[*] Loading Server Identity...")
        with open(SERVER_KEY_PATH, "rb") as f:
            self.rsa_priv_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(SERVER_CERT_PATH, "rb") as f:
            self.cert_bytes = f.read()
            
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"[*] Server listening on {HOST}:{PORT}")
        
        while True:
            client_sock, addr = server.accept()
            print(f"[*] Accepted connection from {addr}")
            client_handler = threading.Thread(
                target=self.handle_client,
                args=(client_sock,)
            )
            client_handler.start()

    def handle_client(self, conn):
        client_id = None
        try:
            # --- HANDSHAKE START ---
            print(f"[{threading.current_thread().name}] Starting Handshake...")
            
            # 1. Receive Client Hello (Client ID + pk_C)
            # Expecting raw bytes or protocol packet? 
            # Let's use protocol packet with seq=0, unencrypted payload.
            # But client doesn't know RecipientID properly yet. 
            # Simple approach: Client sends length-prefixed raw data for handshake to avoid complexity of "unencrypted protocol packet".
            # Or better: Just Use Protocol Packet but payload is plaintext.
            
            # Read Header
            header_data = self.read_exact(conn, HEADER_SIZE)
            nonce, sender_id, recipient, seq, payload_len = unpack_header(header_data)
            client_id = sender_id.rstrip(b'\x00')
            
            # Read Payload (pk_C)
            pk_c_bytes = self.read_exact(conn, payload_len)
            
            print(f"[{client_id.decode()}] Received pk_C. Generating Server Keys...")
            
            # 2. Server Generates Ephemeral Keys & Salt
            sk_s, pk_s_bytes = self.sm.generate_ecdh_keys()
            salt = os.urandom(16)
            
            # 3. Compute Shared Secret & Derive Keys
            shared_secret = self.sm.compute_shared_secret(sk_s, pk_c_bytes)
            key_c2s, key_s2c = self.sm.derive_keys(shared_secret, salt)
            
            # 4. Sign Handshake (pk_S + client_id + salt + pk_C)
            # STRICT REQUIREMENT: "Transcript" implies we verify the Client's Hello too.
            signature = self.sm.sign_handshake(self.rsa_priv_key, pk_s_bytes + client_id + salt + pk_c_bytes)
            
            # 5. Send Server Hello (pk_S + cert + sig + salt)
            # We pack this into a response packet. 
            # Since connection is not yet "secure" technically, we assume this response is plaintext.
            # Format: [pk_S_len(4)][pk_S][cert_len(4)][cert][sig_len(4)][sig][salt(16)]
            # Construct payload
            handshake_payload = (
                struct.pack("!I", len(pk_s_bytes)) + pk_s_bytes +
                struct.pack("!I", len(self.cert_bytes)) + self.cert_bytes +
                struct.pack("!I", len(signature)) + signature +
                salt
            )
            
            # Send using protocol format (plaintext payload)
            # Seq 0
            response_packet = pack_packet(
                os.urandom(12), SERVER_ID, client_id, 0, handshake_payload
            )
            conn.sendall(response_packet)
            
            print(f"[{client_id.decode()}] Handshake Response Sent. Session Established.")
            
            # REGISTER SESSION
            with self.lock:
                self.sessions[client_id] = {
                    "conn": conn,
                    "keys": {"c2s": key_c2s, "s2c": key_s2c},
                    "counters": {"recv": 0, "send": 0},
                    "salt": salt
                }

            # --- MESSAGING LOOP ---
            while True:
                # Read Header
                header_data = self.read_exact(conn, HEADER_SIZE)
                nonce, sender, recipient, seq, payload_len = unpack_header(header_data)
                
                # Validation: Sender ID must match socket
                if sender.rstrip(b'\x00') != client_id:
                     print(f"[!] Warning: Spoofed Sender ID from {client_id}")
                     break

                # Read Encrypted Payload
                ciphertext = self.read_exact(conn, payload_len)
                
                # [TEST 3.1] CONFIDENTIALITY DEMO
                # Show that the data on the wire is illegible (bytes)
                print(f"[SNIFFER] Raw Encrypted Bytes from {client_id.decode()}: {ciphertext[:20]}...")

                # Get Session
                session = self.sessions.get(client_id)
                if not session: break
                
                # --- ANTI-REPLAY CHECK ---
                # Should be strictly greater than last received
                # For simplicty, let's say we expect seq > seq_recv
                # Initial seq_recv is 0. 
                # Note: Client should start seq at 1.
                if seq <= session['counters']['recv']:
                     print(f"[!] Replay/Old Packet Detected: {seq} <= {session['counters']['recv']}")
                     break
                session['counters']['recv'] = seq
                
                # Decrypt
                aad = header_data[12:52] # Sender|Recipient|Seq
                try:
                    plaintext = self.sm.decrypt(session['keys']['c2s'], nonce, ciphertext, aad)
                except Exception as e:
                    print(f"[!] Decryption Failed for {client_id}: {e}")
                    break
                
                print(f"[MSG] {client_id.decode()} -> {recipient.rstrip(b'\x00').decode()}: {len(plaintext)} bytes")
                
                # ROUTING
                dest_id = recipient.rstrip(b'\x00')
                dest_session = self.sessions.get(dest_id)
                
                if dest_session:
                    # Re-Encrypt for Destination
                    dest_conn = dest_session['conn']
                    dest_key = dest_session['keys']['s2c']
                    
                    # Increment Send Counter
                    dest_session['counters']['send'] += 1
                    new_seq = dest_session['counters']['send']
                    
                    new_nonce = os.urandom(12)
                    
                    # Construct packet to get AAD
                    # AAD = Sender(Original) | Recipient(Dest) | Seq(New)
                    # We need to construct the header to get the AAD.
                    # We want to preserve the Original Sender ID so the recipient knows who verified it.
                    # packet args: nonce, sender, recipient, seq, payload
                    
                    # Prepare AAD data virtually
                    # Pack packet helper builds the header.
                    # We can use that.
                    
                    # Encrypt
                    # We need to compute AAD before encrypting? No, we need AAD to encrypt.
                    # The AAD is the header bytes (Sender|Recipient|Seq).
                    # So we construct header first? But we need payload length.
                    # But payload length depends on ciphertext length (plaintext + 16).
                    # So: 
                    # 1. Calculate future payload length = len(plaintext) + 16.
                    # 2. Construct partial header or just the AAD bytes manually.
                    # AAD = sender (16) + recipient (16) + seq (8).
                    
                    # Use helper to ensure padding match
                    dummy_header = pack_packet(new_nonce, client_id, dest_id, new_seq, b'') # empty payload just to get header
                    # Actually pack_packet calculates struct.pack(... len=0)
                    # But get_aad operates on bytes 12:52. Those bytes are independent of payload len.
                    aad_for_dest = get_aad(dummy_header[:HEADER_SIZE])
                    
                    new_ciphertext = self.sm.encrypt_with_nonce(dest_key, new_nonce, plaintext, aad_for_dest)
                    
                    # Final Packet
                    packet_to_send = pack_packet(new_nonce, client_id, dest_id, new_seq, new_ciphertext)
                    
                    dest_conn.sendall(packet_to_send)
                else:
                    print(f"[!] Destination {dest_id} not found.")

        except Exception as e:
            print(f"[!] Error with {client_id}: {e}")
        finally:
            if client_id and client_id in self.sessions:
                del self.sessions[client_id]
            conn.close()
            print(f"[-] Connection closed for {client_id}")

    def read_exact(self, conn, n):
        data = b''
        while len(data) < n:
            packet = conn.recv(n - len(data))
            if not packet:
                raise ConnectionError("Connection closed unexpectedly")
            data += packet
        return data

if __name__ == "__main__":
    server = SecureServer()
    server.start()
