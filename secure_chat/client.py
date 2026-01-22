import socket
import threading
import sys
import os
import struct
from core.security import SecurityManager
from core.protocol import pack_packet, unpack_header, get_aad, HEADER_SIZE

# Configuration
HOST = '127.0.0.1'
PORT = 8000
SERVER_ID = b'SERVER'

class SecureClient:
    def __init__(self, client_id):
        self.client_id = client_id.encode()
        self.sm = SecurityManager()
        self.conn = None
        self.keys = {} # c2s, s2c
        self.counters = {"recv": 0, "send": 0}
        self.salt = None
        
    def start(self):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.conn.connect((HOST, PORT))
            self.perform_handshake()
            
            # Start Listen Thread
            threading.Thread(target=self.listen_loop, daemon=True).start()
            
            # Input Loop
            self.input_loop()
        except KeyboardInterrupt:
            print("\n[-] Exiting...")
        except Exception as e:
            print(f"[-] Error: {e}")
        finally:
            self.conn.close()

    def perform_handshake(self):
        print("[*] Starting Handshake...")
        
        # 1. Generate Client Ephemeral Keys
        sk_c, pk_c_bytes = self.sm.generate_ecdh_keys()
        
        # 2. Send Client Hello (Client ID + pk_C)
        # Using protocol pack but payload is plaintext
        payload = pk_c_bytes # just the key
        packet = pack_packet(
            os.urandom(12), self.client_id, SERVER_ID, 0, payload
        )
        self.conn.sendall(packet)
        
        # 3. Receive Server Hello
        # Format: Header + [pk_S_len][pk_S][cert_len][cert][sig_len][sig][salt]
        header_data = self.read_exact(HEADER_SIZE)
        nonce, sender, recipient, seq, payload_len = unpack_header(header_data)
        
        response_payload = self.read_exact(payload_len)
        
        # Unpack Payload
        offset = 0
        pk_s_len = struct.unpack("!I", response_payload[offset:offset+4])[0]
        offset += 4
        pk_s_bytes = response_payload[offset:offset+pk_s_len]
        offset += pk_s_len
        
        cert_len = struct.unpack("!I", response_payload[offset:offset+4])[0]
        offset += 4
        cert_bytes = response_payload[offset:offset+cert_len]
        offset += cert_len
        
        sig_len = struct.unpack("!I", response_payload[offset:offset+4])[0]
        offset += 4
        signature = response_payload[offset:offset+sig_len]
        offset += sig_len
        
        salt = response_payload[offset:offset+16] # Salt is 16 bytes
        
        # 4. Verify Signature
        # Data = pk_S || client_id || salt || pk_C
        # We must verify that the server signed OUR public key (Transcript integrity)
        data_to_verify = pk_s_bytes + self.client_id + salt + pk_c_bytes
        if not self.sm.verify_handshake(cert_bytes, signature, data_to_verify):
            raise Exception("Server Signature Verification Failed! Potential MitM.")
        print("[+] Server Signature Verified.")
        
        # 5. Derive Keys
        shared_secret = self.sm.compute_shared_secret(sk_c, pk_s_bytes)
        key_c2s, key_s2c = self.sm.derive_keys(shared_secret, salt)
        self.keys = {"c2s": key_c2s, "s2c": key_s2c}
        self.salt = salt
        print("[+] Handshake Complete. Secure Channel Established.")
        print("Usage: @recipient message")

    def input_loop(self):
        while True:
            msg = input(f"[{self.client_id.decode()}] > ")
            if not msg: continue
            
            if msg.startswith("@"):
                try:
                    target, text = msg.split(" ", 1)
                    recipient_id = target[1:].encode() # remove @
                    
                    self.send_message(recipient_id, text.encode())
                except ValueError:
                    print("[!] Invalid format. Use: @recipient message")
            else:
                 print("[!] Invalid format. Use: @recipient message")

    def send_message(self, recipient_id, plaintext):
        self.counters['send'] += 1
        seq_no = self.counters['send']
        nonce = os.urandom(12)
        
        # Construct Dummy Header to get AAD
        # pack_packet ensures padding matches
        dummy_header = pack_packet(nonce, self.client_id, recipient_id, seq_no, b'')
        aad = get_aad(dummy_header[:HEADER_SIZE])
        
        # Encrypt
        ciphertext = self.sm.encrypt_with_nonce(self.keys['c2s'], nonce, plaintext, aad)
        
        # Pack
        packet = pack_packet(nonce, self.client_id, recipient_id, seq_no, ciphertext)
        self.conn.sendall(packet)

    def listen_loop(self):
        while True:
            try:
                header_data = self.read_exact(HEADER_SIZE)
                nonce, sender, recipient, seq, payload_len = unpack_header(header_data)
                
                ciphertext = self.read_exact(payload_len)
                
                # Decrypt
                aad = header_data[12:52] 
                plaintext = self.sm.decrypt(self.keys['s2c'], nonce, ciphertext, aad)
                
                print(f"\n[NEW MSG] {sender.rstrip(b'\x00').decode()}: {plaintext.decode()}")
                print(f"[{self.client_id.decode()}] > ", end='', flush=True)
                
            except Exception as e:
                print(f"\n[!] Connection Error: {e}")
                os._exit(1)

    def read_exact(self, n):
        data = b''
        while len(data) < n:
            packet = self.conn.recv(n - len(data))
            if not packet:
                raise ConnectionError("Connection closed")
            data += packet
        return data

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python client.py <client_id>")
        sys.exit(1)
        
    client = SecureClient(sys.argv[1])
    client.start()
