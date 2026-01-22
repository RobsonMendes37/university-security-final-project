import threading
import time
import sys
import os

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import SecureServer
from client import SecureClient
import socket

def run_server():
    print("[DEMO] Starting Server...")
    s = SecureServer()
    s.start()

def run_client_alice():
    print("[DEMO] Starting Alice...")
    client = SecureClient("Alice")
    # Manually doing what start() does but without blocking input_loop
    client.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.conn.connect(('127.0.0.1', 8000))
    client.perform_handshake()
    
    # Start receiving
    t = threading.Thread(target=client.listen_loop, daemon=True)
    t.start()
    return client

def run_client_bob():
    print("[DEMO] Starting Bob...")
    client = SecureClient("Bob")
    client.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.conn.connect(('127.0.0.1', 8000))
    client.perform_handshake()
    
    t = threading.Thread(target=client.listen_loop, daemon=True)
    t.start()
    return client

if __name__ == "__main__":
    # 1. Start Server in Thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1) # Wait for server
    
    # 2. Start Alice
    alice = run_client_alice()
    time.sleep(0.5)

    # 3. Start Bob
    bob = run_client_bob()
    time.sleep(1)

    # 4. Exchange Messages
    print("\n[DEMO] Alice sending message to Bob...")
    alice.send_message(b"Bob", b"Ola Bob! Mensagem Segura aqui.")
    
    time.sleep(1)
    
    print("\n[DEMO] Bob replying to Alice...")
    bob.send_message(b"Alice", b"Oi Alice! Recebi sua mensagem criptografada.")
    
    time.sleep(2)
    print("\n[DEMO] Demonstration Complete.")
