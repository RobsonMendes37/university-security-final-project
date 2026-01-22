import socket
import threading
import struct
import os
import time
from cryptography.hazmat.primitives import serialization
from core.security import SecurityManager
from core.protocol import pack_packet, unpack_header, get_aad, HEADER_SIZE

# Configuracao
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
        
        # Carregar PKI
        print("[*] Carregando Identidade do Servidor...")
        with open(SERVER_KEY_PATH, "rb") as f:
            self.rsa_priv_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(SERVER_CERT_PATH, "rb") as f:
            self.cert_bytes = f.read()
            
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"[*] Servidor escutando em {HOST}:{PORT}")
        
        while True:
            client_sock, addr = server.accept()
            print(f"[*] Conexao aceita de {addr}")
            client_handler = threading.Thread(
                target=self.handle_client,
                args=(client_sock,)
            )
            client_handler.start()

    def handle_client(self, conn):
        client_id = None
        try:
            # --- INICIO DO HANDSHAKE ---
            print(f"[{threading.current_thread().name}] Iniciando Handshake...")
            
            # 1. Receber Client Hello (ID do Cliente + pk_C)
            # Ler Cabecalho
            header_data = self.read_exact(conn, HEADER_SIZE)
            nonce, sender_id, recipient, seq, payload_len = unpack_header(header_data)
            client_id = sender_id.rstrip(b'\x00')
            
            # Ler Payload (pk_C)
            pk_c_bytes = self.read_exact(conn, payload_len)
            
            print(f"[{client_id.decode()}] Recebido pk_C. Gerando Chaves do Servidor...")
            
            # 2. Servidor Gera Chaves Efemeras & Salt
            sk_s, pk_s_bytes = self.sm.generate_ecdh_keys()
            salt = os.urandom(16)
            
            # 3. Calcular Segredo Compartilhado & Derivar Chaves
            shared_secret = self.sm.compute_shared_secret(sk_s, pk_c_bytes)
            key_c2s, key_s2c = self.sm.derive_keys(shared_secret, salt)
            
            # 4. Assinar Handshake (pk_S + client_id + salt + pk_C)
            # REQUISITO ESTRITO: "Transcript" implica que verificamos o Hello do Cliente tambem.
            signature = self.sm.sign_handshake(self.rsa_priv_key, pk_s_bytes + client_id + salt + pk_c_bytes)
            
            # 5. Enviar Server Hello (pk_S + cert + sig + salt)
            # Formato: [pk_S_len(4)][pk_S][cert_len(4)][cert][sig_len(4)][sig][salt(16)]
            # Construir payload
            handshake_payload = (
                struct.pack("!I", len(pk_s_bytes)) + pk_s_bytes +
                struct.pack("!I", len(self.cert_bytes)) + self.cert_bytes +
                struct.pack("!I", len(signature)) + signature +
                salt
            )
            
            # Enviar usando formato do protocolo (payload em texto claro)
            # Seq 0
            response_packet = pack_packet(
                os.urandom(12), SERVER_ID, client_id, 0, handshake_payload
            )
            conn.sendall(response_packet)
            
            print(f"[{client_id.decode()}] Resposta de Handshake Enviada. Sessao Estabelecida.")
            
            # REGISTRAR SESSAO
            with self.lock:
                self.sessions[client_id] = {
                    "conn": conn,
                    "keys": {"c2s": key_c2s, "s2c": key_s2c},
                    "counters": {"recv": 0, "send": 0},
                    "salt": salt
                }

            # --- LOOP DE MENSAGENS ---
            while True:
                # Ler Cabecalho
                header_data = self.read_exact(conn, HEADER_SIZE)
                nonce, sender, recipient, seq, payload_len = unpack_header(header_data)
                
                # Validacao: Sender ID deve corresponder ao socket
                if sender.rstrip(b'\x00') != client_id:
                     print(f"[!] Aviso: Sender ID falsificado de {client_id}")
                     break

                # Ler Payload Cifrado
                ciphertext = self.read_exact(conn, payload_len)
                
                # [TESTE 3.1] DEMONSTRACAO DE CONFIDENCIALIDADE
                # Mostrar que os dados no fio sao ilegiveis (bytes)
                print(f"[SNIFFER] Bytes Brutos Cifrados de {client_id.decode()}: {ciphertext[:20]}...")

                # Obter Sessao
                session = self.sessions.get(client_id)
                if not session: break
                
                # --- VERIFICACAO ANTI-REPLAY ---
                # Deve ser estritamente maior que o ultimo recebido
                if seq <= session['counters']['recv']:
                     print(f"[!] Replay/Pacote Antigo Detectado: {seq} <= {session['counters']['recv']}")
                     break
                session['counters']['recv'] = seq
                
                # Decifrar
                aad = header_data[12:52] # Sender|Recipient|Seq
                try:
                    plaintext = self.sm.decrypt(session['keys']['c2s'], nonce, ciphertext, aad)
                except Exception as e:
                    print(f"[!] Falha na Decifracao para {client_id}: {e}")
                    break
                
                print(f"[MSG] {client_id.decode()} -> {recipient.rstrip(b'\x00').decode()}: {len(plaintext)} bytes")
                
                # ROTEAMENTO
                dest_id = recipient.rstrip(b'\x00')
                dest_session = self.sessions.get(dest_id)
                
                if dest_session:
                    # Re-Cifrar para o Destino
                    dest_conn = dest_session['conn']
                    dest_key = dest_session['keys']['s2c']
                    
                    # Incrementar Contador de Envio
                    dest_session['counters']['send'] += 1
                    new_seq = dest_session['counters']['send']
                    
                    new_nonce = os.urandom(12)
                    
                    # Construir cabecalho dummy para obter AAD
                    dummy_header = pack_packet(new_nonce, client_id, dest_id, new_seq, b'') 
                    aad_for_dest = get_aad(dummy_header[:HEADER_SIZE])
                    
                    new_ciphertext = self.sm.encrypt_with_nonce(dest_key, new_nonce, plaintext, aad_for_dest)
                    
                    # Pacote Final
                    packet_to_send = pack_packet(new_nonce, client_id, dest_id, new_seq, new_ciphertext)
                    
                    dest_conn.sendall(packet_to_send)
                else:
                    print(f"[!] Destino {dest_id} nao encontrado.")

        except Exception as e:
            print(f"[!] Erro com {client_id}: {e}")
        finally:
            if client_id and client_id in self.sessions:
                del self.sessions[client_id]
            conn.close()
            print(f"[-] Conexao fechada para {client_id}")

    def read_exact(self, conn, n):
        data = b''
        while len(data) < n:
            packet = conn.recv(n - len(data))
            if not packet:
                raise ConnectionError("Conexao fechada inesperadamente")
            data += packet
        return data

if __name__ == "__main__":
    server = SecureServer()
    server.start()
