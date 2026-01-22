import socket
import threading
import sys
import os
import struct
from core.security import SecurityManager
from core.protocol import pack_packet, unpack_header, get_aad, HEADER_SIZE

# Configuracao
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
            
            # Iniciar Thread de Escuta
            threading.Thread(target=self.listen_loop, daemon=True).start()
            
            # Loop de Entrada
            self.input_loop()
        except KeyboardInterrupt:
            print("\n[-] Saindo...")
        except Exception as e:
            print(f"[-] Erro: {e}")
        finally:
            self.conn.close()

    def perform_handshake(self):
        print("[*] Iniciando Handshake...")
        
        # 1. Gerar Chaves Efemeras do Cliente
        sk_c, pk_c_bytes = self.sm.generate_ecdh_keys()
        
        # 2. Enviar Client Hello (ID do Cliente + pk_C)
        # Usando pacote do protocolo mas payload em texto claro
        payload = pk_c_bytes # apenas a chave
        packet = pack_packet(
            os.urandom(12), self.client_id, SERVER_ID, 0, payload
        )
        self.conn.sendall(packet)
        
        # 3. Receber Server Hello
        # Formato: Cabecalho + [pk_S_len][pk_S][cert_len][cert][sig_len][sig][salt]
        header_data = self.read_exact(HEADER_SIZE)
        nonce, sender, recipient, seq, payload_len = unpack_header(header_data)
        
        response_payload = self.read_exact(payload_len)
        
        # Desempacotar Payload
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
        
        salt = response_payload[offset:offset+16] # Salt tem 16 bytes
        
        # 4. Verificar Assinatura
        # Dados = pk_S || client_id || salt || pk_C
        # Devemos verificar que o servidor assinou NOSSA chave publica (Integridade do Transcript)
        data_to_verify = pk_s_bytes + self.client_id + salt + pk_c_bytes
        if not self.sm.verify_handshake(cert_bytes, signature, data_to_verify):
            raise Exception("Verificacao de Assinatura do Servidor Falhou! Potencial MitM.")
        print("[+] Assinatura do Servidor Verificada.")
        
        # 5. Derivar Chaves
        shared_secret = self.sm.compute_shared_secret(sk_c, pk_s_bytes)
        key_c2s, key_s2c = self.sm.derive_keys(shared_secret, salt)
        self.keys = {"c2s": key_c2s, "s2c": key_s2c}
        self.salt = salt
        print("[+] Handshake Completo. Canal Seguro Estabelecido.")
        print("Uso: @destinatario mensagem")

    def input_loop(self):
        while True:
            msg = input(f"[{self.client_id.decode()}] > ")
            if not msg: continue
            
            if msg.startswith("@"):
                try:
                    target, text = msg.split(" ", 1)
                    recipient_id = target[1:].encode() # remover @
                    
                    self.send_message(recipient_id, text.encode())
                except ValueError:
                    print("[!] Formato invalido. Use: @destinatario mensagem")
            else:
                 print("[!] Formato invalido. Use: @destinatario mensagem")

    def send_message(self, recipient_id, plaintext):
        self.counters['send'] += 1
        seq_no = self.counters['send']
        nonce = os.urandom(12)
        
        # Construir Cabecalho Dummy para obter AAD
        dummy_header = pack_packet(nonce, self.client_id, recipient_id, seq_no, b'')
        aad = get_aad(dummy_header[:HEADER_SIZE])
        
        # Cifrar
        ciphertext = self.sm.encrypt_with_nonce(self.keys['c2s'], nonce, plaintext, aad)
        
        # Empacotar
        packet = pack_packet(nonce, self.client_id, recipient_id, seq_no, ciphertext)
        self.conn.sendall(packet)

    def listen_loop(self):
        while True:
            try:
                header_data = self.read_exact(HEADER_SIZE)
                nonce, sender, recipient, seq, payload_len = unpack_header(header_data)
                
                ciphertext = self.read_exact(payload_len)
                
                # Decifrar
                aad = header_data[12:52] 
                plaintext = self.sm.decrypt(self.keys['s2c'], nonce, ciphertext, aad)
                
                print(f"\n[NOVA MSG] {sender.rstrip(b'\x00').decode()}: {plaintext.decode()}")
                print(f"[{self.client_id.decode()}] > ", end='', flush=True)
                
            except Exception as e:
                print(f"\n[!] Erro de Conexao: {e}")
                os._exit(1)

    def read_exact(self, n):
        data = b''
        while len(data) < n:
            packet = self.conn.recv(n - len(data))
            if not packet:
                raise ConnectionError("Conexao fechada")
            data += packet
        return data

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python client.py <client_id>")
        sys.exit(1)
        
    client = SecureClient(sys.argv[1])
    client.start()
