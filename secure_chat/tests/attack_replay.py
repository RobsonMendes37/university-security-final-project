import socket
# Atualizado para alinhar com as mudancas de assinatura do servidor (implicito)
import struct
import os
import time
import sys
# Adicionar diretorio pai ao path para importar core
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.security import SecurityManager
from core.protocol import pack_packet, unpack_header, get_aad, HEADER_SIZE

HOST = '127.0.0.1'
PORT = 8000
SERVER_ID = b'SERVER'

def run_attack():
    print("[*] Iniciando Simulacao de Ataque de Replay...")
    client_id = b'ATACANTE'
    sm = SecurityManager()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
        
        # --- HANDSHAKE ---
        print("[*] Realizando Handshake...")
        sk_c, pk_c_bytes = sm.generate_ecdh_keys()
        
        # Enviar Hello
        packet = pack_packet(os.urandom(12), client_id, SERVER_ID, 0, pk_c_bytes)
        sock.sendall(packet)
        
        # Receber Hello
        header_data = sock.recv(HEADER_SIZE)
        if not header_data: raise Exception("Conexao Fechada")
        _, _, _, _, payload_len = unpack_header(header_data)
        
        response_payload = b''
        while len(response_payload) < payload_len:
            response_payload += sock.recv(payload_len - len(response_payload))
            
        # Parse Salt/Key (Simplificado: assumimos que funciona se chegamos aqui)
        offset = 0
        pk_s_len = struct.unpack("!I", response_payload[offset:offset+4])[0]
        offset += 4
        pk_s_bytes = response_payload[offset:offset+pk_s_len]
        offset += pk_s_len
        
        cert_len = struct.unpack("!I", response_payload[offset:offset+4])[0]
        offset += 4
        # Pular cert
        offset += cert_len
        
        sig_len = struct.unpack("!I", response_payload[offset:offset+4])[0]
        offset += 4
        # Pular sig
        offset += sig_len
        
        salt = response_payload[offset:offset+16]
        
        shared_secret = sm.compute_shared_secret(sk_c, pk_s_bytes)
        key_c2s, key_s2c = sm.derive_keys(shared_secret, salt)
        
        print("[+] Handshake Feito. Chaves Derivadas.")
        
        # --- ATAQUE ---
        print("[*] Gerando Pacote Valido (Seq 1)...")
        seq = 1
        nonce = os.urandom(12)
        plaintext = b"Esta eh uma mensagem valida"
        recipient = b"VITIMA"
        
        dummy_header = pack_packet(nonce, client_id, recipient, seq, b'')
        aad = get_aad(dummy_header[:HEADER_SIZE])
        ciphertext = sm.encrypt_with_nonce(key_c2s, nonce, plaintext, aad)
        
        valid_packet = pack_packet(nonce, client_id, recipient, seq, ciphertext)
        
        print("[*] Enviando Pacote PRIMEIRA VEZ (Deve funcionar)...")
        sock.sendall(valid_packet)
        
        time.sleep(1) 
        
        print("[*] Enviando Pacote SEGUNDA VEZ (REPLAY) (Deve ser rejeitado)...")
        try:
            sock.sendall(valid_packet)
            
            # Tentar ler resposta ou verificar se fechou
            sock.settimeout(2)
            data = sock.recv(1024)
            if not data:
                print("[SUCESSO] Servidor fechou a conexao (EOF). Ataque Mitigado!")
            else:
                 print("[?] Servidor enviou dados de volta. Verifique logs.")
        except socket.timeout:
             print("[?] Timeout do socket. Servidor pode ter descartado silenciosamente.")
        except ConnectionResetError:
             print("[SUCESSO] Conexao Reiniciada pelo Servidor. Ataque Mitigado!")
        
    except Exception as e:
        print(f"[!] Erro: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    run_attack()
