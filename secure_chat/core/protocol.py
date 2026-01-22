import struct

# Constantes do Protocolo
HEADER_FORMAT = "!12s16s16sQI" # Big-endian: Nonce(12), Reciever(16), Destinatario(16), Seq(8), Len(4)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT) # Deve ser 12+16+16+8+4 = 56 bytes

def pack_packet(nonce, sender_id, recipient_id, seq_no, payload):
    """
    Empacota um pacote do protocolo.
    
    Args:
        nonce (bytes): 12 bytes
        sender_id (bytes): 16 bytes (com padding se necessario)
        recipient_id (bytes): 16 bytes (com padding se necessario)
        seq_no (int): Inteiro sem sinal de 8 bytes
        payload (bytes): tamanho variavel
        
    Returns:
        bytes: Pacote empacotado (Cabecalho + Payload)
    """
    # Garante que o comprimento do ID esta correto
    if len(sender_id) > 16:
        sender_id = sender_id[:16]
    else:
        sender_id = sender_id.ljust(16, b'\x00')
        
    if len(recipient_id) > 16:
        recipient_id = recipient_id[:16]
    else:
        recipient_id = recipient_id.ljust(16, b'\x00')

    payload_len = len(payload)
    
    header = struct.pack(HEADER_FORMAT, nonce, sender_id, recipient_id, seq_no, payload_len)
    return header + payload

def unpack_header(data):
    """
    Desempacota o cabecalho dos primeiros HEADER_SIZE bytes.
    
    Args:
        data (bytes): Deve ter pelo menos HEADER_SIZE bytes.
        
    Returns:
        tuple: (nonce, sender_id, recipient_id, seq_no, payload_len)
    """
    if len(data) < HEADER_SIZE:
        raise ValueError("Dados muito curtos para o cabecalho")
        
    nonce, sender_id, recipient_id, seq_no, payload_len = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    
    # Remove padding dos IDs (opcional, mas bom para limpeza)
    sender_id = sender_id.rstrip(b'\x00')
    recipient_id = recipient_id.rstrip(b'\x00')
    
    return nonce, sender_id, recipient_id, seq_no, payload_len

def get_aad(header_bytes):
    """
    Extrai AAD (Dados Associados Autenticados) dos bytes do cabecalho.
    AAD = SenderID | RecipientID | SeqNo
    Isso deve corresponder exatamente ao que o `encrypt` usa.
    
    Como temos os bytes completos do cabecalho, e a estrutura e':
    [Nonce 12s] [Sender 16s] [Recipient 16s] [Seq Q] [Len I]
    
    Queremos os bytes correspondentes ao Remetente, Destinatario, Seq.
    Isso corresponde aos bytes 12 ate 12+16+16+8 = 52.
    Slice: header[12 : 12+16+16+8] -> header[12:52]
    """
    if len(header_bytes) < HEADER_SIZE:
         raise ValueError("Bytes do cabecalho muito curtos")
    return header_bytes[12:52] 
