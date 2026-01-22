import struct

# Protocol Constants
HEADER_FORMAT = "!12s16s16sQI" # Big-endian: Nonce(12), Sender(16), Recipient(16), Seq(8), Len(4)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT) # Should be 12+16+16+8+4 = 56 bytes

def pack_packet(nonce, sender_id, recipient_id, seq_no, payload):
    """
    Packs a protocol packet.
    
    Args:
        nonce (bytes): 12 bytes
        sender_id (bytes): 16 bytes (padded if necessary)
        recipient_id (bytes): 16 bytes (padded if necessary)
        seq_no (int): 8 bytes unsigned int
        payload (bytes): variable length
        
    Returns:
        bytes: Packed packet (Header + Payload)
    """
    # Ensure ID length is correct
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
    Unpacks the header from the first HEADER_SIZE bytes.
    
    Args:
        data (bytes): Must be at least HEADER_SIZE bytes long.
        
    Returns:
        tuple: (nonce, sender_id, recipient_id, seq_no, payload_len)
    """
    if len(data) < HEADER_SIZE:
        raise ValueError("Data too short for header")
        
    nonce, sender_id, recipient_id, seq_no, payload_len = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    
    # Strip padding from IDs (optional, but good for cleanliness)
    sender_id = sender_id.rstrip(b'\x00')
    recipient_id = recipient_id.rstrip(b'\x00')
    
    return nonce, sender_id, recipient_id, seq_no, payload_len

def get_aad(header_bytes):
    """
    Extracts AAD (Associated Authenticated Data) from the header bytes.
    AAD = SenderID | RecipientID | SeqNo
    This must match exactly what `encrypt` uses.
    
    Since we have the full header bytes, and the layout is:
    [Nonce 12s] [Sender 16s] [Recipient 16s] [Seq Q] [Len I]
    
    We want bytes corresponding to Sender, Recipient, Seq.
    That corresponds to bytes 12 to 12+16+16+8 = 52.
    It's easier to just reconstruct it or slice it.
    Slice: header[12 : 12+16+16+8] -> header[12:52]
    """
    if len(header_bytes) < HEADER_SIZE:
         raise ValueError("Header bytes too short")
    return header_bytes[12:52] 
