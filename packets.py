from enum import Enum
from scapy.all import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from fields import QuicVarLenField
from frames import PaddingFrame

from varint import VarInt

AES128_TAG_LENGTH = 16
QUIC1_INITIAL_SALT = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
CRYPTO_FRAME_EXAMPLE = """060041290100012503038df6a32f216764991e7c23959df309a561430025bd405afa27478f8fa0e41ebb
                        000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a13011302130301
                        0000d60000000c000a00000773657276657234000500050100000000000a000a0008001d001700180019
                        000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000
                        10000d000b0a68712d696e7465726f7000120000002b0003020304003300260024001d0020631003f771
                        b845987ff0e8e61c3a1a071b8e46b12c16a47a6802ee0f819365530039003c47db02a841050480080000
                        0604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c000e
                        01040f00200100"""

class QUIC_HEADER_TYPE(Enum):
    SHORT = 0
    LONG = 1

class QUIC_PACKET_TYPE(Enum):
    INITIAL = 0
    ZERORTT = 1
    HANDSHAKE = 2
    RETRY = 3

class QUIC(Packet):
    fields_desc = [
        # Flags
        BitEnumField("header_type", 1 , 1 , {0:"short", 1:"long"}) ,
        BitEnumField("fixed_bit", 1, 1, {0:"error", 1:"1"}) ,
        BitEnumField("type", 0, 2, {0:"initial", 1:"0-RTT", 2:"handshake", 3:"retry"}),
        BitField("reserved", 0, 2) ,
        BitFieldLenField("PNL", 0 , 2 , length_of ="PN", adjust = lambda pkt,x: x-1) ,
        XIntField("version", 0x1 ) ,
        # Connection IDs(DCID / SCID )
        BitFieldLenField("DCIL", None , 8, length_of ="DCID") ,
        StrLenField("DCID", b'', length_from = lambda pkt : pkt.DCIL) ,
        BitFieldLenField("SCIL", None , 8, length_of ="SCID") ,
        StrLenField("SCID", b'', length_from = lambda pkt : pkt.SCIL) ,
        # Token(only when type is initial)
        ConditionalField(QuicVarLenField("token_length", None , length_of ="token") ,
                            lambda pkt : pkt.version != 0 and pkt.type == 0) ,
        ConditionalField(StrLenField("token", b'', length_from = lambda pkt : pkt.token_length),
                            lambda pkt : pkt.version != 0 and pkt.type == 0),
        # Length(only when type is 0 - RTT or initial)
        ConditionalField(QuicVarLenField("length", None) ,
                           lambda pkt : pkt.version != 0 and pkt.type != 3) ,
        # Packet Number(only when type is 0 - RTT or initial)
        ConditionalField(StrLenField("PN", b'\x00', length_from = lambda pkt : pkt.PNL+1) ,
                            lambda pkt : pkt.version != 0 and pkt.type != 3)]
    
    @classmethod
    def initial(cls, DCID, SCID, desired_length : int = 1250, other_frames=b''):
        initial_salt = bytes.fromhex(QUIC1_INITIAL_SALT)
        initial_secret = TLS13_HKDF().extract(initial_salt, DCID)

        client_initial_secret = TLS13_HKDF().expand_label(initial_secret, b"client in", b"", 32)
        server_initial_secret = TLS13_HKDF().expand_label(initial_secret,b"server in", b"", 32)
                                            
        key = TLS13_HKDF().expand_label(client_initial_secret, b"quic key", b"",16)
        iv = TLS13_HKDF().expand_label(client_initial_secret, b"quic iv", b"", 12)
        hp = TLS13_HKDF().expand_label(client_initial_secret, b"quic hp", b"",16)

        # Calculate protected crypto frame and header length to decide on padding length
        header_len = len(cls(DCID=DCID, SCID=SCID))

        crypto_frame = bytes.fromhex(CRYPTO_FRAME_EXAMPLE)
        crypto_len = len(crypto_frame)
        final_crypto_len = crypto_len + AES128_TAG_LENGTH

        padding_len = desired_length - header_len - final_crypto_len
        padding = bytes(PaddingFrame())*padding_len

        payload = crypto_frame + padding
        # Update length field manually
        quic_packet_header = cls(header_type = QUIC_HEADER_TYPE.LONG.value , type = QUIC_PACKET_TYPE.INITIAL.value,
                                    DCID = DCID, SCID = SCID)
        length_field = final_crypto_len + padding_len + quic_packet_header.PNL + 1
        quic_packet_header.length = VarInt(length_field).encode()

        quic_packet = quic_packet_header / payload

        # Encrypt whole packet
        encrypted_quic_packet = QUIC.protect((key,iv,hp), quic_packet)   

        return QUIC(encrypted_quic_packet)
        
    def protect(material , packet):
        (key, iv, hp) = material
        header = packet.copy()
        header.payload = Raw()
        payload = packet[1]
        raw_header = raw(header)
        # Compute nonce
        nonce = int.from_bytes(iv , byteorder = 'big') ^ int.from_bytes(header.PN, byteorder = 'big')
        nonce = nonce.to_bytes(12, byteorder = 'big')
        # Encrypt the payload
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend = default_backend()).encryptor()
        encryptor.authenticate_additional_data(raw_header)
        encrypted_payload = encryptor.update(raw(payload)) + encryptor.finalize() + encryptor.tag
        # Extract the sample
        PNL = header.PNL + 1

        sample_start = 4 - PNL # The receiver will assume PNL is 4
        sample = encrypted_payload[sample_start : sample_start + 16]

        # Compute the mask
        encryptor = Cipher(algorithms.AES(hp) , modes.ECB(), backend = default_backend()).encryptor()
        mask = encryptor.update(sample) + encryptor.finalize()

        # Encrypt the flags and the PN
        encrypted_header = bytearray(raw_header)

        # The least significant bits of the first byte of the packet are masked(packet number length)
        # by the least significant bits of the first mask byte, and the packet number is masked with the remaining bytes.
        for i in range(PNL):
            encrypted_header[-PNL + i] ^= mask[i+1]

        # adjust length based on new payload
        # disabled for now...
        #encrypted_header = bytes(encrypted_header)
        #encrypted_header = QUIC(encrypted_header).set_length(encrypted_header,encrypted_payload)
        #encrypted_header = bytearray(encrypted_header)

        # mask PNL
        encrypted_header[0] ^= (mask[0] & 0x0f)
        return bytes(encrypted_header) + encrypted_payload

    def get_length(self, pkt):
        #_, length_field_size = VarInt().decode(self.length)
        #calculate offset
        pn_offset = 7 + len(self.DCID) + max(1,len(self.SCID)) + 2
        #if packet_type == Initial:
        pn_offset +=  len(self.token)
        length_size = pkt[pn_offset] >> 6
        length_size = int(math.pow(2,length_size))
        length = pkt[pn_offset:pn_offset+length_size]
        return length, length_size , pn_offset

    def set_length(self, pkt, pay):
        #pkt += pay  # if you also want the payload to be taken into account
        _ ,length_field_size, offset = self.get_length(pkt)
        if self.length is None:
            length_field_size = 0
        pkt_len = len(pay)
        tmp_len = self.PNL + 1 + pkt_len
        encoded_len = VarInt(tmp_len).encode()
        # Adds length before PN field
        #pkt = pkt[:offset] + encoded_len + pkt[offset+length_field_size:] 
        #pkt =  pkt[:-(self.PNL+2+length_field_size)] + encoded_len + pkt[-(self.PNL+1):] 
        return pkt

    def post_build(self, pkt, pay):
        return self.set_length(pkt, pay) + pay

    def encode_packet_number(full_pn, largest_acked=None):
        # The number of bits must be at least one more
        # than the base-2 logarithm of the number of contiguous
        # unacknowledged packet numbers, including the new packet.
        if largest_acked is None or largest_acked == 0:
            num_unacked = full_pn + 1
        else:
            num_unacked = full_pn - largest_acked

        min_bits = math.log(num_unacked, 2) + 1
        num_bytes = math.ceil(min_bits / 8)

        # Encode the integer value and truncate to
        # the num_bytes least significant bytes.
        return full_pn.to_bytes(num_bytes,'big')