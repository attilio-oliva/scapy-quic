from scapy.all import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class QuicVarLenField(Field):
    __slots__ = ["fld"]
    length = 0

    def __init__(self, name, default, length_of):
        Field.__init__(self, name, default)
        self.fld = length_of

    def i2m(self, pkt, x):
        if x is None:
            f = pkt.get_field(self.fld)
            x = f.i2len(pkt, pkt.getfieldval(self.fld))
            x = vlenq2str(x)
        return raw(x)

    def m2i(self, pkt, x):
        if s is None:
            return None, 0
        return str2vlenq(x)[1]

    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)

    def getfield(self, pkt, s):
        return str2vlenq(s)

class QUIC(Packet):
    fields_desc = [
        # Flags
        BitEnumField("header_type", 1 , 1 , {0:"short", 1:"long"}) ,
        BitEnumField("fixed_bit", 1, 1, {0:"error", 1:"1"}) ,
        BitEnumField("type", 0, 2, {0:"initial", 1:"0- RTT", 2:"handshake", 3:"retry"}),
        BitField("reserved", 0, 2) ,
        BitFieldLenField("PNL", None , 2 , length_of ="PN", adjust = lambda pkt,x: x-1) ,
        # Version
        XIntField("version", 0x0 ) ,
        # Connection IDs(DCID / SCID )
        BitFieldLenField("DCIL", None , 8, length_of ="DCID") ,
        StrLenField("DCID", b'', length_from = lambda pkt : pkt.DCIL ) ,
        BitFieldLenField("SCIL", None , 8, length_of ="SCID") ,
        StrLenField("SCID", b'', length_from = lambda pkt : pkt.SCIL ) ,
        # Token(only when type is initial )
        ConditionalField(QuicVarLenField("token_length", None , length_of ="token") ,
                            lambda pkt : pkt.version != 0 and pkt.type == 0) ,
        ConditionalField(StrLenField("token", b'', length_from = lambda pkt : pkt.token_length ),
                            lambda pkt : pkt.version != 0 and pkt.type == 0),
        # Length(only when type is 0 - RTT or initial )
        #ConditionalField(QuicVarLenField("length", None ) ,
        #                   lambda pkt : pkt.version != 0 and pkt.type != 3) ,
        # Packet Number(only when type is 0 - RTT or initial )
        ConditionalField(StrLenField("PN", b'\x00', length_from = lambda pkt : pkt.PNL+1) ,
                            lambda pkt : pkt.version != 0 and pkt.type != 3) ]

    def protect(material , packet):
        (key, iv, hp) = material
        header = packet.copy()
        header.payload = Raw()
        payload = packet[1]
        # Compute nonce
        nonce = int.from_bytes(iv , byteorder = 'big') ^ int.from_bytes(header.PN , byteorder = 'big')
        nonce = nonce.to_bytes(12, byteorder = 'big')
        # Encrypt the payload
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend = default_backend()).encryptor()
        encryptor.authenticate_additional_data(raw(header))
        encrypted_payload = encryptor.update(raw(payload)) + encryptor.finalize() + encryptor.tag
        # Extract the sample
        PNL = header.PNL + 1
        sample_start = 4 - PNL # The receiver will assume PNL is 4
        sample = encrypted_payload [ sample_start : sample_start + 16]
        # Compute the mask
        encryptor = Cipher(algorithms.AES(hp) , modes.ECB(), backend = default_backend()).encryptor()
        mask = encryptor.update(sample) + encryptor.finalize()
        # Encrypt the flags and the PN
        encrypted_header = bytearray(raw(header))
        encrypted_header [0] ^= (mask [0] & 0x0f)
        for i in range(PNL):
            encrypted_header[-PNL + i] ^= mask[i+1]
        encrypted_header = bytes(encrypted_header)
        return encrypted_header + encrypted_payload



def vlenq2str(l):
    s = []
    s.append(l & 0x7F)
    l = l >> 7
    while l > 0:
        s.append( 0x80 | (l & 0x7F) )
        l = l >> 7
    s.reverse()
    return bytes(bytearray(s))

def str2vlenq(s=b""):
    i = l = 0
    while i < len(s) and ord(s[i:i+1]) & 0x80:
        l = l << 7
        l = l + (ord(s[i:i+1]) & 0x7F)
        i = i + 1
    if i == len(s):
        warning("Broken vlenq: no ending byte")
    l = l << 7
    l = l + (ord(s[i:i+1]) & 0x7F)
    return s[i+1:], l