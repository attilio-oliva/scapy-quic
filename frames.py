from scapy.all import *
from scapy.layers.tls.handshake import TLS13ClientHello
from fields import QuicVarLenField
from varint import VarInt
from scapy.layers.tls.crypto.suites import TLS_AES_128_GCM_SHA256

class PaddingFrame(Packet):
    fields_desc = [
        QuicVarLenField("type", b'\x00'),
    ]
class PingFrame(Packet):
    fields_desc = [
        QuicVarLenField("type", b'\x01'),
    ]

class CryptoFrame(Packet):
    example_data = TLS13ClientHello(ciphers=TLS_AES_128_GCM_SHA256)
    fields_desc = [
        QuicVarLenField("type", b'\x06'),
        QuicVarLenField("offset", b'\x00'),
        QuicVarLenField("length", b'\x00', length_of="data"),
        StrLenField("data",bytes(example_data), length_from= lambda pkt: VarInt(pkt.length).decode())
    ]