from scapy.all import *
from scapy.layers.tls.extensions import *
from scapy.layers.tls.all import *
from scapy.layers.tls.handshake import TLS13ClientHello
from fields import QuicVarLenField
from transport_ext import QUIC_Ext_Transport
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
    fields_desc = [
        QuicVarLenField("type", b'\x06'),
        QuicVarLenField("offset", b'\x00'),
        QuicVarLenField("length", b'\x00', length_of="data"),
        StrLenField("data",b'', length_from= lambda pkt: VarInt(pkt.length).decode())
    ]
    @classmethod
    def initial(cls, scid):
        key_group = 29 #x25519
        supported_groups = ["x25519"]
        signature_algs = ["sha256+rsaepss",
                        "sha256+rsa"]
        initial_data = TLS13ClientHello(ciphers=TLS_AES_128_GCM_SHA256, 
                                        ext = [TLS_Ext_ServerName(servernames=[
                                                   ServerName(servername="127.0.0.1")
                                                   ]),
                                               TLS_Ext_CSR(stype='ocsp', req=OCSPStatusRequest()),
                                               TLS_Ext_SignatureAlgorithms(sig_algs=signature_algs),
                                               TLS_Ext_ALPN(protocols=[
                                                   ProtocolName(protocol="hq-interop"),
                                                   #ProtocolName(protocol="h3"),
                                                   ProtocolName(protocol="hq-32"),
                                                   ]),
                                               TLS_Ext_SupportedVersion_CH(versions=["TLS 1.3"]),
                                               TLS_Ext_SupportedGroups(groups=supported_groups),
                                               TLS_Ext_KeyShare_CH(
                                                   client_shares=[KeyShareEntry(group=key_group)]),
                                               QUIC_Ext_Transport.initial(scid),
                                               ]
                                        )
        initial_len = VarInt(len(initial_data)).encode()
        frame = cls(length=initial_len, data=initial_data)
        return frame