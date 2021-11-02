from scapy.all import IP, UDP, send
from scapy.packet import Raw
from frames import PaddingFrame

from packets import QUIC
from varint import VarInt
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
import time

## VarInt implementationt test
    # vltest = bytes.fromhex('25')
    # num = VarInt(vltest).decode()
    # print(num)
    # print(VarInt(num).encode())
    # print(VarInt(VarInt(num).encode()).decode())

for x in range(50,51):
    src_ip = '192.168.{}.{}'.format(x-1,x) # spoofed source IP address
    dst_ip = '192.168.100.100' # destination IP address
    src_port = 10000 # source port
    dst_port = 443 # destination port
    payload = "a"*1024# packet payload
    
    DCID = "b{}".format(x)*2
    SCID = "a{}".format(x)*2
    
    hash_length = 16 #sha256
    initial_salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    initial_secret = TLS13_HKDF().extract(initial_salt, DCID.encode())

    client_initial_secret = TLS13_HKDF().expand_label(initial_secret, b"client in", b"", hash_length)
    server_initial_secret = TLS13_HKDF().expand_label(initial_secret,b"server in", b"",hash_length)
                                          
    key = TLS13_HKDF().expand_label(initial_secret, b"quic key", b"",hash_length)
    iv = TLS13_HKDF().expand_label(initial_secret, b"quic iv", b"", 12)
    hp = TLS13_HKDF().expand_label(initial_secret, b"quic hp", b"",hash_length)

    ip_packet = IP(src=src_ip, dst=dst_ip)
    udp_packet = UDP(sport=src_port, dport=dst_port)

    #padding = PaddingFrame()
    
    #padding = bytes(PaddingFrame())*1020
    #padding = bytes(padding)

    # workaround to update lenght field...
    quic_packet = QUIC(bytes(QUIC(type=0, header_type=1, version=0x1 ,SCID = SCID, DCID=DCID) / payload))
    #quic_packet.show2()
    #print(QUIC.encode_packet_number(0), quic_packet["QUIC"].PN)
    quic_packet = QUIC.protect((key,iv,hp), quic_packet)
    
    spoofed_packet = ip_packet / udp_packet / quic_packet 
    send(spoofed_packet)
    time.sleep(0.01)