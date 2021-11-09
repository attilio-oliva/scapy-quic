from scapy.all import IP, UDP, send
from scapy.packet import Raw
from frames import CryptoFrame, PaddingFrame, PingFrame

from packets import QUIC
from varint import VarInt
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
import time

for x in range(50,51):
    src_ip = '192.168.{}.{}'.format(1,17) # spoofed source IP address
    dst_ip = '192.168.1.17' # destination IP address
    src_port = 10000 # source port
    dst_port = 60000 # destination port
    
    DCID = ("b{}".format(x)*2).encode()
    SCID = ("a{}".format(x)*2).encode()

    ip_packet = IP(src=src_ip, dst=dst_ip)
    udp_packet = UDP(sport=src_port, dport=dst_port)

    quic_packet = QUIC.initial(DCID,SCID)

    spoofed_packet = ip_packet / udp_packet / quic_packet 
    send(spoofed_packet)
    time.sleep(0.01)