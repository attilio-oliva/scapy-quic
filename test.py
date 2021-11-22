from scapy.all import IP, UDP, send
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from frames import CryptoFrame, PaddingFrame, PingFrame

from packets import QUIC
from transport_ext import QUIC_Ext_Transport
from varint import VarInt
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
import time

for x in range(50,51):
    src_ip = '127.0.0.1' # spoofed source IP address
    dst_ip = '127.0.0.1' # destination IP address
    src_ip = '::1'
    dst_ip = '::1'
    src_port = 10000 # source port
    dst_port = 60000 # destination port
    
    DCID = bytes.fromhex("4949b5218e99c022")
    SCID = bytes.fromhex("78643036af1314e2")

    ip_packet = IPv6(src=src_ip, dst=dst_ip)
    udp_packet = UDP(sport=src_port, dport=dst_port)
    
    quic_packet = QUIC.initial(DCID,SCID)

    spoofed_packet = ip_packet / udp_packet / quic_packet
    
    send(spoofed_packet)
    #time.sleep(0.01)