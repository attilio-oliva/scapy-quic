from scapy.all import IP, UDP, send

from packets import QUIC
from varint import VarInt

A = '192.168.0.101' # spoofed source IP address
B = '192.168.100.100' # destination IP address
C = 10000 # source port
D = 443 # destination port
payload ="p"*1200# packet payload
key = b"r"*16
iv = b"0"*8
hp = b"c"*16

## VarInt implementationt test
# vltest = bytes.fromhex('25')
# num = VarInt(vltest).decode()
# print(num)
# print(VarInt(num).encode())
# print(VarInt(VarInt(num).encode()).decode())

ip_packet = IP(src=A, dst=B)
udp_packet = UDP(sport=C, dport=D)
quic_packet = QUIC(type=0, header_type=1, version=0x1, SCID = "a"*8, DCID="b"*8) / payload
quic_packet = QUIC.protect((key,iv,hp), quic_packet)
spoofed_packet = ip_packet / udp_packet / quic_packet 
send(spoofed_packet)