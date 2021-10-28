from scapy.all import IP, UDP, send

from packets import QUIC

A = '192.168.0.101' # spoofed source IP address
B = '192.168.100.100' # destination IP address
C = 10000 # source port
D = 443 # destination port
payload ="yada yada yada"# packet payload
key = b"r"*32
iv = b"0"*16
hp = b"c"*32

ip_packet = IP(src=A, dst=B)
udp_packet = UDP(sport=C, dport=D)
quic_packet = QUIC(type=0, header_type=1, version=0x1, SCID = "b"*10, DCID="a"*4)

spoofed_packet = ip_packet / udp_packet / quic_packet / payload
#spoofed_packet = QUIC.protect((key,iv,hp),spoofed_packet)

send(spoofed_packet)