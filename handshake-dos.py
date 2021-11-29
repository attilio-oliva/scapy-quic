from scapy.all import IP, UDP, send
from scapy.layers.inet6 import IPv6
from scapy.main import load_layer, load_module
from scapy.packet import Raw
from scapy.sendrecv import AsyncSniffer, sniff
from packets import QUIC
import time
from scapy.config import conf
import pyshark

def send_handshake(request_pkt):
    src_ip = request_pkt["IP"].dst 
    dst_ip = request_pkt["IP"].src
    
    src_port = request_pkt["UDP"].dstport
    dst_port = request_pkt["UDP"].srcport
    
    DCID = request_pkt["QUIC"].DCID
    SCID = request_pkt["QUIC"].SCID
    
    ip_packet = IP(src=src_ip, dst=dst_ip)
    udp_packet = UDP(sport=src_port, dport=dst_port)

    quic_packet = QUIC.initial(DCID,SCID)
    spoofed_packet = ip_packet / udp_packet / quic_packet

    send(spoofed_packet)
    
capture = pyshark.LiveCapture(interface='lo', display_filter="quic")

for packet in capture.sniff_continuously(packet_count=5):
    send_handshake(packet)