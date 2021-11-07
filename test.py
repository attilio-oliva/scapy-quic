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
    
    DCID = ("b{}".format(x)*2).encode()
    SCID = ("a{}".format(x)*2).encode()
    
    initial_salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    initial_secret = TLS13_HKDF().extract(initial_salt, DCID)

    client_initial_secret = TLS13_HKDF().expand_label(initial_secret, b"client in", b"", 32)
    #server_initial_secret = TLS13_HKDF().expand_label(initial_secret,b"server in", b"", 32)
                                          
    key = TLS13_HKDF().expand_label(client_initial_secret, b"quic key", b"",16)
    iv = TLS13_HKDF().expand_label(client_initial_secret, b"quic iv", b"", 12)
    hp = TLS13_HKDF().expand_label(client_initial_secret, b"quic hp", b"",16)

    #Example from RFC
    #DCID = bytes.fromhex('8394c8f03e515708')
    #initial_secret = bytes.fromhex("7db5df06e7a69e432496adedb0085192 3595221596ae2ae9fb8115c1e9ed0a44")
    #client_initial_secret = bytes.fromhex("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea")  
    # key = bytes.fromhex('1f369613dd76d5467730efcbe3b1a22d')
    # iv = bytes.fromhex('fa044b2f42a3fd3b46fb255c')
    # hp = bytes.fromhex('9f50449e04a0e810283a1e9933adedd2')
    crypto_frame = bytes.fromhex("""060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
                                04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
                                616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
                                04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
                                baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
                                0d0010000e0403050306030203080408 050806002d00020101001c0002400100
                                3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
                                75300901100f088394c8f03e51570806 048000ffff""")
    ip_packet = IP(src=src_ip, dst=dst_ip)
    udp_packet = UDP(sport=src_port, dport=dst_port)

    padding = PaddingFrame()
    
    padding = bytes(PaddingFrame())*917
    padding = bytes(padding)
    # workaround to update lenght field...
    quic_packet = (QUIC(type=0, header_type=1, version=0x1 , SCID=SCID, DCID=DCID) / crypto_frame)
    quic_packet["QUIC"].length = VarInt(1182).encode()
    #quic_packet.show2()
    quic_packet = QUIC.protect((key,iv,hp), quic_packet / padding)
    

    #quic_packet = QUIC(bytes.fromhex(""" c300000001088394c8f03e5157080000449e00000002 
    #        060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
    #        04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
    #        616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
    #        04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
    #        baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
    #        0d0010000e0403050306030203080408 050806002d00020101001c0002400100
    #        3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
    #        75300901100f088394c8f03e51570806 048000ffff """))
    #quic_packet = QUIC.protect((key,iv,hp), quic_packet/padding)
    #quic_packet = QUIC(quic_packet)
    #quic_packet.show2()

    spoofed_packet = ip_packet / udp_packet / quic_packet 
    send(spoofed_packet)
    time.sleep(0.01)