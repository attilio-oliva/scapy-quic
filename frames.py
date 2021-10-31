from scapy.all import *

from fields import QuicVarLenField

class PaddingFrame(Packet):
    fields_desc = [
        QuicVarLenField("type", b'\x00'),
    ]