from scapy.all import *

from varint import VarInt

class QuicVarLenField(Field):
    __slots__ = ["fld"]

    def __init__(self, name, default, length_of=None):
        Field.__init__(self, name, default)
        self.fld = length_of

    def i2m(self, pkt, x):
        if x is None:
            if self.fld is None:
                x = VarInt(0).encode()
            else:
                f = pkt.get_field(self.fld)
                x = f.i2len(pkt, pkt.getfieldval(self.fld))
                x = VarInt(x).encode()
        return raw(x)

    def m2i(self, pkt, x):
        if x is None:
            return None, 0
        return str(VarInt(x).decode())

    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)

    def getfield(self, pkt, s):
        value, length = VarInt(s).decode()
        return raw(s[length:]), value