import math

class VarInt():
    __slots__ = ["number","bytes"]

    def __init__(self, val=''):
        if type(val) is int:
            self.number = val
        elif type(val) is bytes:
            self.bytes = val
        elif type(val) is str:
            self.bytes = bytes.fromhex(val)

    def encode(self,num=None):
        if num is None:
            num = self.number
        self.number = num

        bit_length = num.bit_length()
        byte_length = math.ceil(bit_length/8)
        encoded_length = math.ceil(math.log(byte_length,2))
        encoded_num = num | encoded_length << (bit_length-1)
       
        bin_num = encoded_num.to_bytes(byte_length,'big')
        bin_array = bytearray(bin_num)

        # Note that in QUIC1 the encoded length is put in the two most significant bits
        # This will override the first two most valuable bits with the length
        bin_array[0] = bin_array[0] | (encoded_length << 6)

        self.bytes = bytes(bin_array)
        return self.bytes


    def decode(self, data=None):
        if data is None:
            data = self.bytes
        # The length of variable-length integers is encoded in the
        # first two bits of the first byte.
        byte_array = bytearray(data)
        v = byte_array[0]
        prefix = v >> 6
        length = 1 << prefix

        # Once the length is known, remove these bits and read any
        # remaining bytes.
        v = v & 0x3f
        for x in range(1,length):
            v = (v << 8) + byte_array[x]
        self.number = v
        return self.number