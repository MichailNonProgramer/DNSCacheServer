import binascii,struct

class BufferError(Exception):
    pass

class Buffer(object):
    def __init__(self,data=b''):
        self.data = bytearray(data)
        self.offset = 0

    def remaining(self):
        """
            Return bytes remaining
        """
        return len(self.data) - self.offset

    def get(self,length):
        """
            Gen len bytes at current offset (& increment offset)
        """
        if length > self.remaining():
            raise BufferError("Not enough bytes [offset=%d,remaining=%d,requested=%d]" %
                    (self.offset,self.remaining(),length))
        start = self.offset
        end = self.offset + length
        self.offset += length
        return bytes(self.data[start:end])

    def hex(self):
        """
            Return data as hex string
        """
        return binascii.hexlify(self.data)

    def pack(self,fmt,*args):
        """
            Pack data at end of data according to fmt (from struct) & increment
            offset
        """
        self.offset += struct.calcsize(fmt)
        self.data += struct.pack(fmt,*args)

    def append(self,s):
        """
            Append s to end of data & increment offset
        """
        self.offset += len(s)
        self.data += s

    def update(self,ptr,fmt,*args):
        """
            Modify data at offset `ptr`
        """
        s = struct.pack(fmt,*args)
        self.data[ptr:ptr+len(s)] = s

    def unpack(self,fmt):
        """
            Unpack data at current offset according to fmt (from struct)
        """
        try:
            data = self.get(struct.calcsize(fmt))
            return struct.unpack(fmt,data)
        except struct.error as e:
            raise BufferError("Error unpacking struct '%s' <%s>" %
                    (fmt,binascii.hexlify(data).decode()))