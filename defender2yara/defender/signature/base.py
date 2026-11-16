import struct
from defender2yara.defender.constant import SIG_TYPES

class BaseSig:
    def __init__(self,data:bytes,ptr:int=0):
        self.parse_common_header(data,ptr)

    def parse_common_header(self,data:bytes,ptr:int=0):
        if ptr < 0 or ptr + 4 > len(data):
            raise ValueError(f"Truncated signature header at offset {ptr}")
        offset = 4
        self.sig_type_id = data[ptr+0]
        self.sig_type = SIG_TYPES[data[ptr+0]]
        self.size_low = data[ptr+1]
        self.size_high = struct.unpack('<H',data[ptr+2:ptr+4])[0]
        self.size = self.size_low | self.size_high << 8
        if self.size == 0xffffff:
            if ptr + 8 > len(data):
                raise ValueError(f"Truncated extended signature header at offset {ptr}")
            self.size = struct.unpack('<I',data[ptr+4:ptr+8])[0]
            offset += 4
        self.offset = ptr
        self.header_size = offset
        self.record_size = offset + self.size
        if ptr + self.record_size > len(data):
            raise ValueError(f"Truncated signature payload at offset {ptr}: expected {self.size} bytes")
        self.sig_data = data[ptr+offset:ptr+offset+self.size]