from ..signature import FatXSignature


class XBESignature(FatXSignature):
    def test(self):
        magic = self.read(4)
        if magic == 'XBEH':
            return True
        return False

    def parse(self):
        # 0x104: BaseAddress
        # 0x10c: SizeOfImage
        # 0x110: SizeOfImageHeader
        # 0x114: TimeDateStamp
        # 0x14C: DebugPathName
        # 0x150: DebugFileName
        # 0x154: DebugUnicodeFileName
        self.seek(0x104)
        base_address = self.read_u32()
        self.seek(0x10c)
        self.length = self.read_u32()
        self.seek(0x150)
        debug_file_name_offset = self.read_u32()
        self.seek(debug_file_name_offset - base_address)
        debug_file_name = self.read_cstring()
        self.name = debug_file_name.split('.exe')[0] + '.xbe'
