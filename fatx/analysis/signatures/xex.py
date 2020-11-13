from ..signature import FatXSignature


class XEXSignature(FatXSignature):
    def test(self):
        # TODO: add support for beta XEX's
        if self.read(4) == 'XEX2':
            return True
        return False

    def parse(self):
        self.seek(0x10)
        security_offset = self.read_u32()
        header_count = self.read_u32()
        file_name_offset = None
        for x in xrange(header_count):
            xid = self.read_u32()
            if xid == 0x000183FF:
                file_name_offset = self.read_u32()
            else:
                self.read_u32()
        self.seek(security_offset + 4)
        self.length = self.read_u32()
        if file_name_offset is not None:
            self.seek(file_name_offset + 4)
            self.name = self.read_cstring()
