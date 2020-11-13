from ..signature import FatXSignature


class PDBSignature(FatXSignature):
    def test(self):
        magic = 'Microsoft C/C++ MSF 7.00\r\n\x1A\x44\x53\0\0\0'
        if self.read(0x20) == magic:
            return True
        return False

    def parse(self):
        self.set_endian('<')
        self.seek(0x20)
        block_size = self.read_u32()
        self.seek(0x28)
        num_blocks = self.read_u32()
        self.length = block_size * num_blocks
