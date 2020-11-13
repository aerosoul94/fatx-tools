from ..signature import FatXSignature


class PESignature(FatXSignature):
    def test(self):
        if self.read(4) == 'MZ\x90\0':
            return True
        return False

    def parse(self):
        self.set_endian('<')
        self.seek(0x3C)  # offset to PE Header
        lfanew = self.read_u32()
        self.seek(lfanew)
        sign = self.read_u32()
        if sign != 0x00004550:  # 'PE\0\0'
            return
        self.seek(lfanew + 0x6)
        nsec = self.read_u16()  # NumberOfSections
        last_sec_off = (lfanew + 0xF8) + ((nsec - 1) * 0x28)
        self.seek(last_sec_off + 0x10)
        sec_len = self.read_u32()
        self.seek(last_sec_off + 0x14)
        sec_off = self.read_u32()
        self.length = sec_len + sec_off
