import struct

try:
    xrange
except NameError:
    xrange = range

class FatXSignature(object):
    def __init__(self, offset, volume):
        self.length = 0
        self.name = None
        self.endian = volume.endian_fmt

        self._offset = offset
        self._volume = volume

    def test(self):
        """ Test whether or not this cluster contains this file. """
        raise NotImplementedError("Signature test not implemented!")

    def parse(self):
        """ Fills in file length and file name. """
        raise NotImplementedError("Signature parsing not implemented!")

    def seek(self, offset, whence=0):
        offset += self._offset
        self._volume.seek_file_area(offset, whence)

    def read(self, size):
        return self._volume.infile.read(size)

    def read_u8(self):
        return struct.unpack(self.endian + 'B', self.read(1))[0]

    def read_u16(self):
        return struct.unpack(self.endian + 'H', self.read(2))[0]

    def read_u32(self):
        return struct.unpack(self.endian + 'I', self.read(4))[0]

    def read_u64(self):
        return struct.unpack(self.endian + 'Q', self.read(8))[0]

    def read_float(self):
        return struct.unpack(self.endian + 'f', self.read(4))[0]

    def read_double(self):
        return struct.unpack(self.endian + 'd', self.read(8))[0]

    def read_cstring(self):
        s = []
        while True:
            c = self.read(1)
            if c == chr(0):
                return "".join(s)
            s.append(c)

    def read_wstring(self):
        pass

    def set_endian(self, endian):
        self.endian = endian

    def get_file_name(self):
        file_name = self.name
        if file_name is None:
            # TODO: use file extension instead of classname
            if not hasattr(self.__class__, 'Unnamed_Counter'):
                self.__class__.Unnamed_Counter = 1
            file_name = self.__class__.__name__.lower() + \
                        str(self.__class__.Unnamed_Counter)
            self.__class__.Unnamed_Counter += 1
        return file_name

    def recover(self, path):
        file_name = self.get_file_name()
        whole_path = path + '/' + file_name
        with open(whole_path, 'wb') as f:
            if self.length != 0 and self.length < 0xffffffff:
                self.seek(0)
                data = self.read(self.length)
                f.write(data)

    def __str__(self):
        return "{} at 0x{:x} of length 0x{:x}".format(self.__class__.__name__,
                                                      self._offset,
                                                      self.length)


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


class LiveSignature(FatXSignature):
    def test(self):
        if self.read(4) == 'LIVE':
            return True
        return False

    def parse(self):
        self.length = 0


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


class XEXSignature(FatXSignature):
    def test(self):
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
        return


# this should be handled by main module
all_signatures = [a_signature for a_signature in FatXSignature.__subclasses__()]
