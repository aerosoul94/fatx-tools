import struct

class FatXSignature(object):
    def __init__(self, offset, volume):
        self.file_length = 0
        self.file_name = None

        self.offset = offset
        self.volume = volume

    def test(self):
        """ Test whether or not this cluster contains this file. """
        raise NotImplementedError('Signature test not implemented!')

    def parse(self):
        """ Fills in file length and file name. """
        raise NotImplementedError('Signature parsing not implemented!')

    def seek(self, offset, whence=0):
        offset += self.offset
        self.volume.seek_file_area(offset, whence)

    def read(self, size):
        return self.volume.infile.read(size)

    def read_u8(self):
        return struct.unpack(self.volume.endian_fmt + 'B', self.read(1))[0]

    def read_u16(self):
        return struct.unpack(self.volume.endian_fmt + 'H', self.read(2))[0]

    def read_u32(self):
        return struct.unpack(self.volume.endian_fmt + 'L', self.read(4))[0]

    def read_u64(self):
        return struct.unpack(self.volume.endian_fmt + 'Q', self.read(8))[0]

    def read_float(self):
        return struct.unpack(self.volume.endian_fmt + 'f', self.read(4))[0]

    def read_double(self):
        return struct.unpack(self.volume.endian_fmt + 'd', self.read(8))[0]

    def read_cstring(self):
        str = []
        while True:
            c = self.read(1)
            if c == chr(0):
                return "".join(str)
            str.append(c)

    def get_file_name(self):
        file_name = self.file_name
        if file_name == None:
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
            if (self.file_length != 0 and self.file_length < 0xffffffff):
                self.seek(0)
                data = self.read(self.file_length)
                f.write(data)

    def __str__(self):
        return 'Found {} at 0x{:x} of length 0x{:x}'.format(self.__class__.__name__,
                                                           self.offset,
                                                           self.file_length)


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
        self.file_length = self.read_u32()
        self.seek(0x150)
        debug_file_name_offset = self.read_u32()
        self.seek(debug_file_name_offset - base_address)
        debug_file_name = self.read_cstring()
        self.file_name = debug_file_name.split('.exe')[0] + '.xbe'
        

class PDBSignature(FatXSignature):
    def test(self):
        magic = 'Microsoft C/C++ MSF 7.00'
        if self.read(len(magic)) == magic:
            return True
        return False

    def parse(self):
        self.file_length = 0

class XEXSignature(FatXSignature):
    def test(self):
        if self.read(4) == 'XEX2':
            return True
        return False

    def parse(self):
        self.file_length = 0


# this should be handled by main module
all_signatures = [a_signature for a_signature in FatXSignature.__subclasses__()]

