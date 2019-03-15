import struct

class FatXSignature(object):
    def __init__(self, cluster, volume):
        self.file_length = 0
        self.file_name = None

        self.cluster = cluster
        self.volume = volume

        self.cluster_offset = volume.cluster_to_physical_offset(self.cluster)

    def test(self):
        """ Test whether or not this cluster contains this file. """
        raise NotImplementedError('Signature test not implemented!')

    def parse(self):
        """ Fills in file length and file name. """
        raise NotImplementedError('Signature parsing not implemented!')

    def seek(self, offset, whence=0):
        offset += self.cluster_offset
        self.volume.infile.seek(offset, whence)

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

    def print_stats(self):
        print 'Found {} at 0x{:x} of length 0x{:x}'.format(self.__class__.__name__,
                                                           self.cluster_offset,
                                                           self.file_length)


class XBESignature(FatXSignature):
    def test(self):
        magic = self.read(4)
        if magic == 'XBEH':
            return True
        return False

    def parse(self):
        self.seek(0x10c)
        self.file_length = self.read_u32()

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

