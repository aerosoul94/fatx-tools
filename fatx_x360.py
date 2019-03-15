from fatx_drive import FatXDrive
from fatx_signatures import *
import struct

x360_signatures = [XEXSignature,
                   PDBSignature]

class X360Drive(FatXDrive):
    def __init__(self, file):
        super(X360Drive, self).__init__(file, FatXDrive.ENDIAN_BIG)

        def read_u32(file):
            return struct.unpack('>L', file.read(4))[0]

        # check for devkit header
        ident = read_u32(file)
        if ident == 0x20000:
            file.seek(8)
            data_offset = read_u32(file) * 0x200
            data_length = read_u32(file) * 0x200
            shell_offset = read_u32(file) * 0x200
            shell_length = read_u32(file) * 0x200

            self.add_partition(shell_offset, shell_length)
            self.add_partition(data_offset, data_length)
        else:
            self.add_partition(0x80000, 0x80000000)
            self.add_partition(0x80080000, 0xA0E30000)
            self.add_partition(0x118EB0000, 0x8000000)
            self.add_partition(0x120eb0000, 0x10000000)

            # compute length of data partition
            data_length = self.length - 0x130eb0000
            self.add_partition(0x130eb0000, data_length)