from fatx_filesystem import FatXVolume, FATX_SIGNATURE
from fatx_signatures import *
import struct

x360_signatures = [XEXSignature,
                   PDBSignature]

x_signatures = [XBESignature,
                PDBSignature]

DRIVE_XBOX = 0
DRIVE_X360 = 1

class FatXDrive(object):
    def __init__(self, file):
        def read_u32(f):
            return struct.unpack(self.byteorder + 'L', f.read(4))[0]

        self.file = file
        self.partitions = []
        self.mode = DRIVE_XBOX
        file.seek(0, 2)
        self.length = file.tell()
        file.seek(0, 0)

        self.byteorder = '<'
        file.seek(0xABE80000)
        if read_u32(file) == FATX_SIGNATURE:
            self.add_partition(0x80000, 0x2ee00000)  # CACHE
            self.add_partition(0x2EE80000, 0x2ee00000)  # CACHE
            self.add_partition(0x5DC80000, 0x2ee00000)  # CACHE
            self.add_partition(0x8CA80000, 0x1f400000)  # SHELL
            self.add_partition(0xABE80000, 0x1312D6000)  # DATA
        else:
            file.seek(0)
            self.byteorder = '>'
            self.mode = DRIVE_X360
            if read_u32(file) == 0x20000:
                file.seek(8)
                data_offset = read_u32(file) * 0x200
                data_length = read_u32(file) * 0x200
                shell_offset = read_u32(file) * 0x200
                shell_length = read_u32(file) * 0x200

                # TODO: there are actually more partitions, but I'm not sure
                # TODO: if they're static offsets or pointed to by something.
                self.add_partition(shell_offset, shell_length)
                self.add_partition(data_offset, data_length)
            else:
                self.add_partition(0x120eb0000, 0x10000000)

                # compute length of data partition
                data_length = self.length - 0x130eb0000
                self.add_partition(0x130eb0000, data_length)

    '''
    def __init__(self, file, endian):
        self.file = file
        self.endianess = endian
        self.partitions = []

        file.seek(0, 2)
        self.length = file.tell()
        file.seek(0, 0)
    '''

    def add_partition(self, offset, length):
        self.partitions.append(FatXVolume(self.file, offset, length, self.byteorder))

    def get_partition(self, index):
        return self.partitions[index-1]

    def print_partitions(self):
        print "{:<6} {:<18} {}".format("Index", "Offset", "Length")
        for i, partition in enumerate(self.partitions):
            print "{:<6} {:016x} {:016x}".format(i + 1, partition.offset, partition.length)
        print
