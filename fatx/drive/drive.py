from fatx.filesystem.volume import FatXVolume
from fatx.filesystem.constants import FATX_SIGNATURE
from fatx.analysis.signatures import *

import logging
import struct

x360_signatures = [
    XEXSignature,
    PDBSignature,
    LiveSignature,
    PESignature
]

x_signatures = [
    XBESignature,
    PESignature,
    PDBSignature
]

DRIVE_XBOX = 0
DRIVE_X360 = 1

LOG = logging.getLogger('FATX')


class FatXDrive(object):
    """Representation of a drive which contains FATX volumes.

    TODO: rewrite for handling compressed and physical images.

    Args:
        fp (file): Image file object.
    """
    def __init__(self, fp):
        def read_u32(f):
            return struct.unpack(self.byteorder + 'L', f.read(4))[0]

        self.file = fp
        self.partitions = []
        self.mode = DRIVE_XBOX
        fp.seek(0, 2)
        self.length = fp.tell()
        fp.seek(0, 0)

        LOG.debug("Drive Length: %016x", self.length)

        self.byteorder = '<'
        fp.seek(0xABE80000)
        if read_u32(fp) == FATX_SIGNATURE:
            self.add_partition("Partition5", 0x80000, 0x2ee00000)  # CACHE
            self.add_partition("Partition4", 0x2EE80000, 0x2ee00000)  # CACHE
            self.add_partition("Partition3", 0x5DC80000, 0x2ee00000)  # CACHE
            self.add_partition("Partition2", 0x8CA80000, 0x1f400000)  # SHELL
            self.add_partition("Partition1", 0xABE80000, 0x1312D6000)  # DATA
        else:
            fp.seek(0)
            self.byteorder = '>'
            self.mode = DRIVE_X360
            if read_u32(fp) == 0x20000:
                fp.seek(8)
                # Partition1
                data_offset = read_u32(fp) * 0x200
                data_length = read_u32(fp) * 0x200
                # SystemPartition
                shell_offset = read_u32(fp) * 0x200
                shell_length = read_u32(fp) * 0x200
                # skip
                read_u32(fp)
                read_u32(fp)
                # DumpPartition ("RDMP")
                read_u32(fp)
                read_u32(fp)
                # PixDump
                read_u32(fp)
                read_u32(fp)
                # skip
                read_u32(fp)
                read_u32(fp)
                # skip
                read_u32(fp)
                read_u32(fp)
                # AltFlash
                alt_offset = read_u32(fp)
                alt_length = read_u32(fp)
                # Cache0
                cache0_offset = read_u32(fp)
                cache0_length = read_u32(fp)
                # Cache1
                cache1_offset = read_u32(fp)
                cache1_length = read_u32(fp)

                # 2776A0000 F288F2000 2856A0000 F1A8F2000
                # self.add_partition("Test", 0x130EB0000, 0x1AC1AC4000)
                self.add_partition("SystemPartition", shell_offset, shell_length)
                # self.add_partition("Partition1", 0x2776A0000, 0xF288F2000)
                self.add_partition("Partition1", data_offset, data_length)
                self.add_partition("AltFlash", alt_offset, alt_length)
                self.add_partition("Cache0", cache0_offset, cache0_length)
                self.add_partition("Cache1", cache1_offset, cache1_length)
            else:
                '''
                Name: Offset, Length
                Partition0: 0x0, END
                Cache0: 0x80000, 0x80000000
                Cache1: 0x80080000, 0x80000000
                DumpPartition: 0x100080000, 0x20E30000
                SystemPartition: 0x120eb0000, 0x10000000
                Partition1: 0x130eb0000, END
                '''
                # TODO: test these
                # self.add_partition("Cache0", 0x80000, 0x80000000)
                # self.add_partition("Cache1", 0x80080000, 0x80000000)
                # self.add_partition("DumpPartition", 0x100080000, 0x20E30000)

                # SystemPartititon
                self.add_partition("SystemPartition", 0x120eb0000, 0x10000000)

                # Partition1
                # compute length of data partition
                data_length = self.length - 0x130eb0000
                self.add_partition("Partition1", 0x130eb0000, data_length)

    def add_partition(self, name, offset, length):
        # TODO: support other XBOX file systems?
        fatx = FatXVolume(self.file, name, offset, length, self.byteorder)
        self.partitions.append(fatx)

    def get_partition(self, index):
        return self.partitions[index-1]

    def print_partitions(self):
        print("{:<6} {:<18} {}".format("Index", "Offset", "Length"))
        for i, partition in enumerate(self.partitions):
            print("{:<6} {:016x} {:016x}".format(i + 1,
                                                 partition.offset,
                                                 partition.length))
        print("")
