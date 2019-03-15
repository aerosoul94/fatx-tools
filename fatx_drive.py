from fatx_filesystem import FatXVolume

class FatXDrive(object):
    ENDIAN_LITTLE = 0
    ENDIAN_BIG = 1

    EndOfDrive = 0xffffffffffffffff

    def __init__(self, file, endian):
        self.file = file
        self.endianess = endian
        self.partitions = []

        file.seek(0, 2)
        self.length = file.tell()
        file.seek(0, 0)

    def add_partition(self, offset, length):
        self.partitions.append(FatXVolume(self.file, offset, length, self.endianess))

    def get_partition(self, index):
        return self.partitions[index-1]

    def print_partitions(self):
        print '{:<6} {:<18} {}'.format("Index", "Offset", "Length")
        for i, partition in enumerate(self.partitions):
            print '{:<6} {:016x} {:016x}'.format(i + 1, partition.offset, partition.length)
        print
