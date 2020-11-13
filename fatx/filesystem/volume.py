from fatx.filesystem.dirent import FatXDirent
from fatx.filesystem.timestamp import XTimeStamp, X360TimeStamp
from fatx.filesystem.constants import \
    FATX_SIGNATURE, \
    FATX_PAGE_SIZE, \
    FATX_SECTOR_SIZE, \
    DIRENT_NEVER_USED, \
    DIRENT_NEVER_USED2

import struct
import logging


LOG = logging.getLogger("FATX.FileSystem")


class LazyOffsetPrinter(object):
    def __init__(self, method):
        self.method = method

    def __str__(self):
        return "{:016x}".format(self.method())


# Cached file.tell()
POSITION = None


class FatXVolume(object):
    """Representation of a FATX volume read from a partition.

    Args:
        fo (file): File handle for the image containing this volume.
        name (str): Name of this volume (ex: SystemPartition).
        offset (int): Offset of this volume into the image file.
        length (int): Length of this volume.
        byteorder (str): Either '>' for big-endian or '<' for little endian.
    """

    def __init__(self, fo, name, offset, length, byteorder):
        LOG.debug("Partition Offset: %016x", offset)
        LOG.debug("Partition Length: %016x", length)

        global POSITION
        POSITION = LazyOffsetPrinter(fo.tell)

        self.infile = fo
        self.name = name
        self.offset = offset
        self.length = length
        self.endian_fmt = byteorder
        self.FATX_FORMAT = self.endian_fmt + 'LLLL'
        self.DIRENT_FORMAT = self.endian_fmt + 'BB42sLLLLL'
        # Original Xbox is little endian and Xbox 360 is big endian.
        self.ts_format = XTimeStamp if byteorder == '<' else X360TimeStamp

        self._root = []
        self.file_allocation_table = None

        self.signature = ""
        self.serial_number = 0
        self.sectors_per_cluster = 0
        self.root_dir_first_cluster = 0

        self.bytes_per_cluster = 0
        self.max_clusters = 0
        self.fat_byte_offset = 0
        self.fat16x = False
        self.file_area_byte_offset = 0

        self.debug_log_enabled = LOG.isEnabledFor(logging.DEBUG)

    def __del__(self):
        self.infile.close()

    def mount(self):
        """Loads the FATX file system."""
        LOG.info("Mounting %s", self.name)

        # read volume metadata
        self.read_volume_metadata()

        # calculate file allocation and file area offsets
        self.calculate_offsets()

        if self.debug_log_enabled:
            LOG.debug("Bytes Per Cluster: %08x", self.bytes_per_cluster)
            LOG.debug("Max Clusters: %08x", self.max_clusters)
            LOG.debug("FAT Byte Offset: %08x", self.fat_byte_offset)
            LOG.debug("FILE Area Byte Offset: %08x", self.file_area_byte_offset)

        # get file allocation table (int[])
        self.file_allocation_table = self.read_file_allocation_table()

        self._root = self.read_directory_stream(
            self.cluster_to_physical_offset(self.root_dir_first_cluster))

        # for each dirent in root, populate children
        self.populate_dirent_stream(self._root)

    def read_volume_metadata(self):
        """Reads and verifies the FATX volume header."""
        self.infile.seek(self.offset)

        (self.signature,
         self.serial_number,
         self.sectors_per_cluster,
         self.root_dir_first_cluster) = \
            struct.unpack(self.FATX_FORMAT,
                          self.infile.read(struct.calcsize(self.FATX_FORMAT)))

        # TODO: Remove this in order to handle corrupted metadata
        if self.signature != FATX_SIGNATURE:
            raise ValueError("Invalid FATX signature!")

    def read_file_allocation_table(self):
        """Reads the file allocation table and returns it as a cluster list.

        Returns (int[]): file allocation table as a list.
        """

        def construct_fat_format(num_clusters):
            return self.endian_fmt + (
                    ('H' if self.fat16x else 'L') * num_clusters)

        fat_offset = self.byte_offset_to_physical_offset(self.fat_byte_offset)
        self.infile.seek(fat_offset)
        fat_format = construct_fat_format(self.max_clusters)
        fat_length = struct.calcsize(fat_format)

        LOG.debug("FAT Offset: %s", POSITION)
        LOG.debug("FAT Length: %08x", fat_length)

        fat_table = self.infile.read(fat_length)
        return [entry for entry in struct.unpack(fat_format, fat_table)]

    def is_valid_cluster(self, cluster):
        """Returns whether or not cluster index is within bounds of the
        volume.

        Returns (bool):
        """
        return (cluster - 1) < self.max_clusters

    def get_root(self):
        """Returns the list of dirents at this volume's root.

        Returns (FatxDirent[]):
        """
        return self._root

    def seek_file_area(self, offset, whence=0):
        """Seek relative to file_area_byte_offset."""
        # if offset > (self.length - self.file_area_byte_offset):
        #     raise ValueError("Cannot seek past end of volume.")
        offset += self.file_area_byte_offset + self.offset
        self.infile.seek(offset, whence)

    def read_file_area(self, size):
        """Read from file area."""
        return self.infile.read(size)

    def read_cluster(self, cluster):
        """Read an entire cluster from this volume."""
        self.infile.seek(self.cluster_to_physical_offset(cluster))
        return self.infile.read(self.bytes_per_cluster)

    def seek_to_cluster(self, cluster):
        """Seek to a cluster relative to this volume."""
        self.infile.seek(self.cluster_to_physical_offset(cluster))

    def byte_offset_to_cluster(self, offset):
        """Convert a byte offset (relative to the volume) to a cluster
        index.

        Returns (int):
        """
        return (offset // self.bytes_per_cluster) + 1

    def byte_offset_to_physical_offset(self, offset):
        """Convert a byte offset (relative to the volume) to an offset into the
        image file it belongs to.

        Returns (int):
        """
        return self.offset + offset

    def cluster_to_physical_offset(self, cluster):
        """Convert a cluster index (relative to the volume) to an offset into
        the image file it belongs to.

        Returns (int):
        """
        return (self.offset +
                self.file_area_byte_offset +
                (self.bytes_per_cluster * (cluster - 1)))

    def get_dirent_buffer(self, cluster_map):
        """Concatenates each cluster in cluster_map into one single buffer.

        For files, this would return all clusters containing this file's data.
        For directories, it would return all clusters containing this
        directories dirent streams.

        Args:
            cluster_map (int[]): List of clusters to read.

        Returns (str): Contents of the dirent.
        """
        dirent_buffer = ''
        for cluster in cluster_map:
            dirent_buffer += self.read_cluster(cluster)
        return dirent_buffer

    def get_cluster_chain(self, first_cluster):
        """Get a cluster chain map from the file allocation table starting from
        first_cluser.

        Args:
            first_cluster (int): Index into the file allocation table in which
                to extract cluster map from. This should be supplied from
                FatXDirent.first_cluster.

        Returns (int[]):
        """
        chain = [first_cluster]
        fat_entry = first_cluster
        reserved_indexes = (0xfff0 if self.fat16x else 0xfffffff0)
        while True:
            fat_entry = self.file_allocation_table[fat_entry]

            # break when reserved entry found
            if fat_entry >= reserved_indexes:
                break

            if fat_entry == 0:
                LOG.info("BAIL! Found NULL fat entry!")
                return [first_cluster]

            if fat_entry > len(self.file_allocation_table):
                LOG.info(
                    "BAIL! FAT entry index {} greater than FAT size {}!"
                    .format(fat_entry,
                            len(self.file_allocation_table)))
                return [first_cluster]

            chain.append(fat_entry)
        return chain

    def calculate_offsets(self):
        """Calculates offsets needed to perform work on this volume."""
        # reserved for volume metadata
        reserved_bytes = 0x1000

        # most commonly 0x4000
        self.bytes_per_cluster = self.sectors_per_cluster * FATX_SECTOR_SIZE

        # +1 is reserved_fat_entries
        self.max_clusters = (self.length // self.bytes_per_cluster) + 1
        if self.max_clusters < 0xfff0:
            bytes_per_fat = self.max_clusters * 2
            self.fat16x = True
        else:
            bytes_per_fat = self.max_clusters * 4
            self.fat16x = False

        # align to nearest page
        bytes_per_fat = (bytes_per_fat + (FATX_PAGE_SIZE - 1)) & \
            ~(FATX_PAGE_SIZE - 1)

        # offset of file allocation table
        self.fat_byte_offset = reserved_bytes
        # offset of file area
        self.file_area_byte_offset = self.fat_byte_offset + bytes_per_fat

    def populate_dirent_stream(self, stream):
        """Iterates dirent's from a dirent stream and populates directories
        with its child dirents.

        Args:
            stream (FatXDirent[]): dirent stream
        """
        for dirent in stream:
            LOG.info("%s", dirent.get_full_path())

            # If this directory was deleted, we cannot populate it as the
            # dirent stream it points to is not guaranteed. Once the directory
            # is deleted, the dirent stream it points to may be overwritten.
            if dirent.is_directory() and \
                    not dirent.is_deleted():

                chain_map = self.get_cluster_chain(dirent.first_cluster)

                if self.debug_log_enabled:
                    LOG.debug("Reading directory: %s", dirent.get_full_path())
                    LOG.debug("Directory First Cluster: %08x",
                              dirent.first_cluster)
                    LOG.debug("Chain Map: %s", chain_map)

                for cluster in chain_map:
                    LOG.debug("Reading Cluster: %08x", cluster)

                    dirent_stream = self.read_directory_stream(
                        self.cluster_to_physical_offset(cluster))

                    dirent.add_dirent_stream_to_this_directory(dirent_stream)
                    # TODO: populate_children()
                    self.populate_dirent_stream(dirent_stream)

    def read_directory_stream(self, offset):
        """Reads and unpacks the dirent stream into a list of FatXDirent's.

        Args:
            offset (int): Expects physical offset into the image file, not the
                offset relative to the volume.

        Returns (FatXDirent[]):
        """
        stream = []

        self.infile.seek(offset)
        LOG.debug("Reading dirent stream at: %s", POSITION)
        for _ in xrange(256):
            LOG.debug(" Reading dirent at: %s", POSITION)
            dirent = FatXDirent.from_file(self)

            # TODO: Perhaps I should also do this before creating the object.
            # check for end of dirent stream
            if (dirent.file_name_length == DIRENT_NEVER_USED or
                    dirent.file_name_length == DIRENT_NEVER_USED2):
                LOG.debug(" End of dirent stream")
                break

            LOG.debug(" Read dirent: %s", dirent.file_name)

            stream.append(dirent)

        return stream

    def print_volume_metadata(self):
        """Print the FATX header and other useful volume information."""

        def print_aligned(header, value=''):
            print("{:<26} {}".format(header, value))

        print_aligned("Signature:", self.signature)
        print_aligned("SerialNumber:", hex(self.serial_number))
        print_aligned("SectorsPerCluster:", "{} (0x{:x} bytes)".format(
            self.sectors_per_cluster,
            self.sectors_per_cluster * FATX_SECTOR_SIZE))
        print_aligned('RootDirFirstCluster:', str(self.root_dir_first_cluster))
        print("")

        print_aligned("Calculated Offsets:")
        print_aligned("PartitionOffset:", "0x{:x}".format(self.offset))
        print_aligned("FatByteOffset:", "0x{:x} (+0x{:x})".format(
            self.byte_offset_to_physical_offset(self.fat_byte_offset),
            self.fat_byte_offset))
        print_aligned("FileAreaByteOffset:", "0x{:x} (+0x{:x})".format(
            self.byte_offset_to_physical_offset(self.file_area_byte_offset),
            self.file_area_byte_offset))
        print("")
