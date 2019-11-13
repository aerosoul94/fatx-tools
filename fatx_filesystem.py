import struct
import os
import time
import logging
from datetime import datetime

try:
    xrange
except NameError:
    xrange = range

LOG = logging.getLogger("FATX.FileSystem")

''' TODO:
    (From leftmost bit to rightmost bit)
      Xbox Original Format:
        07:Year
        04:Month
        05:Day
        05:Hour
        06:Minute
        05:DoubleSeconds
      Xbox 360 Format (OLD):
        05:DoubleSeconds
        06:Minute
        05:Hour
        05:Day
        04:Month
        07:Year
      Xbox 360 Format (NEW):
        07:Year
        04:Month
        05:Day
        05:Hour
        06:Minute
        05:DoubleSeconds     
'''


class FatXTimeStamp(object):
    """Representation of a FATX timestamp.

    This handles extraction of each bitfield member of the timestamp."""
    __slots__ = ('time',)

    def __init__(self, time_stamp):
        self.time = time_stamp

    def __str__(self):
        # TODO: think of a reliable way of detecting proto X360 timestamps
        # try:
        #    if self.year > date.today().year:
        #        raise Exception
        #    return str(datetime(year=self.year,
        #                        month=self.month,
        #                        day=self.day,
        #                        hour=self.hour,
        #                        minute=self.min,
        #                        second=self.sec))
        # except:
        #    return str(datetime(year=((self.time & 0xffff) & 0x7f) + 2000,
        #                        month=((self.time & 0xffff) >> 7) & 0xf,
        #                        day=((self.time & 0xffff) >> 0xb),
        #                        hour=((self.time >> 16) & 0x1f),
        #                        minute=((self.time >> 16) >> 5) & 0x3f,
        #                        second=((self.time >> 16) >> 10) & 0xfffe))

        return '{}/{}/{} {}:{:02d}:{:02d}'.format(
            self.month, self.day, self.year,
            self.hour, self.min, self.sec
        )

    @property
    def year(self):
        _year = (self.time & 0xFE000000) >> 25
        return _year

    @property
    def month(self):
        _month = (self.time & 0x1E00000) >> 21
        return _month

    @property
    def day(self):
        _day = (self.time & 0x1F0000) >> 16
        return _day

    @property
    def hour(self):
        _hour = (self.time & 0xF800) >> 11
        return _hour

    @property
    def min(self):
        _min = (self.time & 0x7E0) >> 5
        return _min

    @property
    def sec(self):
        _sec = (self.time & 0x1F) * 2
        return _sec


class X360TimeStamp(FatXTimeStamp):
    """Representation of an Xbox 360 time stamp.

    The Xbox 360 timestamps contains years offset from 1980."""

    @property
    def year(self):
        _year = (((self.time & 0xFE000000) >> 25) + 1980)
        return _year


class XTimeStamp(FatXTimeStamp):
    """Representation of an Original Xbox time stamp.

    The Original Xbox contains years offset from 2000."""

    @property
    def year(self):
        _year = (((self.time & 0xFE000000) >> 25) + 2000)
        return _year


FATX_SECTOR_SIZE = 0x200
FATX_PAGE_SIZE = 0x1000

FATX_SIGNATURE = 0x58544146  # "FATX"
FATX_FILE_NAME_LEN = 42

FATX_MAX_DIRECTORY_SIZE = 0x40000

FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_SYSTEM = 0x00000004
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_ARCHIVE = 0x00000020

# evaluates to 0x37
VALID_FILE_ATTRIBUTES = FILE_ATTRIBUTE_READONLY | \
                        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | \
                        FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ARCHIVE

DIRENT_NEVER_USED = 0x00
DIRENT_DELETED = 0xE5
DIRENT_NEVER_USED2 = 0xFF


class FatXDirent:
    """Representation of directory entity which can be either a file or folder.

    Args:
        data (str): Serialized dirent read from the volume.
        volume (FatXVolume): Volume in which this dirent belongs to.
    """

    def __init__(self, data, volume):
        (self.file_name_length,
         self.file_attributes,
         self.file_name_bytes,
         self.first_cluster,
         self.file_size,
         self.creation_time_i,
         self.last_write_time_i,
         self.last_access_time_i) = struct.unpack(volume.DIRENT_FORMAT, data)

        self.children = []
        self.parent = None
        self.volume = volume
        self.file_name = ''
        self.creation_time = None
        self.last_write_time = None
        self.last_access_time = None

        # Optimization: Avoid creating time stamp objects
        # Marks the end of a directory stream
        if (self.file_name_length == DIRENT_NEVER_USED or
                self.file_name_length == DIRENT_NEVER_USED2):
            return

        ts = volume.ts_format
        self.creation_time = ts(self.creation_time_i)
        self.last_write_time = ts(self.last_write_time_i)
        self.last_access_time = ts(self.last_access_time_i)

        if self.file_name_length == DIRENT_DELETED:
            self.file_name = self.file_name_bytes.split('\xff')[0]
        else:
            self.file_name = self.file_name_bytes[:self.file_name_length]

    @classmethod
    def from_file(cls, volume):
        """Create a FatXDirent object using a file object.

        Args:
            volume (FatXVolume): Volume that we should read from and that of
                which this dirent will belong to.

        Returns (FatXDirent): Unpacked FatXDirent instance.
        """
        data = volume.infile.read(0x40)
        return cls(data, volume)

    def add_dirent_stream_to_this_directory(self, stream):
        """Adds an entire list of dirents (stream) to this directory.

        A dirent stream is a list of dirents that take up an entire cluster.
        Each stream holds contents of a directory.

        Args:
            stream (FatXDirent[]): List of dirents extracted from a single
                cluster.
        """
        if not self.is_directory():
            raise Exception("This dirent is not a directory!")

        for dirent in stream:
            dirent.parent = self
            self.children.append(dirent)

    def add_child(self, child):
        """Child belongs to this dirent.

        Used to add a dirent to this directory.

        Args:
            child (FatXDirent): Child dirent.
        """
        if not self.is_directory():
            raise Exception("Only directories can have children!")

        self.children.append(child)

    def set_parent(self, parent):
        """This dirent belongs to parent dirent.

        Used to give a dirent a directory to belong to.

        Args:
            parent(FatXDirent): parent dirent.
        """
        self.parent = parent

    def has_parent(self):
        """Whether or not this dirent has a parent.

        Returns (bool):
        """
        return self.parent is not None

    def is_file(self):
        """Whether or not this dirent is a file.

        Returns (bool):
        """
        if self.file_attributes & FILE_ATTRIBUTE_DIRECTORY:
            return False
        return True

    def is_directory(self):
        """Whether or not this dirent is a directory.

        Returns (bool):
        """
        if self.file_attributes & FILE_ATTRIBUTE_DIRECTORY:
            return True
        return False

    def is_deleted(self):
        """Whether or not this dirent was deleted.

        Return (bool):
        """
        if self.file_name_length == DIRENT_DELETED:
            return True
        return False

    def get_path(self):
        """Generate a path string for this dirent.

        This only returns the path, and does not include this dirent's name.

        Returns (str): Path string excluding file name.
        """
        ancestry = []
        if self.parent is not None:
            parent = self.parent
            while parent is not None:
                ancestry.append(parent.file_name)
                parent = parent.parent

        return '/'.join(reversed(ancestry))

    def get_full_path(self):
        """Generate a full path string for this dirent.

        This path string does contain this dirent's name.

        Returns (str): Full path string including file name.
        """
        return '/'.join([self.get_path(), self.file_name])

    ###########################################
    # TODO: need to move these to FatXVolume
    def _set_ts(self, path):
        """Sets a file's timestamps to those stored in this dirent.

        Args:
            path (str): Path to this file on disk.
        """
        # TODO: creation_time only supported on Windows
        # TODO: trying to avoid using win32file to avoid external dependencies
        ats = self.last_access_time
        mts = self.last_write_time
        atime = datetime(year=ats.year,
                         month=ats.month,
                         day=ats.day,
                         hour=ats.hour,
                         minute=ats.min,
                         second=ats.sec)
        mtime = datetime(year=mts.year,
                         month=mts.month,
                         day=mts.day,
                         hour=mts.hour,
                         minute=mts.min,
                         second=mts.sec)

        os.utime(path, (time.mktime(atime.timetuple()),
                        time.mktime(mtime.timetuple())))

    def _write_file(self, path):
        fat = self.volume.file_allocation_table
        max_cluster = 0xfff0 if self.volume.fat16x else 0xfffffff0
        cluster = self.first_cluster
        with open(path, 'wb') as f:
            bufsize = self.volume.bytes_per_cluster
            remains = self.file_size
            while cluster <= max_cluster:
                buf = self.volume.read_cluster(cluster)
                wlen = min(remains, bufsize)
                f.write(buf[:wlen])
                remains -= wlen
                cluster = fat[cluster]

        try:
            self._set_ts(path)
        except:
            print("Failed to set timestamps.")

    def _write_dir(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    def write(self, path):
        if self.is_directory():
            self._write_dir(path)
        else:
            self._write_file(path)

    def recover(self, path, undelete=False):
        """Conventionally extract the file using the file allocation table.

        Args:
            path (str): Output path.
            undelete (bool): Whether or not recover deleted files.
        """
        if (self.is_deleted() and
                undelete is False):
            return
        whole_path = path + '/' + self.file_name
        # print attributes (dir/file/del)
        if self.is_directory():
            prefix = 'DIR  '
        else:
            prefix = 'FILE '
        if self.is_deleted():
            prefix = 'DEL  '
        print(prefix + whole_path)
        if self.is_directory():
            # create directory
            self.write(whole_path)
            for dirent in self.children:
                dirent.recover(whole_path, undelete)
            self._set_ts(whole_path)
        else:
            self.write(whole_path)
            # dump regular file

    ###########################################

    def format_attributes(self):
        attributes = ''

        if self.file_attributes & FILE_ATTRIBUTE_READONLY:
            attributes += 'READONLY '
        if self.file_attributes & FILE_ATTRIBUTE_HIDDEN:
            attributes += 'HIDDEN '
        if self.file_attributes & FILE_ATTRIBUTE_SYSTEM:
            attributes += 'SYSTEM '
        if self.file_attributes & FILE_ATTRIBUTE_DIRECTORY:
            attributes += 'DIRECTORY '
        if self.file_attributes & FILE_ATTRIBUTE_ARCHIVE:
            attributes += 'ARCHIVE '

        return attributes

    def print_dirent(self, root_path):
        whole_path = root_path + '/' + self.file_name

        if self.is_deleted():
            prefix = 'DEL  '
        elif self.is_directory():
            prefix = 'DIR  '
        else:
            prefix = 'FILE '

        print(prefix + whole_path)
        if self.is_directory() and not self.is_deleted():
            for child in self.children:
                child.print_dirent(whole_path)

    def print_fields(self):
        def print_aligned(header, value):
            print("{:<26} {}".format(header, value))

        print_aligned("FileNameLength:", self.file_name_length)
        print_aligned("FileName:", self.file_name)
        print_aligned("FileSize:", '0x{:x} bytes'.format(self.file_size))
        print_aligned("FileAttributes:", self.format_attributes())
        print_aligned("FirstCluster", self.first_cluster)
        print_aligned("CreationTime:", str(self.creation_time))
        print_aligned("LastWriteTime:", str(self.last_write_time))
        print_aligned("LastAccessTime:", str(self.last_access_time))


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

    def __del__(self):
        self.infile.close()

    def mount(self):
        """Loads the FATX file system."""
        LOG.info("Mounting %s", self.name)

        # read volume metadata
        self.read_volume_metadata()

        # calculate file allocation and file area offsets
        self.calculate_offsets()

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
            # break when reserved entry found
            if fat_entry <= reserved_indexes:
                break

            if fat_entry == 0:
                LOG.info("BAIL! Found NULL fat entry!")
                return [first_cluster]

            if fat_entry > len(self.file_allocation_table):
                LOG.info(
                    "BAIL! FAT entry index {} greater than FAT size {}!"
                    .format(
                        fat_entry,
                        len(self.file_allocation_table)))
                return [first_cluster]

            fat_entry = self.file_allocation_table[fat_entry]
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

                for cluster in chain_map:
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
        for _ in xrange(256):
            dirent = FatXDirent.from_file(self)

            # TODO: Perhaps I should also do this before creating the object.
            # check for end of dirent stream
            if (dirent.file_name_length == DIRENT_NEVER_USED or
                    dirent.file_name_length == DIRENT_NEVER_USED2):
                break

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
