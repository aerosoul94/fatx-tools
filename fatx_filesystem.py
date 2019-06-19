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
    __slots__ = ('time',)

    def __init__(self, time_stamp):
        self.time = time_stamp

    def __str__(self):
        '''
        try:
            # TODO: think of a reliable way of detecting proto X360 timestamps
            if self.year > date.today().year:
                raise Exception
            return str(datetime(year=self.year, month=self.month, day=self.day,
                            hour=self.hour, minute=self.min, second=self.sec))
        except:
            return str(datetime(year=((self.time & 0xffff) & 0x7f) + 2000,
                                month=((self.time & 0xffff) >> 7) & 0xf,
                                day=((self.time & 0xffff) >> 0xb),
                                hour=((self.time >> 16) & 0x1f),
                                minute=((self.time >> 16) >> 5) & 0x3f,
                                second=((self.time >> 16) >> 10) & 0xfffe))
        '''
        return '{}/{}/{} {}:{:02d}:{:02d}'.format(
                self.month, self.day, self.year,
                self.hour, self.min, self.sec
            )

    @property
    def year(self):
        year = (self.time & 0xFE000000) >> 25
        return year

    @property
    def month(self):
        month = (self.time & 0x1E00000) >> 21
        return month

    @property
    def day(self):
        day = (self.time & 0x1F0000) >> 16
        return day

    @property
    def hour(self):
        hour = (self.time & 0xF800) >> 11
        return hour

    @property
    def min(self):
        min = (self.time & 0x7E0) >> 5
        return min

    @property
    def sec(self):
        sec = (self.time & 0x1F) * 2
        return sec


class X360TimeStamp(FatXTimeStamp):
    @property
    def year(self):
        year = (((self.time & 0xFE000000) >> 25) + 1980)
        return year


class XTimeStamp(FatXTimeStamp):
    @property
    def year(self):
        year = (((self.time & 0xFE000000) >> 25) + 2000)
        return year


FATX_SECTOR_SIZE    = 0x200
FATX_PAGE_SIZE      = 0x1000

FATX_SIGNATURE      = 0x58544146    # "FATX"
FATX_FILE_NAME_LEN  = 42

FATX_MAX_DIRECTORY_SIZE = 0x40000

FILE_ATTRIBUTE_READONLY     = 0x00000001
FILE_ATTRIBUTE_HIDDEN       = 0x00000002
FILE_ATTRIBUTE_SYSTEM       = 0x00000004
FILE_ATTRIBUTE_DIRECTORY    = 0x00000010
FILE_ATTRIBUTE_ARCHIVE      = 0x00000020

# evaluates to 0x37
VALID_FILE_ATTRIBUTES = FILE_ATTRIBUTE_READONLY | \
    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | \
    FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ARCHIVE

DIRENT_NEVER_USED   = 0x00
DIRENT_DELETED      = 0xE5
DIRENT_NEVER_USED2  = 0xFF


class FatXDirent:
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
    def from_file(cls, file, volume):
        data = file.read(0x40)
        return cls(data, volume)

    def add_dirent_stream_to_this_directory(self, stream):
        if not self.is_directory():
            raise Exception("This dirent is not a directory!")

        for dirent in stream:
            dirent.parent = self
            self.children.append(dirent)

    def add_child(self, child):
        """ This child belongs to this dirent. """
        if not self.is_directory():
            raise Exception("Only directories can have children!")

        self.children.append(child)

    def set_parent(self, parent):
        """ This dirent belongs to this parent dirent. """
        self.parent = parent

    def has_parent(self):
        return self.parent is not None

    def is_file(self):
        if self.file_attributes & FILE_ATTRIBUTE_DIRECTORY:
            return False
        return True
    
    def is_directory(self):
        if self.file_attributes & FILE_ATTRIBUTE_DIRECTORY:
            return True
        return False

    def is_deleted(self):
        if self.file_name_length == DIRENT_DELETED:
            return True
        return False

    def get_path(self):
        ancestry = []
        if self.parent is not None:
            parent = self.parent
            while parent is not None:
                ancestry.append(parent.file_name)
                parent = parent.parent

        return '/'.join(reversed(ancestry))

    def get_full_path(self):
        return '/'.join([self.get_path(), self.file_name])

    ###########################################
    # TODO: need to move these to FatXVolume
    def _set_ts(self, path):
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
        """ Recover legitimately using the FAT. """
        if (self.is_deleted() and
            undelete == False):
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
    def __init__(self, file, name, offset, length, byteorder):
        self.infile = file
        self.name = name
        self.offset = offset
        self.length = length
        self.endian_fmt = byteorder
        self.FATX_FORMAT = self.endian_fmt + 'LLLL'
        self.DIRENT_FORMAT = self.endian_fmt + 'BB42sLLLLL'
        self.ts_format = XTimeStamp if byteorder == '<' else X360TimeStamp
        self._root = []

    def __del__(self):
        self.infile.close()

    def mount(self):
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

    def is_valid_cluster(self, cluster):
        return (cluster - 1) < self.max_clusters

    def get_root(self):
        return self._root

    def seek_file_area(self, offset, whence=0):
        """ Seek relative to file_area_byte_offset """
        offset += self.file_area_byte_offset + self.offset
        self.infile.seek(offset, whence)

    def read_file_area(self, size):
        return self.infile.read(size)

    def read_cluster(self, cluster):
        self.infile.seek(self.cluster_to_physical_offset(cluster))
        return self.infile.read(self.bytes_per_cluster)

    def seek_to_cluster(self, cluster):
        self.infile.seek(self.cluster_to_physical_offset(cluster))

    def byte_offset_to_cluster(self, offset):
        return (offset // self.bytes_per_cluster) + 1

    def byte_offset_to_physical_offset(self, offset):
        return self.offset + offset

    def cluster_to_physical_offset(self, cluster):
        return (self.offset +
                self.file_area_byte_offset +
                (self.bytes_per_cluster * (cluster - 1)))

    def read_volume_metadata(self):
        self.infile.seek(self.offset)

        (self.signature,
         self.serial_number,
         self.sectors_per_cluster,
         self.root_dir_first_cluster) = struct.unpack(self.FATX_FORMAT, self.infile.read(struct.calcsize(self.FATX_FORMAT)))

        # TODO: Remove this in order to handle corrupted metadata
        if self.signature != FATX_SIGNATURE:
            raise ValueError("Invalid FATX signature!")

    def get_dirent_buffer(self, cluster_map):
        buffer = ''
        for cluster in cluster_map:
            buffer += self.read_cluster(cluster)
        return buffer

    def get_cluster_chain(self, first_cluster):
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
                LOG.info("BAIL! FAT entry index {} greater than FAT size {}!".format(fat_entry,
                                                                                  len(self.file_allocation_table)))
                return [first_cluster]

            fat_entry = self.file_allocation_table[fat_entry]
            chain.append(fat_entry)
        return chain

    def read_file_allocation_table(self):
        def construct_fat_format(num_clusters):
            return self.endian_fmt + (('H' if self.fat16x else 'L') * num_clusters)

        fat_offset = self.byte_offset_to_physical_offset(self.fat_byte_offset)
        self.infile.seek(fat_offset)
        fat_format = construct_fat_format(self.max_clusters)
        fat_length = struct.calcsize(fat_format)
        fat_table  = self.infile.read(fat_length)
        return [entry for entry in struct.unpack(fat_format, fat_table)]

    def calculate_offsets(self):
        # reserved for volume metadata
        reserved_bytes = 0x1000

        # most commonly 0x4000
        self.bytes_per_cluster = self.sectors_per_cluster * FATX_SECTOR_SIZE
        
        self.max_clusters = (self.length // self.bytes_per_cluster) + 1  # +1 is reserved_fat_entries
        if self.max_clusters < 0xfff0:
            bytes_per_fat = self.max_clusters * 2
            self.fat16x = True
        else:
            bytes_per_fat = self.max_clusters * 4
            self.fat16x = False

        # align to nearest page
        bytes_per_fat = (bytes_per_fat + (FATX_PAGE_SIZE - 1)) & ~(FATX_PAGE_SIZE - 1)

        # offset of file allocation table
        self.fat_byte_offset = reserved_bytes
        # offset of file area
        self.file_area_byte_offset = self.fat_byte_offset + bytes_per_fat

    def populate_dirent_stream(self, stream):
        for dirent in stream:
            LOG.info("%s", dirent.get_full_path())
            if dirent.is_directory() and \
                    not dirent.is_deleted():  # dirent stream not guaranteed if deleted.

                chain_map = self.get_cluster_chain(dirent.first_cluster)

                for cluster in chain_map:
                    dirent_stream = self.read_directory_stream(
                        self.cluster_to_physical_offset(cluster))

                    dirent.add_dirent_stream_to_this_directory(dirent_stream)
                    # TODO: populate_children()
                    self.populate_dirent_stream(dirent_stream)

    def read_directory_stream(self, offset):
        stream = []

        self.infile.seek(offset)
        for _ in xrange(256):
            dirent = FatXDirent.from_file(self.infile, self)

            # TODO: Perhaps I should also do this before creating the object.
            # check for end of dirent stream
            if (dirent.file_name_length == DIRENT_NEVER_USED or
                dirent.file_name_length == DIRENT_NEVER_USED2):
                break

            stream.append(dirent)

        return stream

    def print_volume_metadata(self):
        def print_aligned(header, value=''):
            print("{:<26} {}".format(header, value))

        print_aligned("Signature:", self.signature)
        print_aligned("SerialNumber:", self.serial_number)
        print_aligned("SectorsPerCluster:", "{} (0x{:x} bytes)".format(
            self.sectors_per_cluster, self.sectors_per_cluster * FATX_SECTOR_SIZE))
        print_aligned('RootDirFirstCluster:', self.root_dir_first_cluster)
        print("")

        print_aligned("Calculated Offsets:")
        print_aligned("PartitionOffset:", "0x{:x}".format(self.offset))
        print_aligned("FatByteOffset:", "0x{:x} (+0x{:x})".format(
            self.byte_offset_to_physical_offset(self.fat_byte_offset), self.fat_byte_offset))
        print_aligned("FileAreaByteOffset:", "0x{:x} (+0x{:x})".format(
            self.byte_offset_to_physical_offset(self.file_area_byte_offset), self.file_area_byte_offset))
        print("")
