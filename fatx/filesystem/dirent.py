from fatx.filesystem.constants import \
    DIRENT_DELETED, \
    DIRENT_NEVER_USED, \
    DIRENT_NEVER_USED2, \
    FILE_ATTRIBUTE_DIRECTORY, \
    FILE_ATTRIBUTE_ARCHIVE, \
    FILE_ATTRIBUTE_HIDDEN, \
    FILE_ATTRIBUTE_READONLY, \
    FILE_ATTRIBUTE_SYSTEM

from datetime import datetime
import struct
import time
import os


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