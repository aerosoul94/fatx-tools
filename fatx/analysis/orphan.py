from fatx.filesystem.dirent import FatXDirent
from fatx.filesystem.constants import VALID_FILE_ATTRIBUTES

from datetime import date, datetime
import logging
import string
import os


LOG = logging.getLogger('FATX.Analyzer')


VALID_CHARS = set(string.ascii_letters +
                  string.digits +
                  '!#$%&\'()-.@[]^_`{}~ ' +
                  '\xff')


class FatXOrphan(FatXDirent):
    """Representation of a dirent that has been been recovered by the analyzer.
    This class contains unconventional methods used to operate on recovered
    dirents.
    """
    # @profile
    def is_valid(self):
        """Checks if this recovered dirent is actually valid."""
        # TODO: some valid dirents have invalid cluster indexes
        # TODO: warn user that the file will undoubtedly be corrupted
        # check if it points outside of the partition
        if self.first_cluster > self.volume.max_clusters:
            return False

        # validate file name bytes
        if not all(c in VALID_CHARS for c in self.file_name_bytes):
            return False

        def is_valid_attributes(attr):
            return (attr & ~VALID_FILE_ATTRIBUTES) == 0

        def is_valid_date(dt):
            if dt is None:
                # There has to be a date defined.
                return False

            year = dt.year

            if not (year <= date.today().year):
                return False

            # validate date
            # TODO: check its not from the future
            try:
                datetime(
                    year=year,
                    month=dt.month,
                    day=dt.day,
                    hour=dt.hour,
                    minute=dt.min,
                    second=dt.sec
                )
            except ValueError:
                return False

            return True

        # validate file time stamps
        if (not is_valid_date(self.creation_time) or
            not is_valid_date(self.last_write_time) or
            not is_valid_date(self.last_access_time)):
            return False

        return True

    def set_cluster(self, cluster):
        """ This dirent resides in this cluster. """
        self.cluster = cluster

    def set_offset(self, offset):
        """ This dirent resides at this offset. """
        self.offset = offset

    def rescue_dir(self, path):
        pass

    def recover(self, path):
        """Extracts the file unconventionally by dumping sequential clusters
        since we cannot rely on the file allocation table.

        This method overrides the conventional recover() method in FatXDirent.

        Args:
            path (str): Output path.
        """
        whole_path = path + '/' + self.file_name
        self.volume.seek_to_cluster(self.first_cluster)
        LOG.info('Recovering: %r', whole_path)
        if self.is_directory():
            if not os.path.exists(whole_path):
                try:
                    os.makedirs(whole_path)
                except (OSError, IOError):
                    LOG.exception('Failed to create directory: %s', whole_path)
                    return
            for dirent in self.children:
                dirent.recover(whole_path)
        else:
            try:
                bufsize = 0x100000
                remains = self.file_size

                with open(whole_path, 'wb') as f:
                    while remains > 0:
                        read = min(remains, bufsize)
                        remains -= read
                        buf = self.volume.infile.read(read)
                        f.write(buf)
            except (OSError, IOError, OverflowError):
                LOG.exception('Failed to create file: %s', whole_path)
        try:
            self._set_ts(whole_path)
        except:
            # TODO: try and fix these errors...
            LOG.exception("Failed to set timestamp.")
