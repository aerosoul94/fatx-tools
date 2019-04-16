from __future__ import print_function
from fatx_filesystem import (FatXDirent,
                            DIRENT_DELETED, DIRENT_NEVER_USED,
                            DIRENT_NEVER_USED2, FATX_FILE_NAME_LEN)
import time
import os
import string
import logging
import json

from datetime import date, datetime

__all__ = ['FatXOrphan', 'FatXAnalyzer']

VALID_CHARS = set(string.ascii_letters + string.digits + '!#$%&\'()-.@[]^_`{}~ ')
LOG = logging.getLogger('FATX.Analyzer')

class FatXOrphan(FatXDirent):
    """ An orphaned directory entry. """
    #@profile
    def is_valid(self):
        """ Checks if this recovered dirent is actually valid. """
        # TODO: some valid dirents have invalid cluster indexes
        # TODO: warn user that the file will undoubtedly be corrupted
        # check if it points outside of the partition
        if self.first_cluster > self.volume.max_clusters:
            return False

        # validate file name
        if not all(c in VALID_CHARS for c in self.file_name):
            return False

        def is_valid_date(dt):
            if dt is None:
                # There has to be a date defined.
                return False

            year = dt.year

            if not (year <= date.today().year):
                return False

            # validate date
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

    def add_child(self, child):
        """ This child belongs to this dirent. """
        if not self.is_directory():
            raise Exception("Only directories can have children!")

        self.children.append(child)

    def set_parent(self, parent):
        """ This dirent belongs to this parent dirent. """
        self.parent = parent

    def set_cluster(self, cluster):
        """ This dirent belongs to this cluster. """
        self.cluster = cluster

    def rescue(self, path):
        """ This dumps without relying on the FAT. """
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
                dirent.rescue(whole_path)
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
        self._set_ts(whole_path)


class FatXAnalyzer:
    """ Analyzes a FatX partition for deleted files. """
    def __init__(self, volume):
        self.volume = volume
        self.roots = []     # List[FatXOrphan]
        self.orphanage = [] # List[FatXOrphan]
        self.current_block = 0

    # TODO: add constructor for finding files with corrupted FatX volume metadata
    def get_orphanage(self):
        """ Orphanage contains the list of orphaned dirents. """
        return self.orphanage

    def get_roots(self):
        """ Roots contains a list of linked orphans. """
        return self.roots

    def get_valid_sigs(self):
        """ List of found signatures. """
        return self.found_signatures

    def perform_volume_analysis(self, interval=0x1000):

        pass

    def perform_signature_analysis(self, signatures, interval=0x200, length=0):
        """ Searches for file signatures. """
        LOG.info('signature analysis has begun...')
        # Lets be reasonable
        # BYTE_SIZE    = 0x1     # very slow, you must be desperate?
        # SECTOR_SIZE  = 0x200   # slow, very effective
        # PAGE_SIZE    = 0x1000  # moderate speed, less effective
        # CLUSTER_SIZE = 0x4000  # high speed, least effective
        if interval not in (1, 0x200, 0x1000, 0x4000):
            return ValueError("Valid intervals are 1, 0x200, 0x1000, or 0x4000.")

        if (length == 0 or length > self.volume.length):
            length = self.volume.length

        time0 = time.time()
        self.found_signatures = []
        for index in xrange(length / interval):
            self.current_block = index
            offset = index * interval
            for signature in signatures:
                test = signature(offset, self.volume)
                self.volume.seek_file_area(offset)
                if test.test():
                    test.parse()
                    self.found_signatures.append(test)
                    LOG.info(str(test))
        time1 = time.time()
        LOG.info('analysis finished in %s', time1 - time0)

    def perform_orphan_analysis(self, max_clusters=0):
        """ Searches for FatXDirent structures. """
        LOG.info('orphan analysis has begun...')
        time0 = time.time()
        self.recover_orphans(max_clusters)
        time1 = time.time()
        LOG.info('Linking orphans...')

        # give them a home
        time2 = time.time()
        self.link_orphans()
        time3 = time.time()
        LOG.info('and done. :)')
        LOG.info('Time to analyze partition: %i seconds', time1 - time0)
        LOG.info('Time to rebuild directories: %i seconds', time3 - time2)

    # TODO: optimize file reading
    def recover_orphans(self, max_clusters=0):
        """ Begin search for orphaned dirents. """
        orphans = []
        if (max_clusters > self.volume.max_clusters or
            max_clusters == 0):
            max_clusters = self.volume.max_clusters

        for cluster in range(1, max_clusters):
            self.current_block = cluster
            cache = self.volume.read_cluster(cluster)

            for x in range(256):
                offset = x * 0x40

                name_len = cache[offset]

                # Optimization: Try and avoid creating objects
                # file attributes must be file or directory
                if cache[offset+1] not in ('\x00', '\x10'):
                    continue

                # DIRENT_NEVER_USED and DIRENT_NEVER_USED2
                if name_len in ('\x00', '\x01', '\xff'):
                    continue

                # if file is not deleted, ensure name length is less than max
                if name_len != '\xE5' and name_len > '\x2A':
                    continue

                dirent = FatXOrphan(cache[offset:offset+0x40], self.volume)

                if dirent.is_valid():
                    LOG.info("%#x: %s (cluster %i)", self.volume.cluster_to_physical_offset(cluster),
                                                     dirent.file_name, cluster)
                    dirent.set_cluster(cluster)
                    orphans.append(dirent)

        self.orphanage = orphans

    def find_children(self, parent):
        """ Find children for this directory. """
        for orphan in self.orphanage:
            # if orphan.cluster is in parent.clusters_list
            if orphan.cluster == parent.first_cluster:
                parent.add_child(orphan)
                orphan.set_parent(parent)

    def link_orphans(self):
        """ Link parent directories with their children. """
        for orphan in self.orphanage:
            if orphan.is_directory():
                self.find_children(orphan)

        # find root directories
        for orphan in self.orphanage:
            if orphan.parent is None:
                self.roots.append(orphan)

    def save_dirent(self, root):
        ent = dict()
        ent['offset'] = self.volume.cluster_to_physical_offset(root.cluster)
        ent['cluster'] = root.cluster
        ent['filename'] = root.file_name
        ent['filenamelen'] = root.file_name_length
        ent['filesize'] = root.file_size
        ent['attributes'] = root.file_attributes
        ent['firstcluster'] = root.first_cluster
        ent['creationtime'] = root.creation_time_i
        ent['lastwritetime'] = root.last_write_time_i
        ent['lastaccesstime'] = root.last_access_time_i

        if root.is_directory():
            ent['children'] = []
            for child in root.children:
                ent['children'].append(self.save_dirent(child))

        return ent

    def save_roots(self, name):
        with open('{}.json'.format(name), 'w') as outfile:
            partition = dict()
            # partition['chainmap'] = self.volume.file_allocation_table
            partition['offset'] = self.volume.offset
            partition['length'] = self.volume.length
            partition['roots'] = []
            for root in self.roots:
                partition['roots'].append(self.save_dirent(root))
            json.dump(partition, outfile, indent=1)


