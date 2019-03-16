from __future__ import print_function
from fatx_filesystem import (FatXDirent,
                            DIRENT_DELETED, DIRENT_NEVER_USED,
                            DIRENT_NEVER_USED2, FATX_FILE_NAME_LEN)
import time
import os
import string
import logging
import shutil

from datetime import date, datetime

__all__ = ['FatXOrphan', 'FatXAnalyzer']

VALID_CHARS = set(string.ascii_letters + string.digits + '!#$%&\'()-.@[]^_`{}~ ')
LOG = logging.getLogger('FATX.Analyzer')

class FatXOrphan(FatXDirent):
    """ An orphaned directory entry. """
    def is_valid(self):
        """ Checks if this recovered dirent is actually valid. """
        name_len = self.file_name_length

        # DIRENT_NEVER_USED is never set by the kernel
        # DIRENT_NEVER_USED2 is set during initialization
        # and after a format
        if name_len == DIRENT_NEVER_USED:
            return False

        # validate file name length
        if name_len not in (DIRENT_DELETED, DIRENT_NEVER_USED2)
            and name_len > FATX_FILE_NAME_LEN:
            return False

        # check if it points outside of the partition
        if self.first_cluster > self.volume.max_clusters:
            return False

        # validate file name
        if not all(c in VALID_CHARS for c in self.file_name):
            return False

        def is_valid_date(d, name='UNK'):
            if d is None:
                # There has to be a date defined.
                return False

            if not (2000 <= d.get_year() <= d.today().year):
                # The date has to be between 2000 and the current year
                return False

            try:
                # Validate date+time
                datetime(
                    year=d.get_year(),
                    month=d.get_month(),
                    day=d.get_day(),
                    hour=d.get_hour(),
                    minute=d.get_min(),
                    second=d.get_sec()
                )
            except ValueError:
                return False

            return True

        if (not is_valid_date(self.creation_time, 'creation time') or
            not is_valid_date(self.last_write_time, 'last write time') or
            not is_valid_date(self.last_access_time, '')):
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
                else:
                    for dirent in self.children:
                        dirent.rescue(whole_path)
        else:
            try:
                with open(whole_path, 'wb') as file:
                    shutil.copyfileobj(self.volume.infile, file, length=self.file_size)
            except (OSError, IOError):
                LOG.exception('Failed to create file: %s', whole_path)


class FatXAnalyzer:
    """ Analyzes a FatX partition for deleted files. """
    def __init__(self, volume):
        self.volume = volume
        self.roots = []     # List[FatXOrphan]
        self.orphanage = [] # List[FatXOrphan]

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

    def perform_signature_analysis(self, signatures):
        """ Searches for file signatures. """
        LOG.info('signature analysis has begun...')
        time0 = time.time()
        self.found_signatures = []
        for cluster in range(1, self.volume.max_clusters):
            for signature in signatures:
                test = signature(cluster, self.volume)
                self.volume.seek_to_cluster(cluster)
                if test.test():
                    test.parse()
                    self.found_signatures.append(test)
        time1 = time.time()
        LOG.info('analysis finished in %s', time1 - time0)

        for sig in self.found_signatures:
            sig.print_stats()

    def perform_orphan_analysis(self):
        """ Searches for FatXDirent structures. """
        LOG.info('orphan analysis has begun...')
        time0 = time.time()
        self.recover_orphans()
        time1 = time.time()
        LOG.info('analysis finished in %s seconds. Linking orphans...', time1 - time0)

        # give them a home
        self.link_orphans()
        LOG.info('and done. :)')

    def recover_orphans(self):
        """ Begin search for orphaned dirents. """
        orphans = []

        for cluster in range(1, self.volume.max_clusters):
            cache = self.volume.read_cluster(cluster)

            for x in range(256):
                offset = x * 0x40

                # optimization: dirent->file_name_length == DIRENT_NEVER_USED
                # also avoid 1 character file_name_length
                if cache[offset] in (chr(0), chr(1)):
                    continue

                dirent = FatXOrphan(cache[offset:offset+0x40], self.volume)

                if dirent.is_valid():
                    dirent.set_cluster(cluster)
                    orphans.append(dirent)

        self.orphanage = orphans

    def find_children(self, parent):
        """ Find children for this directory. """
        for orphan in self.orphanage:
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
