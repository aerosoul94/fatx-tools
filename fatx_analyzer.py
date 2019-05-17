from fatx_filesystem import FatXDirent, FATX_SIGNATURE, VALID_FILE_ATTRIBUTES
import time
import os
import string
import logging
import json
import struct

try:
    xrange
except NameError:
    xrange = range

from datetime import date, datetime

__all__ = ['FatXOrphan', 'FatXAnalyzer']

VALID_CHARS = set(string.ascii_letters + string.digits + '!#$%&\'()-.@[]^_`{}~ ' + '\xff')
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
        """ This dirent belongs to this cluster. """
        self.cluster = cluster

    def set_offset(self, offset):
        self.offset = offset

    def rescue_dir(self, path):
        pass

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
        try:
            self._set_ts(whole_path)
        except:
            # TODO: try and fix these errors...
            LOG.exception("Failed to set timestamp.")


class FatXAnalyzer:
    """ Analyzes a FatX partition for deleted files. """
    def __init__(self, volume, full_scan=False):
        self.volume = volume
        self.roots = []      # List[FatXOrphan]
        self.orphanage = []  # List[FatXOrphan]
        self.found_signatures = []
        self.full_scan = full_scan
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

        if length == 0 or length > self.volume.length:
            length = self.volume.length

        time0 = time.time()
        for index in xrange(length / interval):
            self.current_block = index
            offset = index * interval
            for signature in signatures:
                test = signature(offset, self.volume)
                # seek to test
                self.volume.seek_file_area(offset)
                if test.test():
                    # seek to parse
                    self.volume.seek_file_area(offset)
                    test.parse()
                    self.found_signatures.append(test)
                    LOG.info(str(test))
        time1 = time.time()
        LOG.info('analysis finished in %s', time1 - time0)

    def perform_orphan_analysis(self, max_clusters=0):
        """ Searches for FatXDirent structures. """
        LOG.info('Orphan analysis has begun...')
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
            if len(cache) != 0x4000:
                LOG.warn("Failed to read cluster %i" % cluster)
                continue

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
                    offset = self.volume.cluster_to_physical_offset(cluster) + offset
                    LOG.info("%#x: %s (cluster %i)", offset, dirent.file_name, cluster)
                    dirent.set_cluster(cluster)
                    dirent.set_offset(offset)
                    orphans.append(dirent)

        self.orphanage = orphans

    def find_children(self, parent):
        """ Find children for this directory. """
        chain_map = self.volume.get_cluster_chain(parent.first_cluster)
        # chain map should not have any free clusters
        # should be done by get_cluster_chain_map()
        ''' 
        TODO: do our best to detect invalid chains
         check if directories do not have more than 0x40000 dirents
        '''
        '''
        for cluster in chain_map:
            if cluster == 0:
                chain_map = [parent.first_cluster]
        '''
        for orphan in self.orphanage:
            # if orphan.cluster is in parent.clusters_list
            if orphan.cluster in chain_map:
                parent.add_child(orphan)
                # TODO: maybe do away with 'parent' attribute?
                # TODO: we need parent for get_full_path() though
                if orphan.has_parent():
                    LOG.warning('%s already has a parent!', orphan.file_name)
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
        ent['offset'] = root.offset
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

    # TODO: recover fatx volumes
    def perform_volume_analysis(self):
        infile = self.volume.infile
        infile.seek(0, 2)
        inlen = infile.tell()
        infile.seek(0, 1)

        remnants = []

        sig_fmt = self.volume.endian_fmt + "L"

        off = 0
        while off < inlen:
            infile.seek(off)
            sig = struct.unpack(sig_fmt, infile.read(4))
            if sig == FATX_SIGNATURE:
                # TODO: check if not an already recognized partition
                remnants.append(off)
                pass

            off += 0x200

        # check for overlap to avoid scanning the same dirents more than once
        # recover all dirents relative to the current partition
        pass

    def guess_fat_entry_size(self):
        # make sure that first entry is MEDIA and second is LAST
        reserved_fat_entry = struct.unpack(self.volume.endian_fmt + 'L', self.volume.infile.read(4))[0]
        if reserved_fat_entry != 0xfffffff8:
            reserved_fat_entry = struct.unpack(self.volume.endian_fmt + 'H', self.volume.infile.read(2))[0]
            if reserved_fat_entry == 0xfff8:
                self.fat16x = True
        elif reserved_fat_entry == 0xfffffff8:
            self.fat16x = False
        else:
            return False
        return True

    def guess_root_dirent_offset(self):
        # use FatXOrphan to find first dirent.
        return 0

    def calculate_partition_size(self):
        fat_offset = self.volume.infile.tell()

        # is this 16 or 32 bit?
        fat_entry_size = self.guess_fat_entry_size()

        # find root dirent
        root_offset = self.guess_root_dirent_offset()

        # bytes_per_fat should be aligned to nearest page
        bytes_per_fat = root_offset - fat_offset

        # now just do reverse calculation
        max_cluster = bytes_per_fat / fat_entry_size
        length = (max_cluster - 1) * self.volume.bytes_per_cluster

        # make sure partition length doesn't extend past end of drive
        # round to nearest cluster
        drive_length = 0
        length = min(drive_length - self.volume.offset, length)
