from .orphan import FatXOrphan

import logging
import time
import json


LOG = logging.getLogger('FATX.Analyzer')


class FatXAnalyzer:
    """ Implementation of an analyzer that tries to recover files from a FATX
     volume.

     Args:
        volume (FatXVolume): Volume that we will perform recovery on.
        full_scan (bool): (TODO) A full scan will attempt to recover from an
            entire image rather than just the volume.
    """
    def __init__(self, volume, full_scan=False):
        self.volume = volume
        self.roots = []      # List[FatXOrphan]
        self.orphanage = []  # List[FatXOrphan]
        self.current_block = 0

    # TODO: add constructor for finding files with corrupted FatX volume
    #  metadata
    def get_orphanage(self):
        """ Orphanage contains the list of orphaned (recovered) dirents. """
        return self.orphanage

    def get_roots(self):
        """ Roots contains a list of linked orphans. """
        return self.roots

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
        if (max_clusters > self.volume.max_clusters or max_clusters == 0):
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
                    offset = self.volume.cluster_to_physical_offset(cluster) \
                             + offset
                    LOG.info("%#x: %s (cluster %i)",
                             offset, dirent.file_name, cluster)
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
