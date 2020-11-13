import logging
import time


LOG = logging.getLogger('FATX.Analyzer')


class FatXCarver:
    def __init__(self, volume):
        self.volume = volume
        self.found_signatures = []
        self.current_block = 0

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
            return ValueError(
                "Valid intervals are 1, 0x200, 0x1000, or 0x4000.")

        if length == 0 or length > self.volume.length:
            length = self.volume.length

        time0 = time.time()
        for index in xrange(length / interval):
            self.current_block = index
            offset = index * interval
            for signature in signatures:
                test = signature(offset, self.volume)
                # seek to test the data
                self.volume.seek_file_area(offset)
                if test.test():
                    # seek to parse the data
                    self.volume.seek_file_area(offset)
                    test.parse()
                    self.found_signatures.append(test)
                    LOG.info(str(test))
        time1 = time.time()
        LOG.info('analysis finished in %s', time1 - time0)
