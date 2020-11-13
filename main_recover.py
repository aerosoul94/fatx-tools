import argparse
import sys
import os
import logging

from fatx.analysis.metadata_analyzer import FatXAnalyzer
from fatx.analysis.file_carver import FatXCarver
from fatx.drive.drive import FatXDrive, \
    DRIVE_X360, DRIVE_XBOX, x360_signatures, x_signatures


LOG = logging.getLogger('FATX')


def main_recover(arg):
    with open(arg.inputfile, 'rb') as infile:
        drive = FatXDrive(infile)
        basename = os.path.basename(arg.inputfile)

        if drive is not None:
            volume = drive.get_partition(arg.index)
            volume.mount()

            # orphan scanner will look for anything that looks
            # like a valid DIRENT entry for complete file info
            if arg.scan_orphans:
                if arg.recover and not arg.outputpath:
                    raise Exception("Must supply output path if recovering files! (--outputpath)")

                analyzer = FatXAnalyzer(volume)
                analyzer.perform_orphan_analysis(max_clusters=arg.so_length)
                analyzer.save_roots(basename)
                roots = analyzer.get_roots()
                for root in roots:
                    root.print_dirent('.')

                if arg.recover:
                    if not os.path.exists(args.outputpath):
                        os.mkdir(args.outputpath)

                    for root in roots:
                        root_dir = args.outputpath + '/cluster' + str(root.cluster)
                        if not os.path.exists(root_dir):
                            os.mkdir(root_dir)

                        root.recover(root_dir)

            # signature scanner will go through blocks of data
            # testing various signatures to see if they match
            if arg.scan_signatures:
                if arg.recover and not arg.outputpath:
                    raise Exception("Must supply output path if recovering files! (--outputpath)")

                analyzer = FatXCarver(volume)
                if drive.mode == DRIVE_XBOX:
                    analyzer.perform_signature_analysis(x_signatures,
                                                        interval=arg.ss_interval,
                                                        length=arg.ss_length)
                elif drive.mode == DRIVE_X360:
                    analyzer.perform_signature_analysis(x360_signatures,
                                                        interval=arg.ss_interval,
                                                        length=arg.ss_length)

                if arg.recover:
                    for find in analyzer.found_signatures:
                        find.recover(arg.outputpath)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--inputfile", help="Input image file.", type=str)
    parser.add_argument("-o", "--outputpath", help="Output directory", type=str)
    parser.add_argument("-n", "--index", help="Partition index.", type=int)
    parser.add_argument("-r", "--recover", help="Recover files to output path.", action="store_true")
    # TODO:
    #  - Only print the files found if this flag is set.
    #  - Don't use log file. Instead have user redirect stdout to file.
    parser.add_argument("-v", "--verbosity", help="Verbose level.", type=str, default="NOTSET")

    parser.add_argument("-so", "--scan-orphans", help="Use orphan scanner.", action="store_true")
    parser.add_argument("-son", "--so-length", help="Number of clusters to search through.",
                        type=lambda x: int(x, 0), default=0)

    parser.add_argument("-ss", "--scan-signatures", help="Use signature scanner.", action="store_true")
    parser.add_argument("-ssx", "--ss-interval", help="Interval for finding signatures (default is 0x200).",
                        type=lambda x: int(x, 0), default=0x1000)
    parser.add_argument("-ssl", "--ss-length", help="Maximum amount of data to search through.",
                        type=lambda x: int(x, 0), default=0)

    args = parser.parse_args()

    log_verbosity = [v for k, v in logging.__dict__.items() if k.startswith(args.verbosity.upper())][0]

    _stream = logging.StreamHandler(sys.stdout)
    _stream.setLevel(logging.INFO)
    _stream.setFormatter(logging.Formatter('%(levelname).4s: %(message)s'))

    if log_verbosity != logging.NOTSET:
        _file = logging.FileHandler('log.txt', 'w', 'utf-8')
        _file.setLevel(logging.DEBUG)
        _file.setFormatter(
            logging.Formatter('%(module)s::%(funcName)s::%(lineno)d %(levelname).4s %(asctime)s - %(message)s'))
        LOG.setLevel(log_verbosity)
        LOG.addHandler(_file)
    else:
        LOG.setLevel(logging.INFO)

    LOG.addHandler(_stream)

    main_recover(args)
