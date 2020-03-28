from fatx_drive import FatXDrive
import argparse
import os
import logging
import sys


LOG = logging.getLogger('FATX')


def main(arg):
    # TODO: have the option to specify a custom range
    with open(arg.inputfile, 'rb') as infile:
        drive = FatXDrive(infile)

        if arg.print_drive:
            print("Partitions:")
            drive.print_partitions()

        if arg.print_files or arg.print_partition or arg.recover:
            if not arg.index:
                raise Exception("Must specify a partition index in order to print its contents (--index).")

            fatx = drive.get_partition(arg.index)
            fatx.mount()

            if arg.print_partition:
                fatx.print_volume_metadata()

            if arg.print_files or arg.recover:
                root_dir = fatx.get_root()

                if len(root_dir) == 0:
                    print("No files in this partition!")
                else:
                    if arg.print_files:
                        for dirent in root_dir:
                            dirent.print_dirent("root:")
                    if arg.recover:
                        if not arg.outpath:
                            raise Exception("Must specify an output path (--output).")

                        if not os.path.exists(arg.outpath):
                            os.makedirs(arg.outpath)

                        for dirent in root_dir:
                            dirent.recover(arg.outpath, arg.undelete)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Xbox 360 and Xbox Original drive utilities.")
    parser.add_argument("-i", "--inputfile", help="Input image file.", type=str)
    parser.add_argument("-o", "--outpath", help="Path to write recovered files.", type=str)
    parser.add_argument("-n", "--index", help="Partition index.", type=int)
    parser.add_argument("-d", "--print-drive", help="Print drive partitions.", action='store_true')
    parser.add_argument("-f", "--print-files", help="Print files in partition.", action='store_true')
    parser.add_argument("-p", "--print-partition", help="Print partition volume metadata.", action='store_true')
    parser.add_argument("-r", "--recover", help="Recover files.", action="store_true")
    parser.add_argument("-u", "--undelete", help="Recover files marked as deleted.", action="store_true")
    parser.add_argument("-v", "--verbosity", help="Verbose level.", type=str, default="NOTSET")
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

    main(args)
