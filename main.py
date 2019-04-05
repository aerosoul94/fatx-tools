#!/usr/bin/python

from fatx_x360 import X360Drive
from fatx_xog import XOGDrive
import argparse
import os

MODE_XBOG = 0
MODE_X360 = 1

def main(args):
    # TODO: have the option to specify a custom range
    with open(args.inputfile, 'rb') as infile:
        drive = None

        # choose a drive
        if args.mode == MODE_XBOG:
            drive = XOGDrive(infile)
        elif args.mode == MODE_X360:
            drive = X360Drive(infile)

        if args.print_drive:
            print "Partitions:"
            drive.print_partitions()

        if args.print_files or args.print_partition or args.recover:
            if not args.index:
                raise Exception("Must specify a partition index in order to print its contents (--index).")

            fatx = drive.get_partition(args.index)
            fatx.mount()

            if args.print_partition:
                fatx.print_volume_metadata()

            if args.print_files or args.recover:
                root_dir = fatx.get_root()

                if len(root_dir) == 0:
                    print "No files in this partition!"
                else:
                    if args.print_files:
                        for dirent in root_dir:
                            dirent.print_dirent("root:")
                    if args.recover:
                        if not args.outpath:
                            raise Exception("Must specify an output path (--output).")

                        if not os.path.exists(args.outpath):
                            os.makedirs(args.outpath)

                        for dirent in root_dir:
                            dirent.recover(args.outpath, args.undelete)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Xbox 360 and Xbox Original drive utilities.")
    parser.add_argument("-i", "--inputfile", help="Input image file.", type=str)
    parser.add_argument("-o", "--outpath", help="Path to write recovered files.", type=str)
    parser.add_argument("-n", "--index", help="Partition index.", type=int)
    parser.add_argument("-m", "--mode", help="Xbox mode (0=Xbox Original, 1=Xbox 360)", type=int)
    parser.add_argument("-d", "--print-drive", help="Print drive partitions.", action='store_true')
    parser.add_argument("-f", "--print-files", help="Print files in partition.", action='store_true')
    parser.add_argument("-p", "--print-partition", help="Print partition volume metadata.", action='store_true')
    parser.add_argument("-r", "--recover", help="Recover files.", action="store_true")
    parser.add_argument("-u", "--undelete", help="Recover files marked as deleted.", action="store_true")
    args = parser.parse_args()

    main(args)
