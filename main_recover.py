from fatx_analyzer import FatXAnalyzer
from fatx_drive import FatXDrive, DRIVE_XBOX, DRIVE_X360, x360_signatures, x_signatures
import argparse

def main_recover(args):
    with open(args.inputfile, 'rb') as infile:
        drive = FatXDrive(infile)

        if drive is not None:
            volume = drive.get_partition(args.index)
            volume.mount()
            analyzer = FatXAnalyzer(volume)

            # orphan scanner will look for anything that looks
            # like a valid DIRENT entry for complete file info
            if args.scan_orphans:
                if args.recover and not args.outputpath:
                    raise Exception("Must supply output path if recovering files! (--outputpath)")

                analyzer.perform_orphan_analysis(max_clusters=args.so_length)
                roots = analyzer.get_roots()
                for root in roots:
                    root.print_dirent('.')

                if args.recover:
                    for root in roots:
                        root.rescue(args.outputpath)

            # signature scanner will go through blocks of data
            # testing various signatures to see if they match
            if args.scan_signatures:
                if args.recover and not args.outputpath:
                    raise Exception("Must supply output path if recovering files! (--outputpath)")

                if drive.mode == DRIVE_XBOX:
                    analyzer.perform_signature_analysis(x_signatures,
                                                        interval=args.ss_interval,
                                                        length=args.ss_length)
                elif drive.mode == DRIVE_X360:
                    analyzer.perform_signature_analysis(x360_signatures,
                                                        interval=args.ss_interval,
                                                        length=args.ss_length)

                if args.recover:
                    for find in analyzer.found_signatures:
                        find.recover(args.outputpath)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--inputfile", help="Input image file.", type=str)
    parser.add_argument("-o", "--outputpath", help="Output directory", type=str)
    parser.add_argument("-n", "--index", help="Partition index.", type=int)
    parser.add_argument("-r", "--recover", help="Recover files to output path.", action="store_true")

    parser.add_argument("-so", "--scan-orphans", help="Use orphan scanner.", action="store_true")
    parser.add_argument("-son", "--so-length", help="Number of clusters to search through.",
                        type=lambda x: int(x, 0), default=0)

    parser.add_argument("-ss", "--scan-signatures", help="Use signature scanner.", action="store_true")
    parser.add_argument("-ssx", "--ss-interval", help="Interval for finding signatures (default is 0x200).",
                        type=lambda x: int(x, 0), default=0x1000)
    parser.add_argument("-ssl", "--ss-length", help="Maximum amount of data to search through.",
                        type=lambda x: int(x, 0), default=0)

    args = parser.parse_args()

    main_recover(args)
