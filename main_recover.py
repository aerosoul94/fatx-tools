from fatx_analyzer import FatXAnalyzer
from fatx_x360 import X360Drive, x360_signatures
from fatx_xog import XOGDrive, xog_signatures
import argparse

MODE_XBOG = 0
MODE_X360 = 1

def main_recover(args):
	with open(args.inputfile, 'rb') as infile:
		drive = None
		if args.mode == MODE_XBOG:
			drive = XOGDrive(infile)
		elif args.mode == MODE_X360:
			drive = X360Drive(infile)

		if drive is not None:
			volume = drive.get_partition(args.index)
			volume.mount()
			analyzer = FatXAnalyzer(volume)

			# orphan scanner will look for anything that looks
			# like a valid DIRENT entry for complete file info
			if args.scan_orphans:
				if args.recover and not args.outputpath:
					raise Exception("Must supply output path if recovering files! (--outputpath)")

				analyzer.perform_orphan_analysis()
				roots = analyzer.get_roots()
				for root in roots:
					root.print_dirent('.')

				if args.recover:
					for root in roots:
						root.rescue(args.outputpath)

			# signature scanner will go through each cluster
			# testing various signatures to see if they match
			if args.scan_signatures:
				if args.recover and not args.outputpath:
					raise Exception("Must supply output path if recovering files! (--outputpath)")

				if args.mode == MODE_XBOG:
					analyzer.perform_signature_analysis(xog_signatures)
				elif args.mode == MODE_X360:
					analyzer.perform_signature_analysis(x360_signatures)

				if args.recover:
					for find in analyzer.found_signatures:
						find.recover(args.outputpath)


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--inputfile", help="Input image file.", type=str)
	parser.add_argument("-o", "--outputpath", help="Output directory", type=str)
	parser.add_argument("-n", "--index", help="Partition index.", type=int)
	parser.add_argument("-m", "--mode", help="OS Mode (0=XBox Original,1=Xbox 360).", type=int)
	parser.add_argument("-so", "--scan-orphans", help="Use orphan scanner.", action="store_true")
	parser.add_argument("-ss", "--scan-signatures", help="Use signature scanner", action="store_true")
	parser.add_argument("-r", "--recover", help="Recover files to output path.", action="store_true")
	args = parser.parse_args()

	main_recover(args)
