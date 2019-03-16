# fatx-tools
A set of data recovery tools for the Xbox Original and Xbox 360 consoles.

There are currently two tools. The first is for legitimate file system mounting and extracting. The second is for recovering orphaned files.

## Usage
Both tools require an image of an hdd. 

You must specify all of these options:

 * `-i=<infile>` for the image file
 * `-m=(0|1)` 0 for Xbox Original or 1 for Xbox 360

Start by printing partition information `-d` in order to get the index of the partition to work on.
##### Printing drive partition details:
`python main.py -d -m=(0|1) -i=<infile>`

Once you have the partition index, you must specify it to perform any function using `-n=<index>`

### main
This tool reads the file system the way it was meant to be read.
~~~
usage: main.py [-h] [-i INPUTFILE] [-o OUTPATH] [-n INDEX] [-m MODE] [-d] [-f]
               [-p] [-r] [-u]

Xbox 360 and Xbox Original drive utilities.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUTFILE, --inputfile INPUTFILE
                        Input image file.
  -o OUTPATH, --outpath OUTPATH
                        Path to write recovered files.
  -n INDEX, --index INDEX
                        Partition index.
  -m MODE, --mode MODE  Xbox mode (0=Xbox Original, 1=Xbox 360)
  -d, --print-drive     Print drive partitions.
  -f, --print-files     Print files in partition.
  -p, --print-partition
                        Print partition volume metadata.
  -r, --recover         Recover files.
  -u, --undelete        Recover files marked as deleted.
  ~~~

##### Dumping the current file system to a path:
`python main.py -f -r -m=(0|1) -n=<index> -i=<infile> -o=<outpath>`
##### Dumping the current file system including files marked deleted to a path:
`python main.py -f -r -u -m=(0|1) -n=<index> -i=<infile> -o=<outpath>`

  ### main_recover
  This tool uses different analysis methods to find deleted files. You must realize that file integrity is never guaranted as file data can be overwritten each time a new file was written after the file was deleted.

  * The first method (orphan scanner) takes longer but recovers the most accurate file information. It works by checking every 0x40 bytes for valid [dirent]([dirent](https://www.eurasia.nu/wiki/index.php/FATX#Directories)) structures. These structures contain information about the file and information leading to the file's data. It then links them together to create a directory structure that can be dumped.

  * The second method (signature scanner) works by checking each cluster (each file is written starting at a certain cluster) for a file header and extracting the information from the file format itself.
  ~~~
  usage: main_recover.py [-h] [-i INPUTFILE] [-o OUTPUTPATH] [-n INDEX]
                       [-m MODE] [-so] [-ss] [-r]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUTFILE, --inputfile INPUTFILE
                        Input image file.
  -o OUTPUTPATH, --outputpath OUTPUTPATH
                        Output directory
  -n INDEX, --index INDEX
                        Partition index.
  -m MODE, --mode MODE  OS Mode (0=XBox Original,1=Xbox 360).
  -so, --scan-orphans   Use orphan scanner.
  -ss, --scan-signatures
                        Use signature scanner
  -r, --recover         Recover files to output path.
~~~
##### Recover files using the orphan scanner to a path.
`python main_recover.py -r -so -m=(0|1) -n=<index> -i=<infile> -o=<outpath>`
##### Recover files using the signature scanner to a path.
`python main_recover.py -r -ss -m=(0|1) -n=<index> -i=<infile> -o=<outpath>

## TODO
- [ ] Create a GUI
- [ ] Add more signature parsers
- [ ] Add option to analyze custom range
- [ ] Add option to specify a custom interval for scanners
- [ ] Overcome fragmentation