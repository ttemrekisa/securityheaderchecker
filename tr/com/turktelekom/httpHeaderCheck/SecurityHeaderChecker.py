from multiprocessing import freeze_support

__author__="emre.kisa@turktelekom.com.tr"

import argparse
from tr.com.turktelekom.httpHeaderCheck.scripts import HTTPHeaderCheck

def initParameters():
    parser = argparse.ArgumentParser(prog="Security Header Checker",
                                     description="This tool lets you find out which HTTP Security headers are used on given URLS.")
    parser.add_argument("-i", "--inputFileLocation", default=["input.txt"], action="store", nargs=1, type=str,
                        metavar="INPUT_FILE_LOCATION",
                        help="Location of the input file in which URL's are located. There should be 1 URL per line. (Default: ./input.txt)")
    parser.add_argument("-o", "--outputFileLocation", default=["output.txt"], action="store", nargs=1, type=str,
                        metavar="OUTPUT_FILE_LOCATION",
                        help="Location of the output file where the results will be written. (Default: ./output.txt)")
    # parser.add_argument("-n", "--nmapScan", action="store_true",
    #                     help="If available, the tool will first scan the given ip range for open 80 ports using nmap SYN scan. If 80 port is closed or filtered, these IP's will be skipped.")
    # parser.add_argument("-v", "--verbose", default=[1], action="store", type=int,
    #                     metavar="VERBOSITY_LEVEL",
    #                     help="Verbosity level. 0 or 2 (Default: 1)")
    parser.add_argument("--version", action="version", version='%(prog)s v1.0')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    freeze_support()
    args = initParameters()
    HTTPHeaderCheck.main(args)

