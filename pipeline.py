import argparse

from iotfw_tool import *
from lib2vuln import *


def process(args):
    # step 1: obtain listing of all ELF binaries in the firmware image, including hashes
    # TODO
    
    # step 2: compare ELF binaries to database of packages/binaries
    # TODO
    
    # step 3: match detected packages / OSS libraries against CVE database to detect
    #         vulnerable functions
    # TODO
    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Identifies vulnerable functions in an extracted firmware image')
    parser.add_argument('path', required=True, help='Path to the extracted firmware image')
    
    grp = parser.add_argument_group(title='lib2vuln related options')
    grp.add_argument('--no-match-subversion', default=False, action='store_true',
                     help='Do not match the subversion string when matching the vulnerable configuration of CVEs with the queried librarie\'s version')
    grp.add_argument('--match-unversioned', default=False, action='store_true',
                     help='If no version is reported for a vulnerable configuration of a CVE, match the configuration anyway (might produce false positives)')
    
    # TODO: add arguments for other scripts, too (if required)
    
    process(parser.parse_args())
