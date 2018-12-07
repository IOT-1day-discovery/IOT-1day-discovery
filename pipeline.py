#!/usr/bin/python3
import argparse
import os
import pathlib
import subprocess
import sys
import tempfile

from lib2vuln import *

def process(args):
    # The formatstr accepted by FindUniquePackages.exe
    formatstr = '{fs/fullname};{elf/machine};{elf/buildid/hashf};{elf/linkage};{elf/osversion};{elf/stripped};{elf/type};{elf/buildid/hash};{elf/interpreter};{elf/abiversion};{elf/osabi};{elf/endian};{elf/bits};{sha1/hash}'
    # The output file of FindUniquePackages.exe
    binaryVariationsPath = pathlib.Path(args.find_unique_packages_path).parent / 'BinaryVariations.json'

    with tempfile.NamedTemporaryFile(suffix='.csv') as tempcsvf:
        try:
            subprocess.check_call(
                [args.iotfw_tool_path,
                 'print', '--vendor', '--fs', '--firmware', '--sha1', '--elf', formatstr,
                 'firmware', args.path],
                stdout=tempcsvf)
        except subprocess.CalledProcessError as e:
            print('{} failed, aborting'.format(args.iotfw_tool_path), file=sys.stderr)
            return -1

        try:
            try:
                subprocess.check_call(['mono', args.find_unique_packages_path, tempcsvf.name])
            except subprocess.CalledProcessError as e:
                print('{} failed, aborting'.format(args.find_unique_packages_path), file=sys.stderr)
                return -1

            try:
                subprocess.check_call(
                    ['mongoimport', '--jsonArray', '-d', 'PackageParserWeb', '-c', 'BinaryVariations',
                     '--drop', binaryVariationsPath])
            except subprocess.CalledProcessError as e:
                print('mongoimport failed, aborting', file=sys.stderr)
                return -1
        finally:
            try:
                binaryVariationsPath.unlink()
            except FileNotFoundError as e:
                pass

    # step 2: compare ELF binaries to database of packages/binaries
    # TODO
    
    # step 3: match detected packages / OSS libraries against CVE database to detect
    #         vulnerable functions
    # TODO
    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Identifies vulnerable functions in an extracted firmware image')
    parser.add_argument('path', help='Path to the extracted firmware image')

    parser.add_argument('--iotfw-tool-path',
                        default='./iotfw-tool',
                        help='Path to the iotfw-tool executable')
    parser.add_argument('--find-unique-packages-path',
                        default='./packageparserweb/FindUniquePackages/bin/Debug/FindUniquePackages.exe',
                        help='Path to the FindUniquePackages.exe executable')
    parser.add_argument('--import-json-to-mdb-sh-path',
                        default='./packageparserweb/tools/importJsonToMdb.sh',
                        help='Path to the importJsonToMdb.sh script')
    
    grp = parser.add_argument_group(title='lib2vuln related options')
    grp.add_argument('--no-match-subversion', default=False, action='store_true',
                     help='Do not match the subversion string when matching the vulnerable configuration of CVEs with the queried librarie\'s version')
    grp.add_argument('--match-unversioned', default=False, action='store_true',
                     help='If no version is reported for a vulnerable configuration of a CVE, match the configuration anyway (might produce false positives)')
    
    # TODO: add arguments for other scripts, too (if required)
    
    sys.exit(process(parser.parse_args()))
