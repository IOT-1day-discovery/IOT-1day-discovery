#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import requests
import subprocess
import sys
import tempfile

#import lib2vuln as l2v


TMP_FILE = 'tmp_results'


class Lib2VulnFakeArgs:
    # Let's just ignore this piece of awful engineering..
    # We'll do it better next time, when we have more time.
    def __init__(self, args):
        self.cve = None
        self.library = None
        self.version = None
        self.no_match_subversion = False
        self.match_unversioned = False
        self.output = None
        self.extract_references = False
        self.extract_patch_urls = False
        self.extract_patches = False
        self.extract_cves = False

        for k, v in args.items():
            setattr(self, k, v)


def process(args):
    # The formatstr accepted by FindUniquePackages.exe
    formatstr = '{fs/fullname};{elf/machine};{elf/buildid/hashf};{elf/linkage};{elf/osversion};{elf/stripped};{elf/type};{elf/buildid/hash};{elf/interpreter};{elf/abiversion};{elf/osabi};{elf/endian};{elf/bits};{sha1/hash};{firmware/name}'
    # The output file of FindUniquePackages.exe
    binaryVariationsPath = 'BinaryVariations.json'

    print('Collect file hashes..')
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
                print(tempcsvf.name)
                subprocess.check_call(['mono', args.find_unique_packages_path, tempcsvf.name])
            except subprocess.CalledProcessError as e:
                print('{} failed, aborting'.format(args.find_unique_packages_path), file=sys.stderr)
                return -1
            tempcsvf.flush()
            with open(tempcsvf.name, 'rb') as f:
                print(f.read())
            try:
                subprocess.check_call(
                    ['mongoimport', '--jsonArray', '-d', 'PackageParserWeb', '-c', 'BinaryVariations',
                     '--drop', binaryVariationsPath])
            except subprocess.CalledProcessError as e:
                print('mongoimport failed, aborting', file=sys.stderr)
                return -1
        finally:
            try:
                os.unlink(binaryVariationsPath)
            except FileNotFoundError as e:
                pass

    return
    # step 2: compare ELF binaries to database of packages/binaries
    print('Check for matches with DB..')
    libraries = []
    req = requests.get('%s/match/%s' % (args.server, args.path.split('/')[-1]))
    assert(req.status_code == 200)

    j = req.json()
    assert(j)

    print('Collect library names and versions..')
    for lib in j:
        req = requests.get('%s/package/name/%s' % (args.server, lib['fileName']))
        assert(req.status_code == 200)

        libj = req.json()
        assert(libj)

        libraries.append((libj['Package'], libj['Version']))

    # step 3: match detected packages / OSS libraries against CVE database to detect vulnerable functions
    lib2vulns = {}
    for lib, version in libraries:
        args = Lib2VulnFakeArgs({'output': TMP_FILE, 'library': lib, 'version': version})
        try:
            l2v.process(args)
            lib2vulns['%s (%s)' % (lib, version)] = json.parse(TMP_FILE)
        except Exception as e:
            # just to be sure, who knows what's stored in the CVE database / patch files
            print('Exception in lib2vuln:', e)

    if os.path.isfile(TMP_FILE):
        os.unlink(TMP_FILE)

    if not args.output:
        print('=' * 80)
        print('Vulnerable functions in firmware image:')
        print(json.dumps(lib2vulns, indent=4))
    else:
        json.dump(lib2vulns)
    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Identifies vulnerable functions in an extracted firmware image')
    parser.add_argument('path', help='Path to the extracted firmware image')
    parser.add_argument('--server', '-s', default='127.0.0.1', help='Address of the server that hosts the database API for known packages. Default: 127.0.0.1')
    parser.add_argument('output', default=None, help='Path to file where results should be stored')

    # TODO: make me a parser group
    parser.add_argument('--iotfw-tool-path',
                        default='./iotfw-tool',
                        help='Path to the iotfw-tool executable')
    parser.add_argument('--find-unique-packages-path',
                        default='packageparserweb/FindUniquePackages/bin/Debug/FindUniquePackages.exe',
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
