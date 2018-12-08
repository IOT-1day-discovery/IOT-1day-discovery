# IOT-1day-discovery

## dependencies
- mongodb
- .net47 (using mono but any 47 will do)
- node 10.12 or above
- python3 (tested with python 3.7 and python 3.4)
- python3 packages:
  - beautifulsoup4
  - libclang

## Initialize Submodule
Follow the [Git Book](https://git-scm.com/book/en/v2/Git-Tools-Submodules#_cloning_submodules) by Scott Chacon and Ben Straub, on how to initilize the submodule:
```sh
cd ./packageparserweb
git submodule init
git submodule update
```

## iotfw-tool
`iotfw-tool` is the tool used to crawl and extract information about files in unpacked firmware images. List of available actions with basic description can be obtained by running:
```
./iotfw-tool --help
```

### Example 1: Getting information about a file
The most elementary action is printing information about a single file:
```
$ ./iotfw-tool print --fs --sha1 '{fs/dirname};{fs/name};{sha1/hash}' file /bin/true
/bin;true;8b232f29aa114421ceccea5a46cb2e65140ca5e8
```
An example output is given above. The output is based on the format string `{fs/dirname};{fs/name};{sha1/hash}`, which is expanded with corresponding values for the given file. Note the `--fs` and `--sha1` switches - they make variables like `fs/dirname` and `sha1/hash` available for printing, list of accepted switches and corresponding variables can be found at the end of this section.

### Example 2: Getting information about a directory
This is a straigtforward extension of the previous example, simply pass a directory name instead of file name:
```
$ ./iotfw-tool print --fs --sha1 '{fs/dirname};{fs/name};{sha1/hash}' file /bin
/bin;ping;f70403ca7536d64918264ebac831cde8314dcc58
/bin;setfont;73f707873b3a5705acf453237c5cb3a5acd5e370
/bin;bunzip2;78ad41c090546483c6f82d656fdd33d0e23c836e
/bin;systemd-escape;f70e47253a0e9df75c8a06c1a0c299890378ac6e
/bin;ntfsmove;161084c9613082e43993ba4055ba5965b4aa85ab
```

### Example 3: Getting information about firmware
Assuming the extracted firmware is located in directory `/path/to/extracted/firmware`, run:
```
$ ./iotfw-tool print --firmware --fs --sha1 '{firmware/filesystem};{fs/firmware/dirname};{fs/name};{sha1/hash}' firmware /path/to/extracted/firmware
/path/to/extracted/firmware/filesystem;/bin;check_default_by_start;34c783b222588f9529f829bb3ff49077b39799cd
/path/to/extracted/firmware/filesystem;/bin;private.cgi;5dec74c3d6b9a5b08f0a808f63af16a7c64c5dd2
/path/to/extracted/firmware/filesystem;/bin;auto_update;dc37ba3e96c14fdb35a67ce632a45d966b8b74ee
/path/to/extracted/firmware/filesystem;/bin;usb_check;cbf0827de4be8f0882e4f8daf1238df293ec78e3
/path/to/extracted/firmware/filesystem;/bin;igmpproxy;a1ca85e4f3c79d4d53da64c6873e2e26b358a156
```

### Example 4: Getting information about vendor firmwares
Assuming the extracted vendor firmwares are located in directory `/path/to/vendor/firmwares`, run:
```
$ ./iotfw-tool print --vendor --firmware --fs --sha1 '{firmware/name};{firmware/filesystem};{fs/firmware/dirname};{fs/name};{sha1/hash}' vendor /path/to/vendor/firmwares
firmware1;/path/to/vendor/firmwares/firmware1/filesystem;/bin;private.cgi;4db6a1072cce2b9b7295af142f55cdedf4ca7ad4
firmware1;/path/to/vendor/firmwares/firmware1/filesystem;/bin;auto_update;172ae20c49b20cc7317dedb907de28b0c5dd9dc5
firmware1;/path/to/vendor/firmwares/firmware1/filesystem;/bin;cfeupdate;c58ded323cf44ce13c484c1d2980cfdfc519a15e
firmware1;/path/to/vendor/firmwares/firmware1/filesystem;/bin;flash_load_default;150efe995c3e8b068fe094ce03c8219b1ec5269c
firmware1;/path/to/vendor/firmwares/firmware1/filesystem;/bin;detect_dns;60574521947631797c13308bf073f0a5fb4398bd
```

### Example 5: Getting information about all vendors' firmwares
Assuming the vendor directories are located in directory `/path/to/vendors`, run:
```
$ ./iotfw-tool print --vendor --firmware --fs --sha1 '{vendor/name};{firmware/name};{firmware/filesystem};{fs/firmware/dirname};{fs/name};{sha1/hash}' vendors /path/to/vendors
phicomm;firmware2;/path/to/vendors/phicomm/firmware2/_40.extracted/_503000.extracted/filesystem;/bin;igmpproxy;cbf98cb9d72966833cd8e646ca9d18ec37f3cc3f
phicomm;firmware2;/path/to/vendors/phicomm/firmware2/_40.extracted/_503000.extracted/filesystem;/bin;arptables;5cf7dfa8d35d776be294b258e1ef9794e3978a55
phicomm;firmware2;/path/to/vendors/phicomm/firmware2/_40.extracted/_503000.extracted/filesystem;/bin;openssl;9c81c236a6ebc7a8b37d31a76cb67732f7dffe6c
phicomm;firmware2;/path/to/vendors/phicomm/firmware2/_40.extracted/_503000.extracted/filesystem;/bin;guest_control;65a51e951eb0b5186fe1e49bc12afbd331114f17
phicomm;firmware2;/path/to/vendors/phicomm/firmware2/_40.extracted/_503000.extracted/filesystem;/bin;internet_check;d58b7b77cde024b0215e18b60b278f64994b82d2
```

### Example 6: Getting information in a format compatible with FindUniquePackages tool
Assuming the vendor directories are located in directory `/path/to/vendors`, run:
```
$ ./iotfw-tool print --vendor --fs --firmware --sha1 --elf '{fs/fullname};{elf/machine};{elf/buildid/hashf};{elf/linkage};{elf/osversion};{elf/stripped};{elf/type};{elf/buildid/hash};{elf/interpreter};{elf/abiversion};{elf/osabi};{elf/endian};{elf/bits};{sha1/hash}' vendors /path/to/vendors
/path/to/vendors/phicomm/_a3fb4b07ee14405adf227890a86f40abc8b4c5dd.bin.extracted/_40.extracted/_503000.extracted/filesystem/bin/igmpproxy;MIPS, MIPS-II;NULL;dynamically linked;NULL;stripped;executable;NULL;/lib/ld-uClibc.so.0;1;SYSV;LSB;32;cbf98cb9d72966833cd8e646ca9d18ec37f3cc3f
/path/to/vendors/phicomm/_a3fb4b07ee14405adf227890a86f40abc8b4c5dd.bin.extracted/_40.extracted/_503000.extracted/filesystem/bin/arptables;MIPS, MIPS-II;NULL;dynamically linked;NULL;stripped;executable;NULL;/lib/ld-uClibc.so.0;1;SYSV;LSB;32;5cf7dfa8d35d776be294b258e1ef9794e3978a55
/path/to/vendors/phicomm/_a3fb4b07ee14405adf227890a86f40abc8b4c5dd.bin.extracted/_40.extracted/_503000.extracted/filesystem/bin/openssl;MIPS, MIPS-II;NULL;dynamically linked;NULL;stripped;executable;NULL;/lib/ld-uClibc.so.0;1;SYSV;LSB;32;9c81c236a6ebc7a8b37d31a76cb67732f7dffe6c
/path/to/vendors/phicomm/_a3fb4b07ee14405adf227890a86f40abc8b4c5dd.bin.extracted/_40.extracted/_503000.extracted/filesystem/bin/guest_control;MIPS, MIPS-II;NULL;dynamically linked;NULL;stripped;executable;NULL;/lib/ld-uClibc.so.0;1;SYSV;LSB;32;65a51e951eb0b5186fe1e49bc12afbd331114f17
/path/to/vendors/phicomm/_a3fb4b07ee14405adf227890a86f40abc8b4c5dd.bin.extracted/_40.extracted/_503000.extracted/filesystem/bin/internet_check;MIPS, MIPS-II;NULL;dynamically linked;NULL;stripped;executable;NULL;/lib/ld-uClibc.so.0;1;SYSV;LSB;32;d58b7b77cde024b0215e18b60b278f64994b82d2
```

### List of available switches and format variables
* `--vendor` Vendor information
  * `{vendor/name}` Name of the firmware vendor.
  * `{vendor/path}` Path to the vendor directory.
* `--firmware` Firmware information
  * `{firmware/name}` Name of the firmware image.
  * `{firmware/path}` Path to the firmware directory.
  * `{firmware/filesystem}` Path to the root of the firmware's filesystem.
* `--fs` Filesystem-supplied information about a file.
  * `{fs/name}` Filename of the file (without the directory component).
  * `{fs/dirname}` Directory the file resides in.
  * `{fs/fullname}` Full name of the file (both directory and filename components).
  * `{fs/size}` Size of the file.
  * `{fs/mtime}` Last modification time in Unix timestamp format.
  * `{fs/timestamp-utc}` Last modification time in UTC datetime format (`2015-03-14T15:47:04.000000Z`).
  * `{fs/firmware/dirname}` Directory the file resides in, assuming `{firmware/filesystem}` is the filesystem root.
  * `{fs/firmware/fullname}` Full name of the file (both directory and filename components), assuming `{firmware/filesystem}` is the filesystem root.
* `--file` Information given by the `file` utility
  * `{file/output}` Output of the `file` utility when run on the file.
* `--elf` Information about ELF files (**Note: non-ELF files are silently ignored with this switch.**)
  * `{elf/type}` Type of the ELF file (executable, relocatable, shared object).
  * `{elf/bits}` Bitness of the ELF file.
  * `{elf/endian}` Endianness of the ELF file.
  * `{elf/osabi}` Compatible OS ABI (GNU/Linux, SYSV), optional.
  * `{elf/osversion}` OS (kernel) version, optional.
  * `{elf/abiversion}` Compatible ABI version.
  * `{elf/machine}` Compatible machine architecture.
  * `{elf/linkage}` Linkage type (static, dynamic), optional.
  * `{elf/interpreter}` Interpreter filename, optional.
  * `{elf/buildid/hash}` BuildID hash, optional.
  * `{elf/buildid/hashf}` BuildID hash function (e.g. SHA1), optional.
  * `{elf/stripped}` Either `stripped` or `not stripped`.
* `--md5` MD5 information about the file
  * `{md5/hash}` MD5 hash of the file.
* `--sha1` SHA1 information about the file
  * `{sha1/hash}` SHA1 hash of the file.
* `--sha256` SHA256 information about the file
  * `{sha1/hash}` SHA256 hash of the file.

## web crawling
### Documentation
https://iot-1day-discovery.github.io/

please be courteous to the package repositories. Its really easy to get package explosion.
### Fetching ipks from http://archive.openwrt.org/
the archive has no api so we have to convert html tables to json in the fetchIpks package.
```json
[
    "attitude_adjustment/",
    "backfire/",
    "barrier_breaker/",
    "chaos_calmer/",
    "kamikaze/",
    "releases/",
    "snapshots/"
]
```
Above is an example of what one of the cache files will look like.
Each step of fetchIpks will take a exponentially longer time. which is why caching is so key to that project.
```
downloadAndComputeHashes- > InvokeIpkDownload -> InvokeIpkFetch -> InvokeArchTypes -> 
InvokeArchSetter -> InvokeVersionsSetter -> InvokeCodeNamesSetter
```
from *InvokeIpkFetch* to *InvokeCodeNamesSetter* we are just building up every combination of ipk links we need to download. *InvokeIpkDownload* actually downloads the files.
```
downloadAndComputeHashes- > walkAndComputeHashes -> extractIpk
```
*downloadAndComputeHashes*  uses *walkFs* to walk the filesystem hierarchy and generate a list of every ipk file
downloaded. Then we use extractIpk to decompress and then generate the hash of all the files inside the package.
an Ipk package has the following format:
```
data.tar.gz
control.tar.gz
```
At the end of the run you should see the following files in cache/
- codeNames-cache.json
- archOffsets-cache.json
- archTypes-cache.json
- versionTypes-cache.json
- ipks-cache.json
- ipksha1.json

*ipksha1.json* is imported into the mongodb database using:
-tools/importJsonToMdb.sh

### Fetching and parsing package.gz 
repos used:
- http://archive.debian.org/debian/dists/
- http://archive.openwrt.org/
- http://cz.archive.ubuntu.com/ubuntu/dists/
- https://archive.raspbian.org/raspbian/dists/

*fetchPackages.js* has been specialized for each of these distros to pull down package.gz  files.
While we are no longer using this for package retrieval, the version info stored within is very helpful
for retreiving version number in a reiliable fashion. something we need for the cve poriton of the project.
In any case PackageParserCLI has been written to decompress each package.gz fetched by fetchPackages.js parse them into a json and store them into the database.

## parsing files generated by iotfw-tool
This project has  crawled:
- Different file systems:  958
- Unique binary names: 6399
- Unique binary hashes: 18,6373
Sufficed to say every parse job is very time consuming and we want to limit that.
*FindUniquePackages* reads in filesystem.execfiles_detailed.csv.xz files and generates
a JSON file that we feed into mongodb
```json
{
    "name": "airlink_app",
    "files": [
        {
            "filepath": "360/_325bcc38de186d7d96b85839c5696e99b3b42c6f.bin.extracted/filesystem/app/airlink_app/bin/airlink_app",
            "sha1": "0d68987d77b50263e83a64d887a23143ac8f81d3"
        },
        {
            "filepath": "360/_4eacbe421bf35935f5321678d3e677331b5a3027.bin.extracted/filesystem/app/airlink_app/bin/airlink_app",
            "sha1": "b77509dd073ac37453edbf98b2c9ba6d1024734a"
        },
        {
            "filepath": "360/_b84bdd67acc6005eca232a82c3bd97a13b051de0.bin.extracted/filesystem/app/airlink_app/bin/airlink_app",
            "sha1": "2c61d8d13c24360d86cafda5c9c914e0817e25bd"
        }
    ]
}
```
This ordering lists all the unique versions of a given binary name and the file path it was found on.
This ordering reduces the number of files we have to check our db against. this reduces our file size to
39.5 MB vs 251.6 MB that it would have been if we kept all duplicate sha records. thats an 84.3% space savings.

## web frontend
This is more of a database nicesty as making http requests is easier than making mongodb requests.
- run by calling *launch.sh*
### API Documentation
#### GET binary/iot/names/{name}
- [x] fetches all the binaries with this name that we parsed on the iot devices.
- examples:
```bash
curl -X GET \
  http://localhost:8080/binary/iot/names/arp_oversee
```
-output
```json
{
    "k": "arp_oversee",
    "v": [
        {
            "filepath": "360/_325bcc38de186d7d96b85839c5696e99b3b42c6f.bin.extracted/filesystem/app/arp_oversee/bin/arp_oversee",
            "sha1": "89f823fe52353244fcf9cb8373c367e0555b95de"
        },
        {
            "filepath": "360/_4eacbe421bf35935f5321678d3e677331b5a3027.bin.extracted/filesystem/app/arp_oversee/bin/arp_oversee",
            "sha1": "50c74dd2c5301d9f1ac447d2250125e484b69d1f"
        },
        {
            "filepath": "360/_b84bdd67acc6005eca232a82c3bd97a13b051de0.bin.extracted/filesystem/app/arp_oversee/bin/arp_oversee",
            "sha1": "fb0901084f42dea979d02d61613079934389852d"
        }
    ]
}
```
#### GET binary/ipks/sha1/{hash}
- [x] fetches binaries associated with this sha.
- examples:
```bash
curl -X GET \
  http://localhost:8080/binary/ipks/sha1/f44ea9ffb7e15bdb234ffc4f23bdb18823f3d89c \
```
or
```bash
curl -X GET \
  http://localhost:8080/binary/ipks/sha1/4876d0e57e7d35b9596899b4955989f0e69ef9d3 \
```
or any of the other sha1s found in files:
- output
```json
{
        "files": [
            {
                "name": "/usr/bin/ssh",
                "sha1": "4876d0e57e7d35b9596899b4955989f0e69ef9d3"
            },
            {
                "name": "/etc/ssh/ssh_config",
                "sha1": "f44ea9ffb7e15bdb234ffc4f23bdb18823f3d89c"
            },
            {
                "name": "/conffiles",
                "sha1": "1d646f8246fad07f994e4f37d23b33b1dfd2e045"
            },
            {
                "name": "/postrm",
                "sha1": "e21338a5930c6bf8bfb2294a201e5f580a20b690"
            }
        ],
        "descriptors": [
            "ipks",
            "barrier_breaker",
            "14.07",
            "ramips",
            "openssh-client_6.6p1-1_ramips_24kec.ipk"
        ]
    }
```
#### GET binary/ipkNames/{ipkName}
- [ ] fetches binaries associated with this name. (in progress)
#### GET package/sha1/{hash}
- [x] fetches packages associated with this hash
-example
```bash
curl -X GET \
  http://localhost:8080/package/sha1/{sha1 of openssh-client_6.6p1-1_ramips_24kec.ipk}
```
- output
```json
{
    "Package": "openssh-client",
    "Version": "6.6p1-1",
    "Depends": "libc, libopenssl, zlib",
    "Source": "feeds/packages/net/openssh",
    "Section": "net",
    "Maintainer": "Peter Wagner <tripolar@gmx.at>",
    "Architecture": "ramips_24kec",
    "Installed-Size": "310077",
    "Filename": "openssh-client_6.6p1-1_ramips_24kec.ipk",
    "Size": "309896",
    "MD5Sum": "3b4a6b7f474cafe84797aeda585722f3",
    "SHA256sum": "da7cde828734b6b53d618a23185151b1b44b188c00a0269227736b6c4b183cdd",
    "Description":  "OpenSSH client."
}
```
#### GET package/sha256/{hash}
- [x] fetches packages associated with this hash
- example
```bash
curl -X GET \
  http://localhost:8080/package/sha256/da7cde828734b6b53d618a23185151b1b44b188c00a0269227736b6c4b183cdd
```
- output
```json
{
    "Package": "openssh-client",
    "Version": "6.6p1-1",
    "Depends": "libc, libopenssl, zlib",
    "Source": "feeds/packages/net/openssh",
    "Section": "net",
    "Maintainer": "Peter Wagner <tripolar@gmx.at>",
    "Architecture": "ramips_24kec",
    "Installed-Size": "310077",
    "Filename": "openssh-client_6.6p1-1_ramips_24kec.ipk",
    "Size": "309896",
    "MD5Sum": "3b4a6b7f474cafe84797aeda585722f3",
    "SHA256sum": "da7cde828734b6b53d618a23185151b1b44b188c00a0269227736b6c4b183cdd",
    "Description":  "OpenSSH client."
}
```
#### GET package/md5/{hash}
- [x] fetches packages associated with this hash
- example
```bash
curl -X GET \
  http://localhost:8080/package/md5/3b4a6b7f474cafe84797aeda585722f3
```
- output
```json
{
    "Package": "openssh-client",
    "Version": "6.6p1-1",
    "Depends": "libc, libopenssl, zlib",
    "Source": "feeds/packages/net/openssh",
    "Section": "net",
    "Maintainer": "Peter Wagner <tripolar@gmx.at>",
    "Architecture": "ramips_24kec",
    "Installed-Size": "310077",
    "Filename": "openssh-client_6.6p1-1_ramips_24kec.ipk",
    "Size": "309896",
    "MD5Sum": "3b4a6b7f474cafe84797aeda585722f3",
    "SHA256sum": "da7cde828734b6b53d618a23185151b1b44b188c00a0269227736b6c4b183cdd",
    "Description":  "OpenSSH client."
}
```
#### GET package/name/{packageName}
- [ ] fetches packages associated with this hash (in progress)
-example
```bash
curl -X GET \
  http://localhost:8080/name/packageName/openssh-client_6.6p1-1_ramips_24kec.ipk
```
- output
```json
{
    "Package": "openssh-client",
    "Version": "6.6p1-1",
    "Depends": "libc, libopenssl, zlib",
    "Source": "feeds/packages/net/openssh",
    "Section": "net",
    "Maintainer": "Peter Wagner <tripolar@gmx.at>",
    "Architecture": "ramips_24kec",
    "Installed-Size": "310077",
    "Filename": "openssh-client_6.6p1-1_ramips_24kec.ipk",
    "Size": "309896",
    "MD5Sum": "3b4a6b7f474cafe84797aeda585722f3",
    "SHA256sum": "da7cde828734b6b53d618a23185151b1b44b188c00a0269227736b6c4b183cdd",
    "Description":  "OpenSSH client."
}
```

## lib2vuln tool

This tool can take in a CVE number or software name and version and finds CVE's associated with it, links to patches, the patches themselves and vulnerable functions. 
```
usage: lib2vuln.py [-h] [--cve CVE] [--library LIBRARY] [--version VERSION]
                   [--no-match-subversion] [--match-unversioned]
                   [--output OUTPUT]
                   [--extract-references | --extract-patch-urls | --extract-patches | --extract-cves]

Obtain patches/vulnerable from a CVE identifier or for a specific library

optional arguments:
  -h, --help            show this help message and exit
  --extract-references, -er
                        Retrieve URLs referenced by CVE(s) only
  --extract-patch-urls, -eu
                        Retrieve potential patch URLs only
  --extract-patches, -ep
                        Retrieve patches only, do not extract vulnerable
                        functions
  --extract-cves, -ec   Retrieve CVEs only

Output options:
  --cve CVE, -c CVE     Fetch information about an CVE identifier
                        (CVE-2018-...)
  --library LIBRARY, -l LIBRARY
                        Fetch information for a library
  --version VERSION, -v VERSION
                        Fetch information for a specific version of a library

Version matching options:
  --no-match-subversion
                        Do not match the subversion string when matching the
                        vulnerable configuration of CVEs with the queried
                        librarie's version
  --match-unversioned   If no version is reported for a vulnerable
                        configuration of a CVE, match the configuration anyway
                        (might produce false positives)

Output options:
  --output OUTPUT, -o OUTPUT
                        Output file in which to store the output (JSON format)
```
