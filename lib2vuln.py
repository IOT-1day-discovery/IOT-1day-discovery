#!/usr/bin/python
import argparse
import gzip
import itertools
import json
import re
import requests
import urllib

from collections import namedtuple
from operator import itemgetter
from tempfile import NamedTemporaryFile

from bs4 import BeautifulSoup
from clang.cindex import Index, CursorKind, TranslationUnitLoadError
from urllib.parse import urljoin


userAgent = 'Mozilla/5.0 (compatible; CVEBot)'


# ======================= STEP 1: FETCH CVES for library =======================


def checkVersionmatch(v_query, v_config, match_subversion=True, match_unversioned=False):
    '''
    Checks whether the queried version (v1) matches the version v2.
    Two versions are considered identical in 3 cases:
     1. No version information given about the queried library
     2. Configurations does not mention a specific version and match_unversioned is True
     3. The main version string match and either match_subversion is False or the 
        subversion strings (e.g. build/commit nr) match the configuration's version string.
    '''
    if not v_query or (match_unversioned and not v_config):
        return True
    
    v_config = v_config or [None]
    
    # Cases 1, 2 did not apply, so check for case 3: main version need to match
    if v_query[0] != v_config[0]:
        return False
    
    if not match_subversion:
        return True
    
    # filter out wildcards
    v_config = list(filter(lambda x: x and x != '*', v_config))
    
    l = min(len(v_query), len(v_config))
    return v_query[:l] == v_config[:l]

def getCVEsForLib(lib,
                  userAgent='Mozilla/5.0 (compatible; CVEBot)',
                  version=None,
                  match_subversion=True,
                  match_unversioned=False):
    req = requests.get('http://cve.circl.lu/api/search/%s' % lib, headers={'User-Agent': userAgent})
    if req.status_code != 200:
        raise Exception('Cannot fetch CVE details for %s' % lib)
    
    vs = None if not version else version.split('-')
    
    cves = []
    json = req.json()
    for cve in json['data']:
        for conf in cve['vulnerable_configuration']:
            v = conf.split(':')
            if len(v) < 5:
                # invalid configuration not containing a software name
                continue
            _, _, _, _, c_name, *c_version = v
            
            
            if lib == c_name and checkVersionmatch(vs,
                                                   c_version,
                                                   match_subversion=match_subversion,
                                                   match_unversioned=match_unversioned):
                cves.append((cve['id'], conf))
    return cves


# ====================== STEP 2: FETCH REFERENCES FOR CVES =====================


def getCVEReferences(cve, userAgent='Mozilla/5.0 (compatible; CVEBot)'):
    req = requests.get('http://cve.circl.lu/api/cve/%s' % cve, headers={'User-Agent': userAgent})
    if req.status_code != 200:
        print('Cannot fetch CVE details for %s' % cve)
        return []

    json = req.json()
    if not json or 'references' not in json:
        return []
    return json['references']


# ============ STEP 3 AND 4: FILTER PATCH URLS AND RETRIEVE PATCHES =============


def looksLikePatch(s):
    '''
    All patches must contain '+++'/'---', one each for the compared files.
    Further, there needs to be at least one '@@', which describes the changed line
    '''
    return '\n+++' in s and '\n---' in s and '\n@@' in s

def looksLikePatchBytes(s):
    '''
    Same as looksLikePatch(), but for python bytes
    '''
    return b'\n+++' in s and b'\n---' in s and b'\n@@' in s


class PatchPattern:
    '''
    General interface for matching URLs referenced by CVEs. The following attributes
    can / must be overwritten by subclasses implementing this interface.
    '''
    
    '''
    This regular expression has to be overwritten by each subclass. It is matched against
    a URL in order to determine whether a URL is in a certain class of URLS for
    which we can extract patch information. The matched strings for all capturing
    groups specified in this regular expression will be stored in the details attribute
    of this class (maintining order) for reuse when building a new URL to retreive
    the actual patch from (also see URL_REPLACE_STR and URL_REPLACE_WITH).
    '''
    URL_PATTERN = None
    
    '''
    If specified, this regular expression will be used to replace parts of the matched URL.
    In this case, URL_REPLACE_WITH will be used as the replacement.
    '''
    URL_REPLACE_STR = None
    
    '''
    This field serves two purposes. First, if URL_REPLACE_STR is specified, it will
    be used as replacement when building the URL of the patch file. In this case,
    references like '\\1' refer to the corresponding capturing group in URL_REPLACE_STR.
    For more advanced URL patterns, this field can also be assigned a function/lambda
    in order to implement case-by-case replacements.
    The second case is when URL_REPLACE_STR is not specified. Then, URL_REPLACE_WITH
    serves as a python format string (e.g. 'Num: %d  Str: %s' % (...)), again to build
    the patch URL. The strings matched by the capturing groups of URL_PATTERN are passed
    as arguments to the format string, hence there must be as many capturing groups as
    there are placeholders in this string.
    If this field is not redefined by a subclass, the patch URL will be identical
    to the original URL.
    '''
    URL_REPLACE_WITH = None

    '''
    Some links referenced by CVEs redirect to a different site / new server that is
    now used for VCS. However, this might also be considered an error case for
    some of the URL classes. Setting this field to False will ignore all results
    after a patch has been fetched if a redirect is detected (SSL/TLS up-/downgrades 
    are ignored).
    '''
    ALLOW_REDIRECT = True

    '''
    Whether the URL class refers to a website that directly delivers patches
    (or after some transformations as achieved by methods described above) or 
    to a website that just contains links to other websites which might serve
    patches (when set to False.
    This field is used in testAll() and testAllUrls() to match only those URL classes
    that directly provide patches. It is also useful for limiting the crawling depth
    for indirect URL classes (to prevent matching URLs to yet another indirect site
    when already crawling an indirect website)
    '''
    IS_DIRECT = True

    '''
    List of blacklisted domains or keywords. Used by testAll() only after all
    URL classes have been tested, since the regular expression for each class is
    rather specific. The blacklist is required to reduce the number of URLs matching
    the WHITELIST below for frequent hosts known not to provide more helpful information.
    '''
    BLACKLIST = [
        'securitytracker.com/',
        'openwall.com/',
        'ubuntu.com/',
        'mandriva.com/',
        'exploit-db.com/',
        'marc.info/',
        'securityfocus.com/',
        'exchange.xforce.ibmcloud.com/',
        'kb.cert.org/',
        'cvs.sourceforge.net',
        'metasploit.com'
    ]

    '''
    List of keywords to look for in an URL. If a URL did not match any of the regular
    URL classes but contains at least one of these keywords, a KeywordMatch instance
    (see below) is created for this URL.
    '''
    WHITELIST = [
        'commit',
        'git',
        'diff',
        'issue',
        'patch',
        'revision'
    ]

    '''
    Internal list of registered URL classes which can be matched with testAll()
    testAllUrls(). Subclasses can be registered by callig the register() method.
    '''
    PATTERNS = []

    '''
    The timeout for fetching patches
    '''
    TIMEOUT = 8

    def __init__(self, url):
        '''
        PatchPattern subclasses are supposed to be instantiated through the class
        method test(), which will then call this initializer if the URL indeed
        matches the pattern of the tested class. The initializor matches the 
        URL against the URL class' pattern and builds the new URL used for obtaining
        the patch by one of the methods described above.
        @param url  The URL for which a subclass of PatchPattern is created
        '''
        self.url = url
        self.details = re.match(self.URL_PATTERN, url).groups()

        if self.URL_REPLACE_WITH:
            if not self.URL_REPLACE_STR:
                self.new_url = self.URL_REPLACE_WITH % self.details
            else:
                self.new_url = re.sub(self.URL_REPLACE_STR, self.URL_REPLACE_WITH, url)
        else:
            self.new_url = self.url

    def getPatch(self, ua='Mozilla/5.0 (compatible; CVEBot)'):
        '''
        Tries to obtain the patch (or in some cases, a list of patches) for an
        instance of a URL class. If the URL class implements _getPatch(), that
        method is called first. Should it not yield any results, the generic
        approach is used to obtain the patch. Before patches are returned, they
        can be processed by subclasses implementing _processPatches().
        @param userAgent    The user agent string used to fetch the patch
        @returns            A list of one ore more patches
        '''
        r = self._getPatch(userAgent)
        if r != None:
            return r

        try:
            res = requests.get(self.new_url, headers={"User-Agent": userAgent}, timeout=self.TIMEOUT)
            assert(res.status_code == 200)
        except Exception as e:
            '''
            If fetching the newly created patch URL fails, try fetching the original
            URL instead. Especially for older CVEs the older URLs often are redirected
            to a new one. If that is the case, the redirected-to URL can again be
            matched against the known URL classes.
            '''
            print('Cannot fetch %s: %s' % (self.new_url, e))
            if self.url != self.new_url:
                try:
                    res = requests.get(self.url, headers={"User-Agent": userAgent}, timeout=self.TIMEOUT)
                    assert(res.status_code == 200)
                except Exception as e:
                    return []
                if self.url.split('://', 1)[1] != res.url.split('://', 1)[1]:
                    # The original URL redirected somewhere else. Return patches from
                    # the URL patterns recognized in that URL
                    matches = PatchPattern.testAll(res.url)
                    return list(itertools.chain(*[m.getPatch() for m in matches]))
            return []

        if not self.ALLOW_REDIRECT and self.new_url.split('://', 1)[1] != res.url.split('://', 1)[1]:
            return []

        # Apply looksLikePatch() to all patches before we return the result to make
        # sure the crawled text looks like a patch.
        return list(filter(looksLikePatch, self._processPatches([res.text])))

    def _getLinksFrom(self, html, selector, url):
        '''
        Helper method for _getLinksFor(): takes the source code of a HTML document
        and returns all URLs of links in the document which match a certain CSS
        selector.
        @param html         The HTML source code
        @param selector     The CSS selector
        @param url          Base URL of the document required to resolve relative links
        @returns            A list of links
        '''
        soup = BeautifulSoup(html, 'html.parser')

        links = []
        for link in soup.select(selector):
            if 'href' in link.attrs:
                link = urljoin(url, link.attrs['href'])
                if ('://' in url) ^ ('://' in link) or  url.split('://', 1)[1] != link.split('://', 1)[1]:
                    links.append(link)

        return links

    def _getLinksFor(self, url, selector, userAgent):
        '''
        Helper method that extracts all links on a website that match a certain CSS
        selector.
        @param url          The URL of the website
        @param selector     The CSS selector
        @oaram userAgent    The user agent string used to fetch the HTML document
        @returns            A list of links
        '''
        try:
            res = requests.get(self.new_url, headers={"User-Agent": userAgent}, timeout=self.TIMEOUT)
            assert(res.status_code == 200)
        except Exception as e:
            print('Cannot fetch %s: %s' % (self.new_url, e))
            return []
        return self._getLinksFrom(res.text, selector, url)

    def _getPatch(self, userAgent):
        '''
        This method can be implemented by subclasses which require a customzied
        process of fetching the patch.
        @param userAgent    The user agent string used to fetch the patch
        @returns            A list of one or more patches
        '''
        return None

    def _processPatches(self, patches):
        '''
        This method can be implemented by subclasses to postprocess the patches
        found by it.
        @param patches      A list of patches that was found for this URL
        @returns            The postprocessed list of patches
        '''
        return patches

    @staticmethod
    def register(cls):
        '''
        Must be called for each subclass which should be matched by testAll()
        @param cls  The subclass to be registered
        '''
        PatchPattern.PATTERNS.append(cls)

    @classmethod
    def test(cls, url):
        '''
        Matches an URL against this URL class. If it matches, an instance of this
        URL class is created for the tested URL.
        @param url  The URL to be tested
        @returns    Either an instance of the tested class or None
        '''
        if re.match(cls.URL_PATTERN, url):
            return cls(url)
        return None

    @staticmethod
    def testAll(url, allow_indirect=True):
        '''
        Matches an URL against all known (registered) URL classes. If a URL does
        not match any of the known URL classes, contains no blacklisted keywords
        and contains at least one keyword on the whitelist, a KeywordMatch instance
        is created, which might resolve to a patch later when patches are fetched
        (see KeywordMatch / WHITELIST attribute).
        @param url              The URL to be tested
        @param allow_indirect   Whether to match the URL against URL classes of
                                websites that again contain potential links to
                                patches (or links that can be converted in one).
                                See IS_DIRECT attribute
        @returns                A list of PatchPattern instances that match the
                                tested URL
        '''
        res = []
        for pattern in PatchPattern.PATTERNS:
            match = pattern.test(url)
            if match and (allow_indirect or match.IS_DIRECT):
                res.append(match)

        if not res \
            and not any(b in url for b in PatchPattern.BLACKLIST) \
            and any(w in url for w in PatchPattern.WHITELIST):
            res.append(KeywordMatch(url))
        return res

    @staticmethod
    def testAllUrls(urls, allow_indirect=True):
        '''
        Takes a list of URLs and tests all of them against the known URL classes.
        The results are aggregated into one list.
        @param urls             The list of URLs to be tested
        @param allow_indirect   Whether to match the URL against URL classes of
                                websites that again contain potential links to
                                patches (or links that can be converted in one).
                                See IS_DIRECT attribute
        @returns                A list of PatchPattern instances that match the
                                tested URLs
        '''
        res = []
        for url in urls:
            res+= PatchPattern.testAll(url, allow_indirect=allow_indirect)
        return res


class KeywordMatch(PatchPattern):
    '''
    An instance of this class is created for all URLs that could not be matched
    to any of the other known URL classes and that contain no blacklisted and
    at least one whitelisted keyword.
    This helps to fetch patches hidden behind a redirected URL: in getPatch(), this
    class will fetch the original URL and, if it was redirected, match the redirected-to
    URL against known pattern (and starts the whole process again in case of success).
    '''
    URL_PATTERN = r'.+'
    IS_DIRECT = False

    def _getPatch(self, userAgent):
        try:
            res = requests.get(self.new_url, headers={"User-Agent": userAgent}, timeout=self.TIMEOUT)
            assert(res.status_code == 200)
        except Exception as e:
            print('Cannot fetch %s: %s' % (self.new_url, e))
            return []

        # if request was sucessfiul and redirected somewhere new, match that new
        # URL against known URL patterns to get the patch
        if self.new_url.split('://', 1)[1] != res.url.split('://', 1)[1]:
            matches = PatchPattern.testAll(res.url)
            return list(itertools.chain(*[m.getPatch(userAgent) for m in matches]))
        return []


class RawPatch(PatchPattern):
    '''
    URL class of direct links to patch files (identified by the .patch or .patch.gz
    ending for gzipped patches)
    '''
    URL_PATTERN = r'(.+\.(?:patch(?:\.sig)?|diff)(?:.gz)?)$'

    def _getPatch(self, userAgent):
        try:
            req = urllib.request.Request(self.new_url, headers={"User-Agent": userAgent})
            req = urllib.request.urlopen(req, timeout=self.TIMEOUT)
        except Exception as e:
            # no retry with original URL required, since we always use the original URL
            return []
        patchGz = req.read()

        if looksLikePatchBytes(patchGz):
            return [patchGz.decode('utf8', 'ignore')]
        try:
            return [gzip.decompress(patchGz).decode('utf8', 'ignore')]
        except:
            return []


class GithubCommit(PatchPattern):
    '''
    Patches from links to commits on github can be retrieved by appending '.patch'
    '''
    URL_PATTERN = r'^((?:https?://)?(?:www\.)?github\.com/[^/]+/[^/]+/commit/\w+)(?:\.patch|\.diff|[/?#].*)?$'
    URL_REPLACE_WITH = '%s.patch'


class GithubPullRequest(PatchPattern):
    '''
    Patches from links to pull requests on github can be retrieved by
    appending '.patch'
    '''
    URL_PATTERN = r'^((?:https?://)?(?:www\.)?github\.com/[^/]+/[^/]+/pull/\d+)(?:\.patch|\.diff|[/?#].*)?$'
    URL_REPLACE_WITH = '%s.patch'


class GithubIssue(PatchPattern):
    '''
    Patches from links to issues on github can be retrieved by crawling links and
    references to pull requests or commits. Gathered links can then again be matched
    against known URL classes
    '''
    URL_PATTERN = r'^((?:https?://)?(?:www\.)?github\.com/[^/]+/[^/]+/issues/\d+)(?:[/?#].*)?$'
    LINK_SELECTOR = 'div.issue-details a'
    IS_DIRECT = False

    def _getPatch(self, userAgent):
        links = self._getLinksFor(self.new_url, self.LINK_SELECTOR, userAgent)
        matches = PatchPattern.testAllUrls(links, allow_indirect=False)
        return list(itertools.chain(*[m.getPatch() for m in matches]))


class GitlabCommit(PatchPattern):
    '''
    Patches from links to commits on gitlab can be retrieved by appending '.patch'.
    Matches self-hosted gitlab servers (with 'gitlab' in the (sub)domain name)
    and the official one
    '''
    URL_PATTERN = r'^((?:https?://)?(?:www\.)?gitlab(?:\.[^\.]+)?\.[^\.]+/[^/]+/[^/]+/commit/\w+)(?:\.diff|\.patch|[/?#].*)?$'
    URL_REPLACE_WITH = '%s.patch'


class GitlabMergeRequest(PatchPattern):
    '''
    Patches from links to merge requests on github can be retrieved by
    appending '.patch'. Matches self-hosted gitlab servers (with 'gitlab' in the
    (sub)domain name) and the official one
    '''
    URL_PATTERN = r'^((?:https?://)?(?:www\.)?gitlab(?:\.[^\.]+)?\.[^\.]+/[^/]+/[^/]+/merge_requests/\d+)(?:\.diff|\.patch|[/?#].*)?'
    URL_REPLACE_WITH = '%s.patch'


class GitlabIssue(PatchPattern):
    '''
    Patches from links to issues on gitlab can be retrieved by crawling links and
    references to pull requests or commits. Gathered links can then again be matched
    against known URL classes. Matches self-hosted gitlab servers (with 'gitlab' in
    the (sub)domain name) and the official one
    '''
    URL_PATTERN = r'^((?:https?://)?(?:www\.)?gitlab(?:\.[^\.]+)?\.[^\.]+/[^/]+/[^/]+/issues/\d+(?:[/?#].*)?)$'
    LINK_SELECTOR = 'div.issue-details a'
    JSON_FMT = '%s/discussions.json'
    IS_DIRECT = False

    def _getPatch(self, userAgent):
        links = self._getLinksFor(self.new_url, self.LINK_SELECTOR, userAgent)

        try:
            res = requests.get(self.JSON_FMT % self.details, headers={"User-Agent": userAgent}, timeout=self.TIMEOUT)
            assert(res.status_code == 200)
        except Exception as e:
            print('Cannot fetch %s: %s' % (self.new_url, e))
            return []

        j = res.json()
        for entry in j:
            for note in entry['notes']:
                if 'note_html' in note:
                    links+= self._getLinksFrom(note['note_html'], 'a', self.new_url)

        matches = PatchPattern.testAllUrls(links, allow_indirect=False)
        return list(itertools.chain(*[m.getPatch() for m in matches]))


class BitbucketCommit(PatchPattern):
    '''
    Patches from links to commits on gitlab can be retrieved by appending '/raw'
    '''
    URL_PATTERN = r'^((?:https?://)?(?:.+\.)?bitbucket\.org/[^/]+/[^/]+/commits/\w+)(?:/raw|[/?#].*)?$'
    URL_REPLACE_WITH = '%s/raw'


class CGit(PatchPattern):
    '''
    Patches from links to commits on cgit servers can be retrieved by replacing
    '/commit/' with '/patch/'
    '''
    # http(s)://some-domain.com/some/path/(commit|diff|patch)/?some=args&id=required&more-args=why-not
    URL_PATTERN = r'^((?:https?://)?.+/(?:commit|diff|patch)(?:/.*)?\?(?:.+\&)?id=.+(?:\&.+)?)$'
    URL_REPLACE_STR = r'/(commit|diff|patch)/'
    URL_REPLACE_WITH = '/patch/'


class Gitweb1(PatchPattern):
    # http(s)://some-domain.com/some/path/?some=args;more=args;p=required;a=not-required;h=required;order=not-relevant
    URL_PATTERN = r'^((?:https?://)?.+?\?(?:.*(?:;|(?<=\?))p=[^;]+()|.*(?:;|(?<=\?))a=(?:commit(?:diff)?|patch|blob)()|.*(?:;|(?<=\?))h=[^;]+()){2,3}(?:\2|\3)\4.*)$'
    URL_REPLACE_STR = r'(?:(h=\w+)|a=(commit(?:diff)?|patch|blob))'
    URL_REPLACE_WITH = '\\1;a=patch'


class Gitweb2(PatchPattern):
    # http(s)://some-domain-but-not-(www.)github.com/some-name/(commit|patch|blob)/what-commit-or-patch
    URL_PATTERN = r'^((?:https?://)?(?<!(?:www\.)github\.com)(?<!:)/.+/(?:commit(?:diff)?|commit|patch|blob)/[^?]+)$'
    URL_REPLACE_STR = r'/(commit(?:diff)?|diff|patch|blob)/'
    URL_REPLACE_WITH = '/patch/'


class Gitweb3(PatchPattern):
    # http(s)://some-domain.com/any/path/?some=parameters;p=required-or;a=blobdiff(_plain)?;either-p-or-a=required;h=required
    URL_PATTERN = r'^((?:https?://)?.+?\?(?:.*(?:;|(?<=\?))p=[^;]+()|.*(?:;|(?<=\?))a=blobdiff(?:_plain)?()|.*(?:;|(?<=\?))h=[^;]+()){2,3}(?:\2|\3)\4.*)$'
    URL_REPLACE_STR = r'a=blobdiff(?:_plain)?'
    URL_REPLACE_WITH = 'a=blobdiff_plain'


class Hgweb(PatchPattern):
    # http(s)://some-domain.com/any/path/(raw-diff|raw-rev|diff|comparison)/
    URL_PATTERN = r'^((?:https?://)?.+/(?:raw-diff|raw-rev|diff|comparison)/.+)$'
    URL_REPLACE_STR = r'/(raw-diff|raw-rev|diff|comparison)/'
    URL_REPLACE_WITH = '/raw-diff/'


class Loggerhead(PatchPattern):
    # http(s)://some-domain.com/any/path/(diff|revision)/
    URL_PATTERN = r'^((?:https?://)?.+/(?:diff|revision)/.+)$'
    URL_REPLACE_STR = r'/(diff|revision)/'
    URL_REPLACE_WITH = '/diff/'


class Patchwork(PatchPattern):
    # http(s)://some-domain.com/any/path/patch/commit-identifier
    URL_PATTERN = r'^((?:https?://)?.+/patch/\d+)(?:/[^/])?/?$'
    URL_REPLACE_WITH = '%s/raw/'


class Redmine(PatchPattern):
    # http(s)://some-domain.com/any/path/repository/revisions/commit-identifier
    URL_PATTERN = r'^((?:https?://)?.+/repository/revisions/.+)$'
    URL_REPLACE_STR = r'(/revisions/[^?]+(\?.*)?)'
    URL_REPLACE_WITH = lambda self, x: x[1] + (x[2] and '&' or '?') + 'format=diff'


class Sourceforge(PatchPattern):
    # http(s)://some-domain.com/any/path/p/?some=args&(diff|bardiff)=commit-identifier&other-args=why-not
    URL_PATTERN = r'^((?:https?://)?.+/p/.+\?(?:.+&)?(?:diff|barediff)=\w+(?:&.+)?)$'
    URL_REPLACE_STR = r'([?&])diff='
    URL_REPLACE_WITH = '\\1barediff='

    def _processPatches(self, patches):
        return [BeautifulSoup(patches[0], 'lxml').text]


class BugzillaAttachment(PatchPattern):
    # http(s)://some-domain.com/any/path/attachment.cgi?some=args&id=required&other-args=why-not
    URL_PATTERN = r'^((?:https?://)?.+/attachment\.cgi\?(?:.+&)?id=\d+(?:&.+)?)$'
    URL_REPLACE_STR = r'(?:(attachment\.cgi\?)|action=(diff|edit)?)'
    URL_REPLACE_WITH = '\\1action=diff&format=raw&'


class Bugzilla(PatchPattern):
    # http(s)://some-domain.com/any/path/show_bug.cgi?some=args&id=required&other-args=why-not
    URL_PATTERN = r'^((?:https?://)?.+/show_bug\.cgi\?(?:.+&)?id=\d+(?:&.+)?)$'
    LINK_SELECTOR = '.bz_comment_table .bz_comment_text a'
    IS_DIRECT = False

    def _getPatch(self, userAgent):
        links = self._getLinksFor(self.new_url, self.LINK_SELECTOR, userAgent)
        matches = PatchPattern.testAllUrls(links, allow_indirect=False)
        return list(itertools.chain(*[m.getPatch() for m in matches]))


PatchPattern.register(RawPatch)
PatchPattern.register(GithubCommit)
PatchPattern.register(GithubPullRequest)
PatchPattern.register(GithubIssue)
PatchPattern.register(GitlabCommit)
PatchPattern.register(GitlabMergeRequest)
PatchPattern.register(GitlabIssue)
PatchPattern.register(BitbucketCommit)
PatchPattern.register(CGit)
PatchPattern.register(Gitweb1)
PatchPattern.register(Gitweb2)
PatchPattern.register(Hgweb)
PatchPattern.register(Loggerhead)
PatchPattern.register(Patchwork)
PatchPattern.register(Redmine)
PatchPattern.register(Bugzilla)
PatchPattern.register(BugzillaAttachment)
PatchPattern.register(Sourceforge)


# =============== STEP 5: PREPROCESS PATCHES: FIND PATCH SEGMENTS ==============


class PatchSegment(namedtuple('PatchSegment', ['filename', 'pos_descriptor', 'code', 'modifications'])):
    pass


def patch2segments(patch):
    '''
    Splits a patch file into patch segments. A patch segment contains one ore more
    modifications to one file that are spatially close to each other. For every
    reference to a section of the modified file using '@@ <lineno>' in the patch, 
    a new patch section is created.
    Segments are detected by the leading '@@' in the line that describes the location
    within the affected file. For each segment, this function collects the descriptor
    listed in the patch file after the '@@' as well as the code in the affected
    section of the original file. This means, lines in the patch file describing
    an inserted line are ignored, while unchanged or removed lines are included.
    Lastly, this function collects the line numbers of all modified lines (relative
    to the line number in the original file)
    '''
    lines = patch.split('\n')
    segments = []
    found_patch = False

    # accumulate these values for each patch segment while iterating over the patch
    # file line by line
    pos_descriptor = None
    filename = None
    code = []
    modifications = set()
    for l in lines:
        if l.startswith('---'):
            '''
            Wwe might pick up some junk here (if a line starting with '--' is deleted)
            but only the last line starting with '---' will be used to create the
            segment, which will always be the line specifying the modified line.
            '''
            filename = l[4:]

            '''
            Even if this line is a valid line in the source code, do not consider it.
            It is most likely just a divider inserted by some diff tools.
            Only exception: a global piece of code '--some_var' that was added with
            the patch, but we will just ignore this case.
            '''
            continue

        if l.startswith('+++'):
            # Aslo drop lines starting with '+++', same reason..
            continue

        if l.startswith('@@'):
            # found beginning of a patch segment
            if pos_descriptor is not None and filename:
                segments.append(PatchSegment(filename, pos_descriptor, code, modifications))

            pos_descriptor = l.split('@@')[-1]
            code = []
            modifications = set()
            found_patch = True
            continue

        if not found_patch:
            # Drop everything until we find a patch segment
            continue

        if l.startswith(' '):
            code.append(l[1:])
        elif l.startswith('-'):
            # Also add code that was removed with the patch, so we don't further break
            # already broken code. CLANG must be able to parse it!
            code.append(l[1:])
            modifications.add(len(code))
        elif l.startswith('+'):
            # Don't include inserted code in the code extract
            # (could contain the beginning of another comment, and we don't really
            # care about the modification itself, just the fact there is one)
            modifications.add(len(code))
        else:
            '''
            We probably hit the commit message for the next patch segment, or the
            'diff --git' line starting the next segment, as produced by some diff tools
            -> Ignore everything until we find the next line indicating the position in the file
            '''
            if pos_descriptor is not None and filename:
                segments.append(PatchSegment(filename, pos_descriptor, code, modifications))
            pos_descriptor = None
            found_patch = False
    if pos_descriptor is not None:
        segments.append(PatchSegment(filename, pos_descriptor, code, modifications))
    return segments


# ========== STEP 6: PROCESS PATCH SEGMENTS: FIND VULNERABLE FUNCTIONS =========


def segment2vulnfcn(segment, do_prepend=False):
    filename, pos_descriptor, code, modifications = segment

    '''
    Function header declarations can be spread across multiple lines (e.g. if there are many arguments),
    however the position description in a patch file gives only the first line
    of the function header. CLANG will not parse the rest of the file if it finds
    an unmatched parenthesis, thus we need to fix this here.
    '''

    if pos_descriptor and do_prepend:
        # first, remove trailing commas
        if pos_descriptor.endswith(','):
            pos_descriptor = pos_descriptor[:-1]

        # second, match unclosed parentheses
        c_open, c_close = pos_descriptor.count('('), pos_descriptor.count(')')
        pos_descriptor+= ')' * (c_open - c_close)
        if not pos_descriptor.strip().endswith('{'):
            pos_descriptor+= '{'

        '''
        Additionally, add as many opening braces as there are unmatched closing braces
        '''
        c_open = pos_descriptor.count('{') + sum(map(lambda x: x.count('{'), code))
        c_close = pos_descriptor.count('}') + sum(map(lambda x: x.count('}'), code))
        pos_descriptor+= '{' * (c_close - c_open)

    '''
    Write patch segment to temporary file so that it can be processed by CLANG.
    Whatever was listed after the '@@' in the patch file is preprended, as it
    could be the function header and CLANG is nice enough to parse that for us as well.
    '''
    res = []
    with NamedTemporaryFile(mode='w', suffix=filename.split('/')[-1], delete=False) as f:
        if pos_descriptor and do_prepend:
            f.write(pos_descriptor + '\n')
        f.write('\n'.join(code))
        f.flush()
        name = f.name

        try:
            index = Index.create()
            parsed = index.parse(name)
            c = parsed.cursor
        except TranslationUnitLoadError as e:
            # Parsing failed probably because we prepended the position descriptor
            # -> try again without it
            if pos_descriptor:
                return segment2vulnfcn(PatchSegment(filename, '', code, modifications))
            return []
        except Exception as e:
            print('Some error occured while parsing the patch segment: ' + str(e))
            return []

        candidate = None
        last_decl = 0
        first_decl = 0
        for elem in c.walk_preorder():
            # Some function calls are mistaken as a function declaration, however
            # in that case the definition is missing. 
            if elem.kind == CursorKind.FUNCTION_DECL and elem.get_definition():
                if candidate and any(x + do_prepend >= last_decl and x + do_prepend < elem.location.line for x in modifications):
                    res.append('%s: %s' % (filename, candidate))
                last_decl = elem.location.line
                first_decl = first_decl or last_decl
                candidate = elem.displayname
        if candidate and any(x + do_prepend >= last_decl and x + do_prepend <= len(code) + 1 for x in modifications):
            res.append('%s: %s' % (filename, candidate))

    if not res and not do_prepend:
        return segment2vulnfcn(segment, do_prepend=True)

    return res


# ========================== PUTTING IT ALL TOGETHER ===========================


def printOrWrite(args, msg, out):
    '''
    Helper function that either pretty-prints a JSON formatted program output to stdout
    or writes the JSON to a file (not pretty-printed)
    @param args     The CLI arguments parsed by argparse
    @oaram msg      A message to print before dumping the JSON to stdout
    @param out      The datastructure that will be serialized into JSON
    '''
    if not args.output:
        print('=' * 80)
        print(msg)
        print(json.dumps(out, indent=4))
    else:
        with open(args.output, 'w') as f:
            json.dump(out, f)

def process(args):
    '''
    Implements the entire pipeline of finding the vulnerable functions of a library.
    It includes several steps:
     1. Fetch known CVEs for the library (see getCVEsForLib())
     2. Fetch references for the CVEs (see getCVEReferences())
     3. Filter out all URLs from those references which might give us a patch (see PatchPattern.testAll())
     4. Fetch all the patches (see PatchPattern.getPatch())
     5. Preprocess the patches: extract patch segments (see patch2segments())
     6. Process each patch segment to find the function that was modified in it
    
    This CLI program can enter and leave this pipeline at several points:
      Enter: before steps 1, 2
      Leave: after steps 1, 2, 3, 4, 6
    With default parameters, the program will run the pipeline until the last step.
    @param  The CLI argiments parsed by argparse
    '''
    
    # step 1: fetch known CVEs for the library
    if args.library:
        print('Fetch CVEs..')
        cves = getCVEsForLib(args.library,
                             version=args.version,
                             match_subversion=not args.no_match_subversion,
                             match_unversioned=args.match_unversioned)
        cves = sorted(set(map(itemgetter(0), cves)))
    
    if args.cve:
        cves = [args.cve]
    
    if args.extract_cves:
        printOrWrite(args, 'CVEs:', cves)
        return
    
    if not cves:
        print('No CVEs found')
        return
    
    # step 2: fetch the references for the CVEs
    print('Fetch CVE references..')
    cve2url = {cve: getCVEReferences(cve) for cve in cves}
    
    if args.extract_references:
        printOrWrite(args, 'CVEs and referenced URLs:', cve2url)
        return
    
    # step 3: filter out URLs that might give us a patch
    print('Filter patch URLs..')
    url_sorter = lambda url: url.url
    cve2patch_urls = {cve: sorted(PatchPattern.testAllUrls(urls), key=url_sorter) for cve, urls in cve2url.items()}
    
    if args.extract_patch_urls:
        o = {cve: [purl.url for purl in purls] for cve, purls in cve2patch_urls.items()}
        printOrWrite(args, 'CVEs and potential patch URLs:', o)
        return
    
    # step 4: fetch all the patches
    print('Fetch patches')
    cve2patch = {cve: {p.url: p.getPatch() for p in patch_urls} for cve, patch_urls in cve2patch_urls.items()}

    if args.extract_patches:
        printOrWrite(args, 'CVEs and patches:', cve2patch)
        return
    
    # step 5: preprocess patches to partition them into patch segments
    print('Preprocess patches: extract patch segments..')
    cve2segments = {cve: sorted(itertools.chain(*(sorted(itertools.chain(*(patch2segments(p) for p in ps))) for _, ps in patches.items()))) for cve, patches in cve2patch.items()}

    # step 6: process patch segments to find vulnerable functions
    print('Process patches: extract vulnerable functions..')
    cve2vuln_fcn = {cve: sorted(set(itertools.chain(*(segment2vulnfcn(segment) for segment in segments)))) for cve, segments in cve2segments.items()}

    printOrWrite(args, 'CVEs and vulnerable functions:', cve2vuln_fcn)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Obtain patches/vulnerable from a CVE identifier or for a specific library')
    
    grp = parser.add_argument_group('Output options')
    grp.add_argument('--cve', '-c',
                     help='Fetch information about an CVE identifier (CVE-2018-...)')
    grp.add_argument('--library', '-l', default=None,
                     help='Fetch information for a library')
    grp.add_argument('--version', '-v', default=None,
                     help='Fetch information for a specific version of a library')
    
    grp = parser.add_argument_group('Version matching options')
    grp.add_argument('--no-match-subversion', default=False, action='store_true',
                     help='Do not match the subversion string when matching the vulnerable configuration of CVEs with the queried librarie\'s version')
    grp.add_argument('--match-unversioned', default=False, action='store_true',
                     help='If no version is reported for a vulnerable configuration of a CVE, match the configuration anyway (might produce false positives)')
    
    grp = parser.add_argument_group('Output options')
    grp.add_argument('--output', '-o', default=None,
                     help='Output file in which to store the output (JSON format)')
    ex = parser.add_mutually_exclusive_group()
    ex.add_argument('--extract-references', '-er', default=False, action='store_true',
                    help='Retrieve URLs referenced by CVE(s) only')
    ex.add_argument('--extract-patch-urls', '-eu', default=False, action='store_true',
                    help='Retrieve potential patch URLs only')
    ex.add_argument('--extract-patches', '-ep', default=False, action='store_true',
                    help='Retrieve patches only, do not extract vulnerable functions')
    ex.add_argument('--extract-cves', '-ec', default=False, action='store_true',
                    help='Retrieve CVEs only')
    
    args = parser.parse_args()
    
    if not args.cve and not args.library:
        print('No input given')
        parser.print_help()
        exit(1)
    
    process(args)
