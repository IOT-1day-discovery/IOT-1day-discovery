import gzip
import itertools
import requests
import re
import urllib

from urllib.parse import urljoin
from bs4 import BeautifulSoup

userAgent = 'Mozilla/5.0 (compatible; CVEBot)'

class PatchPattern:
    URL_PATTERN = None
    URL_REPLACE_STR = None
    URL_REPLACE_WITH = None
    
    ALLOW_REDIRECT = True
    
    IS_DIRECT = True
    
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
    
    WHITELIST = [
        'commit',
        'git',
        'diff',
        'issue',
        'patch',
        'revision'
    ]
    
    PATTERNS = []
    
    TIMEOUT = 8
    
    def __init__(self, url):
        self.url = url
        self.details = re.match(self.URL_PATTERN, url).groups()
        
        if self.URL_REPLACE_WITH:
            if not self.URL_REPLACE_STR:
                self.new_url = self.URL_REPLACE_WITH % self.details
            else:
                self.new_url = re.sub(self.URL_REPLACE_STR, self.URL_REPLACE_WITH, url)
        else:
            self.new_url = self.url
    
    def getPatch(self, userAgent='Mozilla/5.0 (compatible; CVEBot)'):
        r = self._getPatch(userAgent)
        if r != None:
            return r
        
        try:
            res = requests.request('GET', self.new_url, headers={"User-Agent": userAgent}, timeout=self.TIMEOUT)
            assert(res.status_code == 200)
        except Exception as e:
            print('Cannot fetch %s: %s' % (self.new_url, e))
            if self.url != self.new_url:
                try:
                    res = requests.request('GET', self.url, headers={"User-Agent": userAgent}, timeout=self.TIMEOUT)
                    assert(res.status_code == 200)
                except Exception as e:
                    return []
                if self.url.split('://', 1)[1] != res.url.split('://', 1)[1]:
                    matches = PatchPattern.testAll(res.url)
                    return list(itertools.chain(*[m.getPatch() for m in matches]))
            return []
        
        if not self.ALLOW_REDIRECT and self.new_url.split('://', 1)[1] != res.url.split('://', 1)[1]:
            return []
        
        return [self._processPatch(res.text)]
    
    def _getLinksFrom(self, html, selector, url):
        soup = BeautifulSoup(html, 'html.parser')
        
        links = []
        for link in soup.select(selector):
            if 'href' in link.attrs:
                link = urljoin(url, link.attrs['href'])
                if ('://' in url) ^ ('://' in link) or  url.split('://', 1)[1] != link.split('://', 1)[1]:
                    links.append(link)
        
        return links
    
    def _getLinksFor(self, url, selector, userAgent):
        try:
            res = requests.request('GET', self.new_url, headers={"User-Agent": userAgent}, timeout=self.TIMEOUT)
            assert(res.status_code == 200)
        except Exception as e:
            print('Cannot fetch %s: %s' % (self.new_url, e))
            return []
        return self._getLinksFrom(res.text, selector, url)
    
    def _getPatch(self, userAgent):
        return None
    
    def _processPatch(self, patch):
        return patch
    
    @staticmethod
    def register(cls):
        PatchPattern.PATTERNS.append(cls)
    
    @classmethod
    def test(cls, url):
        if re.match(cls.URL_PATTERN, url):
            return cls(url)
        return None
    
    @staticmethod
    def testAll(url, allow_indirect=True):
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
        res = []
        for url in urls:
            res+= PatchPattern.testAll(url, allow_indirect=allow_indirect)
        return res

class KeywordMatch(PatchPattern):
    URL_PATTERN = r'.+'
    IS_DIRECT = False
    
    def _getPatch(self, userAgent):
        try:
            res = requests.request('GET', self.new_url, headers={"User-Agent": userAgent}, timeout=self.TIMEOUT)
            assert(res.status_code == 200)
        except Exception as e:
            print('Cannot fetch %s: %s' % (self.new_url, e))
            return []
        
        if self.new_url.split('://', 1)[1] != res.url.split('://', 1)[1]:
            matches = PatchPattern.testAll(res.url)
            return list(itertools.chain(*[m.getPatch() for m in matches]))
        return []

class RawPatch(PatchPattern):
    URL_PATTERN = r'(.+\.(?:patch(?:\.sig)?|diff)(?:.gz)?)$'
    
    def _getPatch(self, userAgent):
        try:
            req = urllib.request.Request(self.new_url, headers={"User-Agent": userAgent})
            req = urllib.request.urlopen(req, timeout=self.TIMEOUT)
        except Exception as e:
            # no retry with original URL required, since we always use the original URL
            return []
        patchGz = req.read()
        if b'+++' in patchGz and b'---' in patchGz:
            return [patchGz.decode('utf8', 'ignore')]
        try:
            return [gzip.decompress(patchGz).decode('utf8', 'ignore')]
        except:
            return []

class GithubCommit(PatchPattern):
    URL_PATTERN = r'^((?:https?://)?(?:www\.)?github\.com/[^/]+/[^/]+/commit/\w+)(?:\.patch|\.diff|[/?#].*)?$'
    URL_REPLACE_WITH = '%s.patch'

class GithubPullRequest(PatchPattern):
    URL_PATTERN = r'^((?:https?://)?(?:www\.)?github\.com/[^/]+/[^/]+/pull/\d+)(?:\.patch|\.diff|[/?#].*)?$'
    URL_REPLACE_WITH = '%s.patch'

class GithubIssue(PatchPattern):
    URL_PATTERN = r'^((?:https?://)?(?:www\.)?github\.com/[^/]+/[^/]+/issues/\d+)(?:[/?#].*)?$'
    LINK_SELECTOR = 'div.issue-details a'
    IS_DIRECT = False
    
    def _getPatch(self, userAgent):
        links = self._getLinksFor(self.new_url, self.LINK_SELECTOR, userAgent)
        matches = PatchPattern.testAllUrls(links, allow_indirect=False)
        return list(itertools.chain(*[m.getPatch() for m in matches]))

class GitlabCommit(PatchPattern):
    URL_PATTERN = r'^((?:https?://)?(?:www\.)?gitlab(?:\.[^\.]+)?\.[^\.]+/[^/]+/[^/]+/commit/\w+)(?:\.diff|\.patch|[/?#].*)?$'
    URL_REPLACE_WITH = '%s.patch'

class GitlabMergeRequest(PatchPattern):
    URL_PATTERN = r'^((?:https?://)?(?:www\.)?gitlab(?:\.[^\.]+)?\.[^\.]+/[^/]+/[^/]+/merge_requests/\d+)(?:\.diff|\.patch|[/?#].*)?'
    URL_REPLACE_WITH = '%s.patch'

class GitlabIssue(PatchPattern):
    URL_PATTERN = r'^((?:https?://)?(?:www\.)?gitlab(?:\.[^\.]+)?\.[^\.]+/[^/]+/[^/]+/issues/\d+(?:[/?#].*)?)$'
    LINK_SELECTOR = 'div.issue-details a'
    JSON_FMT = '%s/discussions.json'
    IS_DIRECT = False
    
    def _getPatch(self, userAgent):
        links = self._getLinksFor(self.new_url, self.LINK_SELECTOR, userAgent)
        
        try:
            res = requests.request('GET', self.JSON_FMT % self.details, headers={"User-Agent": userAgent}, timeout=self.TIMEOUT)
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
    URL_PATTERN = r'^((?:https?://)?(?:.+\.)?bitbucket\.org/[^/]+/[^/]+/commits/\w+)(?:/raw|[/?#].*)?$'
    URL_REPLACE_WITH = '%s/raw'

class CGit(PatchPattern):
    URL_PATTERN = r'^((?:https?://)?.+/(?:commit|diff|patch)(?:/.*)?\?(?:.+\&)?id=.+(?:\&.+)?)$'
    URL_REPLACE_STR = r'/(commit|diff|patch)/'
    URL_REPLACE_WITH = '/patch/'

class Gitweb1(PatchPattern):
    # (r'^((?:https?://)?.+\?p=[^;]+;)(?:a=commit;|a=commitdiff;|a=patch;)?(h=.+)$', '%sa=patch;%s', GITWEB),
    # http(s)://some-url.com/some/path/?some=args;more=args;p=required;a=not-required;h=required;order=not-relevant
    URL_PATTERN = r'^((?:https?://)?.+?\?(?:.*(?:;|(?<=\?))p=[^;]+()|.*(?:;|(?<=\?))a=(?:commit(?:diff)?|patch)()|.*(?:;|(?<=\?))h=[^;]+()){2,3}(?:\2|\3)\4.*)$'
    URL_REPLACE_STR = r'(?:(h=\w+)|a=(commit(?:diff)?|patch))'
    URL_REPLACE_WITH = '\\1;a=patch'

class Gitweb2(PatchPattern):
    # http(s)://some-url-but-not-(www.)github.com/some-name/(commit|patch)/what-commit-or-patch
    URL_PATTERN = r'^((?:https?://)?(?<!(?:www\.)github\.com)(?<!:)/.+/(?:commit(?:diff)?|commit|patch)/[^?]+)$'
    URL_REPLACE_STR = r'/(commit(?:diff)?|diff|patch)/'
    URL_REPLACE_WITH = '/patch/'

class Gitweb3(PatchPattern):
    URL_PATTERN = r'^((?:https?://)?.+?\?(?:.*(?:;|(?<=\?))p=[^;]+()|.*(?:;|(?<=\?))a=blobdiff(?:_plain)?()|.*(?:;|(?<=\?))h=[^;]+()){2,3}(?:\2|\3)\4.*)$'
    URL_REPLACE_STR = r'a=blobdiff(?:_plain)?'
    URL_REPLACE_WITH = 'a=blobdiff_plain'

class Hgweb(PatchPattern):
    URL_PATTERN = r'^((?:https?://)?.+/(?:raw-diff|raw-rev|diff|comparison)/.+)$'
    URL_REPLACE_STR = r'/(raw-diff|raw-rev|diff|comparison)/'
    URL_REPLACE_WITH = '/raw-diff/'

class Loggerhead(PatchPattern):
    URL_PATTERN = r'^((?:https?://)?.+/(?:diff|revision)/.+)$'
    URL_REPLACE_STR = r'/(diff|revision)/'
    URL_REPLACE_WITH = '/diff/'

class Patchwork(PatchPattern):
    URL_PATTERN = r'^((?:https?://)?.+/patch/\d+)(?:/[^/])?/?$'
    URL_REPLACE_WITH = '%s/raw/'

class Redmine(PatchPattern):
    URL_PATTERN = r'^((?:https?://)?.+/repository/revisions/.+)$'
    URL_REPLACE_STR = r'(/revisions/[^?]+(\?.*)?)'
    URL_REPLACE_WITH = lambda self, x: x[1] + (x[2] and '&' or '?') + 'format=diff'

class Sourceforge(PatchPattern):
    URL_PATTERN = r'^((?:https?://)?.+/p/.+\?(?:.+&)?(?:diff|barediff)=\w+(?:&.+)?)$'
    URL_REPLACE_STR = r'([?&])diff='
    URL_REPLACE_WITH = '\\1barediff='
    
    def _processPatch(self, patch):
        return BeautifulSoup(patch, 'lxml').text

class Bugzilla(PatchPattern):
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
PatchPattern.register(Sourceforge)

# TODO
# http://code.google.com/p/chromium/issues/detail?id=138673
# CVSweb: http://cvsweb.netbsd.org/bsdweb.cgi/src/dist/ipf/lib/Attic/load_http.c.diff?r1=1.1&r2=1.2&f=u
# https://bitbucket.org/multicoreware/x265/issues/364/integer-overflow-and-affect-top-level

'''
with open('/home/apollon/Downloads/cves', 'r') as f:
    cves = f.read().split('/n')[:-1]

with open('/home/apollon/Downloads/urls', 'r') as f:
    urls = f.read().split('/n')[:-1]

cve2url = {}
for cve in cves[-2000:]:
    cve2url[cve] = getCVEPatchURLs(getCVEReferences(cve))


cve2patch = {}
for cve, urls in cve2url.items():        
    cve2patch[cve] = []                  
    for u in urls:                       
        try:
            cve2patch[cve]+= getPatch(*u)
        except Exception as e:
            print(u, e)
'''
