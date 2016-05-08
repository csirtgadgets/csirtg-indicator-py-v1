import arrow
import datetime
import re
from pprint import pprint

import socket
import re
import sys
import ipaddress
if sys.version_info > (3,):
    from urllib.parse import urlparse
else:
    from urlparse import urlparse
RE_IPV4 = re.compile('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}$')
RE_IPV4_CIDR = re.compile('^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/\d{1,2})$')

# http://stackoverflow.com/a/17871737
RE_IPV6 = re.compile('(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')
# http://goo.gl/Cztyn2 -- probably needs more work
RE_FQDN = re.compile('^((xn--)?(--)?[a-zA-Z0-9-_]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}(--p1ai)?$')
RE_URI_SCHEMES = re.compile('^(https?|ftp)$')

RE_HASH = {
    'uuid': re.compile('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'),
    'md5': re.compile('^[a-fA-F0-9]{32}$'),
    'sha1': re.compile('^[a-fA-F0-9]{40}$'),
    'sha256': re.compile('^[a-fA-F0-9]{64}$'),
    'sha512': re.compile('^[a-fA-F0-9]{128}$'),
}

def resolve_itype(indicator, test_broken=False):
    def _ipv6(s):
        try:
            socket.inet_pton(socket.AF_INET6, s)
        except socket.error:
            if not re.match(RE_IPV6, s):
                return False

        return True

    def _ipv4(s):
        try:
            socket.inet_pton(socket.AF_INET, s)
        except socket.error:
            if not re.match(RE_IPV4, s):
                return False
        return True

    def _ipv4_cidr(s):
        if re.match(RE_IPV4_CIDR, s):
            try:
                ipaddress.ip_network(unicode(s))
            except ValueError as e:
                return False
            return True
        return False

    def _fqdn(s):
        if RE_FQDN.match(s):
            return 1

    def _url(s):
        u = urlparse(s)
        if re.match(RE_URI_SCHEMES, u.scheme):
            if _fqdn(u.netloc) or _ipv4(u.netloc) or _ipv6(u.netloc):
                return True

    def _url_broken(s):
        u = urlparse('{}{}'.format('http://', s))
        if re.match(RE_URI_SCHEMES, u.scheme):
            if _fqdn(u.netloc) or _ipv4(u.netloc) or _ipv6(u.netloc):
                return True

    def _hash(s):
        for h in RE_HASH:
            if re.match(RE_HASH[h], s):
                return h

    if test_broken and _url_broken(indicator):
        return 'broken_url'
    elif _url(indicator):
        return 'url'
    elif _hash(indicator):
        return _hash(indicator)
    elif _fqdn(indicator):
        return 'fqdn'
    elif _ipv4(indicator) or _ipv4_cidr(indicator):
        return 'ipv4'
    elif _ipv6(indicator):
        return 'ipv6'

    raise NotImplementedError('unknown itype for "{}"'.format(indicator))


def _normalize_url(i):
    if resolve_itype(i['indicator'], test_broken=True) == 'broken_url':
        i['indicator'] = '{}{}'.format('http://', i['indicator'])

    return i


def normalize_itype(i, itype=None):
    try:
        if resolve_itype(i['indicator']):
            return i
    except NotImplementedError:
        pass

    i = _normalize_url(i)
    return i


def parse_timestamp(ts):
    try:
        t = arrow.get(ts)
        if t.year < 1980:
            if type(ts) == datetime.datetime:
                ts = str(ts)
            if len(ts) == 8:
                ts = '{}T00:00:00Z'.format(ts)
                t = arrow.get(ts, 'YYYYMMDDTHH:mm:ss')

            if t.year < 1980:
                raise RuntimeError('invalid timestamp: %s' % ts)

        return t
    except ValueError as e:
        print(len(ts))
        if len(ts) == 14:
            match = re.search('^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$', ts)
            if match:
                ts = '{}-{}-{}T{}:{}:{}Z'.format(match.group(1), match.group(2), match.group(3), match.group(4),
                                                 match.group(5), match.group(6))
                t = arrow.get(ts, 'YYYY-MM-DDTHH:mm:ss')
                return t
            else:
                raise RuntimeError('Invalid Timestamp: %s' % ts)
        else:
            raise RuntimeError('Invalid Timestamp: %s' % ts)
    else:
        raise RuntimeError('Invalid Timestamp: %s' % ts)

