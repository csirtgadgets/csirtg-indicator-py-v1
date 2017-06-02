import socket
import re
import ipaddress
from ..exceptions import InvalidIndicator
from ..constants import PYVERSION
from .ztime import parse_timestamp
import sys

if PYVERSION == 3:
    from urllib.parse import urlparse
else:
    from urlparse import urlparse

from pprint import pprint

RE_IPV4 = re.compile('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(\d{1,3})$')
RE_IPV4_CIDR = re.compile('^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/\d{1,2})$')

# http://stackoverflow.com/a/17871737
RE_IPV6 = re.compile('(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')

# http://goo.gl/Cztyn2 -- probably needs more work
# http://stackoverflow.com/a/26987741/7205341
# ^((xn--)?(--)?[a-zA-Z0-9-_@]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}(--p1ai)?$
#RE_FQDN = re.compile('^((?!-))(xn--)?[a-z0-9][a-z0-9-_\.]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$')
# http://stackoverflow.com/questions/14402407/maximum-length-of-a-domain-name-without-the-http-www-com-parts
RE_FQDN = re.compile('^((?!-))(xn--)?[a-z0-9][a-z0-9-_\.]{0,245}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$')
RE_URI_SCHEMES = re.compile('^(https?|ftp)$')
RE_EMAIL = re.compile('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$')
RE_ASN = re.compile('^(AS|as)[0-9]{1,6}$')

RE_HASH = {
    'uuid': re.compile('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'),
    'md5': re.compile('^[a-fA-F0-9]{32}$'),
    'sha1': re.compile('^[a-fA-F0-9]{40}$'),
    'sha256': re.compile('^[a-fA-F0-9]{64}$'),
    'sha512': re.compile('^[a-fA-F0-9]{128}$'),
}

RE_IPV4_PADDING = re.compile(r"(^|\.)0+([^/.])")


def ipv4_normalize(i):
    return RE_IPV4_PADDING.sub(r'\1\2', i)


def resolve_itype(indicator, test_broken=False):
    def _ipv6(s):
        try:
            socket.inet_pton(socket.AF_INET6, s)
            return True
        except socket.error:
            pass
        except UnicodeEncodeError:
            return False

        if PYVERSION == 2:
            try:
                s = unicode(s)
            except UnicodeDecodeError:
                return False

        try:
            ipaddress.IPv6Network(s)
            return True
        except ipaddress.AddressValueError:
            pass

    def _ipv4(s):

        try:
            socket.inet_pton(socket.AF_INET, s)
            return True
        except socket.error:
            pass
        except UnicodeEncodeError:
            return False

        if re.match(RE_IPV4, s):
            return True

    def _ipv4_cidr(s):
        if not re.match(RE_IPV4_CIDR, s):
            return False

        if PYVERSION == 2:
            try:
                s = unicode(s)
            except UnicodeDecodeError:
                return False

        try:
            ipaddress.ip_network(s)
            return True
        except ValueError as e:
            return False

    def _fqdn(s):
        if RE_FQDN.match(s):
            return True

    def _url(s):
        u = urlparse(s)

        if not u:
            return

        if not re.match(RE_URI_SCHEMES, str(u.scheme)):
            return

        u = u.hostname

        if _ipv6(u):
            return True

        if ':' in u:  # 192.168.1.1:81
            u1 = u.split(':')[0]
            if _ipv4(u1):
                return True

            if _fqdn(u1):
                return True

        if _fqdn(u):
            return True

        if _ipv4(u):
            return True

    def _url_broken(s):
        if PYVERSION == 2:
            s = s.encode('utf-8')

        u = urlparse('{}{}'.format('http://', s))

        if not re.match(RE_URI_SCHEMES, u.scheme):
            return

        if _fqdn(u.hostname) or _ipv4(u.hostname) or _ipv6(u.hostname):
            return True

    def _hash(s):
        for h in RE_HASH:
            if re.match(RE_HASH[h], s):
                return h

    def _email(s):
        if re.match(RE_EMAIL, s):
            return True

    def _asn(s):
        if re.match(RE_ASN, s):
            return True

    if test_broken and _url_broken(indicator):
        return 'broken_url'

    elif _url(indicator):
        return 'url'

    elif _hash(indicator):
        return _hash(indicator)

    elif _ipv4(indicator) or _ipv4_cidr(indicator):
        return 'ipv4'

    elif _ipv6(indicator):
        return 'ipv6'

    elif _email(indicator):
        return 'email'

    elif _fqdn(indicator):
        return 'fqdn'

    elif _asn(indicator):
        return 'asn'

    try:
        error = 'unknown itype for "{}"'.format(indicator)
    except UnicodeEncodeError:
        error = 'unknown itype for "{}"'.format(indicator.encode('utf-8'))

    raise InvalidIndicator(error)


def _normalize_url(i):
    if resolve_itype(i['indicator'], test_broken=True) == 'broken_url':
        if PYVERSION == 2:
            i['indicator'] = i['indicator'].encode('utf-8')

        i['indicator'] = '{}{}'.format('http://', i['indicator'])

    return i


def normalize_itype(i, itype=None):
    try:
        if resolve_itype(i['indicator']):
            return i
    except InvalidIndicator:
        pass

    i = _normalize_url(i)
    return i


def is_subdomain(i):
    itype = resolve_itype(i)
    if itype is not 'fqdn':
        return

    bits = i.split('.')
    if len(bits) > 2:
        bits.pop(0)
        return '.'.join(bits)


def is_ipv4_net(i):
    try:
        if resolve_itype(i) != 'ipv4':
            return False
    except InvalidIndicator:
        return False

    if not re.match(RE_IPV4_CIDR, i):
        return False

    if PYVERSION == 2:
        i = unicode(i)

    try:
        ipaddress.ip_network(i)
        return True
    except ValueError:
        return False


def _normalize_url(i):
    if resolve_itype(i['indicator'], test_broken=True) == 'broken_url':
        if PYVERSION == 2:
            i['indicator'] = i['indicator'].encode('utf-8')
        i['indicator'] = '{}{}'.format('http://', i['indicator'])

    return i


def url_to_fqdn(u):
    u = urlparse(u)
    return u.hostname
