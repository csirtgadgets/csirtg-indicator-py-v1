import socket
import re
import ipaddress
from ..exceptions import InvalidIndicator
from ..constants import PYVERSION, RE_ASN, RE_EMAIL, RE_FQDN, RE_HASH, RE_IPV4, RE_IPV4_CIDR, RE_IPV4_PADDING, \
    RE_URI_SCHEMES


if PYVERSION == 3:
    from urllib.parse import urlparse
    from urllib.parse import urlsplit
    from urllib.parse import urlunsplit
else:
    from urlparse import urlparse


#RE_URI_SCHEMES = re.compile(r'^(https?|ftp)$')


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


def normalize_indicator(i, itype=None, lowercase=False, lowercase_explicit=False):
    if itype == 'fqdn':
        i = i.rstrip('.')
        # only don't lowercase if lowercase=False and lowercase_explicit=True (set by user)
        if lowercase or not lowercase_explicit:
            i = i.lower()
    elif itype == 'url':
        u = urlparse(i)
        i = u.geturl().rstrip('/')
        if lowercase and lowercase_explicit:
            i = i.lower()
        elif lowercase or not lowercase_explicit:
            scheme, netloc, path, qs, anchor = urlsplit(i)
            netloc = netloc.rstrip('.').lower()
            i = urlunsplit((scheme, netloc, path, qs, anchor))

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
