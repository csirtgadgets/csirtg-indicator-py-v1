# -*- coding: utf-8 -*-
import sys
if sys.version_info > (3,):
    from urllib.parse import urlparse
    basestring = (str, bytes)
else:
    from urlparse import urlparse

import json
import textwrap
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from datetime import datetime
import codecs
import pytricia
from .utils import parse_timestamp, resolve_itype, is_subdomain
from . import VERSION
from .exceptions import InvalidIndicator
from base64 import b64encode
from .constants import PYVERSION, IPV4_PRIVATE_NETS, PROTOCOL_VERSION, FIELDS, FIELDS_TIME, LOG_FORMAT
import logging

from pprint import pprint

IPV4_PRIVATE = pytricia.PyTricia()

for x in IPV4_PRIVATE_NETS:
    IPV4_PRIVATE[x] = True


class Indicator(object):

    def __init__(self, indicator=None, version=PROTOCOL_VERSION, **kwargs):
        self.version = version

        for k in FIELDS:
            if k == 'indicator':  # handle this at the end
                continue

            if kwargs.get(k) is None:
                v = None
                if k is 'confidence':
                    v = 0

                setattr(self, k, v)
                continue

            if k in FIELDS_TIME:
                kwargs[k] = parse_timestamp(kwargs[k]).datetime
                setattr(self, k, kwargs[k])
                continue

            if isinstance(kwargs[k], basestring):
                kwargs[k] = kwargs[k].lower()
                if k in ['tags', 'peers']:
                    kwargs[k] = kwargs[k].split(',')

            setattr(self, k, kwargs[k])

        self._indicator = None
        if indicator:
            self.indicator = indicator


    @property
    def indicator(self):
        return self.__indicator

    @indicator.setter
    def indicator(self, i):
        if PYVERSION == 2:
            i = codecs.unicode_escape_encode(i.decode('utf-8'))[0]

        i = i.lower()
        self.itype = resolve_itype(i)
        self._indicator = i

        if self.itype == 'url':
            u = urlparse(self._indicator)
            self._indicator = u.geturl().rstrip('/').lower()

        if self.mask and (self.itype == 'ipv4' or self.itype == 'ipv6'):
            self._indicator = '{}/{}'.format(self._indicator, int(self.mask))

    @indicator.getter
    def indicator(self):
        return self._indicator

    def magic(self, data):
        for e in data:
            try:
                itype = self.resolve_itype(e)
                i = Indicator(itype=itype, indicator=e)
                return i
            except InvalidIndicator:
                pass

    def is_private(self):
        if self.itype and self.itype == 'ipv4':
            if IPV4_PRIVATE.get(str(self.indicator)):
                return True
        return False

    def is_subdomain(self):
        return is_subdomain(self.indicator)

    def format_keys(self):
        d = self.__dict__()
        for k in d:
            if PYVERSION == 2:
                if not isinstance(d[k], unicode):
                    continue
            else:
                if not isinstance(d[k], str):
                    continue

            if '{' not in d[k]:
                continue

            try:
                d[k] = d[k].format(**d)
            except KeyError:
                pass

        yield Indicator(**d)

    def __dict__(self):
        s = str(self)
        return json.loads(s)

    def __repr__(self):
        i = {}
        for k in FIELDS:
            v = getattr(self, k)
            if not v:
                continue

            if k == 'message':
                if PYVERSION == 2:
                    v = codecs.unicode_escape_encode(v.decode('utf-8'))[0]
                else:
                    v = v.encode('utf-8')

                v = b64encode(v).decode('utf-8')

            if k in FIELDS_TIME and isinstance(v, datetime):
                v = v.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            if isinstance(v, basestring):
                if k is not 'message' and not k.endswith('time'):
                    v = v.lower()

            i[k] = v

        sort_keys = False
        indent = None
        if logging.getLogger('').getEffectiveLevel() == logging.DEBUG:
            sort_keys = True
            indent = 4
        try:
            return json.dumps(i, indent=indent, sort_keys=sort_keys, separators=(',', ': '))
        except UnicodeDecodeError as e:
            i['asn_desc'] = unicode(i['asn_desc'].decode('latin-1'))
            return json.dumps(i, indent=indent, sort_keys=sort_keys, separators=(',', ': '))


def main():
    p = ArgumentParser(
        description=textwrap.dedent('''\
             Env Variables:
                CSIRTG_INDICATOR_TLP
                CSIRTG_INDICATOR_GROUP

            example usage:
                $ csirtg-indicator -d
            '''),
        formatter_class=RawDescriptionHelpFormatter,
        prog='csirtg-indicator'
    )

    p.add_argument('-d', '--debug', dest='debug', action="store_true")
    p.add_argument('-V', '--version', action='version', version=VERSION)

    p.add_argument('--group', help="specify group")
    p.add_argument('--indicator', help="specify indicator")
    p.add_argument('--tlp', help='specify tlp', default='green')
    p.add_argument('--tags', help='specify tags')

    args = p.parse_args()

    loglevel = logging.getLevelName('INFO')

    if args.debug:
        loglevel = logging.DEBUG

    console = logging.StreamHandler()
    logging.getLogger('').setLevel(loglevel)
    console.setFormatter(logging.Formatter(LOG_FORMAT))
    logging.getLogger('').addHandler(console)

    i = Indicator(indicator=args.indicator, tlp=args.tlp, tags=args.tags)

    print(i)


if __name__ == '__main__':
    main()
