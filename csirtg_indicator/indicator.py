# -*- coding: utf-8 -*-
from pprint import pprint
import uuid
import logging
from .constants import PYVERSION, IPV4_PRIVATE_NETS, PROTOCOL_VERSION, FIELDS, FIELDS_TIME, LOG_FORMAT
from base64 import b64encode
from .exceptions import InvalidIndicator
from . import VERSION
from .utils import resolve_itype, is_subdomain, ipv4_normalize, normalize_indicator
from .utils.ztime import parse_timestamp
import pytricia
import codecs
from datetime import datetime
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import textwrap
import json
import sys
import re
if sys.version_info > (3,):
    from urllib.parse import urlparse
    basestring = (str, bytes)
else:
    from urlparse import urlparse


IPV4_PRIVATE = pytricia.PyTricia()

for x in IPV4_PRIVATE_NETS:
    IPV4_PRIVATE[x] = True


class Indicator(object):

    def __init__(self, indicator=None, version=PROTOCOL_VERSION, **kwargs):
        self.version = version
        if 'lowercase' in kwargs:
            self._lowercase = kwargs.get('lowercase')
            # indicate lowercase arg was explicitly passed by user rather than just a default value
            self._lowercase_explicit = True
        else:
            # set lowercase to True by default, but ensure we can later determine it was not user specified
            self._lowercase = True
            self._lowercase_explicit = False

        for k in FIELDS:
            if k in ['indicator', 'confidence', 'count']:  # handle this at the end
                continue

            if kwargs.get(k) is None:
                v = None

                setattr(self, k, v)
                continue

            # set this at the end
            if k in FIELDS_TIME:
                continue

            if isinstance(kwargs[k], basestring):
                # always strip whitespace
                kwargs[k] = re.sub(r'\r|\t|\n', ' ', kwargs[k]).strip()
                
                if self._lowercase is True and k != 'reference': # don't lower reference which may be a url
                    kwargs[k] = kwargs[k].lower()
                if k in ['tags', 'peers']:
                    kwargs[k] = kwargs[k].split(',')
                    
            # handle issue of single element containing multiple comma-delimited tags (e.g.: tags=["malware,phishing"] )
            elif isinstance(kwargs[k], list):
                if k in ['tags']:
                    tmp_list = []
                    for x in kwargs[k]:
                        if ',' in x:
                            tmp_list.extend([y.strip() for y in x.split(',') if y])
                        else:
                            tmp_list.append(x.strip())
                    kwargs[k] = tmp_list

            setattr(self, k, kwargs[k])

        self._indicator = None
        if indicator:
            self.indicator = indicator.strip()

        self._confidence = 0
        self.confidence = kwargs.get('confidence', 0)

        self._count = None
        self.count = kwargs.get('count', 1)

        self._group = None
        self.group = kwargs.get('group', 'everyone')

        for k in FIELDS_TIME:
            setattr(self, k, kwargs.get(k, None))

        if not self.uuid:
            self.uuid = str(uuid.uuid4())

    @property
    def indicator(self):
        return self.__indicator

    @indicator.setter
    def indicator(self, i):
        if not i:
            self._indicator = None
            return

        if PYVERSION == 2:
            try:
                i = codecs.unicode_escape_encode(i.decode('utf-8'))[0]
            except Exception:
                i = codecs.unicode_escape_encode(
                    i.encode('utf-8', 'ignore').decode('utf-8'))[0]

        self.itype = resolve_itype(i.lower())
        self._indicator = i

        if self.itype in ['url', 'fqdn', 'ssdeep']:
            self._indicator = normalize_indicator(self._indicator, itype=self.itype, 
                lowercase=self._lowercase, lowercase_explicit=self._lowercase_explicit)

        elif self.itype == 'ipv4':
            self._indicator = ipv4_normalize(self._indicator)

        else:
            self._indicator = self._indicator.lower()

        if self.mask and (self.itype in ['ipv4', 'ipv6']):
            self._indicator = '{}/{}'.format(self._indicator, int(self.mask))
            self.mask = None

    @indicator.getter
    def indicator(self):
        return self._indicator

    @property
    def confidence(self):
        return self._confidence

    def _time_setter(self, v):
        if not v:
            return

        if isinstance(v, datetime):
            return v
        else:
            return parse_timestamp(v).to('utc').datetime

    @property
    def reporttime(self):
        return self._reporttime

    @reporttime.getter
    def reporttime(self):
        return self._reporttime

    @reporttime.setter
    def reporttime(self, v):
        self._reporttime = self._time_setter(v)

    @property
    def lasttime(self):
        return self._lasttime

    @lasttime.getter
    def lasttime(self):
        return self._lasttime

    @lasttime.setter
    def lasttime(self, v):
        self._lasttime = self._time_setter(v)

    @property
    def firsttime(self):
        return self._firsttime

    @firsttime.getter
    def firsttime(self):
        return self._firsttime

    @firsttime.setter
    def firsttime(self, v):
        self._firsttime = self._time_setter(v)

    @confidence.setter
    def confidence(self, v):
        self._confidence = float(v)

    @confidence.getter
    def confidence(self):
        return self._confidence

    @property
    def lowercase(self):
        return self._lowercase

    @lowercase.setter
    def lowercase(self, v):
        self._lowercase = bool(v)

    @lowercase.getter
    def lowercase(self):
        return self._lowercase

    @property
    def lowercase_explicit(self):
        return self._lowercase_explicit

    @lowercase.setter
    def lowercase_explicit(self, v):
        self._lowercase_explicit = bool(v)

    @lowercase.getter
    def lowercase_explicit(self):
        return self._lowercase_explicit

    @property
    def count(self):
        return self._count

    @count.setter
    def count(self, v):
        self._count = int(v)

    @count.getter
    def count(self):
        return self._count

    def magic(self, data):
        for e in data:
            try:
                itype = self.resolve_itype(e)
                i = Indicator(itype=itype, indicator=e)
                return i
            except InvalidIndicator:
                pass

    def is_private(self):
        if not self.itype:
            return False

        if self.itype != 'ipv4':
            return False

        if IPV4_PRIVATE.get(str(self.indicator)):
            return True

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
            except (KeyError, ValueError, IndexError):
                pass

        return Indicator(**d)

    def __dict__(self):
        s = str(self)
        return json.loads(s)

    def __repr__(self):
        i = {}
        for k in FIELDS:

            v = getattr(self, k)
            # Handle confidence 0.0
            if not v and not v == 0.0:
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
                if k not in ['indicator', 'message', 'reference'] and not k.endswith('time') and self._lowercase is True:
                    v = v.lower()

            if k == 'confidence':
                v = float(v)

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

    def __eq__(self, other):
        d1 = self.__dict__()
        d2 = other.__dict__()
        return d1 == d2


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
