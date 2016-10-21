import json
import logging
import textwrap
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from datetime import datetime

import arrow
import pytricia
from .utils import parse_timestamp, resolve_itype, is_subdomain
from . import VERSION
import sys
from .exceptions import InvalidIndicator
from base64 import b64encode, b64decode
from zlib import compress,decompress

if sys.version_info > (3,):
    from urllib.parse import urlparse
else:
    from urlparse import urlparse

from pprint import pprint

TLP = "green"
GROUP = "everyone"
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s] - %(message)s'
PROTOCOL_VERSION = '0.00a0'


IPV4_PRIVATE = pytricia.PyTricia()
IPV4_PRIVATE_NETS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.2.0/24",
    "224.0.0.0/4",
    "240.0.0.0/5",
    "248.0.0.0/5"
]

for x in IPV4_PRIVATE_NETS:
    IPV4_PRIVATE[x] = True


class Indicator(object):

    def __init__(self, indicator=None, version=PROTOCOL_VERSION, **kwargs):
        self.version = version

        self.tlp = kwargs.get('tlp')
        self.provider = kwargs.get('provider')
        self.reporttime = kwargs.get('reporttime')
        self.group = kwargs.get('group')
        self.itype = kwargs.get('itype')
        self.protocol = kwargs.get('protocol')
        self.portlist = kwargs.get('portlist')
        self.tags = kwargs.get('tags')
        self.application = kwargs.get('application')
        self.reference = kwargs.get('reference')
        self.reference_tlp = kwargs.get('reference_tlp')
        self.confidence = kwargs.get('confidence')
        self.firsttime = kwargs.get('firsttime')
        self.lasttime = kwargs.get('lasttime')
        self.peers = kwargs.get('peers')
        self.longitude = kwargs.get('longitude')
        self.latitude = kwargs.get('latitude')
        self.city = kwargs.get('city')
        self.cc = kwargs.get('cc')
        self.timezone = kwargs.get('timezone')
        self.description = kwargs.get('description')
        self.altid = kwargs.get('altid')
        self.altid_tlp = kwargs.get('altid_tlp')
        self.additional_data = kwargs.get('additional_data')
        self.mask = kwargs.get('mask')
        self.rdata = kwargs.get('rdata')
        self.asn_desc = kwargs.get('asn_desc')
        self.asn = kwargs.get('asn')

        self.message = kwargs.get('message')

        if self.tags and isinstance(self.tags, str):
            self.tags = self.tags.split(',')

        if self.description:
            self.description = self.description.replace('\"', '').lower()

        if self.timezone:
            self.timezone = self.timezone.lower()

        if self.reporttime and isinstance(self.reporttime, str):
            self.reporttime = parse_timestamp(self.reporttime).datetime

        if self.firsttime:
            self.firsttime = parse_timestamp(self.firsttime).datetime

        if self.lasttime:
            self.lasttime = parse_timestamp(self.lasttime).datetime

        if self.asn and self.asn.lower() == 'na':
            self.asn = None

        self.asn = self.asn

        if self.asn_desc and self.asn_desc.lower() == 'na':
            self.asn_desc = None

        self._indicator = None
        self.indicator = indicator

    @property
    def indicator(self):
        return self.__indicator

    @indicator.setter
    def indicator(self, i):
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

    def __dict__(self):
        s = str(self)
        return json.loads(s)

    def __repr__(self):
        o = {
            "version": self.version,
            "indicator": self.indicator,
            "itype": self.itype,
            "tlp": self.tlp,
            "provider": self.provider,
            "portlist": self.portlist,
            "protocol": self.protocol,
            "asn": self.asn,
            "asn_desc": self.asn_desc,
            "cc": self.cc,
            "group": self.group,
            "reference": self.reference,
            "reference_tlp": self.reference_tlp,
            "application": self.application,
            'confidence': self.confidence,
            'peers': self.peers,
            'city': self.city,
            'longitude': self.longitude,
            'latitude': self.latitude,
            'description': self.description,
            'additional_data': self.additional_data,
            'rdata': self.rdata
        }

        if self.tags:
            if isinstance(self.tags, str):
                if ',' in self.tags:
                    self.tags = self.tags.split(",")
                else:
                    self.tags = [self.tags]
            o['tags'] = self.tags

        if self.timezone:
            o['timezone'] = self.timezone.lower()

        if self.reporttime and isinstance(self.reporttime, datetime):
            o['reporttime'] = self.reporttime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            o['reporttime'] = self.reporttime

        if self.firsttime and isinstance(self.firsttime, datetime):
            o['firsttime'] = self.firsttime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            o['firsttime'] = self.firsttime

        if self.lasttime and isinstance(self.lasttime, datetime):
            o['lasttime'] = self.lasttime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            o['lasttime'] = self.lasttime

        if self.message:
            if isinstance(self.message, str):
                self.message = self.message.encode("utf-8")

            self.message = b64encode(self.message)
            o['message'] = self.message.decode('utf-8')  # make json parser happy
        try:
            return json.dumps(o, sort_keys=True, indent=4, separators=(',', ': '))
        except UnicodeDecodeError as e:
            o['asn_desc'] = unicode(o['asn_desc'].decode('latin-1'))
            return json.dumps(o, sort_keys=True, indent=4, separators=(',', ': '))


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
