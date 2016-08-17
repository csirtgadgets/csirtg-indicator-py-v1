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

if sys.version_info > (3,):
    from urllib.parse import urlparse
else:
    from urlparse import urlparse

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
    "192.0.2.0/24",
    "224.0.0.0/4",
    "240.0.0.0/5",
    "248.0.0.0/5"
]

for x in IPV4_PRIVATE_NETS:
    IPV4_PRIVATE[x] = True


class Indicator(object):

    def __init__(self, indicator=None, itype=None, tlp=TLP, tags=[], group=GROUP,
                 reporttime=arrow.get(datetime.utcnow()).datetime,
                 provider=None,  protocol=None, portlist=None,  asn=None,
                 firsttime=arrow.get(datetime.utcnow()).datetime, lasttime=arrow.get(datetime.utcnow()).datetime,
                 asn_desc=None, cc=None, application=None, reference=None, reference_tlp=None, confidence=None,
                 peers=None, city=None, longitude=None, latitude=None, timezone=None, description=None, altid=None,
                 altid_tlp=None, additional_data=None, mask=None, rdata=None, version=PROTOCOL_VERSION, **kwargs):

        if isinstance(tags, str):
            if ',' in tags:
                tags = tags.split(",")
            else:
                tags = [tags]

        self.logger = logging.getLogger(__name__)

        self.version = version

        self.indicator = indicator
        self.tlp = tlp
        self.provider = provider
        self.reporttime = reporttime
        self.group = group
        self.itype = itype
        self.protocol = protocol
        self.portlist = portlist
        self.tags = tags
        self.application = application
        self.reference = reference
        self.reference_tlp = reference_tlp
        self.confidence = confidence
        self.firsttime = firsttime
        self.lasttime = lasttime
        self.peers = peers
        self.longitude = longitude
        self.latitude = latitude
        self.city = city
        self.timezone = timezone
        self.description = description
        self.altid = altid
        self.altid_tlp = altid_tlp
        self.additional_data = additional_data
        self.mask = mask
        self.rdata = rdata

        if self.description:
            self.description = self.description.replace('\"', '').lower()

        if timezone:
            self.timezone = timezone.lower()

        if reporttime and isinstance(reporttime, str):
            self.reporttime = parse_timestamp(reporttime).datetime

        if firsttime:
            self.firsttime = parse_timestamp(firsttime).datetime

        if lasttime:
            self.lasttime = parse_timestamp(lasttime).datetime

        if asn and asn.lower() == 'na':
            asn = None

        self.asn = asn

        if asn_desc and asn_desc.lower() == 'na':
            asn_desc = None

        self.asn_desc = asn_desc
        self.cc = cc

        if self.indicator and not itype:
            self.itype = resolve_itype(self.indicator)

        if self.mask and self.itype == 'ipv4':
            self.indicator = '{}/{}'.format(self.indicator, int(self.mask))

        if self.itype == 'url':
            u = urlparse(self.indicator)
            self.indicator = u.geturl().rstrip('/').lower()

    def magic(self, data):
        for e in data:
            try:
                itype = self.resolve_itype(e)
                i = Indicator(itype=itype, indicator=e)
                return i
            except NotImplementedError:
                pass

    def is_private(self):
        if self.itype and self.itype == 'ipv4':
            if IPV4_PRIVATE.get(str(self.indicator)):
                return True
        return False

    def is_subdomain(self):
        return is_subdomain(self.indicator)

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
