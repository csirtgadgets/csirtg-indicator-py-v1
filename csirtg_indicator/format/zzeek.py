from .plugin import Plugin
import re
from csirtg_indicator import Indicator
from csirtg_indicator.constants import PYVERSION
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


from pprint import pprint

itype = {
    'ipv4': 'ADDR',
    'cidr': 'SUBNET',
    'ipv6': 'ADDR',
    'url': 'URL',
    'fqdn': 'DOMAIN',
    'md5': 'FILE_HASH',
    'sha1': 'FILE_HASH',
    'sha256': 'FILE_HASH',
    'ja3': 'JA3',
}

COLUMNS = ['fields', 'indicator', 'indicator_type', 'meta.cif_description', 'meta.cif_tags', 'meta.cif_confidence', 'meta.source', 'meta.do_notice']

HEADER = '#' + '\t'.join(COLUMNS)
SEP = '|'


def _i_to_zeek(i, cols):
    if isinstance(i, Indicator):
        i = i.__dict__()

    cols = ['indicator', 'itype', 'description', 'tags', 'confidence', 'provider']

    r = []

    if i['itype'] == 'ipv4':
        if "/" in i['indicator']:
            i['itype'] = 'cidr'

    if (i['itype'] == 'md5') and ('ja3' in i['tags']):
        i['itype'] = 'ja3'

    if i['itype'] is 'url':
        i['indicator'] = re.sub(r'(https?\:\/\/)', '', i['indicator'])

    for c in cols:
        y = i.get(c, '-')

        if type(y) is list:
            y = SEP.join(y)

        if isinstance(y, int):
            y = str(y)

        if PYVERSION == 2:
            if isinstance(y, unicode):
                y = y.encode('utf-8')
        else:
            if isinstance(y, bytes):
                y = y.encode('utf-8')

        if c is 'itype':
            y = 'Intel::{0}'.format(itype[i[c]])

        r.append(str(y))

    r.append('T')
    return "\t".join(r)


def get_lines(data, cols=COLUMNS):
    output = StringIO()
    output.write("{0}\n".format(HEADER))
    cols = ['indicator', 'itype', 'description', 'tags', 'confidence', 'provider']

    for i in data:
        i = _i_to_zeek(i, cols)

        output.write(i)
        output.write("\n")
        yield output.getvalue()

        if isinstance(output, StringIO):
            output.truncate(0)


class Zeek(Plugin):
    __name__ = 'zeek'

    def __init__(self, *args, **kwargs):
        super(Zeek, self).__init__(*args, **kwargs)

        self.cols = COLUMNS

    def __repr__(self):
        text = []
        for i in self.data:
            i = _i_to_zeek(i, self.cols)
            text.append(i)

        text = "\n".join(text)

        text = "{0}\n{1}".format(HEADER, text)
        return text
