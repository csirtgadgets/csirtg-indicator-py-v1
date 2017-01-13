from .plugin import Plugin
import re
from csirtg_indicator import Indicator
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


from pprint import pprint

itype = {
    'ipv4': 'ADDR',
    'url': 'URL',
    'fqdn': 'DOMAIN',
    'md5': 'FILE_HASH',
    'sha1': 'FILE_HASH',
    'sha256': 'FILE_HASH',
}

COLUMNS = ['fields', 'indicator', 'indicator_type', 'meta.desc', 'meta.cif_confidence', 'meta.source', 'meta.do_notice']

HEADER = '#' + '\t'.join(COLUMNS)
SEP = '|'


def get_lines(data, cols=COLUMNS):
    output = StringIO()
    output.write("{0}\n".format(HEADER))

    for i in data:
        if isinstance(i, Indicator):
            i = i.__dict__()

        r = []
        if i['itype'] is 'url':
            i['indicator'] = re.sub(r'(https?\:\/\/)', '', i['indicator'])

        for c in cols:
            y = i.get(c, '-')

            if type(y) is list:
                y = SEP.join(y)

            y = str(y)
            if c is 'itype':
                y = 'Intel::{0}'.format(itype[i[c]])
            r.append(y)

        # do_notice
        # https://www.bro.org/bro-exchange-2013/exercises/intel.html
        # https://github.com/csirtgadgets/massive-octo-spice/issues/438
        r.append('T')

        output.write("\t".join(r))
        output.write("\n")
        yield output.getvalue()

        if isinstance(output, StringIO):
            output.truncate(0)


class Bro(Plugin):
    __name__ = 'bro'

    def __init__(self, *args, **kwargs):
        super(Bro, self).__init__(*args, **kwargs)

        self.cols = ['indicator', 'itype', 'tags', 'confidence', 'provider']

    def __repr__(self):
        text = []
        for i in self.data:
            if isinstance(i, Indicator):
                i = i.__dict__()

            r = []
            if i['itype'] is 'url':
                i['indicator'] = re.sub(r'(https?\:\/\/)', '', i['indicator'])

            for c in self.cols:
                y = i.get(c, '-')

                if type(y) is list:
                    y = SEP.join(y)

                y = str(y)
                if c is 'itype':
                    y = 'Intel::{0}'.format(itype[i[c]])
                r.append(y)

            # do_notice
            # https://www.bro.org/bro-exchange-2013/exercises/intel.html
            # https://github.com/csirtgadgets/massive-octo-spice/issues/438
            r.append('T')

            text.append("\t".join(r))

        text = "\n".join(text)

        text = "{0}\n{1}".format(HEADER, text)
        return text
