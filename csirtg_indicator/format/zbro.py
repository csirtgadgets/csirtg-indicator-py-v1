from .plugin import Plugin
import re

from pprint import pprint

itype = {
    'ipv4': 'ADDR',
    'url': 'URL',
    'fqdn': 'DOMAIN',
    'md5': 'FILE_HASH',
    'sha1': 'FILE_HASH',
    'sha256': 'FILE_HASH',
}

HEADER = '#' + '\t'.join(['fields', 'indicator', 'indicator_type', 'meta.desc', 'meta.cif_confidence', 'meta.source', 'meta.do_notice'])
SEP = '|'


class Bro(Plugin):
    __name__ = 'bro'

    def __init__(self, *args, **kwargs):
        super(Bro, self).__init__(*args, **kwargs)

        self.cols = ['indicator', 'itype', 'tags', 'confidence', 'provider']

    def __repr__(self):
        text = []
        for d in self.data:
            r = []
            if d['itype'] is 'url':
                d['indicator'] = re.sub(r'(https?\:\/\/)', '', d['indicator'])

            for c in self.cols:
                y = d.get(c, '-')
                if type(y) is list:
                    y = SEP.join(y)
                y = str(y)
                if c is 'itype':
                    y = 'Intel::{0}'.format(itype[d[c]])
                r.append(y)

            # do_notice
            # https://www.bro.org/bro-exchange-2013/exercises/intel.html
            # https://github.com/csirtgadgets/massive-octo-spice/issues/438
            r.append('T')

            text.append("\t".join(r))

        text = "\n".join(text)

        text = "{0}\n{1}".format(HEADER, text)
        return text
