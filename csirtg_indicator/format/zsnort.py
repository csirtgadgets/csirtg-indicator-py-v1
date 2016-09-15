from .plugin import Plugin
import os

SID = os.environ.get('CSIRTG_INDICATOR_SNORT_SID', 5000000000)
THRESHOLD = os.environ.get('CSIRTG_INDICATOR_SNORT_THRESHOLD', 'type limit,track by_src,count 1,seconds 3600')
SRC = os.environ.get('CSIRTG_INDICATOR_SNORT_SRC', 'any')
DEST = os.environ.get('CSIRTG_INDICATOR_SNORT_DST', 'any')
MSG_PREFIX = os.environ.get('CSIRTG_INDICATOR_SNORT_MSG_PREFIX', 'CSIRTG')
TLP_DEFAULT = os.environ.get('CSIRTG_INDICATOR_SNORT_TLP', 'GREEN')
PRIORITY = os.environ.get('CSIRTG_INDICATOR_SNORT_PRIOIRTY', 1)
CLASSTYPE = os.environ.get('CSIRTG_INDICATOR_SNORT_CLASSTYPE', False)
TAG = os.environ.get('CSIRTG_INDICATOR_SNORT_TAG', False)


class Snort(Plugin):
    __name__ = 'snort'

    def __init__(self, *args, **kwargs):
        super(Snort, self).__init__(*args, **kwargs)

        self.cols = ['indicator', 'itype', 'tags', 'confidence', 'provider']

    def _dict_to_rule(self, rule, opts=False):
        r = ' '.join([
            rule['action'],
            rule['proto'],
            rule['src'],
            rule['sport'],
            rule['dir'],
            rule['dst'],
            rule['dport'],
        ])

        if opts:
            opstring = '; '.join('{}: {}'.format(v, opts[v]) for v in opts if opts[v])
            r = '{} ({};)'.format(r, opstring)

        return r

    def __repr__(self):
        text = []
        sid = SID
        for d in self.data:
            portlist = 'any'
            if d.get('portlist') and d['portlist'] is not None:
                porlist = str(d['portlist'])

            r = {
                'action': 'alert',
                'proto': d.get('protocol', 'IP'),
                'src': SRC,
                'sport': 'any',
                'dir': '->',
                'dst': d['indicator'],
                'dport': portlist,
            }

            opts = {
                'msg': '{} - {} - {}'.format(MSG_PREFIX, TLP_DEFAULT, ','.join(d['tags'])),
                'sid': sid,
                'threshold': THRESHOLD,
                'classtype': CLASSTYPE,
                'reference': d.get('altid', ''),
                'priority': PRIORITY,
                'tag': TAG,

            }

            if d['itype'] == 'ipv4':
                pass

            if d['itype'] == 'ipv4':
                pass

            if d['itype'] == 'fqdn':
                pass

            if d['itype'] == 'url':
                pass

            text.append(self._dict_to_rule(r, opts))
            sid += 1

        return "\n".join(text)
