from .plugin import Plugin
import os
from csirtg_indicator import Indicator

SID = os.environ.get('CSIRTG_INDICATOR_SNORT_SID', 5000000000)
THRESHOLD = os.environ.get('CSIRTG_INDICATOR_SNORT_THRESHOLD', 'type limit,track by_src,count 1,seconds 3600')
SRC = os.environ.get('CSIRTG_INDICATOR_SNORT_SRC', 'any')
DEST = os.environ.get('CSIRTG_INDICATOR_SNORT_DST', 'any')
MSG_PREFIX = os.environ.get('CSIRTG_INDICATOR_SNORT_MSG_PREFIX', 'CSIRTG')
TLP_DEFAULT = os.environ.get('CSIRTG_INDICATOR_SNORT_TLP', 'GREEN')
PRIORITY = os.environ.get('CSIRTG_INDICATOR_SNORT_PRIOIRTY', 1)
CLASSTYPE = os.environ.get('CSIRTG_INDICATOR_SNORT_CLASSTYPE', False)
TAG = os.environ.get('CSIRTG_INDICATOR_SNORT_TAG', False)


def _dict_to_rule(rule, opts=False):
    r = ' '.join([
        rule['action'],
        rule['proto'],
        rule['src'],
        rule.get('sport', 'any'),
        rule['dir'],
        rule['dst'],
        rule.get('dport', 'any'),
    ])

    if opts:
        opstring = '; '.join('{}: {}'.format(v, opts[v]) for v in opts if opts[v])
        r = '{} ({};)'.format(r, opstring)

    return r


def _indicator_to_rule(i, sid):
    portlist = 'any'
    if i.get('portlist') and i['portlist'] is not None:
        portlist = str(i['portlist'])

    r = {
        'action': 'alert',
        'proto': i.get('protocol', 'IP'),
        'src': SRC,
        'sport': 'any',
        'dir': '->',
        'dst': i['indicator'],
        'dport': portlist,
    }

    opts = {
        'msg': '{} - {} - {}'.format(MSG_PREFIX, TLP_DEFAULT, ','.join(i['tags'])),
        'sid': sid,
        'threshold': THRESHOLD,
        'classtype': CLASSTYPE,
        'reference': i.get('altid', ''),
        'priority': PRIORITY,
        'tag': TAG,

    }

    if r['proto'] is None:
        r['proto'] = 'IP'

    return _dict_to_rule(r, opts)


def get_lines(data, sid=SID):
    for i in data:
        if isinstance(i, Indicator):
            i = i.__dict__()

            yield _indicator_to_rule(i, sid)
            sid += 1


class Snort(Plugin):
    __name__ = 'snort'

    def __init__(self, *args, **kwargs):
        super(Snort, self).__init__(*args, **kwargs)

    def __repr__(self):
        text = []
        sid = SID
        for i in self.data:
            if isinstance(i, Indicator):
                i = i.__dict__()

            text.append(_indicator_to_rule(i, sid))
            sid += 1

        return "\n".join(text)
