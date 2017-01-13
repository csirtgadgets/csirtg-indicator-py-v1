import json
from .plugin import Plugin
from csirtg_indicator import Indicator
from csirtg_indicator.constants import COLUMNS
from pprint import pprint


def _indicator_row(i, cols):
    if isinstance(i, Indicator):
        i = i.__dict__()

    r = dict()
    for c in cols:
        y = i.get(c, u'')
        if type(y) is list:
            y = u','.join(y)

        r[c] = y

    return r


def get_lines(data, cols=COLUMNS, stream=False):
    for i in data:

        i = _indicator_row(i, cols)

        if stream:
            i = [i]

        yield json.dumps(i)


class Json(Plugin):

    def __repr__(self):
        output = []
        
        for i in reversed(self.data):
            r = _indicator_row(i, self.cols)
                
            output.append(r)
            
        return json.dumps(output)
