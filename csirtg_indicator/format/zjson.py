import json
from .plugin import Plugin
from csirtg_indicator import Indicator
from csirtg_indicator.constants import COLUMNS
from pprint import pprint

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


def get_lines(data, cols=COLUMNS, output=StringIO(), stream=False):

    for i in data:

        if isinstance(i, Indicator):
            i = i.__dict__()

        r = dict()
        for c in cols:
            y = i.get(c, u'')
            if type(y) is list:
                y = u','.join(y)

            r[c] = y

        if stream:
            i = [i]

        json.dump(i, output)
        yield output.getvalue().rstrip('\r\n')

        if isinstance(output, StringIO):
            output.truncate(0)


class Json(Plugin):

    def __repr__(self):
        output = []
        
        for i in reversed(self.data):
            if isinstance(i, Indicator):
                i = i.__dict__()

            r = dict()
            for c in self.cols:
                y = i.get(c, u'')
                if type(y) is list:
                    y = u','.join(y)
                
                r[c] = y
                
            output.append(r)
            
        return json.dumps(output)
