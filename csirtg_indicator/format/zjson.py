import json
from .plugin import Plugin
from csirtg_indicator import Indicator


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
