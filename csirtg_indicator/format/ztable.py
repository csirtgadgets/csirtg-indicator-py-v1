from prettytable import PrettyTable
from pprint import pprint
from .plugin import Plugin
import arrow
from csirtg_indicator.constants import PYVERSION
from csirtg_indicator import Indicator


class Table(Plugin):
    __name__ = 'table'

    def __repr__(self):
        t = PrettyTable(self.cols)
        t.align['provider'] = 'l'
        for i in reversed(self.data):
            if isinstance(i, Indicator):
                i = i.__dict__()

            r = []
            for c in self.cols:
                y = i.get(c, '')

                if type(y) is list:
                    y = ','.join(y)

                if y and (c in ['firsttime', 'lasttime', 'reporttime']):
                    y = arrow.get(y).format('YYYY-MM-DDTHH:mm:ss.SSSSS')
                    y = '{}Z'.format(y)
                else:
                    y = str(y)
                y = (y[:self.max_field_size] + '..') if len(y) > self.max_field_size else y

                r.append(y)
            t.add_row(r)
        return str(t)
