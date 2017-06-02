import arrow
from datetime import datetime
import pendulum
import re


def human_to_dt(ts):
    t = arrow.utcnow()
    if ts == 'now':
        return t

    if ts == 'hour':
        return t.replace(minute=0, second=0, microsecond=0)

    if ts == 'day':
        return t.replace(hour=0, minute=0, second=0, microsecond=0)

    if ts == 'month':
        return t.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def parse_timestamp(ts):
    if isinstance(ts, arrow.Arrow):
        return ts

    t = human_to_dt(ts)
    if t:
        return t

    try:
        t = arrow.get(ts)
        if t.year < 1980:
            if type(ts) == datetime:
                ts = str(ts)
            if len(ts) == 8:
                ts = '{}T00:00:00Z'.format(ts)
                t = arrow.get(ts, 'YYYYMMDDTHH:mm:ss')

            if t.year < 1970:
                raise RuntimeError('invalid timestamp: %s' % ts)

        return t

    except ValueError as e:
        if len(ts) == 14:
            match = re.search('^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$', ts)
            if match:
                ts = '{}-{}-{}T{}:{}:{}Z'.format(match.group(1), match.group(2), match.group(3), match.group(4),
                                                 match.group(5), match.group(6))
                t = arrow.get(ts, 'YYYY-MM-DDTHH:mm:ss')
                return t
            else:
                raise RuntimeError('Invalid Timestamp: %s' % ts)
        else:
            raise RuntimeError('Invalid Timestamp: %s' % ts)

    except arrow.parser.ParserError as e:
        t = pendulum.parse(ts)
        t = arrow.get(t)
        return t

    else:
        raise RuntimeError('Invalid Timestamp: %s' % ts)