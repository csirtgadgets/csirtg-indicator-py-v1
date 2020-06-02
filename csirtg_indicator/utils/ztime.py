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

    ts_len = len(ts)
    
    try:
        t = arrow.get(ts)
        if t.year < 1980:
            if type(ts) == datetime:
                ts = str(ts)
            if ts_len == 8:
                ts = '{}T00:00:00Z'.format(ts)
                t = arrow.get(ts, 'YYYYMMDDTHH:mm:ssZ')

            if t.year < 1970:
                raise RuntimeError('a invalid timestamp: %s' % ts)

        return t

    except arrow.parser.ParserError as e:
        # epoch timestamp like 1590673128 or 1590673128.02 (assuming 9-10 digit epoch; will work until year 2286)
        if isinstance(ts, str) and ts_len >=9 and ts_len <= 13:
            try:
                ts_f = float(ts)
                t = arrow.get(ts_f)
                return t
            except:
                pass

        if ts_len == 14:
            match = re.search(r'^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$', ts)
            if match:
                ts = '{}-{}-{}T{}:{}:{}Z'.format(match.group(1), match.group(2), match.group(3), match.group(4),
                                                 match.group(5), match.group(6))
                t = arrow.get(ts, 'YYYY-MM-DDTHH:mm:ss')
                return t
            else:
                raise RuntimeError('Invalid Timestamp: %s' % ts)

        if ts_len == 16:
            # 20160219T224322Z
            match = re.search(r'^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$', ts)
            if match:
                ts = '{}-{}-{}T{}:{}:{}Z'.format(match.group(1), match.group(2), match.group(3), match.group(4),
                                                 match.group(5), match.group(6))
                t = arrow.get(ts, 'YYYY-MM-DDTHH:mm:ss')
                return t
            else:
                raise RuntimeError('Invalid Timestamp: %s' % ts)

        try:
            t = arrow.get(ts, ['YYYY-MM-DD HH:mm:ss ZZZ', 'ddd, DD MMM YYYY HH:mm:ss Z', 'x'])
            if t.year < 1980:
                if type(ts) == datetime:
                    ts = str(ts)
                if ts_len == 8:
                    ts = '{}T00:00:00Z'.format(ts)
                    t = arrow.get(ts, 'YYYYMMDDTHH:mm:ssZ')

                if t.year < 1970:
                    raise RuntimeError('invalid timestamp: %s' % ts)
            return t

        except arrow.parser.ParserError as e:
            t = pendulum.parse(ts, strict=False)
            t = arrow.get(t)
            return t

    else:
        raise RuntimeError('Invalid Timestamp: %s' % ts)
