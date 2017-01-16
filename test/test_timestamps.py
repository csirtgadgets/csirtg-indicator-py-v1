from csirtg_indicator import Indicator
import arrow
import json


def test_indicator_timestamps():
    f = arrow.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    l = arrow.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    r = arrow.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    i = Indicator('192.168.1.1', firsttime=f, lasttime=l, reporttime=r)

    assert i.firsttime == arrow.get(f).datetime
    assert i.lasttime == arrow.get(l).datetime
    assert i.reporttime == arrow.get(r).datetime

    s = str(i)
    i = json.loads(s)

    assert i['firsttime'] == f
    assert i['lasttime'] == l
    assert i['reporttime'] == r
