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


def test_indicator_timezones():
    t = '2017-03-06T11:41:48-06:00'
    a = arrow.get('2017-03-06T17:41:48Z').datetime

    i = Indicator('example.com', firsttime=t, lasttime=t, reporttime=t)

    assert i.firsttime == a
    assert i.lasttime == a
    assert i.reporttime == a


def test_lasttime_only():
    l = arrow.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    i = Indicator('192.168.1.1', lasttime=l)

    assert i.lasttime == arrow.get(l).datetime

    s = str(i)
    i = json.loads(s)

    assert i.get('firsttime') is None


def test_firsttime_only():
    l = arrow.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    i = Indicator('192.168.1.1', firsttime=l)

    assert i.firsttime == arrow.get(l).datetime

    s = str(i)
    i = json.loads(s)

    assert i.get('lasttime') is None
