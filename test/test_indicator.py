from csirtg_indicator import Indicator
import json
from csirtg_indicator.exceptions import InvalidIndicator
from random import randint, uniform

def test_indicator_ipv4():
    i = Indicator('192.168.1.1')
    assert i.is_private()
    assert i.indicator == '192.168.1.1'
    assert i.itype == 'ipv4'


def test_indicator_fqdn():
    i = Indicator('example.org')

    assert i.is_private() is False
    assert i.indicator == 'example.org'
    assert i.itype == 'fqdn'


def test_indicator_url():
    i = Indicator('http://example.org', tags='botnet,malware')

    assert i.is_private() is False
    assert i.indicator == 'http://example.org'
    assert i.itype is not 'fqdn'
    assert i.itype is 'url'
    assert 'botnet' in i.tags
    assert 'malware' in i.tags


def test_indicator_str():
    i = Indicator('http://example.org', tags='botnet,malware')

    s = json.loads(str(i))

    assert 'botnet' in s['tags']

    i = Indicator(**s)

    assert 'malware' in i.tags


def test_get_set():
    i = Indicator('localhost.com')

    try:
        i.indicator = 'localhost'
    except InvalidIndicator:
        pass

    i.indicator = 'localhost.org'
    assert i.itype == 'fqdn'

    i.indicator = 'https://192.168.1.1'
    assert i.itype == 'url'

    assert str(i)
    print(i)


def test_format_indicator():
    i = Indicator('example.com')
    i.altid = 'https://csirtg.io/search?q={indicator}'

    i = i.format_keys()
    assert i.altid == 'https://csirtg.io/search?q=example.com'


def test_indicator_dest():
    i = Indicator(indicator='192.168.1.1', dest='10.0.0.1', portlist="23", protocol="tcp", dest_portlist='21,22-23')
    assert i.dest
    assert i.dest_portlist


def test_confidence_str():
    c = uniform(0.001, 9.99)
    assert Indicator(indicator='192.168.1.1', confidence=c).confidence == c

    try:
        Indicator(indicator='192.168.1.1', confidence=',')
        raise RuntimeError('should not set confidence to ,')
    except ValueError:
        pass


def test_count_str():
    c = randint(0, 500)
    assert Indicator(indicator='192.168.1.1', count=c).count == c

    try:
        Indicator(indicator='192.168.1.1', count=',')
        raise RuntimeError('should not set confidence to ,')
    except ValueError:
        pass


def test_uuid():
    u1 = Indicator(indicator='192.168.1.1').uuid
    u2 = Indicator(indicator='192.168.1.1').uuid

    assert u1 is not None
    assert u2 is not None
    assert u1 != u2


def test_eq():
    u1 = Indicator(indicator='192.168.1.1')
    u2 = Indicator(indicator='192.168.1.1')

    u2.uuid = u1.uuid
    assert u1 == u2