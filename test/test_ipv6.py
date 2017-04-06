from csirtg_indicator import Indicator
from csirtg_indicator.exceptions import InvalidIndicator
from faker import Faker
fake = Faker()


def _not(data):
    for d in data:
        try:
            d = Indicator(d)
            assert d.itype is not 'ipv6'
        except InvalidIndicator:
            pass


def _ok(data):
    for d in data:
        assert Indicator(d).itype is 'ipv6'


def test_ipv6_ok():
    data = [
        '2001:1608:10:147::21',
        '2001:4860:4860::8888',
        '2001:4860::/64',
        '2001:4860::/48',
        '2001:4860::/32'
    ]

    _ok(data)


def test_ipv6_nok():
    data = [
        'example.com',
        'http://example.com:81',
        '192.168.1.1',
        '127.0.0./1'
    ]

    _not(data)


def test_ipv6_random():
    for d in range(0, 100):
        assert Indicator(indicator=fake.ipv6()).itype == 'ipv6'