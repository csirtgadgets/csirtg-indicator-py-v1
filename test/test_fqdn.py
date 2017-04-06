from csirtg_indicator import Indicator
from csirtg_indicator.utils import is_subdomain
from faker import Faker
fake = Faker()


GOOD = [
    'hdxturkceizle.xn--6frz82g',
    'xn--1--blcfn0a0ai7a1a7e.xn--p1acf',
    'example.org',
    '1.2.3.4.com',
    'xn----jtbbmekqknepg3a.xn--p1ai',
    'dualstack.cddf-prod-frontend-1ho73vqwbi0tw-1326553765.us-east-1.elb.amazonaws.com',
    'laser-retargeting-server-production.us-east-1-prod-core-edge-public.spongecell.net',
]


def _not(data):
    for d in data:
        d = Indicator(d)
        assert d.itype != 'fqdn'


def test_fqdn_ip():
    data = ['192.168.1.0/24', '192.168.1.1', '2001:1608:10:147::21', '2001:4860:4860::8888']
    _not(data)


def test_fqdn_urls():
    data = [
        'http://192.168.1.1/1.html',
        'http://www41.xzmnt.com',
        'http://get.ahoybest.com/n/3.6.16/12205897/microsoft lync server 2010.exe',
        'https://example.com:443/1.html'
    ]
    _not(data)


def test_fqdn_ok():

    for d in GOOD:
        d = Indicator(d)
        assert d.itype is 'fqdn'


def test_fqdn_subdomain():
    data = [
        'www.yahoo.com',
        'www.ww2.yahoo.com',
    ]

    for d in data:
        print(Indicator(indicator=d).is_subdomain())
        assert Indicator(indicator=d).is_subdomain()


    data = [
        'yahoo.com',
        'google.com',
        'http://google.com',
        'https://www.google.com',
        'http://www2.www.google.com',
    ]

    for d in data:
        assert not Indicator(indicator=d).is_subdomain()


def test_fqdn_random():
    for d in range(0, 100):
        assert Indicator(indicator=fake.domain_name()).itype == 'fqdn'

