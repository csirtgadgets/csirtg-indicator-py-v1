from csirtg_indicator import Indicator
from csirtg_indicator.exceptions import InvalidIndicator

# https://blogs.msdn.microsoft.com/testing123/2009/02/06/email-address-test-cases/
# https://newgtlds.icann.org/en/program-status/delegated-strings
GOOD = [
    'email@domain.com',
    'firstname.lastname@domain.com',
    'email@subdomain.domain.com',
    'firstname+lastname@domain.com',
    'email@123.123.123.123',
    'email@[123.123.123.123]',
    #'“email”@domain.com',
    '1234567890@domain.com',
    'email@domain-one.com',
    '_______@domain.com',
    'email@domain.name',
    'email@domain.co.jp',
    'firstname-lastname@domain.com',
    'wes@example.org',
    'info@sunandsky.co.uk',
    'wes.info@sunandsky.co.uk'
]

BAD = [
    'plainaddress',
    '#@%^%#$@#$@#.com',
    '@domain.com',
    'Joe Smith <email@domain.com>',
    'email.domain.com',
    'email@domain@domain.com',
    '.email@domain.com',
    'email.@domain.com',
    'email..email@domain.com',
    'あいうえお@domain.com',
    'email@domain.com (Joe Smith)',
    #'email@domain',
    #'email@-domain.com',
    #'email@domain.web',
    #'email@111.222.333.44444',
    'email@domain..com'
]


def _not(data):
    for d in data:
        d = Indicator(d)
        assert d.itype != 'email'


def test_email_ip():
    data = ['192.168.1.0/24', '192.168.1.1', '2001:1608:10:147::21', '2001:4860:4860::8888']
    _not(data)


def test_email_fqdn():
    data = [
        '1.2.3.4.org',
        'www41.xzmnt.com',
    ]
    _not(data)


def test_email_ok():

    for d in GOOD:
        d = Indicator(d)
        assert d.itype is 'email'

    for d in BAD:
        try:
            d = Indicator(d)
        except InvalidIndicator:
            pass

        if isinstance(d, Indicator):
            assert d.itype is not 'email'
