#info@sunandsky.co.uk


from csirtg_indicator import Indicator


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
    data = [
        'wes@example.org',
        'info@sunandsky.co.uk',
        'wes.info@sunandsky.co.uk',
    ]

    for d in data:
        d = Indicator(d)
        assert d.itype is 'email'
