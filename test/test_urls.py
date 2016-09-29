from csirtg_indicator import Indicator
from csirtg_indicator.exceptions import InvalidIndicator
from csirtg_indicator.utils import url_to_fqdn

GOOD = [
    # 'http://58.147.128.10:81/val/1.html',
    # 'http://192.168.1.1/1.html',
    # 'http://www41.xzmnt.com',
    # 'http://get.ahoybest.com/n/3.6.16/12205897/microsoft lync server 2010.exe',
    # 'http://webmail.epuc.com.br:32000/mail/settings.html',
    'http://www.@sokoyetu.co.ke/aol5/a000l.html',
    'https://example.com:443/1.html',
    'http://test1.test2.example.com'
]


def _not(data):
    for d in data:
        d = Indicator(d)
        assert d.itype != 'url'


def test_urls_ip():
    data = ['192.168.1.0/24', '192.168.1.1', '2001:1608:10:147::21', '2001:4860:4860::8888']
    _not(data)


def test_urls_fqdn():
    data = ['example.org', '1.2.3.4.com', 'xn----jtbbmekqknepg3a.xn--p1ai']
    _not(data)


def test_urls_not_ok():
    data = [
        'http://wp-content/plugins/tinymce-advanced/mce/emoticons/img/Yahoo-login/yahoo.html'
    ]

    for d in data:
        try:
            d = Indicator(d)
        except InvalidIndicator:
            pass
        else:
            raise NotImplementedError


def test_urls_ok():

    for d in GOOD:
        d = Indicator(d)
        assert d.itype is 'url'


def test_urls_fqdns():
    for g in GOOD:
        assert url_to_fqdn(g)
