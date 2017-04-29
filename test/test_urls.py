# -*- coding: utf-8 -*-
from csirtg_indicator import Indicator
from csirtg_indicator.exceptions import InvalidIndicator
from csirtg_indicator.utils import url_to_fqdn
from faker import Faker
fake = Faker()


GOOD = [
    'http://58.147.128.10:81/val/1.html',
    'http://192.168.1.1/1.html',
    'http://www41.xzmnt.com',
    'http://get.ahoybest.com/n/3.6.16/12205897/microsoft lync server 2010.exe',
    'http://webmail.epuc.com.br:32000/mail/settings.html',
    'http://www.@sokoyetu.co.ke/aol5/a000l.html',
    'https://example.com:443/1.html',
    'http://test1.test2.example.com',
    'http://xz.job391.com/down/ï¿½ï¿½ï¿½ï¿½à¿ªï¿½ï¿½@89_1_60',
    'http://refreshdharan.com/bg/excel2/index.php?userid={dong.keonkwonfinancialconsultd@yahoo.com}',
    'http://https.www.paypal.blahblahblahblah.web.cgi.bin.blahblah.blahblahblahblah.blahblahblah-blah-blah-blah.com/signin/',
    'http://ppleid.apple.com.account.manage.wets.myapleid.woa.wa.directt.myappleid.woa.25napplic2faccount.25napplic2faccountmyappleid.woa9limgdpx25napplic2faccountmya4343.25woa9limgdpx25napplic2faccountmya4343.25nap.bhsfser.com/c13cc8f750e0e241e2d23f5e2ded1706/index/src/index/index.php',
    'http://bartrender.ro/template/acct/identity.php?zxjyb3iuc2lnbm9urxjyb3iÃƒÂƒÃ†Â’ÃƒÂ‚Ã†Â’ÃƒÂƒÃ¢Â€Â ÃƒÂ‚Ã¢Â€Â™?ÃƒÂƒÃ†Â’ÃƒÂ‚Ã†Â’ÃƒÂƒÃ‚Â¢ÃƒÂ‚Ã¢Â‚Â¬ÃƒÂ‚Ã…Â¡ÃƒÂƒÃ†Â’ÃƒÂ‚Ã¢Â€ÂšÃƒÂƒÃ¢Â€ÂšÃƒÂ‚Ã‚Â¤a0bf64c8ba839a7a7015?update9712608810q7kjakh91ky912908aafjhadf782325zddg=%3D'
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


def test_urls_random():
    for d in range(0, 100):
        assert Indicator(indicator=fake.uri()).itype == 'url'
