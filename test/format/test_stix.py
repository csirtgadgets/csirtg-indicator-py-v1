try:
    # Python 2
    from StringIO import StringIO
except ImportError:
    # Python 3
    from io import StringIO

STIX_ENABLED = True

try:
    from stix.core import STIXHeader
    from stix.core import STIXPackage
    from csirtg_indicator.format.zstix import Stix
except ImportError:
    STIX_ENABLED = False

data = [
    # fqdn
    {
        'indicator': "example.com",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "10",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['botnet', 'malware']
    },
    # https with path
    {
        'indicator': "https://example.com/with-path.php",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "7",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['phishing']
    },
    # http no path
    {
        'indicator': "http://naked-url.tld",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "8.5",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['botnet', 'malware']
    },
    # ipv4
    {
        'indicator': "1.1.1.1",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "8",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['exploit', 'malware']
    },
    # email
    {
        'indicator': "really@badspammer.tld",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "7.5",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['spam']
    },
    # ipv6
    {
        'indicator': "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "8",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['botnet', 'malware']
    },
    # asn
    {
        'indicator': "23456",
        'itype': "asn",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "10",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['scanner']
    },
    # sha512
    {
        'indicator': "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "10",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['malware']
    },
    # md5
    {
        'indicator': "098f6bcd4621d373cade4e832627b4f6",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "10",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['malware']
    },
    # sha1
    {
        'indicator': "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "10",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['malware']
    },
    # sha256
    {
        'indicator': "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "10",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['malware']
    }

]


def test_stix():
    if STIX_ENABLED:
        d = Stix(data)
        stix_pkg = STIXPackage.from_xml(StringIO(str(d)))

        assert len(stix_pkg.indicators.indicator) == len(data)
    else:
        print('STIX package not installed, skipping test')

if __name__ == '__main__':
    test_stix()
