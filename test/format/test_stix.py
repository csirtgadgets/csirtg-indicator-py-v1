STIX_ENABLED = True

try:
    from stix.core import STIXHeader
    from csirtg_indicator.format.zstix import Stix
except ImportError:
    STIX_ENABLED = False

data = [
    {
        'indicator': "example.com",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "85",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['botnet', 'malware']
    },
    {
        'indicator': "example.com",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "85",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['botnet', 'malware']
    },
    {
        'indicator': "example.com",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "85",
        'reporttime': '2015-01-01T00:00:00Z',
        'tags': ['botnet', 'malware']
    }
]


def test_stix():
    if STIX_ENABLED:
        d = Stix(data)
        print(d)
        assert len(str(d)) > 2
    else:
        print('STIX package not installed, skipping test')
