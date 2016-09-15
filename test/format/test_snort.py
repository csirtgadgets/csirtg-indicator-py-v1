from csirtg_indicator.format.zsnort import Snort

import re
RULE_PATTERN = r'^alert (TCP|UDP|IP) (\S+) (\S+) -> ([^,]+)\s(\S+)\s\([^.]+\)'

def test_format_snort():
    data = [
        {
            'indicator': "example.com",
            'provider': "me.com",
            'tlp': "amber",
            'confidence': "85",
            'reporttime': '2015-01-01T00:00:00Z',
            'itype': 'fqdn',
            'tags': ['botnet']
        },
        {
            'indicator': "http://example.com/1234.htm",
            'provider': "me.com",
            'tlp': "amber",
            'confidence': "85",
            'reporttime': '2015-01-01T00:00:00Z',
            'itype': 'url',
            'tags': ['botnet']
        },
        {
            'indicator': "https://example.com/1234.htm",
            'provider': "me.com",
            'tlp': "amber",
            'confidence': "85",
            'reporttime': '2015-01-01T00:00:00Z',
            'itype': 'url',
            'tags': ['botnet']
        },
        {
            'indicator': "192.168.1.1",
            'portlist': 8888,
            'protocol': 'tcp',
            'provider': "me.com",
            'tlp': "amber",
            'confidence': "85",
            'reporttime': '2015-01-01T00:00:00Z',
            'itype': 'ipv4',
            'tags': ['botnet']
        }
    ]

    text = str(Snort(data))
    assert text
    assert re.findall(RULE_PATTERN, text)


if __name__ == '__main__':
    test_format_snort()
