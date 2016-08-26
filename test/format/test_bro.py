from csirtg_indicator.format.zbro import Bro


def test_format_bro():
    data = [
        {
            'indicator': "example.com",
            'provider': "me.com",
            'tlp': "amber",
            'confidence': "85",
            'reporttime': '2015-01-01T00:00:00Z',
            'itype': 'fqdn'
        },
        {
            'indicator': "http://example.com/1234.htm",
            'provider': "me.com",
            'tlp': "amber",
            'confidence': "85",
            'reporttime': '2015-01-01T00:00:00Z',
            'itype': 'url',
        },
        {
            'indicator': "https://example.com/1234.htm",
            'provider': "me.com",
            'tlp': "amber",
            'confidence': "85",
            'reporttime': '2015-01-01T00:00:00Z',
            'itype': 'url',
        },
        {
            'indicator': "192.168.1.1",
            'provider': "me.com",
            'tlp': "amber",
            'confidence': "85",
            'reporttime': '2015-01-01T00:00:00Z',
            'itype': 'ipv4'
        }
    ]

    text = str(Bro(data))
    print(text)
    assert text

if __name__ == '__main__':
    test_format_bro()
