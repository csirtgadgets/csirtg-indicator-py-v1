from csirtg_indicator.format.zcsv import Csv


def test_format_csv():
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
    print(Csv(data))
    assert str(Csv(data))
