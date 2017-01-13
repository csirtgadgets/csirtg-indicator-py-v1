# -*- coding: utf-8 -*-
from csirtg_indicator.format.zsnort import Snort, get_lines
from csirtg_indicator.indicator import Indicator
import pytest


import re
RULE_PATTERN = r'^alert (TCP|UDP|IP) (\S+) (\S+) -> ([^,]+)\s(\S+)\s\([^.]+\)'

@pytest.fixture
def indicator():
    i = {
        'indicator': "example.com",
        'provider': "me.com",
        'tlp': "amber",
        'confidence': "85",
        'reporttime': '2015-01-01T00:00:00Z',
        'itype': 'fqdn',
        'tags': 'botnet'
    }
    return Indicator(**i)


def test_format_snort(indicator):
    data = [
        indicator, indicator
    ]

    text = str(Snort(data))
    assert text
    assert re.findall(RULE_PATTERN, text)


def test_format_snort2(indicator):
    data = [indicator, indicator]

    lines = get_lines(data)
    assert len(list(lines)) > 0


if __name__ == '__main__':
    test_format_snort()
