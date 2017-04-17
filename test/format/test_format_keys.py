# -*- coding: utf-8 -*-
import pytest
from csirtg_indicator.indicator import Indicator
from pprint import pprint


@pytest.fixture
def indicator():
    i = {
            'indicator': "http://refreshdharan.com/bg/excel2/index.php?userid={dong.keonkwonfinancialconsultd@yahoo.com}",
            'itype': 'fqdn',
            'provider': "me.com",
            'tlp': "amber",
            'confidence': "85",
            'reporttime': '2015-01-01T00:00:00Z'
        }
    return Indicator(**i)


def test_format_keys(indicator):

    i =indicator.format_keys()
    assert i.indicator == indicator.indicator

if __name__ == '__main__':
    test_format_keys()
