from csirtg_indicator import Indicator
from base64 import b64encode, b64decode
import json
from pprint import pprint


def test_message_ok():
    data = 'original message'
    d = Indicator('me@example.com', message=data)

    assert d.itype is 'email'
    assert d.message == data

    d = str(d)

    assert isinstance(d, str)

    d = json.loads(d)

    pprint(d['message'])
    pprint(b64decode(d['message'].encode('utf-8')))

    assert (b64decode(d['message']).decode('utf-8') == data)

