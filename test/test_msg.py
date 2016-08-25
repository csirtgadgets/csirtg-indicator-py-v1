from csirtg_indicator import Indicator
from base64 import b64encode, b64decode
import json
from pprint import pprint


def test_msg_ok():
    data = 'original message'
    d = Indicator('me@example.com', msg=data)

    assert d.itype is 'email'
    assert d.msg == data

    d = str(d)

    assert isinstance(d, str)

    d = json.loads(d)

    assert (b64decode(d['msg']).decode('utf-8') == data)

