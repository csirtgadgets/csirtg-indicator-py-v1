import sys

PYVERSION = 2
if sys.version_info > (3,):
    PYVERSION = 3

COLUMNS = ['tlp', 'lasttime', 'reporttime', 'itype', 'indicator', 'cc', 'asn', 'asn_desc', 'confidence', 'description',
           'tags', 'rdata', 'provider']
MAX_FIELD_SIZE = 30
