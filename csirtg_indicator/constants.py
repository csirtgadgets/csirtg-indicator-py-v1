import sys

PYVERSION = 2
if sys.version_info > (3,):
    PYVERSION = 3

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s] - %(message)s'
PROTOCOL_VERSION = '0.00a14'

FORMAT_COLUMNS = ['tlp', 'group', 'lasttime', 'indicator', 'count', 'confidence', 'tags', 'description', 'rdata',
                  'provider']

COLUMNS = FORMAT_COLUMNS

MAX_FIELD_SIZE = 30

IPV4_PRIVATE_NETS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.2.0/24",
    "224.0.0.0/4",
    "240.0.0.0/5",
    "248.0.0.0/5"
]


FIELDS_CORE = [
    'indicator', 'itype', 'tlp', 'provider', 'group', 'tlp', 'provider', 'count', 'message', 'tags', 'confidence',
    'description', 'version', 'uuid'
]

FIELDS_TIME = [
    'firsttime', 'lasttime', 'reporttime'
]

FIELDS_META = [
    'application', 'reference', 'reference_tlp', 'altid', 'altid_tlp', 'additional_data'
]

FIELDS_GEO = [
    'cc', 'latitude', 'timezone', 'longitude', 'city', 'region'
]

FIELDS_IP = [
    'portlist', 'protocol', 'asn', 'asn_desc', 'dest', 'dest_portlist', 'mask', 'rdata', 'peers'
]

FIELDS = FIELDS_CORE + FIELDS_GEO + FIELDS_META + FIELDS_IP + FIELDS_TIME
