import sys
import re

PYVERSION = 2
if sys.version_info > (3,):
    PYVERSION = 3

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s] - %(message)s'
PROTOCOL_VERSION = '0.00a14'

FORMAT_COLUMNS = ['tlp', 'group', 'reporttime', 'indicator', 'firsttime', 'lasttime', 'count', 'tags', 'description', 'confidence',
                  'rdata', 'provider']

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
    'cc', 'latitude', 'timezone', 'longitude', 'city', 'region', 'location'
]

FIELDS_IP = [
    'portlist', 'protocol', 'asn', 'asn_desc', 'dest', 'dest_portlist', 'mask', 'rdata', 'rtype', 'peers'
]

FIELDS = FIELDS_CORE + FIELDS_GEO + FIELDS_META + FIELDS_IP + FIELDS_TIME

RE_IPV4 = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(\d{1,3})$')
RE_IPV4_CIDR = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/\d{1,2})$')
RE_IPV4_PADDING = re.compile(r'(^|\.)0+([^/.])')

# http://stackoverflow.com/a/17871737
RE_IPV6 = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')

# https://regex101.com/r/FLA9Bv/59
RE_FQDN = re.compile(r'^(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w\.]+?\-\.(?:[\w\.\-]+?))(?=[\w\.\-]*?[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)(?:[\w\-]+?\.)+?(?![^a-zA-Z])[A-Za-z0-9\-]{2,64}(?<!\-)\.?$')
#RE_URI_SCHEMES = re.compile(r'^(https?|ftp)://')
RE_URI_SCHEMES = re.compile(r'^(https?|ftp)$')
RE_EMAIL = re.compile(r"^[-\w+.!#$%&'*\/=?^_`{|}~;]+@[-.0-9a-zA-Z][-.0-9a-zA-Z]*[a-zA-Z]{2,}$")
RE_ASN = re.compile(r'^(AS|as)[0-9]{1,6}$')

RE_HASH = {
    'uuid': re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'),
    'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
    'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
    'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
    'sha512': re.compile(r'^[a-fA-F0-9]{128}$'),
    'ssdeep': re.compile(r'^(\d+):([\w\/+]+):([\w\/+]+)$'),
}

