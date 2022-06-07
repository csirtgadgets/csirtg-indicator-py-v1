from .ztable import Table
from .zcsv import Csv
from .zjson import Json
from .zzeek import Zeek
from .zsnort import Snort
from .zbind import Bind
from .zbindrpz import BindRPZ
from .zbindrpzip import BindRPZIP

FORMATS = {
    'table': Table,
    'csv': Csv,
    'json': Json,
    'bro': Zeek,
    'zeek': Zeek,
    'snort': Snort,
    'bind': Bind,
    'bindrpz': BindRPZ,
    'bindrpzip': BindRPZIP,
}

STIX_ENABLED = True

try:
    from stix.core import STIXHeader
    from .zstix import Stix
    FORMATS['stix'] = Stix
except ImportError:
    STIX_ENABLED = False
