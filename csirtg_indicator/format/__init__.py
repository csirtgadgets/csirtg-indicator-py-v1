from .ztable import Table
from .zcsv import Csv
from .zjson import Json
from .zbro import Bro
from .zsnort import Snort
from .zbind import Bind
from .zbindrpz import BindRPZ

FORMATS = {
    'table': Table,
    'csv': Csv,
    'json': Json,
    'bro': Bro,
    'snort': Snort,
    'bind': Bind,
    'bindrpz': BindRPZ,
}

STIX_ENABLED = True

try:
    from stix.core import STIXHeader
    from .zstix import Stix
    FORMATS['stix'] = Stix
except ImportError:
    STIX_ENABLED = False
