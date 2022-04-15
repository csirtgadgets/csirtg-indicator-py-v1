import arrow
from .plugin import Plugin
import stix.indicator
from stix.core import STIXPackage, STIXHeader
from cybox.common import Hash
from cybox.objects.file_object import File
from cybox.objects.address_object import Address
from csirtg_indicator.constants import RE_IPV4, RE_IPV6, RE_FQDN, RE_EMAIL, RE_ASN, RE_HASH, RE_URI_SCHEMES
from csirtg_indicator import Indicator


class Stix(Plugin):

    def __init__(self, *args, **kwargs):
        super(Stix, self).__init__(*args, **kwargs)

    def _create_indicator(self, d):
        def _hash(keypair, hash_type):
            hash_type = 'TYPE_{}'.format(hash_type.upper())
            h = Hash(keypair.get('indicator'), getattr(Hash, hash_type))
            f = File()
            f.add_hash(h)
            return f

        def _address_email(address):
            if RE_EMAIL.search(address):
                return 1

        def _address_ipv4(address):
            if RE_IPV4.search(address):
                return 1

        def _address_ipv6(address):
            if RE_IPV6.search(address):
                return 1

        def _address_fqdn(address):
            if RE_FQDN.search(address):
                return 1

        def _address_url(address):
            if RE_URI_SCHEMES.search(address):
                return 1

        def _address(keypair):
            address = keypair.get('indicator')

            if _address_email(address):
                return Address(address, 'e-mail')
            elif _address_url(address):
                return Address(address, 'url')
            elif _address_fqdn(address):
                return Address(address, 'fqdn')
            elif _address_ipv4(address):
                return Address(address, 'ipv4-addr')
            elif _address_ipv6(address):
                return Address(address, 'ipv6-addr')

        indicator = stix.indicator.Indicator(timestamp=arrow.get(d.get('reporttime')).datetime)
        indicator.set_producer_identity(d.get('provider'))

        indicator.set_produced_time(arrow.utcnow().datetime)

        indicator.description = d.get('description') or ','.join(d.get('tags'))

        itype = d.get('itype')
        i = d.get('indicator')

        f = None

        for hash_type in RE_HASH.keys():
            if itype == hash_type or RE_HASH[hash_type].search(i):
                f = _hash(d, hash_type)
                break

        if not f:
            if itype == 'asn' or RE_ASN.search(i):
                f = Address(i, 'asn')
            else:
                f = _address(d)

        indicator.add_object(f)
        return indicator

    def __repr__(self):
        stix_package = STIXPackage()
        stix_header = STIXHeader()
        stix_package.stix_header = stix_header

        for d in self.data:
            if isinstance(d, Indicator):
                d = d.__dict__()
            i = self._create_indicator(d)
            stix_package.add_indicator(i)

        return str(stix_package.to_xml().decode('utf-8'))
