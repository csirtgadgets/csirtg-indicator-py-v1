from .plugin import Plugin
import time
import os
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

OUTPUT_PATH = os.getenv('CSIRTG_INDICATOR_BINDRPZ_PATH', '/etc/bind/rpz')


def get_lines(data, filename=OUTPUT_PATH):
    output = StringIO()
    text = [
            ';;; generated by: {} at {}'.format('csirtg-indicator', time.strftime('%Y-%M-%dT%H:%m:%S %Z')),
'; RPZ DATA!',
'$TTL    1',
'@       IN      SOA     localhost. root.localhost. (',
'                              1         ; Serial',
'                         604800         ; Refresh',
'                          86400         ; Retry',
'                        2419200         ; Expire',
'                          86400 )       ; Negative Cache TTL',
';',
'@       IN      NS      localhost.'
   ]
    output.write(text)

    for i in data:
        if i['itype'] is not 'fqdn':
            continue

        text.append('{}        CNAME .'.format(i['indicator'], filename))
        text.append('*.{}        CNAME .'.format(i['indicator'], filename))
        yield output.getvalue()

        if isinstance(output, StringIO):
            output.truncate(0)


class BindRPZ(Plugin):

    def __init__(self, *args, **kwargs):
        super(BindRPZ, self).__init__(*args, **kwargs)

        self.output = kwargs.get('output', OUTPUT_PATH)

    def __repr__(self):
        text = [
            ';;; generated by: {} at {}'.format('csirtg-indicator', time.strftime('%Y-%M-%dT%H:%m:%S %Z')),
'; RPZ DATA!',
'$TTL    1',
'@       IN      SOA     localhost. root.localhost. (',
'                              1         ; Serial',
'                         604800         ; Refresh',
'                          86400         ; Retry',
'                        2419200         ; Expire',
'                          86400 )       ; Negative Cache TTL',
';',
'@       IN      NS      localhost.'
        ]
        for i in self.data:
            if i['itype'] is not 'fqdn':
                pass

            text.append('{}        CNAME .'.format(i['indicator'], self.output))
            text.append('*.{}        CNAME .'.format(i['indicator'], self.output))

        return '\n'.join(text)
