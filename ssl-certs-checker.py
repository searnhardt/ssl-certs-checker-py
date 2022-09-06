#!/usr/bin/env python
#Verified on Python 3.10.5

import OpenSSL.crypto as crypto
import click
import socket
import ssl

from datetime import datetime
from prettytable import PrettyTable


pt = PrettyTable()
pt.field_names = [
    "Host",
    "Common Name",
    "NotBefore",
    "NotAfter",
    "Issuer",
]
pt.align = "l"


def expiration_check(target: str,port: int) -> None:
    ctx = ssl.create_default_context()
    
    socket.setdefaulttimeout(1)
    sock = socket.create_connection((target, port))
    sock = ctx.wrap_socket(sock, server_hostname=target)
        
    sslobj = sock._sslobj
    
    verified_chain = sslobj.get_verified_chain()
    cert_info = verified_chain[0].public_bytes()
    

    x509 = crypto.load_certificate(
        crypto.FILETYPE_PEM,
        cert_info
    )

    pt.add_row([
        target,
        x509.get_subject().CN,
        datetime.strptime(
            x509.get_notBefore().decode('ascii'),
            '%Y%m%d%H%M%SZ'
        ),
        datetime.strptime(
            x509.get_notAfter().decode('ascii'),
            '%Y%m%d%H%M%SZ'
        ),
        x509.get_issuer().CN,
    ])


@click.command()
@click.option('-H', '--hosts', help='target hosts, splits by comma')
def check(hosts):
    for host in hosts.split(','):
        if host.find(":") > 0:
            host, port = host.split(':')
            expiration_check(host,int(port))
        else:
            expiration_check(host,443)

    print(pt.get_string(sortby="NotAfter", reversesort=False))


if __name__ == '__main__':
    check()
