#!/usr/bin/python
"""
This is a simple script for user enumeration on SMTP, using the VRFY command.
"""

import socket
import sys

if len(sys.argv) != 3:
        print("Usage: smtp-user-vrfy.py <username> <target_ip>")
        sys.exit(0)

# Connect to the Server
ip = sys.argv[2]
s = socket.create_connection((ip,25))

# Receive the banner
banner = s.recv(1024)

print(banner)

# VRFY a user
user = (sys.argv[1]).encode()
s.send(f'VRFY  {user}\r\n'.encode())
result = s.recv(1024)

print(result)

# Close the socket
s.close()
