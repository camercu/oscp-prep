# OSCP Prep

My extended cheatsheet is [CHEATSHEET.md](CHEATSHEET.md).

Here is my general workflow:

1. Scan host with nmap.
2. Poke at each service you find for **20 mins tops**.
3. Use service-specific enumeration techniques from the [CHEETSHEET](CHEATSHEET.md).
4. Gain initial access with whatever exploit you can find.
5. Get a stable interactive shell.
6. Perform OS-specific enumeration once on box with user-level access, looking for privesc vectors.
7. Take notes of possible privesc vectors. Only try each one **for 20 mins max** before going round-robin to next.
8. Perform OS- or service-specific privesc to get root!
9. If box is part of network (e.g. Active Directory), gather useful data (creds) to help pivot.

# Quick Reference

These are some commands I use all the time:

## Scanning

```sh
# Prefer rustscan for speed, but sometimes too fast and ports not detected
sudo rustscan --ulimit 5000 -a $VICTIM_IP -- -n -Pn -sV -sC -oA tcp-all

# nmap scripts are located at:
/usr/share/nmap/scripts
# Use ls, grep, etc. to find useful stuff.
# Also check the script-help
nmap --script-help="nfs-*"
```

- [ ] Check service versions with `searchsploit`
- [ ] Read ALL output!
- [ ] Don't forget UDP!
- [ ] (advanced) Don't forget IPv6

## Web Services

```sh
# check what technologies a website is using
whatweb -v -a3 http://10.10.10.123 | tee whatweb.log

# scan for web directories
ulimit -n 8192 # prevent file access error during scanning
gobuster dir -ezqrkw /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -x "html,htm,txt,sh,php,cgi" -o gobust.log -u http://10.10.10.123

# Wordpress sites:
wpscan --update --url http://$VICTIM_IP/ | tee wpscan.log
# see cheatsheet for agressive scan
```

- [ ] Check out robots.txt (should be in nmap output)
- [ ] Examine SSL certs for emails & domains
- [ ] Look for software versions (help/about pages?), check in `searchsploit`
- [ ] View source, look for link directories and juicy comments
- [ ] Try default creds for login portals
- [ ] Try SQLi in all form fields and URL query params
- [ ] Try LFI/RFI in URL query params
- [ ] Try command injection in form fields
- [ ] Try NoSQL injection in form fields

## SMB

```sh
# general enumeration scan. Also try with usernames: guest, administrator
# add: -u guest
enum4linux -aMld 10.10.10.123 | tee enum4linux.log

# list available shares
smbmap -H $VICTIM_IP
# try with '-u guest' if getting "[!] Authentication error"

# recursively list directory contents
smbmap -R -H $VICTIM_IP

# tar entire smb share locally
smbclient //10.10.10.123/SHARENAME -N -Tc smbfiles.tar

# interactive SMB session without creds
smbclient -N //$VICTIM_IP/SHARENAME
# or with creds
smbclient '\\TARGET_IP\dirname' -W DOMAIN -U username
> help # view available commands
# ls, cd, get, put
# recursively get all files:
> recurse on
> prompt off
> mget *
```

## Linux enumeration

```sh
# basic SA
env
uname -a
cat /etc/*release
ip a
netstat -untap
ps -ef wwf
sudo -l
cat /etc/passwd
cat /etc/crontab

# find world-writable files
find / -mount -type f -perm -o+w 2>/dev/null
```

- [ ] Look for plaintext credentials in config files, web source, shell history
- [ ] [Download](tools/linux/get-linpeas.sh) and run `linpeas.sh` on the host