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

# interactive SMB session without creds
smbclient -N //$VICTIM_IP/SHARENAME
# or with creds
smbclient '\\TARGET_IP\dirname' -W DOMAIN -U username
```