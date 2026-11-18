' Intrusion Monitor - silent launcher
' Starts the monitor with NO console window. Double-click this file to run.
Dim sh, here
Set sh = CreateObject("WScript.Shell")
here = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
sh.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File """ & here & "IntrusionMonitor.ps1""", 0, False
