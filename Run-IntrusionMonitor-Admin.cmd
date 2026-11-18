@echo off
REM Elevated launch - adds firewall port-scan detection, decoy share, and blocking.
REM Triggers a UAC prompt. Only use on a PC you administer.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-STA','-WindowStyle','Hidden','-File','\"%~dp0IntrusionMonitor.ps1\"'"
