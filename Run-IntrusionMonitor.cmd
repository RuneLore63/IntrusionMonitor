@echo off
REM Standard-user launch, no lingering console window.
REM (IntrusionMonitor.vbs is the cleanest - it opens nothing at all.)
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0IntrusionMonitor.ps1"
