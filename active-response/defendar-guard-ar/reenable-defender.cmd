@echo off
REM Wrapper Wazuh calls; forwards stdin to the PowerShell AR script.
PowerShell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\Program Files\Sysinternals\reenable-defender.ps1"
