@echo off
REM Wazuh AR wrapper - execd runs .cmd/.exe, not .ps1 directly.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0agb-kill-block.ps1"
