@echo off
:: get-forensics.cmd - Wazuh Active Response Wrapper
:: This script passes Wazuh AR execution to ps-forensics.ps1
setlocal

:: Wazuh AR passes input via stdin, so we pipe it to the PS script
set SCRIPT_PATH="C:\Program Files\Sysinternals\ps-forensics.ps1"

where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    pwsh.exe -ExecutionPolicy Bypass -File %SCRIPT_PATH%
) else (
    powershell.exe -ExecutionPolicy Bypass -File %SCRIPT_PATH%
)
endlocal
