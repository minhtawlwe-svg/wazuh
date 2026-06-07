@echo off
:: pssuspend.cmd - Wazuh Active Response Wrapper
:: This script passes Wazuh AR execution to pssuspend_v2.ps1
setlocal

:: Wazuh AR passes input via stdin, so we pipe it to the PS script
set SCRIPT_PATH="C:\Program Files\Sysinternals\pssuspend_v2.ps1"
set PWSH_PATH="C:\Program Files\PowerShell\7\pwsh.exe"

:: Check if PowerShell 7 exists at the explicit path and use it
if exist %PWSH_PATH% (
    %PWSH_PATH% -ExecutionPolicy Bypass -File %SCRIPT_PATH%
) else (
    powershell.exe -ExecutionPolicy Bypass -File %SCRIPT_PATH%
)
endlocal
