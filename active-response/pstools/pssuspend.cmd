@echo off
:: pssuspend.cmd - Wazuh Active Response Wrapper
:: Run pssuspend_v2.ps1 silently in background

setlocal

set SCRIPT_PATH=C:\Program Files\Sysinternals\pssuspend_v2.ps1

:: Prefer PowerShell 7 if available
where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    pwsh.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "%SCRIPT_PATH%"
) else (
    powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "%SCRIPT_PATH%"
)

endlocal
