@echo off
setlocal EnableExtensions

set SCRIPT_PATH=C:\Program Files\Sysinternals\pssuspend_v2.ps1

REM ---- Priority 1: PowerShell 7 (pwsh) ----
if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" (
    "%ProgramFiles%\PowerShell\7\pwsh.exe" ^
        -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
        -WindowStyle Hidden -File "%SCRIPT_PATH%"
    goto :end
)

if exist "%ProgramFiles(x86)%\PowerShell\7\pwsh.exe" (
    "%ProgramFiles(x86)%\PowerShell\7\pwsh.exe" ^
        -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
        -WindowStyle Hidden -File "%SCRIPT_PATH%"
    goto :end
)

REM ---- Priority 2: Windows PowerShell (Default fallback) ----
if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" (
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" ^
        -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
        -WindowStyle Hidden -File "%SCRIPT_PATH%"
    goto :end
)

REM ---- Final fallback (just in case PATH works) ----
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
    -WindowStyle Hidden -File "%SCRIPT_PATH%"

:end
endlocal
