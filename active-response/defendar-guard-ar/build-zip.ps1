# build-zip.ps1 - rebuild defender-guard.zip from the live files in this folder.
# Run on the dev box BEFORE committing:
#     pwsh -File build-zip.ps1
# or on Linux/macOS:
#     python3 -c "import zipfile,os,pathlib; z=zipfile.ZipFile('defender-guard.zip','w',zipfile.ZIP_DEFLATED,9); [z.write(n) for n in ['reenable-defender.cmd','reenable-defender.ps1','watchdog-service.ps1','enforce-tamper-protection.ps1','tamper-protection-policy.xml','ossec.conf','_inner-install.ps1'] if os.path.exists(n)]; z.close()"

$files = @(
    'reenable-defender.cmd',
    'reenable-defender.ps1',
    'watchdog-service.ps1',
    'enforce-tamper-protection.ps1',
    'tamper-protection-policy.xml',
    'ossec.conf',
    '_inner-install.ps1'
)

if (Test-Path 'defender-guard.zip') { Remove-Item 'defender-guard.zip' -Force }

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open('defender-guard.zip', [System.IO.Compression.ZipArchiveMode]::Create)
foreach ($f in $files) {
    if (Test-Path $f) {
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Resolve-Path $f).Path, $f) | Out-Null
        Write-Host "  + $f" -ForegroundColor Green
    } else {
        Write-Host "  !! missing: $f" -ForegroundColor Red
    }
}
$zip.Dispose()

Write-Host ""
Write-Host ("wrote defender-guard.zip ({0} bytes)" -f (Get-Item defender-guard.zip).Length) -ForegroundColor Cyan
