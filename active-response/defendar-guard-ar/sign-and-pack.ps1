# sign-and-pack.ps1 - sign every .ps1 / .cmd in this folder with a self-signed
# code-signing certificate, then rebuild defender-guard.zip. Run elevated.
#
# WHY THIS EXISTS:
#   Defender AMSI blocks any PowerShell script from the internet that combines
#   download/replace + SYSTEM-scheduled-task persistence, even after MOTW is
#   cleared. A signed script receives a different AMSI trust path: Defender
#   honors signed publishers. Set-AuthenticodeSignature on a self-signed cert
#   installed in the LocalMachine TrustedPeople store is enough to flip
#   those scripts to "trusted publisher" for Defender AMSI.
#
# Run once per dev machine. Re-run after editing any .ps1 / .cmd file.

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# 1. Create or fetch the self-signed code-signing cert.
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Subject "CN=Defender-Guard-AR,O=Local Dev" `
                                      -Type CodeSigningCert `
                                      -CertStoreLocation Cert:\CurrentUser\My `
                                      -NotAfter (Get-Date).AddYears(5)
    Write-Host "  + created self-signed cert: $($cert.Thumbprint)" -ForegroundColor Green
}

# Export the cert to a .cer so the agent can trust the publisher.
$certPath = Join-Path $here "defender-guard.cer"
Export-Certificate -Cert $cert -FilePath $certPath | Out-Null
Write-Host "  + exported public cert: $certPath" -ForegroundColor Green

# 2. Sign every script in this folder.
Get-ChildItem -Path $here -Include *.ps1,*.cmd -File | ForEach-Object {
    $sig = Get-AuthenticodeSignature -FilePath $_.FullName
    if ($sig.SignatureCertificate -and $sig.SignatureCertificate.Thumbprint -eq $cert.Thumbprint -and $sig.Status -eq 'Valid') {
        Write-Host "  -- already signed: $($_.Name)" -ForegroundColor DarkGray
        return
    }
    Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $cert | Out-Null
    Write-Host "  OK signed: $($_.Name)" -ForegroundColor Green
}

# 3. Rebuild the zip including the cert so the installer can offer to
#    import it on the agent.
if (Test-Path "$here\defender-guard.zip") { Remove-Item "$here\defender-guard.zip" -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open("$here\defender-guard.zip", [System.IO.Compression.ZipArchiveMode]::Create)
$files = @('reenable-defender.cmd','reenable-defender.ps1','watchdog-service.ps1','enforce-tamper-protection.ps1','tamper-protection-policy.xml','ossec.conf','_inner-install.ps1','defender-guard.cer')
foreach ($f in $files) {
    $p = Join-Path $here $f
    if (Test-Path $p) {
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Resolve-Path $p).Path, $f) | Out-Null
    }
}
$zip.Dispose()
Write-Host ""
Write-Host ("wrote defender-guard.zip ({0} bytes, signed)" -f (Get-Item "$here\defender-guard.zip").Length) -ForegroundColor Cyan
Write-Host ""
Write-Host "Next:" -ForegroundColor Yellow
Write-Host "  1. Commit the regenerated defender-guard.zip + the new defender-guard.cer"
Write-Host "  2. On each agent, run install.ps1; it will offer to import defender-guard.cer into"
Write-Host "     LocalMachine TrustedPeople so AMSI trusts the publisher."
