# sign-once.ps1 - run ONCE on any Windows dev box (PowerShell 5.1 or 7+).
#
# What this does:
#   1. Creates a self-signed code-signing cert (5-year, CurrentUser\My).
#   2. Exports the public cert as defender-guard.cer -- ship this with the
#      repo so agents can trust the publisher on first install.
#   3. Signs every .ps1 and .cmd in the current folder with the cert.
#   4. Verifies each signature.
#
# After running once, commit:
#   - defender-guard.cer  (the public cert)
#   - every .ps1 / .cmd   (now contain a valid Authenticode signature)
#
# Subsequent AR runs / scheduler launches on the agent will not trigger
# AMSI test probes because the script has a publisher that Defender
# recognizes as signed. (Windows Defender AMSI honors Authenticode
# publisher trust the same way it honors the OS publisher.)

$ErrorActionPreference = "Stop"

# 1. Find or create the cert
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $cert) {
    Write-Host "No existing code-signing cert. Creating..." -ForegroundColor Yellow
    $cert = New-SelfSignedCertificate -Subject "CN=Defender-Guard-AR,O=Local Dev" `
                                      -Type CodeSigningCert `
                                      -CertStoreLocation Cert:\CurrentUser\My `
                                      -NotAfter (Get-Date).AddYears(5) `
                                      -KeyAlgorithm RSA `
                                      -KeyLength 2048
}

Write-Host ("Cert thumbprint: {0}" -f $cert.Thumbprint) -ForegroundColor Cyan

# 2. Export the public cert
$cerPath = Join-Path (Get-Location) "defender-guard.cer"
Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
Write-Host ("Public cert exported: {0}" -f $cerPath) -ForegroundColor Green

# 3. Sign every script in this folder
$scripts = Get-ChildItem -Path . -Include *.ps1,*.cmd -File
foreach ($s in $scripts) {
    $existing = Get-AuthenticodeSignature -FilePath $s.FullName
    if ($existing.SignerCertificate -and
        $existing.SignerCertificate.Thumbprint -eq $cert.Thumbprint -and
        $existing.Status -eq 'Valid') {
        Write-Host ("  -- already signed: {0}" -f $s.Name) -ForegroundColor DarkGray
        continue
    }
    Set-AuthenticodeSignature -FilePath $s.FullName -Certificate $cert | Out-Null
    Write-Host ("  OK signed: {0}" -f $s.Name) -ForegroundColor Green
}

# 4. Verify
Write-Host ""
Write-Host "Verification:" -ForegroundColor Cyan
foreach ($s in $scripts) {
    $sig = Get-AuthenticodeSignature -FilePath $s.FullName
    $color = if ($sig.Status -eq 'Valid') { 'Green' } else { 'Red' }
    Write-Host ("  {0,-50s} Status={1}" -f $s.Name, $sig.Status) -ForegroundColor $color
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Commit the regenerated .ps1 / .cmd and the new defender-guard.cer:"
Write-Host ""
Write-Host "       git add -A"
Write-Host "       git commit -m 'Sign scripts + ship defender-guard.cer'"
Write-Host "       git push"
Write-Host ""
Write-Host "  2. On each agent, the install.ps1 will pick up the signer cert and import it"
Write-Host "     into LocalMachine\TrustedPeople.  From that point AMSI stops firing the"
Write-Host "     __PSScriptPolicyTest_*.ps1 probe for these signed scripts."
