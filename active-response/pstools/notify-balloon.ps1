# notify-balloon.ps1
# Shows a system tray notification to the active user.
Add-Type -AssemblyName System.Windows.Forms
$balloon = New-Object System.Windows.Forms.NotifyIcon
$balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon((Get-Process -Id $PID).Path)
$balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
$balloon.BalloonTipTitle = "Software Policy Alert"
$balloon.BalloonTipText = "A non-approved application was blocked for your security. Contact IT for help."
$balloon.Visible = $true
$balloon.ShowBalloonTip(10000)
Start-Sleep -Seconds 12
$balloon.Dispose()
