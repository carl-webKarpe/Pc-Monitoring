# Stops the MST Monitoring Agent from starting automatically (the agent files and settings are kept).
# Run:  powershell -ExecutionPolicy Bypass -File .\uninstall-autostart.ps1
$taskName = 'MST Monitoring Agent'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
  Write-Host "Automatic start removed. Close the agent window to stop the running agent." -ForegroundColor Green
} else {
  Write-Host 'Automatic start was not installed.'
}
