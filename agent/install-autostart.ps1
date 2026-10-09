# Starts the MST Monitoring Agent automatically when this Windows user signs in.
# Run in PowerShell from the agent folder:   powershell -ExecutionPolicy Bypass -File .\install-autostart.ps1
# Remove it again with:                       powershell -ExecutionPolicy Bypass -File .\uninstall-autostart.ps1
$ErrorActionPreference = 'Stop'
$agent = $PSScriptRoot
$taskName = 'MST Monitoring Agent'

if (-not (Test-Path "$agent\.venv\Scripts\python.exe")) { Write-Host 'The agent is not installed yet (no .venv). Follow agent\README.md first.' -ForegroundColor Red; exit 1 }
if (-not (Test-Path "$agent\config.json")) { Write-Host 'config.json is missing. Copy config.example.json to config.json and fill it in first.' -ForegroundColor Red; exit 1 }

Write-Host 'Checking the connection to the MST server...'
& "$agent\.venv\Scripts\python.exe" "$agent\run_agent.py" --check
if ($LASTEXITCODE -ne 0) { Write-Host 'The MST server did not accept this PC. Fix the problem above, then run this script again.' -ForegroundColor Red; exit 1 }

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument "/c `"$agent\start-agent.bat`"" -WorkingDirectory $agent
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
# Runs as the signed-in user (it watches that user's Downloads/Desktop/Documents), with no time limit.
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Reports file activity in the configured folders to the MST server (authorized computer laboratory monitoring).' -Force | Out-Null

Write-Host "Done. '$taskName' now starts automatically when $user signs in." -ForegroundColor Green
$answer = Read-Host 'Start it now? (y/n)'
if ($answer -match '^[yY]') { Start-ScheduledTask -TaskName $taskName; Write-Host 'Started. A window titled "MST Monitoring Agent" is open.' }
