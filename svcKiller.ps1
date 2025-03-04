Write-Host "Starting svcKiller.ps1..."

# Get all svchost.exe processes
$svchostProcesses = Get-WmiObject Win32_Process | Where-Object { $_.Name -eq "svchost.exe" }

# Initialize an array to store suspicious process IDs
$SuspiciousProcesses = @()

# Loop through each process and check the owner
foreach ($proc in $svchostProcesses) {
    $owner = $proc.GetOwner()
    $user = "$($owner.Domain)\$($owner.User)"
    $processID = $proc.ProcessId  # Renamed from PID to processID

    # Filter: Only add process IDs where the user is NOT SYSTEM, LOCAL SERVICE, or NETWORK SERVICE
    if ($owner.User -and $owner.User -ne "SYSTEM" -and $owner.User -ne "LOCAL SERVICE" -and $owner.User -ne "NETWORK SERVICE") {
        $SuspiciousProcesses += $processID
        Write-Host "Suspicious svchost.exe detected - Process ID: $processID, User: $user" -ForegroundColor Yellow
    }
}

# Stop only suspicious svchost.exe processes
if ($SuspiciousProcesses.Count -gt 0) {
    foreach ($processID in $SuspiciousProcesses) {
        try {
            Stop-Process -Id $processID -Force -ErrorAction Stop
            Write-Host "Stopped svchost.exe with Process ID: $processID" -ForegroundColor Green
        } catch {
            Write-Host "Failed to stop Process ID: $processID - $_" -ForegroundColor Red
        }
    }
} else {
    Write-Host "No suspicious svchost.exe processes found." -ForegroundColor Cyan
}
