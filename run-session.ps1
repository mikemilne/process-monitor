# Orchestrates one observability test session:
#  1. Capture a fresh process baseline
#  2. Spin up several mcp-test-agent processes generating real DNS+network traffic
#  3. Let them run for ~2 minutes, then ensure they've stopped
#  4. Pull matching Sysmon events (IDs 1,5,3,22) and correlate against both
#     the initial capture (remote-app's first_pidlist.csv) and this session's baseline
#  5. Write log.txt with session metadata for later debugging

$ErrorActionPreference = "Stop"
Set-Location "C:\Users\mmilne\Documents\process-monitor"

$initialBaseline = "C:\Users\mmilne\Documents\remote-app\first_pidlist.csv"
$sessionBaseline = "session_baseline_pidlist.csv"
$sysmonOut = "sysmon_events.csv"
$logPath = "log.txt"
$log = New-Object System.Collections.Generic.List[string]

function Log($msg) {
    $line = "[$((Get-Date).ToUniversalTime().ToString('o'))] $msg"
    Write-Host $line
    $log.Add($line)
}

Log "=== Observability test session starting ==="
Log "Sysmon service: $((Get-Service Sysmon64).Status), version check via Sysmon64.exe -c summarized below"

# 1. Baseline capture
Log "Running baseline-capture.exe -> $sessionBaseline"
& ".\baseline-capture\baseline-capture.exe" $sessionBaseline | ForEach-Object { Log "  $_" }

$sessionStart = (Get-Date).ToUniversalTime()
Log "Session start (UTC): $($sessionStart.ToString('o'))"

# 2. Launch test agents
$agentDefs = @(
    @{ Name = "agent-openmeteo"; Target = "https://api.open-meteo.com/v1/forecast?latitude=47.6&longitude=-122.3&current_weather=true" },
    @{ Name = "agent-noaa";      Target = "https://api.weather.gov/points/47.6,-122.3" },
    @{ Name = "agent-nxdomain";  Target = "https://mcp-agent-test.invalid/tool" }
)

$procs = @()
foreach ($a in $agentDefs) {
    $stdout = "$($a.Name).stdout.log"
    $stderr = "$($a.Name).stderr.log"
    $p = Start-Process -FilePath ".\mcp-test-agent\mcp-test-agent.exe" `
        -ArgumentList @("-name", $a.Name, "-target", $a.Target, "-duration", "2m", "-interval", "15s") `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -PassThru -WindowStyle Hidden
    Log "Launched $($a.Name) target=$($a.Target) PID=$($p.Id)"
    $procs += [PSCustomObject]@{ Def = $a; Process = $p }
}

# 3. Wait for agents to self-terminate (2m duration + margin), then force-stop stragglers
Log "Waiting for test agents to run for ~2 minutes and self-terminate..."
$waitDeadline = (Get-Date).AddSeconds(150)
foreach ($entry in $procs) {
    $remaining = [Math]::Max(1, ($waitDeadline - (Get-Date)).TotalSeconds)
    try {
        Wait-Process -Id $entry.Process.Id -Timeout $remaining -ErrorAction Stop
        Log "$($entry.Def.Name) (PID=$($entry.Process.Id)) exited on its own"
    } catch {
        Log "$($entry.Def.Name) (PID=$($entry.Process.Id)) did not exit in time, stopping it"
        Stop-Process -Id $entry.Process.Id -Force -ErrorAction SilentlyContinue
    }
}

Start-Sleep -Seconds 5   # let Sysmon flush the last few events to the log
$sessionEnd = (Get-Date).ToUniversalTime()
Log "Session end (UTC): $($sessionEnd.ToString('o'))"

# Fold each agent's stdout/stderr into the log
foreach ($a in $agentDefs) {
    $stdout = "$($a.Name).stdout.log"
    $stderr = "$($a.Name).stderr.log"
    Log "--- $($a.Name) stdout ---"
    if (Test-Path $stdout) { Get-Content $stdout | ForEach-Object { $log.Add("  $_") } }
    if ((Test-Path $stderr) -and (Get-Item $stderr).Length -gt 0) {
        Log "--- $($a.Name) stderr ---"
        Get-Content $stderr | ForEach-Object { $log.Add("  $_") }
    }
}

# Confirm no leftover test-agent processes remain ("shut the test environment back down")
$leftover = Get-Process -Name "mcp-test-agent" -ErrorAction SilentlyContinue
if ($leftover) {
    Log "WARNING: leftover mcp-test-agent processes found, force-stopping: $($leftover.Id -join ',')"
    $leftover | Stop-Process -Force
} else {
    Log "Confirmed: no mcp-test-agent processes remain running"
}

# 4. Correlate Sysmon events
Log "Running sysmon-capture.exe for window $($sessionStart.ToString('o')) .. $($sessionEnd.ToString('o'))"
$captureOut = & ".\sysmon-capture\sysmon-capture.exe" `
    -start $sessionStart.ToString("o") -end $sessionEnd.ToString("o") `
    -initial-baseline $initialBaseline -session-baseline $sessionBaseline -out $sysmonOut
$captureOut | ForEach-Object { Log "  $_" }

Log "=== Session complete ==="
Log "Outputs: $sessionBaseline, $sysmonOut, $logPath"

$log | Set-Content -Path $logPath -Encoding utf8
Write-Host "`nWrote log to $logPath"
