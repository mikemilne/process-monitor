# Orchestrates one observability test session:
#  1. Capture a fresh process baseline
#  2. Start a packet capture (remote-app's capture.exe, "session" mode)
#     scoped to the real HTTPS targets the agents will call
#  3. Spin up several mcp-test-agent processes generating real DNS+network
#     traffic, with SSLKEYLOGFILE pointed at a shared key log so their TLS
#     session secrets get logged
#  4. Let them run for ~2 minutes, then ensure they've stopped; wait for the
#     capture to autostop alongside them
#  5. Pull matching Sysmon events (IDs 1,5,3,22) and correlate against both
#     the initial capture (remote-app's first_pidlist.csv) and this
#     session's baseline
#  6. Merge the Sysmon telemetry with the decrypted capture into one
#     timestamped session_report.txt (process-monitor's session-report tool)
#  7. Write log.txt with session metadata for later debugging

$ErrorActionPreference = "Stop"
Set-Location "C:\Users\mmilne\Documents\process-monitor"

$initialBaseline = "C:\Users\mmilne\Documents\remote-app\first_pidlist.csv"
$sessionBaseline = "session_baseline_pidlist.csv"
$sysmonOut = "sysmon_events.csv"
$logPath = "log.txt"
$reportOut = "session_report.txt"
$pcapPath = "session_capture.pcapng"
$keylogPath = "session_keylog.log"
$captureExe = "..\remote-app\capture\capture.exe"
$sessionReportExe = ".\session-report\session-report.exe"
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

# 2. Start packet capture for the real (non-.invalid) targets, in the
#    background, before the agents start generating traffic. A fresh key
#    log file is shared by every agent process below.
Remove-Item -ErrorAction SilentlyContinue $pcapPath, $keylogPath
New-Item -ItemType File -Path $keylogPath | Out-Null

$agentDefs = @(
    @{ Name = "agent-openmeteo"; Target = "https://api.open-meteo.com/v1/forecast?latitude=47.6&longitude=-122.3&current_weather=true" },
    @{ Name = "agent-noaa";      Target = "https://api.weather.gov/points/47.6,-122.3" },
    @{ Name = "agent-nxdomain";  Target = "https://mcp-agent-test.invalid/tool" }
)
$captureTargets = $agentDefs | Where-Object { $_.Name -ne "agent-nxdomain" } | ForEach-Object { $_.Target }

Log "Starting packet capture -> $pcapPath (targets: $($captureTargets -join ', '))"
$captureArgs = @("session", "-duration", "2m30s", "-pcap", $pcapPath) + $captureTargets
$captureProc = Start-Process -FilePath $captureExe -ArgumentList $captureArgs `
    -RedirectStandardOutput "capture.stdout.log" -RedirectStandardError "capture.stderr.log" `
    -PassThru -WindowStyle Hidden
Log "Launched packet capture PID=$($captureProc.Id)"
Start-Sleep -Seconds 3   # let the capture attach to the interface before agents start

# 3. Launch test agents, all writing TLS session keys into the shared key log
$env:SSLKEYLOGFILE = (Resolve-Path $keylogPath).Path

$sessionStart = (Get-Date).ToUniversalTime()
Log "Session start (UTC): $($sessionStart.ToString('o'))"

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

# 4. Wait for agents to self-terminate (2m duration + margin), then force-stop stragglers
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

Log "Waiting for packet capture to autostop..."
try {
    Wait-Process -Id $captureProc.Id -Timeout 60 -ErrorAction Stop
    Log "Packet capture (PID=$($captureProc.Id)) finished"
} catch {
    Log "Packet capture did not exit in time, stopping it"
    Stop-Process -Id $captureProc.Id -Force -ErrorAction SilentlyContinue
}
Get-Content "capture.stdout.log" -ErrorAction SilentlyContinue | ForEach-Object { Log "  [capture] $_" }
Get-Content "capture.stderr.log" -ErrorAction SilentlyContinue | ForEach-Object { Log "  [capture] $_" }

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

# 5. Correlate Sysmon events
Log "Running sysmon-capture.exe for window $($sessionStart.ToString('o')) .. $($sessionEnd.ToString('o'))"
$captureOut = & ".\sysmon-capture\sysmon-capture.exe" `
    -start $sessionStart.ToString("o") -end $sessionEnd.ToString("o") `
    -initial-baseline $initialBaseline -session-baseline $sessionBaseline -out $sysmonOut
$captureOut | ForEach-Object { Log "  $_" }

# 6. Merge Sysmon telemetry with the decrypted capture into one report
Log "Running session-report.exe -> $reportOut"
# -show-key-material=false: this report is a committed sample artifact, so
# raw TLS session secrets are left out. Run session-report.exe directly with
# -show-key-material to get them for local-only analysis.
$reportOutLines = & $sessionReportExe -sysmon-csv $sysmonOut -pcap $pcapPath -keylog $keylogPath -out $reportOut -show-key-material=$false
$reportOutLines | ForEach-Object { Log "  $_" }

Log "=== Session complete ==="
Log "Outputs: $sessionBaseline, $sysmonOut, $reportOut, $logPath"

$log | Set-Content -Path $logPath -Encoding utf8
Write-Host "`nWrote log to $logPath"
