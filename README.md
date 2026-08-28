# process-monitor

Windows observability test harness built on top of
[remote-app](https://github.com/mikemilne/remote-app). Captures a process
baseline, generates real outbound DNS/network traffic from simulated
"MCP agent" processes, and correlates the resulting Sysmon telemetry
(Process Create/Terminate, Network Connect, DNS Query) against the baseline
by PID.

## Layout

- `baseline-capture/` - Go program, snapshots running processes to CSV
  (same approach as `remote-app`).
- `mcp-test-agent/` - Go program that periodically resolves DNS and makes an
  HTTPS request to a target URL, standing in for an agent calling a remote
  MCP tool backend. Used with three targets: a real weather API
  (`api.open-meteo.com`), NOAA's API (`api.weather.gov`), and a deliberately
  unresolvable `.invalid` host to exercise a DNS-failure case.
- `sysmon-capture/` - Go program that queries the
  `Microsoft-Windows-Sysmon/Operational` event log for Event IDs 1
  (ProcessCreate), 5 (ProcessTerminate), 3 (NetworkConnect), and 22
  (DnsQuery) within a time window, and cross-references each event's PID
  against one or more baseline CSVs.
- `sysmon-config.xml` - minimal Sysmon config enabling only the four event
  types above.
- `run-session.ps1` - orchestrates a full session: baseline capture, launch
  test agents for ~2 minutes, wait for them to self-terminate, then run
  `sysmon-capture`.
- `session_baseline_pidlist.csv`, `sysmon_events.csv`, `log.txt`,
  `agent-*.stdout.log` / `agent-*.stderr.log` - output from an actual run of
  this harness.

## Requirements

- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
  installed with `sysmon-config.xml`:
  `Sysmon64.exe -accepteula -i sysmon-config.xml`
- Go toolchain to build the three programs (`go build` in each directory).

## Usage

```
.\run-session.ps1
```

See `log.txt` for session notes, including caveats on PID reuse and why
`ProcessGuid` (not PID) is the reliable per-process identifier.
