// sysmon-capture reads Sysmon Operational log events (Process Create=1,
// Process Terminate=5, Network Connect=3, DNS Query=22) created within a
// time window, cross-references each event's PID against one or more
// baseline process-list CSVs, and writes a unified correlated CSV.
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type sysmonEvent struct {
	EventId     int               `json:"EventId"`
	TimeCreated string            `json:"TimeCreated"`
	Data        map[string]string `json:"Data"`
}

func fetchEvents(startUTC, endUTC time.Time) ([]sysmonEvent, error) {
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
try {
  $events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=22) and TimeCreated[@SystemTime>='%s' and @SystemTime<='%s']]]"
} catch {
  if ($_.Exception.Message -match 'No events were found') { $events = @() } else { throw }
}
$out = foreach ($e in $events) {
  $xml = [xml]$e.ToXml()
  $data = @{}
  foreach ($d in $xml.Event.EventData.Data) {
    if ($d.Name) { $data[$d.Name] = $d.'#text' }
  }
  [PSCustomObject]@{
    EventId = $e.Id
    TimeCreated = $e.TimeCreated.ToUniversalTime().ToString('o')
    Data = $data
  }
}
$out | ConvertTo-Json -Depth 6 -Compress
`, startUTC.Format("2006-01-02T15:04:05.000Z"), endUTC.Format("2006-01-02T15:04:05.000Z"))

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("running powershell: %w: %s", err, string(out))
	}

	trimmed := string(out)
	if len(trimmed) == 0 || trimmed == "\r\n" || trimmed == "\n" {
		return nil, nil
	}

	var events []sysmonEvent
	if err := json.Unmarshal(out, &events); err != nil {
		var single sysmonEvent
		if err2 := json.Unmarshal(out, &single); err2 != nil {
			// No events matched -> ConvertTo-Json of empty array prints nothing/"null".
			return nil, nil
		}
		events = []sysmonEvent{single}
	}
	return events, nil
}

func loadBaseline(path string) map[string]string {
	result := map[string]string{}
	if path == "" {
		return result
	}
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not open baseline %s: %v\n", path, err)
		return result
	}
	defer f.Close()

	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 1 {
		return result
	}
	for _, row := range rows[1:] {
		if len(row) < 2 {
			continue
		}
		pid := row[1]
		name := row[0]
		result[pid] = name
	}
	return result
}

var eventTypeNames = map[int]string{
	1:  "ProcessCreate",
	5:  "ProcessTerminate",
	3:  "NetworkConnect",
	22: "DnsQuery",
}

func main() {
	startFlag := flag.String("start", "", "session start time, RFC3339 (required)")
	endFlag := flag.String("end", "", "session end time, RFC3339 (required)")
	initialBaseline := flag.String("initial-baseline", "", "path to the initial process capture CSV (e.g. first_pidlist.csv)")
	sessionBaseline := flag.String("session-baseline", "", "path to the pre-session baseline capture CSV")
	outPath := flag.String("out", "sysmon_events.csv", "output CSV path")
	flag.Parse()

	if *startFlag == "" || *endFlag == "" {
		fmt.Fprintln(os.Stderr, "error: -start and -end are required (RFC3339)")
		os.Exit(1)
	}
	start, err := time.Parse(time.RFC3339, *startFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing -start: %v\n", err)
		os.Exit(1)
	}
	end, err := time.Parse(time.RFC3339, *endFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing -end: %v\n", err)
		os.Exit(1)
	}

	initialMap := loadBaseline(*initialBaseline)
	sessionMap := loadBaseline(*sessionBaseline)

	events, err := fetchEvents(start.UTC(), end.UTC())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error fetching sysmon events:", err)
		os.Exit(1)
	}

	f, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error creating csv:", err)
		os.Exit(1)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"EventType", "TimeCreated", "ProcessGuid", "PID", "Image",
		"ParentPID", "ParentImage", "CommandLine",
		"Protocol", "SourceIp", "SourcePort", "DestinationIp", "DestinationPort", "DestinationHostname", "Initiated",
		"QueryName", "QueryStatus", "QueryResults",
		"InInitialCapture", "InSessionBaseline", "BaselineProcessName",
	}
	if err := w.Write(header); err != nil {
		fmt.Fprintln(os.Stderr, "error writing header:", err)
		os.Exit(1)
	}

	counts := map[int]int{}
	for _, e := range events {
		counts[e.EventId]++
		d := e.Data
		pid := d["ProcessId"]

		inInitial := "No"
		if _, ok := initialMap[pid]; ok {
			inInitial = "Yes"
		}
		inSession := "No"
		baselineName := ""
		if n, ok := sessionMap[pid]; ok {
			inSession = "Yes"
			baselineName = n
		}

		record := []string{
			eventTypeNames[e.EventId], e.TimeCreated, d["ProcessGuid"], pid, d["Image"],
			d["ParentProcessId"], d["ParentImage"], d["CommandLine"],
			d["Protocol"], d["SourceIp"], d["SourcePort"], d["DestinationIp"], d["DestinationPort"], d["DestinationHostname"], d["Initiated"],
			d["QueryName"], d["QueryStatus"], d["QueryResults"],
			inInitial, inSession, baselineName,
		}
		if err := w.Write(record); err != nil {
			fmt.Fprintln(os.Stderr, "error writing record:", err)
			os.Exit(1)
		}
	}

	fmt.Printf("wrote %d sysmon events to %s\n", len(events), *outPath)
	for _, id := range []int{1, 5, 3, 22} {
		fmt.Printf("  EventID %d (%s): %d\n", id, eventTypeNames[id], counts[id])
	}
}
