// baseline-capture extracts the list of processes running on the local
// Windows machine (name, PID, command line) and writes them to a CSV file,
// used as the pre-monitoring-session baseline for PID cross-referencing.
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type process struct {
	Name        string  `json:"Name"`
	ProcessID   int     `json:"ProcessId"`
	CommandLine *string `json:"CommandLine"`
}

func fetchProcesses() ([]process, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance Win32_Process | Select-Object Name,ProcessId,CommandLine | ConvertTo-Json -Compress")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running powershell: %w", err)
	}

	var procs []process
	if err := json.Unmarshal(out, &procs); err != nil {
		var single process
		if err2 := json.Unmarshal(out, &single); err2 != nil {
			return nil, fmt.Errorf("parsing json: %w", err)
		}
		procs = []process{single}
	}
	return procs, nil
}

func main() {
	outPath := "session_baseline_pidlist.csv"
	if len(os.Args) > 1 {
		outPath = os.Args[1]
	}

	procs, err := fetchProcesses()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error creating csv:", err)
		os.Exit(1)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{"Name", "PID", "CommandLine"}); err != nil {
		fmt.Fprintln(os.Stderr, "error writing header:", err)
		os.Exit(1)
	}

	for _, p := range procs {
		cmdLine := ""
		if p.CommandLine != nil {
			cmdLine = *p.CommandLine
		}
		record := []string{p.Name, fmt.Sprintf("%d", p.ProcessID), cmdLine}
		if err := w.Write(record); err != nil {
			fmt.Fprintln(os.Stderr, "error writing record:", err)
			os.Exit(1)
		}
	}

	fmt.Printf("wrote %d processes to %s\n", len(procs), outPath)
}
