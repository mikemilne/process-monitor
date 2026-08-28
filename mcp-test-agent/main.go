// mcp-test-agent simulates an agent process that periodically calls out to a
// remote MCP-style tool backend (a real public weather API, mirroring what
// the weather-mcp server itself calls under the hood). Each iteration does a
// real DNS lookup plus an HTTPS request against -target, generating the
// process/network/DNS telemetry that Sysmon Event IDs 1/5/3/22 capture.
//
// Run standalone (not through an MCP client) since the goal is to exercise
// real outbound DNS+network behavior, not the MCP wire protocol itself.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	name := flag.String("name", "agent", "agent identifier for logging")
	target := flag.String("target", "https://api.open-meteo.com/v1/forecast?latitude=47.6&longitude=-122.3&current_weather=true", "URL to call each iteration")
	duration := flag.Duration("duration", 2*time.Minute, "total time to run before exiting")
	interval := flag.Duration("interval", 15*time.Second, "time between calls")
	flag.Parse()

	pid := os.Getpid()
	u, err := url.Parse(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s pid=%d] invalid target %q: %v\n", *name, pid, *target, err)
		os.Exit(1)
	}
	host := u.Hostname()

	fmt.Printf("[%s pid=%d] starting, target host=%s duration=%s interval=%s\n", *name, pid, host, *duration, *interval)

	client := &http.Client{Timeout: 10 * time.Second}
	deadline := time.Now().Add(*duration)
	iteration := 0

	for time.Now().Before(deadline) {
		iteration++
		start := time.Now()

		resolver := &net.Resolver{}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		addrs, dnsErr := resolver.LookupHost(ctx, host)
		cancel()
		if dnsErr != nil {
			fmt.Printf("[%s pid=%d] iter=%d %s DNS lookup for %s FAILED: %v\n", *name, pid, iteration, start.UTC().Format(time.RFC3339), host, dnsErr)
		} else {
			fmt.Printf("[%s pid=%d] iter=%d %s DNS lookup for %s -> %v\n", *name, pid, iteration, start.UTC().Format(time.RFC3339), host, addrs)

			req, _ := http.NewRequest("GET", *target, nil)
			req.Header.Set("User-Agent", "sysmon-observability-test/1.0 (local test harness; non-production)")
			resp, httpErr := client.Do(req)
			if httpErr != nil {
				fmt.Printf("[%s pid=%d] iter=%d HTTP request FAILED: %v\n", *name, pid, iteration, httpErr)
			} else {
				fmt.Printf("[%s pid=%d] iter=%d HTTP %s -> status=%d\n", *name, pid, iteration, host, resp.StatusCode)
				resp.Body.Close()
			}
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		sleep := *interval
		if sleep > remaining {
			sleep = remaining
		}
		time.Sleep(sleep)
	}

	fmt.Printf("[%s pid=%d] exiting after %d iterations\n", *name, pid, iteration)
}
