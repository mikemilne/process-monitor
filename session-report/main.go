// session-report merges the process/network/DNS telemetry from a
// sysmon-capture CSV with the decrypted TLS/HTTP traffic captured by
// remote-app's capture tool (a .pcapng + an SSLKEYLOGFILE-format key log),
// and produces a single chronological, timestamped text file describing
// what the monitored session actually did:
//
//	timestamp:PID:process started with command ...
//	timestamp:PID:DNS lookup to "host"
//	timestamp:PID:DNS host resolved to IP address x.y.z.n
//	timestamp:PID:process "name" connected to ip/port with protocol tcp
//	timestamp:PID:TLS handshake completed ... cipher_suite=... key_exchange_group=...
//	timestamp:PID:[SENT] HTTPS request ...
//	timestamp:PID:[RECEIVED] HTTPS response ...
//
// PID attribution for the decrypted traffic is done by matching the TCP
// client port of each capture stream against the SourcePort recorded in the
// sysmon NetworkConnect events for that same session.
package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type reportEntry struct {
	ts   time.Time
	text string
}

func main() {
	sysmonCSV := flag.String("sysmon-csv", "sysmon_events.csv", "sysmon-capture output CSV")
	pcapPath := flag.String("pcap", `..\remote-app\capture\capture.pcapng`, "capture .pcapng file")
	keylogPath := flag.String("keylog", `..\remote-app\capture\keylog.log`, "SSLKEYLOGFILE produced alongside the capture")
	tsharkPath := flag.String("tshark", `C:\Program Files\Wireshark\tshark.exe`, "path to tshark.exe")
	outPath := flag.String("out", "session_report.txt", "output report file")
	showKeyMaterial := flag.Bool("show-key-material", true, "embed the raw TLS session secret values in the report (disable before publishing/committing the report anywhere secrets shouldn't go)")
	flag.Parse()

	if err := run(*sysmonCSV, *pcapPath, *keylogPath, *tsharkPath, *outPath, *showKeyMaterial); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(sysmonCSV, pcapPath, keylogPath, tsharkPath, outPath string, showKeyMaterial bool) error {
	entries, sourcePortToPID, err := sysmonEntries(sysmonCSV)
	if err != nil {
		return fmt.Errorf("reading sysmon csv: %w", err)
	}
	fmt.Printf("loaded %d process/dns/network events from %s\n", len(entries), sysmonCSV)

	var keylogSecrets map[string][]keylogSecret
	if showKeyMaterial {
		keylogSecrets, err = loadKeylog(keylogPath)
		if err != nil {
			return fmt.Errorf("reading keylog: %w", err)
		}
	}

	handshakes, err := tlsHandshakeEntries(tsharkPath, pcapPath, keylogPath, sourcePortToPID, keylogSecrets)
	if err != nil {
		return fmt.Errorf("extracting TLS handshake info: %w", err)
	}
	fmt.Printf("extracted %d TLS handshake(s) from %s\n", len(handshakes), pcapPath)
	entries = append(entries, handshakes...)

	httpEntries, err := httpTrafficEntries(tsharkPath, pcapPath, keylogPath, sourcePortToPID)
	if err != nil {
		return fmt.Errorf("extracting HTTP/1.1 traffic: %w", err)
	}
	fmt.Printf("extracted %d decrypted HTTP/1.1 request/response entries from %s\n", len(httpEntries), pcapPath)
	entries = append(entries, httpEntries...)

	http2Entries, err := http2TrafficEntries(tsharkPath, pcapPath, keylogPath, sourcePortToPID)
	if err != nil {
		return fmt.Errorf("extracting HTTP/2 traffic: %w", err)
	}
	fmt.Printf("extracted %d decrypted HTTP/2 request/response entries from %s\n", len(http2Entries), pcapPath)
	entries = append(entries, http2Entries...)

	sort.SliceStable(entries, func(i, j int) bool { return entries[i].ts.Before(entries[j].ts) })

	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()

	fmt.Fprintf(w, "# session report generated %s\n", time.Now().UTC().Format(time.RFC3339))
	for _, e := range entries {
		fmt.Fprintln(w, e.text)
	}

	fmt.Printf("wrote %d total entries to %s\n", len(entries), outPath)
	return nil
}

// --- sysmon_events.csv -> process/DNS/network entries -----------------

func sysmonEntries(path string) ([]reportEntry, map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 1 {
		return nil, nil, err
	}
	header := rows[0]
	col := func(name string) int {
		for i, h := range header {
			if h == name {
				return i
			}
		}
		return -1
	}
	idx := map[string]int{
		"EventType": col("EventType"), "TimeCreated": col("TimeCreated"), "PID": col("PID"),
		"Image": col("Image"), "CommandLine": col("CommandLine"),
		"Protocol": col("Protocol"), "SourceIp": col("SourceIp"), "SourcePort": col("SourcePort"),
		"DestinationIp": col("DestinationIp"), "DestinationPort": col("DestinationPort"), "Initiated": col("Initiated"),
		"QueryName": col("QueryName"), "QueryResults": col("QueryResults"),
	}

	var entries []reportEntry
	sourcePortToPID := map[string]string{}

	for _, row := range rows[1:] {
		get := func(field string) string {
			i := idx[field]
			if i < 0 || i >= len(row) {
				return ""
			}
			return row[i]
		}
		eventType := get("EventType")
		pid := get("PID")
		ts, err := time.Parse(time.RFC3339Nano, get("TimeCreated"))
		if err != nil {
			continue
		}

		switch eventType {
		case "ProcessCreate":
			cmd := get("CommandLine")
			if cmd == "" {
				cmd = get("Image")
			}
			entries = append(entries, reportEntry{ts, fmt.Sprintf("%s:%s:process started with command %s",
				formatTS(ts), pid, cmd)})

		case "DnsQuery":
			name := get("QueryName")
			if name == "" {
				continue
			}
			entries = append(entries, reportEntry{ts, fmt.Sprintf("%s:%s:DNS lookup to %q",
				formatTS(ts), pid, name)})
			for _, ip := range parseDNSResults(get("QueryResults")) {
				entries = append(entries, reportEntry{ts, fmt.Sprintf("%s:%s:DNS %s resolved to IP address %s",
					formatTS(ts), pid, name, ip)})
			}

		case "NetworkConnect":
			if get("Initiated") != "true" {
				continue
			}
			srcPort := get("SourcePort")
			if pid != "" && srcPort != "" {
				sourcePortToPID[srcPort] = pid
			}
			name := filepath.Base(get("Image"))
			entries = append(entries, reportEntry{ts, fmt.Sprintf("%s:%s:process %q connected to %s/%s with protocol %s",
				formatTS(ts), pid, name, get("DestinationIp"), get("DestinationPort"), get("Protocol"))})
		}
	}
	return entries, sourcePortToPID, nil
}

func parseDNSResults(raw string) []string {
	var ips []string
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "::ffff:")
		if part == "" {
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			ips = append(ips, part)
		}
	}
	return ips
}

// --- keylog.log ---------------------------------------------------------

// keylogSecret holds one "<label> <client_random> <secret>" line.
type keylogSecret struct {
	label, secret string
}

func loadKeylog(path string) (map[string][]keylogSecret, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := map[string][]keylogSecret{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 {
			continue
		}
		label, clientRandom, secret := fields[0], fields[1], fields[2]
		result[clientRandom] = append(result[clientRandom], keylogSecret{label, secret})
	}
	return result, nil
}

// --- TLS handshake extraction via tshark --------------------------------

var cipherNames = map[string]string{
	"0x1301": "TLS_AES_128_GCM_SHA256", "0x1302": "TLS_AES_256_GCM_SHA384", "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
	"0xc02b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "0xc02c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	"0xc02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "0xc030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"0xcca8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "0xcca9": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}
var groupNames = map[string]string{
	"23": "secp256r1", "24": "secp384r1", "25": "secp521r1", "29": "x25519", "30": "x448",
	"4588": "X25519Kyber768Draft00", "25497": "X25519MLKEM768",
}

func cipherName(hex string) string {
	if n, ok := cipherNames[strings.ToLower(hex)]; ok {
		return n
	}
	return hex
}
func groupName(csv string) string {
	var names []string
	for _, g := range strings.Split(csv, ",") {
		if n, ok := groupNames[g]; ok {
			names = append(names, n)
		} else if g != "" {
			names = append(names, g)
		}
	}
	return strings.Join(names, "+")
}
func tlsVersionName(cipherHex, legacyVersionHex string) string {
	switch strings.ToLower(cipherHex) {
	case "0x1301", "0x1302", "0x1303":
		return "TLS 1.3"
	}
	switch strings.ToLower(legacyVersionHex) {
	case "0x0303":
		return "TLS 1.2"
	case "0x0302":
		return "TLS 1.1"
	case "0x0301":
		return "TLS 1.0"
	}
	return legacyVersionHex
}

type handshakeStream struct {
	clientPort, serverIP, serverPort string
	clientRandom, cipherHex, groupHex, legacyVersion string
	tsServer time.Time
	haveServer bool
}

func tlsHandshakeEntries(tsharkPath, pcapPath, keylogPath string, sourcePortToPID map[string]string, secrets map[string][]keylogSecret) ([]reportEntry, error) {
	fields := []string{"frame.time_epoch", "tcp.stream", "tcp.srcport", "tcp.dstport", "ip.dst",
		"tls.handshake.type", "tls.handshake.version", "tls.handshake.random",
		"tls.handshake.ciphersuite", "tls.handshake.extensions_key_share_group"}
	rows, err := runTsharkFields(tsharkPath, pcapPath, keylogPath,
		"tls.handshake.type==1 || tls.handshake.type==2", fields)
	if err != nil {
		return nil, err
	}

	streams := map[string]*handshakeStream{}
	for _, row := range rows {
		if len(row) < 10 {
			continue
		}
		ts := parseEpoch(row[0])
		stream := row[1]
		srcport, dstport, dstip := row[2], row[3], row[4]
		htype := row[5]

		s := streams[stream]
		if s == nil {
			s = &handshakeStream{}
			streams[stream] = s
		}
		if strings.Contains(htype, "1") && !strings.Contains(htype, "2") {
			// ClientHello
			s.clientPort, s.serverPort, s.serverIP = srcport, dstport, dstip
			s.clientRandom = row[7]
			s.legacyVersion = row[6]
		}
		if strings.Contains(htype, "2") {
			// ServerHello (+ EncryptedExtensions, coalesced)
			s.haveServer = true
			s.tsServer = ts
			if row[8] != "" {
				s.cipherHex = row[8]
			}
			if row[9] != "" {
				s.groupHex = row[9]
			}
		}
	}

	var entries []reportEntry
	for _, s := range streams {
		if !s.haveServer || s.clientRandom == "" {
			continue
		}
		pid := sourcePortToPID[s.clientPort]
		if pid == "" {
			// Not one of the monitored agents' connections (e.g. other
			// background HTTPS traffic sharing port 443 during the
			// session) — we hold no key log entry for it either way.
			continue
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "%s:%s:TLS handshake completed with %s:%s, version=%s, cipher_suite=%s, key_exchange_group=%s, client_random=%s",
			formatTS(s.tsServer), pid, s.serverIP, s.serverPort,
			tlsVersionName(s.cipherHex, s.legacyVersion), cipherName(s.cipherHex), groupName(s.groupHex), s.clientRandom)
		if secs, ok := secrets[s.clientRandom]; ok {
			sb.WriteString("\n    session keys exchanged (NSS keylog format):")
			for _, sec := range secs {
				fmt.Fprintf(&sb, "\n      %s: %s", sec.label, sec.secret)
			}
		} else if secrets == nil {
			sb.WriteString("\n    session keys exchanged (redacted; rerun with -show-key-material to include the raw secret values)")
		}
		entries = append(entries, reportEntry{s.tsServer, sb.String()})
	}
	return entries, nil
}

// --- HTTP request/response extraction via tshark ------------------------

func httpTrafficEntries(tsharkPath, pcapPath, keylogPath string, sourcePortToPID map[string]string) ([]reportEntry, error) {
	fields := []string{"frame.time_epoch", "tcp.srcport", "tcp.dstport",
		"http.request.method", "http.request.full_uri", "http.request.version", "http.request.line",
		"http.response.code", "http.response.phrase", "http.content_type", "http.response.line",
		"http.file_data", "http.request_in"}
	rows, err := runTsharkFields(tsharkPath, pcapPath, keylogPath, "http", fields)
	if err != nil {
		return nil, err
	}

	var entries []reportEntry
	for _, row := range rows {
		if len(row) < 13 {
			continue
		}
		ts := parseEpoch(row[0])
		srcport, dstport := row[1], row[2]
		method, uri, version, reqLines := row[3], row[4], row[5], row[6]
		code, phrase, contentType, respLines := row[7], row[8], row[9], row[10]
		body := hexDecode(row[11])

		clientPort := srcport
		if dstport != "443" {
			clientPort = dstport
		}
		pid := sourcePortToPID[clientPort]
		if pid == "" {
			continue
		}

		var sb strings.Builder
		if method != "" {
			fmt.Fprintf(&sb, "%s:%s:[SENT] HTTPS request %s %s %s", formatTS(ts), pid, method, uri, version)
			if headers := splitAggregated(reqLines); len(headers) > 0 {
				sb.WriteString("\n    Headers:")
				for _, h := range headers {
					fmt.Fprintf(&sb, "\n      %s", h)
				}
			}
			if len(body) > 0 {
				fmt.Fprintf(&sb, "\n    Body:\n      %s", indent(prettyBody(contentType, body), "      "))
			}
		} else if code != "" {
			fmt.Fprintf(&sb, "%s:%s:[RECEIVED] HTTPS response %s %s for %s", formatTS(ts), pid, code, phrase, uri)
			if headers := splitAggregated(respLines); len(headers) > 0 {
				sb.WriteString("\n    Headers:")
				for _, h := range headers {
					fmt.Fprintf(&sb, "\n      %s", h)
				}
			}
			fmt.Fprintf(&sb, "\n    Body (%s):\n      %s", contentType, indent(prettyBody(contentType, body), "      "))
		} else {
			continue
		}
		entries = append(entries, reportEntry{ts, sb.String()})
	}
	return entries, nil
}

// --- HTTP/2 request/response extraction via tshark -----------------------
//
// Modern APIs commonly negotiate h2 over ALPN, which the http.* fields above
// don't cover — HTTP/2 has its own dissector with its own field names, and
// pseudo-headers (:method, :path, :authority, :scheme, :status) stand in
// for the HTTP/1.1 request/status line.

type headerPair struct{ name, value string }

func headerVal(pairs []headerPair, name string) string {
	for _, p := range pairs {
		if p.name == name {
			return p.value
		}
	}
	return ""
}

func nonPseudoHeaders(pairs []headerPair) []headerPair {
	var out []headerPair
	for _, p := range pairs {
		if !strings.HasPrefix(p.name, ":") {
			out = append(out, p)
		}
	}
	return out
}

type h2StreamKey struct{ tcpStream, streamID string }

type h2Exchange struct {
	clientPort              string
	reqHeaders, respHeaders []headerPair
	reqTS, respTS           time.Time
	reqBody, respBody       []byte
}

func http2TrafficEntries(tsharkPath, pcapPath, keylogPath string, sourcePortToPID map[string]string) ([]reportEntry, error) {
	headerFields := []string{"frame.time_epoch", "tcp.stream", "tcp.srcport", "tcp.dstport",
		"http2.streamid", "http2.header.name", "http2.header.value"}
	headerRows, err := runTsharkFields(tsharkPath, pcapPath, keylogPath, "http2.type==1", headerFields)
	if err != nil {
		return nil, err
	}
	dataFields := []string{"frame.time_epoch", "tcp.stream", "tcp.srcport", "tcp.dstport",
		"http2.streamid", "http2.data.data"}
	dataRows, err := runTsharkFields(tsharkPath, pcapPath, keylogPath, "http2.type==0", dataFields)
	if err != nil {
		return nil, err
	}

	exchanges := map[h2StreamKey]*h2Exchange{}
	get := func(stream, id string) *h2Exchange {
		k := h2StreamKey{stream, id}
		e := exchanges[k]
		if e == nil {
			e = &h2Exchange{}
			exchanges[k] = e
		}
		return e
	}

	for _, row := range headerRows {
		if len(row) < 7 {
			continue
		}
		ts := parseEpoch(row[0])
		stream, srcport, dstport, streamID := row[1], row[2], row[3], row[4]
		names := strings.Split(row[5], aggregatorChar)
		values := strings.Split(row[6], aggregatorChar)
		var pairs []headerPair
		for i := range names {
			if i < len(values) {
				pairs = append(pairs, headerPair{names[i], values[i]})
			}
		}
		e := get(stream, streamID)
		if dstport == "443" {
			e.clientPort = srcport
			e.reqHeaders = pairs
			e.reqTS = ts
		} else {
			if e.clientPort == "" {
				e.clientPort = dstport
			}
			e.respHeaders = pairs
			e.respTS = ts
		}
	}
	for _, row := range dataRows {
		if len(row) < 6 {
			continue
		}
		stream, _, dstport, streamID := row[1], row[2], row[3], row[4]
		body := hexDecode(row[5])
		e := get(stream, streamID)
		if dstport == "443" {
			e.reqBody = append(e.reqBody, body...)
		} else {
			e.respBody = append(e.respBody, body...)
		}
	}

	var entries []reportEntry
	for _, e := range exchanges {
		pid := sourcePortToPID[e.clientPort]
		if pid == "" {
			continue
		}

		uri := fmt.Sprintf("%s://%s%s", headerVal(e.reqHeaders, ":scheme"), headerVal(e.reqHeaders, ":authority"), headerVal(e.reqHeaders, ":path"))

		if len(e.reqHeaders) > 0 {
			var sb strings.Builder
			fmt.Fprintf(&sb, "%s:%s:[SENT] HTTPS request %s %s HTTP/2", formatTS(e.reqTS), pid, headerVal(e.reqHeaders, ":method"), uri)
			if hdrs := nonPseudoHeaders(e.reqHeaders); len(hdrs) > 0 {
				sb.WriteString("\n    Headers:")
				for _, h := range hdrs {
					fmt.Fprintf(&sb, "\n      %s: %s", h.name, h.value)
				}
			}
			if len(e.reqBody) > 0 {
				fmt.Fprintf(&sb, "\n    Body:\n      %s", indent(prettyBody(headerVal(e.reqHeaders, "content-type"), e.reqBody), "      "))
			}
			entries = append(entries, reportEntry{e.reqTS, sb.String()})
		}
		if len(e.respHeaders) > 0 {
			contentType := headerVal(e.respHeaders, "content-type")
			var sb strings.Builder
			fmt.Fprintf(&sb, "%s:%s:[RECEIVED] HTTPS response %s for %s", formatTS(e.respTS), pid, headerVal(e.respHeaders, ":status"), uri)
			if hdrs := nonPseudoHeaders(e.respHeaders); len(hdrs) > 0 {
				sb.WriteString("\n    Headers:")
				for _, h := range hdrs {
					fmt.Fprintf(&sb, "\n      %s: %s", h.name, h.value)
				}
			}
			fmt.Fprintf(&sb, "\n    Body (%s):\n      %s", contentType, indent(prettyBody(contentType, e.respBody), "      "))
			entries = append(entries, reportEntry{e.respTS, sb.String()})
		}
	}
	return entries, nil
}

func prettyBody(contentType string, data []byte) string {
	if len(data) == 0 {
		return "(empty body)"
	}
	if strings.Contains(strings.ToLower(contentType), "json") || json.Valid(data) {
		var buf bytes.Buffer
		if err := json.Indent(&buf, data, "", "  "); err == nil {
			return buf.String()
		}
	}
	if utf8.Valid(data) {
		return string(data)
	}
	return fmt.Sprintf("(binary body, %d bytes)", len(data))
}

func indent(s, prefix string) string {
	return strings.ReplaceAll(s, "\n", "\n"+prefix)
}

// --- tshark helpers -------------------------------------------------------

const aggregatorChar = "\x1f"

func runTsharkFields(tsharkPath, pcapPath, keylogPath, displayFilter string, fields []string) ([][]string, error) {
	args := []string{"-r", pcapPath, "-o", "tls.keylog_file:" + keylogPath,
		"-Y", displayFilter, "-T", "fields",
		"-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=" + aggregatorChar}
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	out, err := exec.Command(tsharkPath, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("running tshark: %w", err)
	}

	var rows [][]string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		rows = append(rows, strings.Split(line, "\t"))
	}
	return rows, nil
}

func splitAggregated(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, aggregatorChar) {
		// tshark's fields output represents the line ending as the literal
		// two-character escapes \r\n, not actual CR/LF bytes.
		part = strings.TrimSuffix(part, `\r\n`)
		part = strings.TrimRight(part, "\r\n")
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// hexDecode decodes tshark's fields-mode byte-array output, which is a
// contiguous hex string (no colon separators, unlike -T json/pdml mode).
func hexDecode(s string) []byte {
	s = strings.ReplaceAll(s, ":", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func parseEpoch(s string) time.Time {
	sec, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return time.Time{}
	}
	whole := int64(sec)
	frac := sec - float64(whole)
	return time.Unix(whole, int64(frac*1e9)).UTC()
}

func formatTS(ts time.Time) string {
	return ts.UTC().Format("2006-01-02T15:04:05.000Z")
}
