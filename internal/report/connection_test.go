package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/schematest"
	"github.com/crypt0rr/SpeeDNS/internal/transport"
	"github.com/crypt0rr/SpeeDNS/schema"
)

// connectionReport has a DoH target that reached an IPv6 peer over h2, a UDP
// target that recorded no connection, and a system resolver whose address
// must not survive --redact-system in any of the new fields.
func connectionReport() benchmark.Report {
	doh := reportTarget("4", catalog.DoH, 2, false)
	doh.DialAddress = "dns.example:443"
	doh.Connection = transport.ConnectionInfo{RemoteAddress: "[2001:db8::4]:443", TLSVersion: "TLS 1.3", HTTPProtocol: "h2"}
	plain := reportTarget("5", catalog.UDP, 2, false)
	system := reportTarget("system-stub", catalog.TCP, 0, false)
	system.Target.Address = "127.0.0.53"
	system.DialAddress = "127.0.0.53:53"
	system.Connection = transport.ConnectionInfo{RemoteAddress: "127.0.0.54:53"}
	system.Stats = benchmark.Statistics{Total: 1, Failures: 1}
	system.OpenError = "read tcp 127.0.0.54:53: i/o timeout"
	return benchmark.Report{
		Seed: 1, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1},
		Targets: []benchmark.TargetResult{doh, plain, system},
	}
}

// TestReportsCarryTheConnectionEachTargetMade pins #242 and #258 in the
// machine formats: remote_address, tls_version and http_protocol are new,
// optional JSON fields and three CSV columns appended after the last one,
// while dial_address keeps naming the configured candidate.
func TestReportsCarryTheConnectionEachTargetMade(t *testing.T) {
	for _, redact := range []bool{false, true} {
		var output bytes.Buffer
		if err := WriteJSONWithOptions(&output, connectionReport(), false, JSONOptions{RedactSystem: redact}); err != nil {
			t.Fatal(err)
		}
		if err := schematest.Validate(schema.ReportV1(), output.Bytes()); err != nil {
			t.Fatalf("redact=%v: %v", redact, err)
		}
		var decoded struct {
			Results []struct {
				Target map[string]any `json:"target"`
			} `json:"results"`
		}
		if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		doh, plain, system := decoded.Results[0].Target, decoded.Results[1].Target, decoded.Results[2].Target
		for field, want := range map[string]string{
			"dial_address": "dns.example:443", "remote_address": "[2001:db8::4]:443", "tls_version": "TLS 1.3", "http_protocol": "h2",
		} {
			if doh[field] != want {
				t.Fatalf("redact=%v: DoH %s = %v, want %q", redact, field, doh[field], want)
			}
		}
		for _, field := range []string{"remote_address", "tls_version", "http_protocol"} {
			if _, present := plain[field]; present {
				t.Fatalf("a target without a connection must omit %s: %v", field, plain)
			}
		}
		wantSystem := "127.0.0.54:53"
		if redact {
			wantSystem = redactedValue
			if strings.Contains(output.String(), "127.0.0.5") {
				t.Fatalf("redacted JSON leaked the system resolver's address:\n%s", output.String())
			}
		}
		if system["remote_address"] != wantSystem {
			t.Fatalf("redact=%v: system remote_address = %v, want %q", redact, system["remote_address"], wantSystem)
		}

		var csvOutput bytes.Buffer
		if err := WriteCSVWithOptions(&csvOutput, connectionReport(), CSVOptions{RedactSystem: redact}); err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(&csvOutput).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		header := rows[0]
		if got := strings.Join(header[len(header)-3:], ","); got != "remote_address,tls_version,http_protocol" {
			t.Fatalf("CSV must end with the connection columns, got %s", got)
		}
		tail := func(row []string) string { return strings.Join(row[len(row)-3:], ",") }
		if got := tail(rows[1]); got != "[2001:db8::4]:443,TLS 1.3,h2" {
			t.Fatalf("DoH CSV connection = %q", got)
		}
		if got := tail(rows[2]); got != ",," {
			t.Fatalf("UDP CSV connection = %q, want empty cells", got)
		}
		if got := tail(rows[3]); got != wantSystem+",," {
			t.Fatalf("redact=%v: system CSV connection = %q", redact, got)
		}
		if redact && strings.Contains(csvOutput.String(), "127.0.0.5") {
			t.Fatalf("redacted CSV leaked the system resolver's address:\n%s", csvOutput.String())
		}
	}
}
