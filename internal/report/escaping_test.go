package report

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

// hostileSAN is the kind of string a certificate can carry into a TLS error:
// ESC passes the IA5String check that x509 applies to subject alternative
// names, so a hostile or intercepted endpoint can hide a line of terminal
// output behind one.
const (
	hostileSAN        = "\x1b[2K\rspoofed.example"
	hostileSANEscaped = `\x1b[2K\x0dspoofed.example`
)

func hostileReport() benchmark.Report {
	target := catalog.Target{
		Resolver: catalog.ResolverProfile{
			ID:   "hostile",
			Name: "Hostile\x1b[2K resolver",
			// A --resolver-file owner survives catalog.Validate with its
			// control characters intact; only surrounding space is trimmed.
			Owner:  "Owner\x1b[2K\rhidden",
			Policy: "unfiltered\x1b[2K",
		},
		Protocol: catalog.DoT,
		Address:  "192.0.2.10",
		Spec:     catalog.TransportSpec{Port: 853, ServerName: "resolver.example\x1b[2K"},
	}
	result := benchmark.TargetResult{
		Target:      target,
		DialAddress: "192.0.2.10:853",
		OpenError:   "x509: certificate is valid for " + hostileSAN + ", not resolver.example",
		Stats:       benchmark.Statistics{Total: 1, Failures: 1},
	}
	return benchmark.Report{
		Seed: 1, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1},
		Targets: []benchmark.TargetResult{result},
		Warnings: []string{
			"Hostile\x1b[2K resolver 192.0.2.10/dot could not open a session: " + result.OpenError,
		},
	}
}

func TestDetailsWarningsEscapeControlCharacters(t *testing.T) {
	var output bytes.Buffer
	if err := WriteTableWithOptions(&output, hostileReport(), TableOptions{Details: true}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if index := strings.IndexAny(text, "\x1b\r"); index >= 0 {
		t.Fatalf("--details output kept a control character at byte %d: %q", index, text)
	}
	if !strings.Contains(text, "could not open a session: x509: certificate is valid for "+hostileSANEscaped) {
		t.Fatalf("--details output did not render the escaped warning: %s", text)
	}
}

func TestCompactWarningsEscapeControlCharacters(t *testing.T) {
	run := hostileReport()
	run.Warnings = append(run.Warnings, "global diagnostic \x1b[2K\rhidden")
	var output bytes.Buffer
	if err := WriteTableWithOptions(&output, run, TableOptions{}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if index := strings.IndexAny(text, "\x1b\r"); index >= 0 {
		t.Fatalf("compact output kept a control character at byte %d: %q", index, text)
	}
	if !strings.Contains(text, `global diagnostic \x1b[2K\x0dhidden`) {
		t.Fatalf("compact output did not render the escaped warning: %s", text)
	}
}

func TestTableCellsEscapeControlCharactersFromConfiguredResolvers(t *testing.T) {
	var output bytes.Buffer
	if err := WriteTableWithOptions(&output, hostileReport(), TableOptions{Details: true}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{
		`Owner\x1b[2K\x0dhidden`,
		`Hostile\x1b[2K resolver`,
		`unfiltered\x1b[2K`,
		`resolver.example\x1b[2K`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("table output missing escaped cell %q: %s", expected, text)
		}
	}
}

func TestColoredTableKeepsStatusColorsWhileEscapingUntrustedText(t *testing.T) {
	if got := styledStatus("FAILED", true); got != ansiRed+"FAILED"+ansiReset {
		t.Fatalf("styledStatus lost its color codes: %q", got)
	}
	var output bytes.Buffer
	if err := WriteTableWithOptions(&output, hostileReport(), TableOptions{Details: true, Color: true}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, ansiRed+"FAILED"+ansiReset) {
		t.Fatalf("colored table lost the status color codes: %q", text)
	}
	if strings.Contains(text, "\x1b[2K") || strings.Contains(text, "\r") {
		t.Fatalf("colored table kept an untrusted control sequence: %q", text)
	}
}

func TestCSVEscapesControlCharactersBeforeTheFormulaGuard(t *testing.T) {
	run := hostileReport()
	run.Targets[0].Target.Resolver.Owner = "\x1b=cmd|'/C calc'!A1"
	var output bytes.Buffer
	if err := WriteCSV(&output, run); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(output.String(), "\x1b") {
		t.Fatalf("CSV output kept an escape character: %q", output.String())
	}
	reader := csv.NewReader(strings.NewReader(output.String()))
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("CSV rows = %d, want 2", len(rows))
	}
	values := make(map[string]string, len(rows[0]))
	for index, name := range rows[0] {
		values[name] = rows[1][index]
	}
	if got, want := values["owner"], `'\x1b=cmd|'/C calc'!A1`; got != want {
		t.Fatalf("CSV owner = %q, want %q", got, want)
	}
	if got, want := values["open_error"], "x509: certificate is valid for "+hostileSANEscaped+", not resolver.example"; got != want {
		t.Fatalf("CSV open_error = %q, want %q", got, want)
	}
	if got, want := values["tls_server_name"], `resolver.example\x1b[2K`; got != want {
		t.Fatalf("CSV tls_server_name = %q, want %q", got, want)
	}
}

func TestRedactionMatchesEscapedSystemResolverText(t *testing.T) {
	systemTarget := catalog.Target{
		Resolver: catalog.ResolverProfile{
			ID: "system-stub-127-0-0-53", Name: "System DNS stub (scope: corp\x1b[2K.example)",
			Owner: "local stub/forwarder", Policy: "local forwarding",
		},
		Protocol: catalog.UDP, Address: "127.0.0.53", Spec: catalog.TransportSpec{Port: 53},
	}
	system := benchmark.TargetResult{
		Target: systemTarget, DialAddress: "127.0.0.53:53",
		Stats: benchmark.Statistics{Total: 1, Failures: 1},
	}
	run := benchmark.Report{
		Seed: 7, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1},
		Targets: []benchmark.TargetResult{system},
		Warnings: []string{
			// The benchmark escapes the labels it builds, so redaction must
			// recognise the escaped spelling of a local resolver name.
			`System DNS stub (scope: corp\x1b[2K.example) 127.0.0.53/udp could not open a session: timeout`,
		},
	}
	var output bytes.Buffer
	if err := WriteTableWithOptions(&output, run, TableOptions{Details: true, RedactSystem: true}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Contains(text, "corp") || strings.Contains(text, "127.0.0.53") {
		t.Fatalf("redacted output leaked local resolver details: %s", text)
	}
	if !strings.Contains(text, redactedSystemName) {
		t.Fatalf("redacted output missing the redacted name: %s", text)
	}
}

// TestRawObservationTextIsEscaped covers the one report value that reaches a
// consumer straight from the measured endpoint. A DoH status line and a TLS
// diagnostic both quote endpoint-chosen text, and --raw puts them in the JSON
// report, so they need the same escaping as the target metadata beside them.
func TestRawObservationTextIsEscaped(t *testing.T) {
	result := reportTarget("1", catalog.UDP, 2, true)
	result.Observations = []benchmark.Observation{{
		Name: "example.com", QType: 1, LatencyMS: 2,
		Error:         "DoH HTTP status 418 \x1b[2Jteapot",
		ResponseClass: "answer\x1b[31m",
	}}
	result.Cold = []benchmark.ColdObservation{{
		Name: "example.com", QType: 1, Error: "dial \x1b[2Kfailed",
	}}
	run := benchmark.Report{
		StartedAt: time.Unix(0, 0), FinishedAt: time.Unix(1, 0),
		Targets: []benchmark.TargetResult{result},
	}
	var output bytes.Buffer
	if err := WriteJSON(&output, run, true); err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsRune(output.Bytes(), 0x1b) {
		t.Fatalf("raw JSON report contains an unescaped escape byte:\n%s", output.String())
	}
	for _, want := range []string{`DoH HTTP status 418 \\x1b[2Jteapot`, `answer\\x1b[31m`, `dial \\x1b[2Kfailed`} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("raw JSON report does not contain %q:\n%s", want, output.String())
		}
	}
}
