package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/safetext"
	"github.com/crypt0rr/SpeeDNS/internal/transport"
)

// hostileSAN is the kind of string a certificate can carry into a TLS error:
// ESC passes the IA5String check that x509 applies to subject alternative
// names, so a hostile or intercepted endpoint can hide a line of terminal
// output behind one. The right-to-left override inside it would not pass that
// check; it stands in for the same kind of text arriving through any other
// endpoint diagnostic, such as a QUIC close reason.
const (
	hostileSAN        = "\x1b[2K\rspoofed\u202e.example"
	hostileSANEscaped = `\x1b[2K\x0dspoofed\u{202e}.example`
	// hostileServerName is a configured TLS identity. catalog.Validate only
	// checks that a server name is not blank, so a --resolver-file entry can
	// carry an isolate and a zero-width space into every report format.
	hostileServerName        = "resolver.example\x1b[2K\u2066\u200b"
	hostileServerNameEscaped = `resolver.example\x1b[2K\u{2066}\u{200b}`
	// hostileDoHStatus is the error a DoH endpoint speaking HTTP/1.1 produces
	// with a reason phrase of its choosing: net/http keeps the phrase as sent,
	// and the transport quotes it. During a --dnssec run it becomes a probe
	// error and, through the bogus probe, the assessment's reason.
	hostileDoHStatus        = "DoH HTTP status 418 \x1b[2J\x1b[H\u202eteapot\ufeff"
	hostileDoHStatusEscaped = `DoH HTTP status 418 \x1b[2J\x1b[H\u{202e}teapot\u{feff}`
	hostileBootstrap        = "192.0.2.10\u200d"
	hostileBootstrapEscaped = `192.0.2.10\u{200d}`
	// hostileDialAddress is the candidate above as the session dialled it.
	hostileDialAddress        = hostileBootstrap + ":853"
	hostileDialAddressEscaped = hostileBootstrapEscaped + ":853"
	// hostileDoHURL is a configured DoH endpoint. catalog.Validate parses it
	// with net/url, which rejects ASCII control bytes but accepts an 8-bit
	// CSI (U+009B) and a right-to-left override in the path, so a
	// --resolver-file entry carries both into endpoint_url.
	hostileDoHURL        = "https://doh.example/dns-query\u009b2J\u202e"
	hostileDoHURLEscaped = `https://doh.example/dns-query\x9b2J\u{202e}`
	// hostileTLSVersion and hostileHTTPProtocol stand in for the negotiated
	// versions a session describes. crypto/tls cannot produce such text
	// today, but the fields are escaped like every other endpoint string, so
	// no sink depends on where a value came from.
	hostileTLSVersion          = "TLS 1.3\x1b[2K"
	hostileTLSVersionEscaped   = `TLS 1.3\x1b[2K`
	hostileHTTPProtocol        = "h2\u202e"
	hostileHTTPProtocolEscaped = `h2\u{202e}`
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
		Spec: catalog.TransportSpec{
			Port: 853, ServerName: hostileServerName,
			BootstrapAddresses: []string{hostileBootstrap},
		},
	}
	result := benchmark.TargetResult{
		Target:      target,
		DialAddress: hostileDialAddress,
		Connection: transport.ConnectionInfo{
			RemoteAddress: hostileDialAddress, TLSVersion: hostileTLSVersion, HTTPProtocol: hostileHTTPProtocol,
		},
		OpenError: "x509: certificate is valid for " + hostileSAN + ", not resolver.example",
		Stats:     benchmark.Statistics{Total: 1, Failures: 1},
		DNSSEC: &benchmark.DNSSECAssessment{
			Verdict: benchmark.DNSSECInconclusive,
			Reason:  "the bogus probe did not complete: " + hostileDoHStatus,
			Probes: []benchmark.DNSSECProbe{
				{
					Role: benchmark.DNSSECRoleSigned, Name: benchmark.DNSSECProbeSignedName, QType: 1,
					Error: "x509: certificate is valid for " + hostileSAN + ", not resolver.example",
				},
				{
					Role: benchmark.DNSSECRoleBogus, Name: benchmark.DNSSECProbeBogusName, QType: 1,
					Error: hostileDoHStatus,
				},
			},
		},
	}
	doh := benchmark.TargetResult{
		Target: catalog.Target{
			Resolver: target.Resolver,
			Protocol: catalog.DoH,
			Address:  "192.0.2.20",
			Spec:     catalog.TransportSpec{Port: 443, URL: hostileDoHURL},
		},
		DialAddress: "192.0.2.20:443",
		Stats:       benchmark.Statistics{Total: 1, Failures: 1},
	}
	return benchmark.Report{
		Seed: 1, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1},
		Targets: []benchmark.TargetResult{result, doh},
		Warnings: []benchmark.Warning{
			benchmark.TargetWarning(result.Target, "could not open a session: "+result.OpenError),
		},
	}
}

// rawUntrustedRune returns the first rune in text that must never reach a
// consumer unescaped - a C0, DEL or C1 control other than the newline that
// separates lines of output, or a format character such as a bidirectional
// override or a zero-width space - and false when there is none.
//
// Only the format characters safetext escapes count. Others, such as the soft
// hyphen that terminals draw as a hyphen, stay as written on purpose, so a
// fixture carrying one must not read as an escaping failure here.
func rawUntrustedRune(text string) (rune, bool) {
	for _, value := range text {
		if value == '\n' {
			continue
		}
		if unicode.IsControl(value) || (unicode.Is(unicode.Cf, value) && safetext.Escape(string(value)) != string(value)) {
			return value, true
		}
	}
	return 0, false
}

func assertNoRawUntrustedRune(t *testing.T, label, text string) {
	t.Helper()
	if value, found := rawUntrustedRune(text); found {
		t.Fatalf("%s kept a raw U+%04X: %q", label, value, text)
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
	run.Warnings = append(run.Warnings, benchmark.RunWarning("global diagnostic \x1b[2K\rhidden"))
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
		hostileDoHURLEscaped,
		hostileDialAddressEscaped,
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
	if len(rows) != len(run.Targets)+1 {
		t.Fatalf("CSV rows = %d, want %d", len(rows), len(run.Targets)+1)
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
	if got, want := values["tls_server_name"], hostileServerNameEscaped; got != want {
		t.Fatalf("CSV tls_server_name = %q, want %q", got, want)
	}
}

// TestRedactionUsesStructuredTargetIdentity covers redaction of a local
// resolver's identity. A warning carries its target rather than a rendered
// label, so redaction reads the attribution directly instead of matching a
// rebuilt - and possibly escaped - label against the message text. A control
// character in the resolver name therefore cannot defeat it.
func TestRedactionUsesStructuredTargetIdentity(t *testing.T) {
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
		Warnings: []benchmark.Warning{
			benchmark.TargetWarning(systemTarget, "could not open a session: timeout"),
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

// TestDNSSECSectionEscapesEndpointText covers the opt-in DNSSEC section. Both
// probe errors and the reason quote endpoint-chosen text, and the section is
// printed in the compact table as well as with --details, after the
// comparison tables - where a clear-screen sequence could replace everything
// above it with a forged verdict.
func TestDNSSECSectionEscapesEndpointText(t *testing.T) {
	for _, options := range []TableOptions{{}, {Details: true}, {Color: true}} {
		var output bytes.Buffer
		if err := WriteTableWithOptions(&output, hostileReport(), options); err != nil {
			t.Fatal(err)
		}
		text := output.String()
		// The status colours are the only escape sequences the table writes
		// itself, so they are the only ones allowed through.
		visible := strings.NewReplacer(ansiGreen, "", ansiYellow, "", ansiRed, "", ansiReset, "").Replace(text)
		assertNoRawUntrustedRune(t, "DNSSEC table", visible)
		for _, want := range []string{
			"error: x509: certificate is valid for " + hostileSANEscaped,
			"error: " + hostileDoHStatusEscaped,
			"the bogus probe did not complete: " + hostileDoHStatusEscaped,
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("table (%+v) is missing %q:\n%s", options, want, text)
			}
		}
	}
	// The cells hold the escaped text exactly once: the table reads the
	// assessment redactDNSSEC already escaped and does not escape it again.
	rows := dnssecRows(hostileReport(), TableOptions{})
	if got, want := rows[0][5], "error: "+hostileDoHStatusEscaped; got != want {
		t.Fatalf("bogus probe cell = %q, want %q", got, want)
	}
	if got, want := rows[0][6], "the bogus probe did not complete: "+hostileDoHStatusEscaped; got != want {
		t.Fatalf("basis cell = %q, want %q", got, want)
	}
}

// decodedJSONStrings returns every string in a decoded JSON document, object
// keys included, so a test can check the values a consumer such as jq -r
// would print rather than the encoded bytes, where encoding/json has already
// turned a raw ESC into \u001b.
func decodedJSONStrings(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		var values []string
		for _, element := range typed {
			values = append(values, decodedJSONStrings(element)...)
		}
		return values
	case map[string]any:
		var values []string
		for key, element := range typed {
			values = append(values, key)
			values = append(values, decodedJSONStrings(element)...)
		}
		return values
	default:
		return nil
	}
}

func decodeJSONReport(t *testing.T, run benchmark.Report, raw bool, options JSONOptions) (map[string]any, JSONReport) {
	t.Helper()
	var output bytes.Buffer
	if err := WriteJSONWithOptions(&output, run, raw, options); err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(output.Bytes(), &generic); err != nil {
		t.Fatal(err)
	}
	var typed JSONReport
	if err := json.Unmarshal(output.Bytes(), &typed); err != nil {
		t.Fatal(err)
	}
	return generic, typed
}

// TestJSONEscapesEndpointText covers the JSON report after decoding. The
// session error, the endpoint metadata and the DNSSEC text used to come back
// with a raw ESC from jq -r while the name and owner beside them were escaped.
func TestJSONEscapesEndpointText(t *testing.T) {
	run := hostileReport()
	generic, document := decodeJSONReport(t, run, true, JSONOptions{})
	for _, value := range decodedJSONStrings(generic) {
		assertNoRawUntrustedRune(t, "decoded JSON", value)
	}
	result, doh := document.Results[0], document.Results[1]
	for _, check := range []struct{ field, got, want string }{
		{"open_error", result.OpenError, "x509: certificate is valid for " + hostileSANEscaped + ", not resolver.example"},
		{"target.tls_server_name", result.Target.TLSServerName, hostileServerNameEscaped},
		{"target.bootstrap_addresses[0]", result.Target.BootstrapAddresses[0], hostileBootstrapEscaped},
		{"target.dial_address", result.Target.DialAddress, hostileDialAddressEscaped},
		{"target.remote_address", result.Target.RemoteAddress, hostileDialAddressEscaped},
		{"target.tls_version", result.Target.TLSVersion, hostileTLSVersionEscaped},
		{"target.http_protocol", result.Target.HTTPProtocol, hostileHTTPProtocolEscaped},
		{"doh target.endpoint_url", doh.Target.EndpointURL, hostileDoHURLEscaped},
		{"dnssec.reason", result.DNSSEC.Reason, "the bogus probe did not complete: " + hostileDoHStatusEscaped},
		{"dnssec.probes[0].error", result.DNSSEC.Probes[0].Error, "x509: certificate is valid for " + hostileSANEscaped + ", not resolver.example"},
		{"dnssec.probes[1].error", result.DNSSEC.Probes[1].Error, hostileDoHStatusEscaped},
	} {
		if check.got != check.want {
			t.Fatalf("%s = %q, want %q", check.field, check.got, check.want)
		}
	}
	// One rendered value: the table's basis cell is the JSON reason.
	if rows := dnssecRows(hostileReport(), TableOptions{}); rows[0][6] != result.DNSSEC.Reason {
		t.Fatalf("table basis %q differs from JSON reason %q", rows[0][6], result.DNSSEC.Reason)
	}
	// The assessment is shared by pointer, so escaping it in place would
	// rewrite the measured result. Only the rendering is escaped.
	if !strings.Contains(run.Targets[0].DNSSEC.Reason, "\x1b") || !strings.Contains(run.Targets[0].DNSSEC.Probes[1].Error, "\x1b") {
		t.Fatalf("rendering the report rewrote the measured assessment: %#v", run.Targets[0].DNSSEC)
	}
}

// TestCSVCarriesTheSameEscapedValuesAsJSON checks the two machine formats
// agree on every endpoint string they share, and that no CSV cell keeps a raw
// control or format character.
func TestCSVCarriesTheSameEscapedValuesAsJSON(t *testing.T) {
	var output bytes.Buffer
	if err := WriteCSV(&output, hostileReport()); err != nil {
		t.Fatal(err)
	}
	assertNoRawUntrustedRune(t, "CSV", output.String())
	rows, err := csv.NewReader(strings.NewReader(output.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	_, document := decodeJSONReport(t, hostileReport(), false, JSONOptions{})
	if len(rows) != len(document.Results)+1 {
		t.Fatalf("CSV rows = %d, want one per JSON result plus the header", len(rows))
	}
	for index, result := range document.Results {
		values := make(map[string]string, len(rows[0]))
		for column, name := range rows[0] {
			values[name] = rows[index+1][column]
		}
		for _, check := range []struct{ column, json string }{
			{"open_error", result.OpenError},
			{"endpoint_url", result.Target.EndpointURL},
			{"tls_server_name", result.Target.TLSServerName},
			{"bootstrap_addresses", strings.Join(result.Target.BootstrapAddresses, ";")},
			{"dial_address", result.Target.DialAddress},
			{"remote_address", result.Target.RemoteAddress},
			{"tls_version", result.Target.TLSVersion},
			{"http_protocol", result.Target.HTTPProtocol},
			{"owner", result.Target.Owner},
		} {
			if values[check.column] != check.json {
				t.Fatalf("CSV %s for %s = %q, JSON has %q", check.column, result.Target.ID, values[check.column], check.json)
			}
		}
	}
}

// TestCSVGuardsAValueLedByAnInvisibleCharacter covers the second escape form.
// A leading right-to-left override or zero-width space renders as \u{...},
// and the formula character behind it must not reach a spreadsheet unguarded.
func TestCSVGuardsAValueLedByAnInvisibleCharacter(t *testing.T) {
	for _, testCase := range []struct{ value, want string }{
		{"\u202e=cmd|'/C calc'!A1", `'\u{202e}=cmd|'/C calc'!A1`},
		{"\u200b+1", `'\u{200b}+1`},
		{"\ufeff@SUM(A1)", `'\u{feff}@SUM(A1)`},
		{"resolver\u200b", `resolver\u{200b}`},
	} {
		if got := csvCell(testCase.value); got != testCase.want {
			t.Fatalf("csvCell(%q) = %q, want %q", testCase.value, got, testCase.want)
		}
	}
}

// TestJSONTargetReferencesMatchTheEscapedTargetID covers the sections that
// refer to a target by ID. results[].target.id is escaped, so a reference
// written raw would no longer join with it, and a consumer printing it would
// get the raw control characters the result itself hides.
func TestJSONTargetReferencesMatchTheEscapedTargetID(t *testing.T) {
	hostile := reportTarget("1", catalog.UDP, 2, true)
	hostile.Target.Resolver.ID = "evil\x1b[2K\u202e"
	hostile.Target.Resolver.Policy = "unfiltered\u200b"
	reference := reportTarget("2", catalog.UDP, 2, false)
	reference.Target.Resolver.Policy = hostile.Target.Resolver.Policy
	run := benchmark.Report{
		Seed: 1, SampleSize: 1, Queries: 2, QueryTypes: []uint16{1},
		Targets: []benchmark.TargetResult{hostile, reference},
		Rankings: []benchmark.Ranking{
			{Protocol: catalog.UDP, TargetID: hostile.Target.ID(), Rank: 1},
			{Protocol: catalog.UDP, TargetID: reference.Target.ID(), Rank: 2},
		},
		PairedEffects: []benchmark.PairedEffect{{
			Protocol: catalog.UDP, Policy: hostile.Target.Resolver.Policy,
			TargetID: hostile.Target.ID(), ReferenceTargetID: reference.Target.ID(), Samples: 2,
		}},
		Divergence: []benchmark.DivergenceDetail{{
			Name: "example.com", QType: 1, Policy: hostile.Target.Resolver.Policy, Compared: 2, Baseline: "answer",
			Classes:  map[string]int{"answer": 1, "nxdomain": 1},
			Excluded: []benchmark.DivergenceExclusion{{TargetID: hostile.Target.ID(), ResponseClass: "nxdomain", Treatment: "latency-excluded"}},
		}},
	}
	generic, document := decodeJSONReport(t, run, false, JSONOptions{ProfileView: true})
	for _, value := range decodedJSONStrings(generic) {
		assertNoRawUntrustedRune(t, "decoded JSON", value)
	}
	id := document.Results[0].Target.ID
	if want := `evil\x1b[2K\u{202e}@192.0.2.1/udp`; id != want {
		t.Fatalf("results[0].target.id = %q, want %q", id, want)
	}
	var profile JSONProfileComparison
	for _, comparison := range document.ProfileComparisons {
		if comparison.ID == `evil\x1b[2K\u{202e}` {
			profile = comparison
		}
	}
	if len(profile.Transports) == 0 {
		t.Fatalf("no profile comparison carries the escaped resolver ID: %+v", document.ProfileComparisons)
	}
	for _, check := range []struct{ field, got string }{
		{"rankings[0].target_id", document.Rankings[0].TargetID},
		{"paired_effects[0].target_id", document.PairedEffects[0].TargetID},
		{"divergence[0].excluded[0].target_id", document.Divergence[0].Excluded[0].TargetID},
		{"profile_comparisons[].transports[0].target_id", profile.Transports[0].TargetID},
	} {
		if check.got != id {
			t.Fatalf("%s = %q, want the escaped result ID %q", check.field, check.got, id)
		}
	}
	if got, want := document.PairedEffects[0].Policy, `unfiltered\u{200b}`; got != want {
		t.Fatalf("paired_effects[0].policy = %q, want %q", got, want)
	}
	if got, want := document.Divergence[0].Policy, `unfiltered\u{200b}`; got != want {
		t.Fatalf("divergence[0].policy = %q, want %q", got, want)
	}
}

// TestJSONEscapesProvenanceInterfaceNames covers the run provenance. Interface
// names come from the operating system, which allows control characters in
// them, so they are escaped in JSON like every other string SpeeDNS did not
// produce itself.
func TestJSONEscapesProvenanceInterfaceNames(t *testing.T) {
	run := benchmark.Report{
		StartedAt: time.Unix(10, 0), FinishedAt: time.Unix(11, 0),
		Provenance: &benchmark.RunProvenance{
			Version: "v0.0.0", OS: "linux", Architecture: "amd64",
			Interfaces: []string{"eth\x1b[2J0", "wg\u202e0"},
			Protocols:  []catalog.Protocol{catalog.UDP}, CorpusEntries: 1,
			Timeout: time.Second, Concurrency: 1,
		},
	}
	generic, _ := decodeJSONReport(t, run, false, JSONOptions{})
	for _, value := range decodedJSONStrings(generic) {
		assertNoRawUntrustedRune(t, "JSON", value)
	}
	interfaces := generic["run"].(map[string]any)["provenance"].(map[string]any)["interfaces"].([]any)
	if interfaces[0] != `eth\x1b[2J0` || interfaces[1] != `wg\u{202e}0` {
		t.Fatalf("interfaces = %q, want escaped names", interfaces)
	}
}
