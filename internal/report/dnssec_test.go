package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/schema"
)

func dnssecAssessment(verdict string) *benchmark.DNSSECAssessment {
	return &benchmark.DNSSECAssessment{
		Verdict: verdict,
		Reason:  "fixture reason",
		Probes: []benchmark.DNSSECProbe{
			{
				Role: benchmark.DNSSECRoleSigned, Name: benchmark.DNSSECProbeSignedName, QType: 1,
				Success: true, ResponseCode: "NOERROR", Answers: 1, AuthenticatedData: true, LatencyMS: 3,
			},
			{
				Role: benchmark.DNSSECRoleBogus, Name: benchmark.DNSSECProbeBogusName, QType: 1,
				Success: true, RCode: 2, ResponseCode: "SERVFAIL", CheckingDisabled: true,
			},
		},
	}
}

func dnssecReport() benchmark.Report {
	validating := reportTarget("1", catalog.UDP, 2, true)
	validating.DNSSEC = dnssecAssessment(benchmark.DNSSECValidating)
	open := reportTarget("2", catalog.UDP, 2, true)
	open.DNSSEC = &benchmark.DNSSECAssessment{
		Verdict: benchmark.DNSSECNotValidating, Reason: "served bogus data",
		Probes: []benchmark.DNSSECProbe{{Role: benchmark.DNSSECRoleSigned, Error: "probe failed"}},
	}
	unknown := reportTarget("3", catalog.TCP, 2, true)
	unknown.DNSSEC = &benchmark.DNSSECAssessment{Verdict: benchmark.DNSSECInconclusive, Reason: "no answer"}
	quiet := reportTarget("4", catalog.TCP, 2, true)
	return benchmark.Report{
		Seed: 1, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1},
		Targets:  []benchmark.TargetResult{validating, open, unknown, quiet},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: validating.Target.ID(), Rank: 1}},
	}
}

func TestTableShowsDNSSECVerdictsOnlyWhenProbed(t *testing.T) {
	var probed bytes.Buffer
	if err := WriteTableWithOptions(&probed, dnssecReport(), TableOptions{Color: true}); err != nil {
		t.Fatal(err)
	}
	text := probed.String()
	for _, expected := range []string{
		"DNSSEC validation probes", "VALIDATING", "NOT VALIDATING", "INCONCLUSIVE",
		"NOERROR answers=1 AD", "SERVFAIL answers=0 CD", "error: probe failed", "fixture reason", "\x1b[32m", "\x1b[31m",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("table missing %q:\n%s", expected, text)
		}
	}
	// The target without an assessment must not appear in the probe section.
	section := text[strings.Index(text, "DNSSEC validation probes"):]
	if strings.Contains(section, "192.0.2.4") {
		t.Fatalf("unprobed target leaked into the DNSSEC section:\n%s", section)
	}

	var plain bytes.Buffer
	if err := WriteTableWithOptions(&plain, goldenReport(), TableOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.String(), "DNSSEC") {
		t.Fatalf("default report printed a DNSSEC section:\n%s", plain.String())
	}
}

func TestDNSSECSectionWriterErrors(t *testing.T) {
	if err := WriteTableWithOptions(contentFailWriter{needle: "DNSSEC validation probes"}, dnssecReport(), TableOptions{}); err == nil {
		t.Fatal("expected a DNSSEC section header write error")
	}
}

func TestDNSSECProbeTextVariants(t *testing.T) {
	cases := []struct {
		probe benchmark.DNSSECProbe
		want  string
	}{
		{benchmark.DNSSECProbe{}, "no response"},
		{benchmark.DNSSECProbe{Error: "boom"}, "error: boom"},
		{benchmark.DNSSECProbe{Success: true, ResponseCode: "SERVFAIL"}, "SERVFAIL answers=0"},
		{benchmark.DNSSECProbe{Success: true, ResponseCode: "NOERROR", Answers: 2, AuthenticatedData: true, CheckingDisabled: true}, "NOERROR answers=2 AD CD"},
	}
	for _, tc := range cases {
		if got := dnssecProbeText(tc.probe); got != tc.want {
			t.Fatalf("dnssecProbeText(%+v) = %q, want %q", tc.probe, got, tc.want)
		}
	}
	assessment := benchmark.DNSSECAssessment{Probes: []benchmark.DNSSECProbe{{Role: benchmark.DNSSECRoleSigned, Success: true, ResponseCode: "NOERROR"}}}
	if got := dnssecProbeTextForRole(assessment, benchmark.DNSSECRoleBogus); got != "—" {
		t.Fatalf("missing probe role text = %q", got)
	}
}

func TestDNSSECAppearsInJSONAndCSV(t *testing.T) {
	run := dnssecReport()
	var jsonOutput bytes.Buffer
	if err := WriteJSON(&jsonOutput, run, false); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"\"dnssec\"", "\"verdict\": \"validating\"", "\"role\": \"bogus\"", "\"response_code\": \"SERVFAIL\""} {
		if !strings.Contains(jsonOutput.String(), expected) {
			t.Fatalf("JSON missing %q:\n%s", expected, jsonOutput.String())
		}
	}
	var schemaDocument map[string]any
	if err := json.Unmarshal(schema.ReportV1(), &schemaDocument); err != nil {
		t.Fatal(err)
	}
	var instance any
	decoder := json.NewDecoder(bytes.NewReader(jsonOutput.Bytes()))
	decoder.UseNumber()
	if err := decoder.Decode(&instance); err != nil {
		t.Fatal(err)
	}
	if err := validateJSONSchema(schemaDocument, instance, schemaDocument, "$"); err != nil {
		t.Fatalf("DNSSEC JSON does not match schema: %v\n%s", err, jsonOutput.String())
	}

	var csvOutput bytes.Buffer
	if err := WriteCSV(&csvOutput, run); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(csvOutput.String()), "\n")
	// The column's position is owned by TestCSVHeaderIsAppendOnly; this test
	// only cares that the verdict is published and carries the right value.
	// Asserting it was last stopped being true the moment anything else was
	// appended after it.
	headers := strings.Split(lines[0], ",")
	verdictColumn := -1
	for index, name := range headers {
		if name == "dnssec_verdict" {
			verdictColumn = index
		}
	}
	if verdictColumn < 0 {
		t.Fatalf("CSV header has no DNSSEC column: %s", lines[0])
	}
	if got := strings.Split(lines[1], ",")[verdictColumn]; got != "validating" {
		t.Fatalf("CSV verdict for the validating target = %q", got)
	}
	if got := strings.Split(lines[4], ",")[verdictColumn]; got != "" {
		t.Fatalf("CSV verdict for the unprobed target = %q, want empty", got)
	}
}

func TestDNSSECObservationFlagsSurviveRawJSON(t *testing.T) {
	run := dnssecReport()
	run.Targets[0].Observations = []benchmark.Observation{
		{Name: "example.com", QType: 1, Success: true, Usable: true, AuthenticatedData: true, CheckingDisabled: true},
	}
	var output bytes.Buffer
	if err := WriteJSON(&output, run, true); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"\"authenticated_data\": true", "\"checking_disabled\": true"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("raw JSON missing %q:\n%s", expected, output.String())
		}
	}
}

func TestDNSSECProbeErrorsAreRedactedForSystemTargets(t *testing.T) {
	system := reportTarget("system-dnssec", catalog.UDP, 2, true)
	system.Target.Resolver = catalog.ResolverProfile{
		ID: "system-dnssec", Name: "System DNS", Owner: "configured locally", Policy: "local",
	}
	system.Target.Address = "127.0.0.53"
	system.DNSSEC = &benchmark.DNSSECAssessment{
		Verdict: benchmark.DNSSECInconclusive,
		Reason:  "the bogus probe did not complete: dial 127.0.0.53: refused",
		Probes:  []benchmark.DNSSECProbe{{Role: benchmark.DNSSECRoleBogus, Error: "dial 127.0.0.53: refused"}},
	}
	run := benchmark.Report{Seed: 1, QueryTypes: []uint16{1}, Targets: []benchmark.TargetResult{system}}

	var redacted bytes.Buffer
	if err := WriteJSONWithOptions(&redacted, run, false, JSONOptions{RedactSystem: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(redacted.String(), "127.0.0.53") {
		t.Fatalf("redacted JSON leaked the system address:\n%s", redacted.String())
	}
	var table bytes.Buffer
	if err := WriteTableWithOptions(&table, run, TableOptions{RedactSystem: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(table.String(), "127.0.0.53") {
		t.Fatalf("redacted table leaked the system address:\n%s", table.String())
	}
	// Public targets keep their assessment untouched.
	public := reportTarget("public", catalog.UDP, 2, true)
	public.DNSSEC = dnssecAssessment(benchmark.DNSSECValidating)
	if got := redactDNSSEC(public, true, redactedValue); got != public.DNSSEC {
		t.Fatal("a public target's assessment was copied unnecessarily")
	}
}
