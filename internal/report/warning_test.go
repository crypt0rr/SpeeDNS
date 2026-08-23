package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

func warningReportForViews() benchmark.Report {
	failing := reportTarget("view", catalog.UDP, 1, false)
	failing.Stats = benchmark.Statistics{
		Total: 4, Successes: 1, UsableResponses: 1, Scored: 1, Failures: 3,
		SuccessRate: 0.25, UsableRate: 0.25, MedianMS: 2, P95MS: 3, ScoreMS: 2.4,
	}
	return benchmark.Report{
		Seed: 42, SampleSize: 4, Queries: 4, QueryTypes: []uint16{1},
		Targets:  []benchmark.TargetResult{failing},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: failing.Target.ID(), Rank: 1}},
		Warnings: []benchmark.Warning{
			benchmark.TargetWarning(failing.Target, "had 3/4 failed queries"),
			benchmark.RunWarning("benchmark interrupted before all targets completed"),
		},
	}
}

// TestWarningViewsUseStructuredAttribution asserts that the default table keeps
// the compact per-endpoint line, that --details keeps the full producer list,
// and that both decide per-endpoint membership from the warning value.
func TestWarningViewsUseStructuredAttribution(t *testing.T) {
	run := warningReportForViews()
	target := run.Targets[0]

	if warnings := compactWarnings(run); len(warnings) != 2 ||
		warnings[0] != "Resolver view 192.0.2.view/udp: 3/4 queries failed" ||
		warnings[1] != "benchmark interrupted before all targets completed" {
		t.Fatalf("compact warnings = %#v", warnings)
	}

	var table bytes.Buffer
	if err := WriteTable(&table, run, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(table.String(), "  - Resolver view 192.0.2.view/udp: 3/4 queries failed\n") {
		t.Fatalf("default table lost the compact per-target warning: %s", table.String())
	}
	if strings.Contains(table.String(), "had 3/4 failed queries") {
		t.Fatalf("default table repeated the raw per-target warning: %s", table.String())
	}

	var details bytes.Buffer
	if err := WriteTable(&details, run, true); err != nil {
		t.Fatal(err)
	}
	expected := target.Target.DisplayName() + " " + target.Target.Address + "/udp had 3/4 failed queries"
	if !strings.Contains(details.String(), "  - "+expected+"\n") {
		t.Fatalf("details table lost the full per-target warning: %s", details.String())
	}
	if !strings.Contains(details.String(), "  - benchmark interrupted before all targets completed\n") {
		t.Fatalf("details table lost the run-level warning: %s", details.String())
	}

	var encoded bytes.Buffer
	if err := WriteJSON(&encoded, run, false); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(encoded.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Warnings) != 2 || decoded.Warnings[0] != expected ||
		decoded.Warnings[1] != "benchmark interrupted before all targets completed" {
		t.Fatalf("JSON warnings = %#v", decoded.Warnings)
	}
}

// TestWarningAttributionSurvivesProducerLabelDrift is the regression test for
// the prefix-matching contract this refactor removed. The producer here labels
// the same endpoint differently from the way the report layer renders it, which
// is exactly what a rebuilt-label prefix match failed to recognise: the compact
// view then leaked the raw producer line next to the line it rebuilt itself.
func TestWarningAttributionSurvivesProducerLabelDrift(t *testing.T) {
	run := warningReportForViews()
	drifted := run.Targets[0].Target
	drifted.Resolver.Name = "Owner view / Resolver view"
	run.Warnings[0] = benchmark.TargetWarning(drifted, "had 3/4 failed queries [drifted label]")

	rendered := run.Warnings[0].String()
	if strings.HasPrefix(rendered, targetWarningLabelWithOptions(run.Targets[0], false)) {
		t.Fatalf("drifted warning still matches the report label prefix: %q", rendered)
	}

	warnings := compactWarnings(run)
	if len(warnings) != 2 || warnings[0] != "Resolver view 192.0.2.view/udp: 3/4 queries failed" {
		t.Fatalf("drifted label changed the compact view: %#v", warnings)
	}
	if strings.Contains(strings.Join(warnings, "\n"), "drifted label") {
		t.Fatalf("compact view leaked an attributed warning: %#v", warnings)
	}

	var details bytes.Buffer
	if err := WriteTable(&details, run, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(details.String(), "  - "+rendered+"\n") {
		t.Fatalf("details table lost the drifted warning: %s", details.String())
	}
}

// TestRedactedWarningsUseWarningAttribution asserts that redaction substitutes
// the identity of the endpoint a warning belongs to, including when that
// endpoint is no longer present in the results, and leaves other endpoints and
// run-level text handling unchanged.
func TestRedactedWarningsUseWarningAttribution(t *testing.T) {
	systemTarget := catalog.Target{
		Resolver: catalog.ResolverProfile{
			ID: "system-stub-127-0-0-53", Name: "System DNS stub (scope: corp.example)",
			Owner: "local stub/forwarder (interface: utun0)", Policy: "local forwarding",
		},
		Protocol: catalog.UDP, Address: "127.0.0.53", Spec: catalog.TransportSpec{Port: 53},
	}
	system := benchmark.TargetResult{
		Target: systemTarget, DialAddress: "127.0.0.53:53", OpenError: "dial udp 127.0.0.53:53: timeout",
		Stats: benchmark.Statistics{Total: 1, Failures: 1},
	}
	public := reportTarget("public", catalog.UDP, 1, false)
	dropped := systemTarget
	dropped.Resolver.ID = "system-stub-127-0-0-54"
	dropped.Address = "127.0.0.54"
	run := benchmark.Report{
		Seed: 7, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1},
		Targets:  []benchmark.TargetResult{system, public},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: public.Target.ID(), Rank: 1}},
		Warnings: []benchmark.Warning{
			benchmark.TargetWarning(systemTarget, "could not open a session: dial udp 127.0.0.53:53: timeout"),
			benchmark.TargetWarning(public.Target, "had 1/2 failed queries"),
			benchmark.TargetWarning(dropped, "could not open a session: dial udp 127.0.0.54:53: timeout"),
			benchmark.RunWarning("global diagnostic mentions 127.0.0.53"),
		},
	}

	redacted := renderWarnings(run, true, redactedTargetIDs(run, true))
	want := []string{
		"System DNS (redacted) redacted/udp could not open a session: dial udp redacted: timeout",
		public.Target.DisplayName() + " " + public.Target.Address + "/udp had 1/2 failed queries",
		"System DNS (redacted) redacted/udp could not open a session: dial udp redacted:53: timeout",
		"global diagnostic mentions redacted",
	}
	if len(redacted) != len(want) {
		t.Fatalf("redacted warnings = %#v", redacted)
	}
	for index, value := range want {
		if redacted[index] != value {
			t.Fatalf("redacted warning %d = %q, want %q", index, redacted[index], value)
		}
	}

	plain := renderWarnings(run, false, nil)
	if plain[0] != run.Warnings[0].String() || plain[3] != "global diagnostic mentions 127.0.0.53" {
		t.Fatalf("unredacted warnings = %#v", plain)
	}

	var table bytes.Buffer
	if err := WriteTableWithOptions(&table, run, TableOptions{RedactSystem: true, Protocols: []catalog.Protocol{catalog.UDP}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(table.String(), "127.0.0.5") || strings.Contains(table.String(), "utun0") {
		t.Fatalf("redacted default table leaked a local identity: %s", table.String())
	}
	if !strings.Contains(table.String(), "  - global diagnostic mentions redacted\n") {
		t.Fatalf("redacted default table lost the run-level warning: %s", table.String())
	}
	if !strings.Contains(table.String(), "System DNS (redacted) redacted/udp: unavailable; 1/1 queries failed") {
		t.Fatalf("redacted default table lost the compact per-target warning: %s", table.String())
	}
}
