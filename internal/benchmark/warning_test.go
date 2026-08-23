package benchmark

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

// TestCollectWarningsAttributesWarningsStructurally asserts that a per-target
// warning names its endpoint through the value, not through the text: the
// message alone never carries the endpoint identity, so no consumer has to
// rebuild a label to recover the attribution.
func TestCollectWarningsAttributesWarningsStructurally(t *testing.T) {
	target := testTarget(catalog.UDP, "attributed")
	other := testTarget(catalog.TCP, "other")
	warnings := collectWarnings([]TargetResult{
		{Target: target, OpenError: "dial failed", Stats: Statistics{Total: 4, Failures: 1, Divergent: 1, Truncated: 1, Scored: 1}},
		{Target: other, Incomplete: true},
	})
	if len(warnings) != 6 {
		t.Fatalf("warnings = %#v", warnings)
	}
	for index, warning := range warnings[:5] {
		if !warning.Targeted() || warning.Target.ID() != target.ID() {
			t.Fatalf("warning %d was not attributed to %s: %#v", index, target.ID(), warning)
		}
		if strings.Contains(warning.Message, target.DisplayName()) || strings.Contains(warning.Message, target.Address) {
			t.Fatalf("warning %d embedded the endpoint identity in the message: %q", index, warning.Message)
		}
	}
	if !warnings[5].Targeted() || warnings[5].Target.ID() != other.ID() {
		t.Fatalf("incomplete warning attribution = %#v", warnings[5])
	}
	if got := warnings[0].String(); got != target.DisplayName()+" "+target.Address+"/udp could not open a session: dial failed" {
		t.Fatalf("rendered warning = %q", got)
	}
	if len(collectWarnings(nil)) != 0 {
		t.Fatal("empty results produced warnings")
	}
}

// TestTargetWarningCopiesTargetIdentity asserts that a recorded warning keeps
// the identity it was created with when the caller reuses its target value.
func TestTargetWarningCopiesTargetIdentity(t *testing.T) {
	target := testTarget(catalog.UDP, "copied")
	warning := TargetWarning(target, "had 1/1 failed queries")
	target.Resolver.Name = "Renamed"
	if warning.Target.DisplayName() == "Renamed" {
		t.Fatalf("warning aliased the caller's target: %#v", warning.Target)
	}
	if got := warning.RenderWith("Redacted Name", "redacted"); got != "Redacted Name redacted/udp had 1/1 failed queries" {
		t.Fatalf("RenderWith = %q", got)
	}
}

// TestRunWarningsCarryNoEndpoint asserts run-level warnings render as their
// message regardless of the identity a presenter offers.
func TestRunWarningsCarryNoEndpoint(t *testing.T) {
	warning := RunWarning("benchmark interrupted before all targets completed")
	if warning.Targeted() || warning.String() != warning.Message {
		t.Fatalf("run warning = %#v", warning)
	}
	if got := warning.RenderWith("Name", "192.0.2.1"); got != warning.Message {
		t.Fatalf("run warning RenderWith = %q", got)
	}
}

// TestWarningJSONShapeIsAnArrayOfStrings pins the published report contract:
// the structured form must not change how warnings appear in JSON.
func TestWarningJSONShapeIsAnArrayOfStrings(t *testing.T) {
	target := testTarget(catalog.UDP, "json")
	report := Report{Warnings: []Warning{
		TargetWarning(target, "had 2/2 failed queries"),
		RunWarning("benchmark interrupted before all targets completed"),
	}}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	want := []string{
		target.DisplayName() + " " + target.Address + "/udp had 2/2 failed queries",
		"benchmark interrupted before all targets completed",
	}
	if len(decoded.Warnings) != len(want) {
		t.Fatalf("warnings = %#v", decoded.Warnings)
	}
	for index, value := range want {
		if decoded.Warnings[index] != value {
			t.Fatalf("warning %d = %q, want %q", index, decoded.Warnings[index], value)
		}
	}

	var roundTripped Report
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatal(err)
	}
	for index, warning := range roundTripped.Warnings {
		if warning.Targeted() || warning.String() != want[index] {
			t.Fatalf("decoded warning %d = %#v", index, warning)
		}
	}
	if err := json.Unmarshal([]byte(`{"warnings":[7]}`), &roundTripped); err == nil {
		t.Fatal("non-string warning was accepted")
	}
}
