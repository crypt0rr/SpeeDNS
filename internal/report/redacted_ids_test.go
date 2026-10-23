package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

// TestRedactedTargetIDsMatchTheWrittenReport pins the exported mapping that
// --assert failure messages use (#243). It must be the report's own
// numbering, so a stderr line and the JSON beside it name a redacted system
// target identically, and it must be empty when redaction is off.
func TestRedactedTargetIDsMatchTheWrittenReport(t *testing.T) {
	public := benchmark.TargetResult{Target: catalog.Target{
		Resolver: catalog.ResolverProfile{ID: "public", Name: "Public"}, Protocol: catalog.UDP, Address: "192.0.2.1",
	}}
	first := benchmark.TargetResult{Target: catalog.Target{
		Resolver: catalog.ResolverProfile{ID: "system-10-20-30-40", Name: "System DNS"}, Protocol: catalog.UDP, Address: "10.20.30.40",
	}}
	second := first
	second.Target.Protocol = catalog.TCP
	run := benchmark.Report{Targets: []benchmark.TargetResult{public, first, second}}

	ids := RedactedTargetIDs(run, true)
	if len(ids) != 2 || ids[first.Target.ID()] != "system-redacted-1@redacted/udp" || ids[second.Target.ID()] != "system-redacted-2@redacted/tcp" {
		t.Fatalf("RedactedTargetIDs = %#v", ids)
	}
	if _, ok := ids[public.Target.ID()]; ok {
		t.Fatalf("a public target was given a redacted ID: %#v", ids)
	}
	var written bytes.Buffer
	if err := WriteJSONWithOptions(&written, run, false, JSONOptions{RedactSystem: true}); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if !strings.Contains(written.String(), `"`+id+`"`) {
			t.Fatalf("the redacted report does not use %q: %s", id, written.String())
		}
	}
	if ids := RedactedTargetIDs(run, false); ids != nil {
		t.Fatalf("RedactedTargetIDs without redaction = %#v", ids)
	}
}
