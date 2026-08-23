package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReportV1IsEmbeddedJSONSchema(t *testing.T) {
	contents := ReportV1()
	if len(contents) == 0 {
		t.Fatal("report schema is empty")
	}
	var document map[string]any
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("report schema is not valid JSON: %v", err)
	}
	for _, field := range []string{"$schema", "$id", "title", "type", "$defs"} {
		if _, ok := document[field]; !ok {
			t.Fatalf("report schema is missing %q", field)
		}
	}
	if document["type"] != "object" || !strings.HasSuffix(document["$id"].(string), "/schema/report-v1.json") {
		t.Fatalf("unexpected report schema identity: %#v", document)
	}
	copyOfContents := ReportV1()
	copyOfContents[0] = 'x'
	if ReportV1()[0] == 'x' {
		t.Fatal("ReportV1 did not return an independent copy")
	}
}

// TestLiveResultsV1IsEmbeddedJSONSchema mirrors the report-v1 test for the
// live-results contract. The schema package is what lets Go tests check
// encoder output against the contract scripts/publish-live-results.py
// enforces, so the accessor needs the same independent-copy guarantee.
func TestLiveResultsV1IsEmbeddedJSONSchema(t *testing.T) {
	contents := LiveResultsV1()
	if len(contents) == 0 {
		t.Fatal("LiveResultsV1 returned no schema")
	}
	var document map[string]any
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("live-results schema is not valid JSON: %v", err)
	}
	definitions, ok := document["$defs"].(map[string]any)
	if !ok {
		t.Fatal("live-results schema has no $defs")
	}
	if _, ok := definitions["stats"]; !ok {
		t.Fatal("live-results schema has no $defs/stats")
	}

	contents[0] = 'x'
	if LiveResultsV1()[0] == 'x' {
		t.Fatal("LiveResultsV1 did not return an independent copy")
	}
}
