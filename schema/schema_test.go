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
