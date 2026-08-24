package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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

// TestRepositoryTracksNoBinaries fails if a compiled artifact is committed.
//
// A 14 MB scratch binary reached main in the v0.3.0 pre-release commit, swept
// in by a `git add -A` after an audit left a build in .gotmp/. Nothing caught
// it: gofmt, vet, staticcheck and the coverage gate all only look at Go source,
// and the earlier stray-file check grepped for .pyc and .patch by name.
//
// This matters more than tidiness. The Go module zip is immutable once
// proxy.golang.org fetches a tag, so a binary committed at a release tag can
// never be removed -- only superseded.
func TestRepositoryTracksNoBinaries(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	listed, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("git ls-files unavailable: %v", err)
	}

	// Files that are legitimately non-text. Keep this list short and explicit:
	// every entry is a decision that something binary belongs in the tree.
	allowed := map[string]bool{}

	var offenders []string
	for _, name := range strings.Split(string(listed), "\x00") {
		if name == "" || allowed[name] {
			continue
		}
		path := filepath.Join(root, name)
		info, statErr := os.Stat(path)
		if statErr != nil || info.IsDir() {
			continue
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		// A NUL byte in the first 8 KB is the same heuristic git itself uses to
		// decide a blob is binary.
		head := content
		if len(head) > 8192 {
			head = head[:8192]
		}
		if bytes.IndexByte(head, 0) >= 0 {
			offenders = append(offenders, fmt.Sprintf("%s (%d bytes)", name, len(content)))
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("compiled or binary artifacts are tracked:\n  %s", strings.Join(offenders, "\n  "))
	}
}
