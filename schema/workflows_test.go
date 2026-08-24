package schema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestWorkflowsParse fails if any GitHub Actions workflow is not valid YAML.
//
// Nothing in the tree parsed these files. A release workflow GitHub cannot read
// passes every gate and then fails at the worst possible moment -- after a tag
// is pushed, when the tag is already public and the module proxy may already
// have fetched it. The v0.1.0 release did fail at exactly that point for a
// different reason, and needed a manual re-dispatch.
//
// This asserts only that the documents parse and carry the keys Actions
// requires. It deliberately does not validate against a schema of the Actions
// language: that is a snapshot of a platform which changes without commits, and
// a linter pinned to yesterday's schema fails on correct workflows.
func TestWorkflowsParse(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no workflows found; the glob no longer matches the repository layout")
	}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		var document map[any]any
		if err := yaml.Unmarshal(content, &document); err != nil {
			t.Fatalf("%s is not valid YAML, so GitHub cannot run it: %v", filepath.Base(path), err)
		}
		// "on" is a YAML 1.1 boolean, so some parsers key it as true rather
		// than as the string. Accept either spelling.
		_, named := document["on"]
		_, boolean := document[true]
		if !named && !boolean {
			t.Fatalf("%s has no trigger block, so it would never run", filepath.Base(path))
		}
		if _, ok := document["jobs"]; !ok {
			t.Fatalf("%s declares no jobs", filepath.Base(path))
		}
	}
}

// TestReleaseWorkflowFetchesFullHistory guards a specific way the release
// breaks late. release.yml chooses the previous stable tag by walking the tag
// list, and validates that the release tag points at the checked-out commit.
// Both need the tags, and actions/checkout fetches a shallow single commit with
// no tags unless told otherwise -- so a missing fetch-depth turns a correct
// workflow into one that silently picks the wrong range or aborts.
func TestReleaseWorkflowFetchesFullHistory(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if !strings.Contains(text, "fetch-depth: 0") {
		t.Fatal("release.yml does not request full history; tag selection and tag validation both need the tags")
	}
	if !strings.Contains(text, "fetch-tags: true") && !strings.Contains(text, "fetch-depth: 0") {
		t.Fatal("release.yml does not fetch tags")
	}
}
