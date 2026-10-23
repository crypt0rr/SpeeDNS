//go:build unix

package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestOutputWriterUpdatesEveryHardLinkedName pins that a report reaches every
// name of a hard-linked destination. Renaming a new file over one name would
// detach it from the others, which would keep showing the previous report, so
// such a file is written in place. Link counts come from the Unix stat
// structure, hence the build tag.
func TestOutputWriterUpdatesEveryHardLinkedName(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "report.json")
	alias := filepath.Join(directory, "latest.json")
	if err := os.WriteFile(path, []byte("a previous report longer than the new one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		t.Fatalf("create hard link: %v", err)
	}
	if err := preflightOutput(path); err != nil {
		t.Fatalf("hard-linked preflight = %v", err)
	}
	writer, finalize, err := outputWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "new report"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path, alias} {
		if content, err := os.ReadFile(name); err != nil || string(content) != "new report" {
			t.Fatalf("%s = %q/%v", name, content, err)
		}
	}
	first, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.Stat(alias)
	if err != nil || !os.SameFile(first, second) {
		t.Fatalf("the hard link was broken: %v/%v", second, err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 2 {
		t.Fatalf("a temporary file was left behind: %v/%v", entries, err)
	}
}
