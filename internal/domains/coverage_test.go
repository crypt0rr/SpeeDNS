package domains

import (
	"errors"
	"os"
	"strings"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("reader failed") }

func TestLoadUsesEmbeddedAndFileLists(t *testing.T) {
	got, err := Load(" ")
	if err != nil || len(got) != 1000 {
		t.Fatalf("embedded Load = %d/%v", len(got), err)
	}
	dir := t.TempDir()
	path := dir + "/names.txt"
	if err := os.WriteFile(path, []byte("# comment\nExample.COM.\nexample.org\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = Load(path)
	if err != nil || len(got) != 2 || got[0] != "example.com" || got[1] != "example.org" {
		t.Fatalf("file Load = %#v/%v", got, err)
	}
	if _, err := Load(dir + "/missing.txt"); err == nil {
		t.Fatal("expected missing domain file error")
	}
}

func TestLoadReaderReportsScannerFailures(t *testing.T) {
	if _, err := loadReader(failingReader{}); err == nil || !strings.Contains(err.Error(), "read domain list") {
		t.Fatalf("reader failure = %v", err)
	}
	tooLong := strings.Repeat("a", 64*1024) + "\n"
	if _, err := loadReader(strings.NewReader(tooLong)); err == nil || !strings.Contains(err.Error(), "read domain list") {
		t.Fatalf("oversized line error = %v", err)
	}
	if _, err := loadReader(strings.NewReader("\n# only comments\n.\n")); err == nil || !strings.Contains(err.Error(), "domain list is empty") {
		t.Fatalf("empty reader error = %v", err)
	}
}

func TestValidateIgnoresEmptyInputsAndRequiresAName(t *testing.T) {
	got, err := validate([]string{" ", "# comment", "Example.COM.", "example.com", "example.org."})
	if err != nil || len(got) != 2 || got[0] != "example.com" || got[1] != "example.org" {
		t.Fatalf("validated names = %#v/%v", got, err)
	}
	if _, err := validate(nil); err == nil {
		t.Fatal("expected nil validation input to fail")
	}
	if _, err := validate([]string{"example..com"}); err == nil {
		t.Fatal("expected invalid name to fail")
	}
}
