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

func TestNormalizeIgnoresEmptyInputsAndRequiresAName(t *testing.T) {
	got, err := Normalize([]string{" ", "# comment", "Example.COM.", "example.com", "example.org."})
	if err != nil || len(got) != 2 || got[0] != "example.com" || got[1] != "example.org" {
		t.Fatalf("validated names = %#v/%v", got, err)
	}
	if _, err := Normalize(nil); err == nil {
		t.Fatal("expected nil validation input to fail")
	}
	if _, err := Normalize([]string{"example..com"}); err == nil {
		t.Fatal("expected invalid name to fail")
	}
}

func TestCacheMissNamesAreBoundedAndUnique(t *testing.T) {
	names, err := CacheMissNames("ABCDEF0123456789", CacheMissDefaultSample)
	if err != nil || len(names) != CacheMissDefaultSample || names[0] != "speedns-abcdef0123456789-0001.example.com" || names[len(names)-1] != "speedns-abcdef0123456789-0010.example.com" {
		t.Fatalf("cache-miss names = %#v/%v", names, err)
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] {
			t.Fatalf("duplicate cache-miss name %q", name)
		}
		seen[name] = true
	}
	if _, err := CacheMissNames("", 1); err == nil {
		t.Fatal("empty cache-miss nonce was accepted")
	}
	if _, err := CacheMissNames("not-hex", 1); err == nil {
		t.Fatal("non-hex cache-miss nonce was accepted")
	}
	if _, err := CacheMissNames("aa", 0); err == nil {
		t.Fatal("zero cache-miss sample was accepted")
	}
	if _, err := CacheMissNames("aa", CacheMissMaxSample+1); err == nil {
		t.Fatal("oversized cache-miss sample was accepted")
	}
	nonce, err := NewCacheMissNonce()
	if err != nil || len(nonce) != 16 {
		t.Fatalf("generated cache-miss nonce = %q/%v", nonce, err)
	}
	oldRandomRead := randomRead
	randomRead = func([]byte) (int, error) { return 0, errors.New("random source failed") }
	if _, err := NewCacheMissNonce(); err == nil || !strings.Contains(err.Error(), "random source failed") {
		t.Fatalf("random nonce failure = %v", err)
	}
	randomRead = oldRandomRead
}
