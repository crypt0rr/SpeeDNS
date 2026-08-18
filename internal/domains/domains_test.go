package domains

import (
	"strings"
	"testing"
)

func TestLoadNormalizesCommentsAndDuplicates(t *testing.T) {
	got, err := loadReader(strings.NewReader("# comment\nExample.COM.\nexample.com\nexample.org.\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "example.com" || got[1] != "example.org" {
		t.Fatalf("normalized domains = %#v", got)
	}
}

func TestLoadRejectsInvalidName(t *testing.T) {
	_, err := loadReader(strings.NewReader("example..com"))
	if err == nil {
		t.Fatal("expected invalid domain to fail")
	}
}
