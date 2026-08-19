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

func TestLoadConvertsUnicodeToIDNAAndDeduplicatesAfterNormalization(t *testing.T) {
	got, err := loadReader(strings.NewReader("BÜCHER.example.\nxn--bcher-kva.example\n例え。テスト\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"xn--bcher-kva.example", "xn--r8jz45g.xn--zckzah"}
	if len(got) != len(want) {
		t.Fatalf("normalized domain count = %d, want %d: %#v", len(got), len(want), got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("normalized domain %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestLoadRejectsStrictDomainSyntaxWithSourceLine(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{name: "whitespace", value: "example .com", want: "whitespace"},
		{name: "wildcard", value: "*.example.com", want: "wildcard"},
		{name: "control", value: "example\x00.com", want: "control"},
		{name: "empty label", value: "example..com", want: "empty label"},
		{name: "long label", value: strings.Repeat("a", 64) + ".example", want: "invalid domain name"},
		{name: "leading hyphen", value: "-example.com", want: "invalid domain name"},
		{name: "trailing hyphen", value: "example-.com", want: "invalid domain name"},
		{name: "underscore", value: "_service.example", want: "invalid domain name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadReader(strings.NewReader("# ignored\nexample.com\n" + tc.value + "\n"))
			if err == nil || !strings.Contains(err.Error(), "line 3") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validation error = %v, want line 3 and %q", err, tc.want)
			}
		})
	}
}

func TestLoadRejectsOverlongDomain(t *testing.T) {
	labels := make([]string, 0, 5)
	for index := 0; index < 5; index++ {
		labels = append(labels, strings.Repeat("a", 63))
	}
	_, err := loadReader(strings.NewReader(strings.Join(labels, ".")))
	if err == nil || !strings.Contains(err.Error(), "domain name") {
		t.Fatalf("overlong domain error = %v", err)
	}
}

func TestNormalizeRejectsInvalidUTF8(t *testing.T) {
	if _, err := normalize(string([]byte{0xff})); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
}
