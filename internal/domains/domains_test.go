package domains

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/crypt0rr/SpeeDNS/data"
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

func TestLoadValidatesBundledCorpus(t *testing.T) {
	domains, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 1000 {
		t.Fatalf("bundled corpus count = %d, want 1000", len(domains))
	}
}

func TestLoadReportsEmbeddedCorpusVerificationFailure(t *testing.T) {
	oldVerify := verifyEmbeddedCorpus
	verifyEmbeddedCorpus = func() (data.CorpusMetadata, error) {
		return data.CorpusMetadata{}, errors.New("checksum mismatch")
	}
	t.Cleanup(func() { verifyEmbeddedCorpus = oldVerify })
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "verify embedded domain corpus") {
		t.Fatalf("embedded corpus error = %v", err)
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

func TestCorpusDigestUsesCanonicalNormalizedSequence(t *testing.T) {
	if got := CorpusDigest([]string{"example.com", "example.org"}); got != "ace801686b06c8b2d759d4bad10d00af484d636b25b373c59002031e8c4e1504" {
		t.Fatalf("corpus digest = %q", got)
	}
	if CorpusDigest([]string{"example.org", "example.com"}) == CorpusDigest([]string{"example.com", "example.org"}) {
		t.Fatal("corpus digest ignored domain order")
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
		{name: "interior underscore", value: "under_score.example", want: "leading underscore"},
		{name: "doubled underscore", value: "__dmarc.example", want: "leading underscore"},
		{name: "bare underscore label", value: "_.example", want: "must name a host or service"},
		{name: "non-ldh ascii", value: "ex!ample.com", want: "leading underscore"},
		{name: "at sign", value: "user@example.com", want: "leading underscore"},
		{name: "slash", value: "example.com/path", want: "leading underscore"},
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

func TestLoadAcceptsUnderscoredServiceLabels(t *testing.T) {
	got, err := loadReader(strings.NewReader(
		"_dmarc.example.com\n" +
			"_sip._tcp.example.com\n" +
			"_443._TCP.Example.COM.\n" +
			"selector1._domainkey.example.com\n" +
			"_dmarc.BÜCHER.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"_dmarc.example.com",
		"_sip._tcp.example.com",
		"_443._tcp.example.com",
		"selector1._domainkey.example.com",
		"_dmarc.xn--bcher-kva.example",
	}
	if len(got) != len(want) {
		t.Fatalf("service label count = %d, want %d: %#v", len(got), len(want), got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("service label %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestNormalizeKeepsLengthLimitsOnUnderscoredLabels(t *testing.T) {
	if _, err := Normalize([]string{"_" + strings.Repeat("a", 62) + ".example"}); err != nil {
		t.Fatalf("63-octet service label = %v", err)
	}
	if _, err := Normalize([]string{"_" + strings.Repeat("a", 63) + ".example"}); err == nil {
		t.Fatal("64-octet service label was accepted")
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

// TestNormalizeTrimsEveryRootLabelForm pins the root-label rule against the
// Unicode tables x/net/idna selects by Go toolchain. UTS-46 maps the
// ideographic and fullwidth stops onto the ASCII separator, so all four forms
// have to survive normalization identically on every supported toolchain.
func TestNormalizeTrimsEveryRootLabelForm(t *testing.T) {
	for _, input := range []string{
		"example.com.",
		"EXAMPLE.COM.",
		"example.com。",
		"example.com．",
		"example.com｡",
	} {
		got, err := Normalize([]string{input})
		if err != nil {
			t.Fatalf("Normalize(%q) error = %v", input, err)
		}
		if len(got) != 1 || got[0] != "example.com" {
			t.Fatalf("Normalize(%q) = %#v, want [example.com]", input, got)
		}
	}
}

// TestNormalizeSkipsBareRootLabels covers names that consist only of label
// separators; they carry no queryable name and must be skipped rather than
// rejected, matching the documented handling of a bare root dot.
func TestNormalizeSkipsBareRootLabels(t *testing.T) {
	for _, input := range []string{"。", "．", "｡", "。．"} {
		if _, err := Normalize([]string{input, "example.com"}); err != nil {
			t.Fatalf("Normalize(%q, example.com) error = %v", input, err)
		}
	}
	if _, err := Normalize([]string{"。"}); err == nil {
		t.Fatal("expected a list of only root labels to be empty")
	}
}

// TestValidateInputsCapsReportedInvalidNames keeps the error readable for a
// list that is wrong throughout: every invalid entry is collected, but a
// thousand-line file must not produce a thousand-line error.
func TestValidateInputsCapsReportedInvalidNames(t *testing.T) {
	lines := make([]string, 0, maxReportedInvalidNames+5)
	for index := 0; index < maxReportedInvalidNames+5; index++ {
		lines = append(lines, fmt.Sprintf("bad %d.example", index))
	}
	_, err := Normalize(lines)
	if err == nil {
		t.Fatal("expected an invalid domain list to fail")
	}
	if !strings.Contains(err.Error(), "and possibly more") {
		t.Fatalf("capped error missing the truncation note: %v", err)
	}
	if got := strings.Count(err.Error(), "whitespace is not allowed"); got != maxReportedInvalidNames {
		t.Fatalf("reported %d invalid names, want %d: %v", got, maxReportedInvalidNames, err)
	}
}
