package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// manPage returns the shipped page. Release archives carry it as
// docs/speedns.1 and the Linux packages install it as
// /usr/share/man/man1/speedns.1, so it is the only reference documentation
// inside a package - README.md ships only in the tar.gz archive.
func manPage(t *testing.T) string {
	t.Helper()
	page, err := os.ReadFile("../../docs/speedns.1")
	if err != nil {
		t.Fatal(err)
	}
	return string(page)
}

// TestManPageDocumentsEveryFlag keeps docs/speedns.1 in step with the flag set.
// The page is hand-maintained, so without this it drifts silently: it had
// fallen seven flags behind by the time this test was added.
func TestManPageDocumentsEveryFlag(t *testing.T) {
	page := manPage(t)
	var missing []string
	newRootCommand().Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Hidden {
			return
		}
		// Entries are written as ".B --name" optionally followed by an
		// argument placeholder, so match the flag name at a word boundary.
		if !strings.Contains(page, ".B --"+flag.Name+"\n") &&
			!strings.Contains(page, ".B --"+flag.Name+" ") {
			missing = append(missing, "--"+flag.Name)
		}
	})
	if len(missing) > 0 {
		t.Fatalf("docs/speedns.1 does not document %s", strings.Join(missing, ", "))
	}
}

// exitStatusSection returns just the EXIT STATUS section. Scoping matters: the
// --assert entry legitimately writes ".B 4" in its prose, so a whole-page
// search would report status 4 as documented even when the section omits it.
func exitStatusSection(t *testing.T, page string) string {
	t.Helper()
	start := strings.Index(page, ".SH EXIT STATUS")
	if start < 0 {
		t.Fatal("docs/speedns.1 has no EXIT STATUS section")
	}
	section := page[start+len(".SH EXIT STATUS"):]
	if end := strings.Index(section, "\n.SH "); end >= 0 {
		section = section[:end]
	}
	return section
}

// TestManPageDocumentsEveryExitStatus pins the EXIT STATUS section against the
// codes exitCodeForError can actually return. Status 4 was returned by the
// binary and documented in README.md and METHODOLOGY.md, but was missing from
// the page the packages install.
func TestManPageDocumentsEveryExitStatus(t *testing.T) {
	section := exitStatusSection(t, manPage(t))
	for _, code := range exitCodes() {
		if !strings.Contains(section, fmt.Sprintf(".B %d\n", code)) {
			t.Fatalf("docs/speedns.1 EXIT STATUS does not document status %d", code)
		}
	}
}

// TestManPageDocumentsEachFlagOnce guards the failure mode that
// TestManPageDocumentsEveryFlag cannot see: it only checks that each flag is
// present, so a second .TP entry added instead of editing the first passes.
// Two entries render as one run-together paragraph stating the same option
// twice with different rules, and the man page is the only reference
// documentation inside the deb, rpm, apk and Arch packages.
func TestManPageDocumentsEachFlagOnce(t *testing.T) {
	entry := regexp.MustCompile(`(?m)^\.TP\n\.B (--[a-z][a-z0-9-]*)`)
	counts := make(map[string]int)
	for _, match := range entry.FindAllStringSubmatch(manPage(t), -1) {
		counts[match[1]]++
	}
	if len(counts) == 0 {
		t.Fatal("no option entries found; the entry pattern no longer matches the page")
	}
	var duplicated []string
	for flag, count := range counts {
		if count > 1 {
			duplicated = append(duplicated, fmt.Sprintf("%s (%d entries)", flag, count))
		}
	}
	if len(duplicated) > 0 {
		sort.Strings(duplicated)
		t.Fatalf("docs/speedns.1 documents these flags more than once: %s", strings.Join(duplicated, ", "))
	}
}
