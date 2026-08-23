package main

import (
	"fmt"
	"os"
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
