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
	// Scoped to OPTIONS: a subcommand section may document its own --format,
	// which is a different flag rather than a duplicate entry.
	for _, match := range entry.FindAllStringSubmatch(optionsSection(t), -1) {
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

// manPageEntries splits the OPTIONS list into one body per documented flag.
func manPageEntries(t *testing.T) map[string]string {
	t.Helper()
	return optionEntries(t, optionsSection(t))
}

// optionsSection returns the OPTIONS section alone.
//
// These guards are about the flags of the root command, and the page also
// documents subcommand flags in their own sections -- `speedns diff` has its
// own --format, which is not a duplicate of the root one and is not a root flag
// at all. Scoping to the section keeps each guard asking the question it means.
func optionsSection(t *testing.T) string {
	t.Helper()
	page := manPage(t)
	start := strings.Index(page, ".SH OPTIONS")
	if start < 0 {
		t.Fatal("docs/speedns.1 has no OPTIONS section")
	}
	rest := page[start+len(".SH OPTIONS"):]
	if end := strings.Index(rest, "\n.SH "); end >= 0 {
		return rest[:end]
	}
	return rest
}

// optionEntries splits a section into one body per documented flag.
//
// It splits rather than matching a regexp with a trailing "\n.TP" delimiter.
// That delimiter CONSUMES the marker that starts the next entry, and Go's
// regexp scans on from the end of each match, so every second entry was
// skipped: on a 25-entry OPTIONS section the old pattern reported 13. Both
// guards built on this were therefore checking half the page.
func optionEntries(t *testing.T, section string) map[string]string {
	t.Helper()
	header := regexp.MustCompile(`^\.B (--[a-z][a-z0-9-]*)`)
	entries := make(map[string]string)
	for _, chunk := range strings.Split(section, "\n.TP\n") {
		match := header.FindStringSubmatch(chunk)
		if match == nil {
			continue
		}
		body := chunk
		if newline := strings.IndexByte(chunk, '\n'); newline >= 0 {
			body = chunk[newline+1:]
		}
		entries[match[1]] = body
	}
	if len(entries) == 0 {
		t.Fatal("no option entries found; the entry pattern no longer matches the page")
	}
	return entries
}

// TestManPageDocumentsOnlyRealFlags is the reverse of
// TestManPageDocumentsEveryFlag, which only checks that every real flag is
// present. Nothing stopped the page describing a flag the binary does not
// have -- a rename that updated the code and not the docs leaves the old name
// documented, and a reader of the packaged man page is told to use an option
// that exits 2.
func TestManPageDocumentsOnlyRealFlags(t *testing.T) {
	real := make(map[string]bool)
	newRootCommand().Flags().VisitAll(func(flag *pflag.Flag) { real[flag.Name] = true })

	var invented []string
	for name := range manPageEntries(t) {
		if !real[strings.TrimPrefix(name, "--")] {
			invented = append(invented, name)
		}
	}
	if len(invented) > 0 {
		sort.Strings(invented)
		t.Fatalf("docs/speedns.1 documents flags the binary does not have: %s", strings.Join(invented, ", "))
	}
}

// TestManPageStatesEveryDefault derives the expected values from pflag rather
// than restating them, so the page cannot quietly disagree with the binary
// after a default changes. Only flags whose default is meaningful to a reader
// are required: an empty string or a false boolean is the absence of an
// option, not a value worth printing.
func TestManPageStatesEveryDefault(t *testing.T) {
	entries := manPageEntries(t)
	var missing []string
	newRootCommand().Flags().VisitAll(func(flag *pflag.Flag) {
		// An empty string, a false boolean, a zero, or an empty repeatable
		// list are all the ABSENCE of an option rather than a value a reader
		// needs told. "[]" is what pflag reports for an unset --assert or
		// --resolver.
		switch flag.DefValue {
		case "", "false", "0", "[]":
			return
		}
		if flag.Hidden {
			return
		}
		body, documented := entries["--"+flag.Name]
		if !documented {
			return // TestManPageDocumentsEveryFlag owns that failure.
		}
		if !strings.Contains(body, flag.DefValue) {
			missing = append(missing, fmt.Sprintf("--%s (default %q)", flag.Name, flag.DefValue))
		}
	})
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("docs/speedns.1 does not state these defaults:\n  %s\n\nA reader of the packaged man page cannot discover them.",
			strings.Join(missing, "\n  "))
	}
}
