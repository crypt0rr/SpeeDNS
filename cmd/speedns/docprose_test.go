package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// TestShippedProseHasNoMergeResidue scans the documentation for the wreckage a
// merge-conflict resolution leaves when it keeps both sides.
//
// This has happened twice. Before v0.2.0, three README paragraphs and two
// man-page entries were duplicated, each pair holding a stale copy that
// contradicted the accurate one. Before v0.3.0, METHODOLOGY.md still carried
// three such blocks, one of them stating the opposite of what the code does
// about DoH reconnects. Nothing reads these files, so both survived every gate
// and shipped inside release archives.
//
// Two mechanical signatures are checked, and deliberately no more. A paragraph
// repeated verbatim is always a mistake, and a paragraph starting mid-sentence
// is always wreckage. Detecting a near-duplicate that CONTRADICTS its
// neighbour would need a natural-language linter, which would over-fire and be
// deleted; that residue is left to review.
// orphanedTailLimit is the longest first sentence still treated as a fragment.
// It sits between the longest real residue seen (45 characters) and the
// shortest legitimate lower-case opening in these documents (70).
const orphanedTailLimit = 60

// firstSentence returns the paragraph up to and including its first full stop.
// Go's regexp has no lookbehind, and a plain scan is clearer here anyway.
func firstSentence(paragraph string) string {
	for index, r := range paragraph {
		if r != '.' {
			continue
		}
		rest := paragraph[index+1:]
		if rest == "" || rest[0] == ' ' || rest[0] == '\n' {
			return paragraph[:index+1]
		}
	}
	return paragraph
}

func TestShippedProseHasNoMergeResidue(t *testing.T) {
	for _, name := range []string{"README.md", "METHODOLOGY.md", "CACHE_MISS.md", "CONTRIBUTING.md", "TESTING.md"} {
		content, err := os.ReadFile(filepath.Join("../..", name))
		if err != nil {
			continue
		}
		text := string(content)

		// Fenced blocks legitimately repeat lines and legitimately start with
		// a lowercase continuation, so they are removed before scanning.
		fence := regexp.MustCompile("(?s)```.*?```")
		text = fence.ReplaceAllString(text, "")

		seen := make(map[string]int)
		for index, block := range strings.Split(text, "\n\n") {
			paragraph := strings.TrimSpace(block)
			// Headings, list items and table rows are structure rather than
			// prose; they repeat and wrap for good reasons.
			if paragraph == "" || strings.HasPrefix(paragraph, "#") ||
				strings.HasPrefix(paragraph, "|") || strings.HasPrefix(paragraph, "- ") ||
				strings.HasPrefix(paragraph, ">") || strings.HasPrefix(paragraph, "<") {
				continue
			}
			// Only substantial paragraphs are checked for verbatim repetition:
			// a short line legitimately recurs across sections. The
			// mid-sentence check below has no such floor, because the shortest
			// residue seen was a bare 23-character fragment.
			if len(paragraph) >= 120 {
				if first, duplicate := seen[paragraph]; duplicate {
					t.Errorf("%s: the paragraph at block %d repeats block %d verbatim:\n  %.140s...",
						name, index, first, paragraph)
				}
				seen[paragraph] = index
			}

			// Merge residue opens with the TAIL of a sentence whose head lives
			// in the copy above it, so it both starts in lower case and
			// finishes that borrowed sentence almost immediately. Requiring
			// both signals is what separates it from ordinary prose: the
			// historical fragments closed after 6, 36 and 45 characters,
			// while a paragraph legitimately starting lower case -- "macOS
			// discovery gives...", or a sentence continuing from a code block
			// -- runs to 70 and beyond before its first full stop.
			if !unicode.IsLower([]rune(paragraph)[0]) {
				continue
			}
			if len(firstSentence(paragraph)) <= orphanedTailLimit {
				t.Errorf("%s: the paragraph at block %d begins mid-sentence, which is merge residue:\n  %.140s...",
					name, index, paragraph)
			}
		}
	}
}
