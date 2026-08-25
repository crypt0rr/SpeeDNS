package compare

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/crypt0rr/SpeeDNS/internal/safetext"
)

// notComparedNote is printed on every comparison. The absence of a latency
// verdict is a deliberate design decision, not an oversight, and a reader
// reaching for one deserves to be told why it is not there.
const notComparedNote = `WHAT IS NOT COMPARED
  Latency is not compared: not median, p95, score, rank, or any interval. The
  difference between two runs is dominated by the network path and the time of
  day, which no field in either report records, so no threshold computed from
  them can bound it. Six identical back-to-back runs on one host moved a
  target's p95 by 248%% and its score by 50%% with nothing changed. To compare
  resolver speed, measure them together in one run.
`

// WriteTable renders the diff for a human.
func WriteTable(writer io.Writer, diff Diff) error {
	if _, err := fmt.Fprintf(writer, "SpeeDNS run diff\n  baseline  %s  %s\n  current   %s  %s\n\n",
		safetext.Escape(diff.Baseline.Path), runStamp(diff.Baseline),
		safetext.Escape(diff.Current.Path), runStamp(diff.Current)); err != nil {
		return err
	}
	if !diff.Comparable() {
		return writeRefusal(writer, diff)
	}
	if _, err := fmt.Fprintf(writer, "COMPARABLE\n  Every gated run parameter matches. %d endpoint(s) compared.\n  This diff reports what each resolver did, never how fast it did it.\n",
		diff.Compared); err != nil {
		return err
	}
	if len(diff.Findings) > 0 {
		if _, err := io.WriteString(writer, "\nFINDINGS\n"); err != nil {
			return err
		}
		for _, finding := range diff.Findings {
			if _, err := fmt.Fprintf(writer, "  %-9s %-34s %s\n",
				finding.Code, safetext.Escape(finding.TargetID), safetext.Escape(finding.Detail)); err != nil {
				return err
			}
		}
	} else if diff.Compared > 0 {
		if _, err := fmt.Fprintf(writer, "\nWITHIN NOISE\n  %d endpoint(s) compared; no count moved beyond its floor.\n", diff.Compared); err != nil {
			return err
		}
	}
	if err := writeSection(writer, "NOT COMPARED", diff.Suppressions, func(s Suppression) string {
		return fmt.Sprintf("  %-20s %-34s %s\n", s.Reason, safetext.Escape(s.Scope), safetext.Escape(s.Detail))
	}); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "\n"+notComparedNote); err != nil {
		return err
	}
	return writeContext(writer, diff)
}

func writeRefusal(writer io.Writer, diff Diff) error {
	if _, err := io.WriteString(writer,
		"RUNS NOT COMPARABLE\n"+
			"  These two runs did not measure the same thing. No comparison is reported and\n"+
			"  no count from either report is shown.\n\n"); err != nil {
		return err
	}
	for _, blocker := range diff.Blockers {
		if _, err := fmt.Fprintf(writer, "  %-28s %s -> %s\n      %s\n",
			blocker.Field, safetext.Escape(blocker.Baseline), safetext.Escape(blocker.Current),
			safetext.Escape(blocker.Reason)); err != nil {
			return err
		}
	}
	_, err := io.WriteString(writer,
		"\n  This refusal is not a fault in either run. A comparison is declined because\n"+
			"  the two runs answer different questions, not because either measurement is\n"+
			"  wrong. Re-run the current benchmark with the baseline's parameters to\n"+
			"  produce a comparable pair.\n")
	return err
}

func writeContext(writer io.Writer, diff Diff) error {
	if len(diff.Disclosures) == 0 && len(diff.AddedWarnings) == 0 && len(diff.RemovedWarnings) == 0 {
		return nil
	}
	if _, err := io.WriteString(writer, "\nCONTEXT\n"); err != nil {
		return err
	}
	for _, disclosure := range diff.Disclosures {
		if _, err := fmt.Fprintf(writer, "  - %s\n", safetext.Escape(disclosure.Detail)); err != nil {
			return err
		}
	}
	// Warnings are echoed rather than turned into findings: every one is
	// derived from a statistic this diff already handles, so promoting them
	// would re-import the very claims the suppressions remove.
	for _, pair := range []struct {
		marker   string
		warnings []string
	}{{"+", diff.AddedWarnings}, {"-", diff.RemovedWarnings}} {
		for _, warning := range pair.warnings {
			if _, err := fmt.Fprintf(writer, "  %s %s\n", pair.marker, safetext.Escape(warning)); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeSection[T any](writer io.Writer, title string, items []T, render func(T) string) error {
	if len(items) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(writer, "\n%s\n", title); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := io.WriteString(writer, render(item)); err != nil {
			return err
		}
	}
	return nil
}

// jsonDiff is the compare-v1 document. On a refusal it carries no count from
// either report, matching the table.
type jsonDiff struct {
	SchemaVersion int           `json:"schema_version"`
	Comparable    bool          `json:"comparable"`
	Baseline      jsonSide      `json:"baseline"`
	Current       jsonSide      `json:"current"`
	Blockers      []Blocker     `json:"blockers"`
	Findings      []Finding     `json:"findings"`
	NotCompared   []Suppression `json:"not_compared"`
	Disclosures   []Disclosure  `json:"disclosures"`
	Warnings      jsonWarnings  `json:"warnings"`
	Compared      int           `json:"compared"`
}

type jsonSide struct {
	Path      string `json:"path"`
	StartedAt string `json:"started_at,omitempty"`
}

type jsonWarnings struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// WriteJSON renders the diff for a machine.
func WriteJSON(writer io.Writer, diff Diff) error {
	document := jsonDiff{
		SchemaVersion: 1,
		Comparable:    diff.Comparable(),
		Baseline:      jsonSide{Path: diff.Baseline.Path, StartedAt: stamp(diff.Baseline)},
		Current:       jsonSide{Path: diff.Current.Path, StartedAt: stamp(diff.Current)},
		Blockers:      orEmptyBlockers(diff.Blockers),
		Findings:      orEmptyFindings(diff.Findings),
		NotCompared:   orEmptySuppressions(diff.Suppressions),
		Disclosures:   orEmptyDisclosures(diff.Disclosures),
		Warnings:      jsonWarnings{Added: orEmptyStrings(diff.AddedWarnings), Removed: orEmptyStrings(diff.RemovedWarnings)},
		Compared:      diff.Compared,
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func runStamp(report Report) string {
	if report.Run == nil || report.Run.StartedAt.IsZero() {
		return "(no start time)"
	}
	return report.Run.StartedAt.UTC().Format("2006-01-02T15:04:05Z")
}

func stamp(report Report) string {
	if report.Run == nil || report.Run.StartedAt.IsZero() {
		return ""
	}
	return report.Run.StartedAt.UTC().Format("2006-01-02T15:04:05Z")
}

func orEmptyBlockers(items []Blocker) []Blocker {
	if items == nil {
		return []Blocker{}
	}
	return items
}

func orEmptyFindings(items []Finding) []Finding {
	if items == nil {
		return []Finding{}
	}
	return items
}

func orEmptySuppressions(items []Suppression) []Suppression {
	if items == nil {
		return []Suppression{}
	}
	return items
}

func orEmptyDisclosures(items []Disclosure) []Disclosure {
	if items == nil {
		return []Disclosure{}
	}
	return items
}

func orEmptyStrings(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}
