package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/crypt0rr/SpeeDNS/internal/compare"
	"github.com/spf13/cobra"
)

// newDiffCommand builds the subcommand that compares two saved reports.
//
// It is a subcommand rather than a --baseline flag on a run: a flag would fuse
// measuring with comparing, so a user could not compare two archived reports
// without measuring again, and the comparability of the pair would be decided
// after the fact rather than constructed. This form needs no network at all.
func newDiffCommand() *cobra.Command {
	var format string
	var output string
	var required []string

	command := &cobra.Command{
		Use:   "diff BASELINE.json CURRENT.json",
		Short: "Compare what two saved runs measured",
		Long: "Compare two SpeeDNS JSON reports and report what each resolver did\n" +
			"differently: reachability, response codes, whether it answered, and its\n" +
			"DNSSEC verdict.\n\n" +
			"It never compares latency. The difference between two runs is dominated by\n" +
			"the network path and the time of day, which no field in a report records, so\n" +
			"no threshold computed from two reports can bound it. To compare resolver\n" +
			"speed, measure the resolvers together in one run.\n\n" +
			"Both runs must have asked the same questions. When they did not, the diff is\n" +
			"declined with the fields that differ and exits 3.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(cmd.OutOrStdout(), args[0], args[1], format, output, required)
		},
	}
	command.Flags().StringVar(&format, "format", "table", "output format: table or json")
	command.Flags().StringVar(&output, "output", "", "write the diff to a file instead of standard output")
	command.Flags().StringArrayVar(&required, "require", nil,
		"fail with status 4 unless a named condition holds, or 3 if no endpoint was compared: "+strings.Join(compare.RequireNames(), ", "))
	return command
}

func runDiff(stdout io.Writer, baselinePath, currentPath, format, output string, required []string) error {
	if format != "table" && format != "json" {
		return fmt.Errorf("unsupported output format %q (choose table or json)", format)
	}
	baseline, err := compare.Load(baselinePath)
	if err != nil {
		return err
	}
	current, err := compare.Load(currentPath)
	if err != nil {
		return err
	}
	diff := compare.Compare(baseline, current)

	// Conditions are validated before the diff is written, so a typo is a usage
	// error rather than a gate that appears to have run.
	var results []compare.RequireResult
	if len(required) > 0 {
		if results, err = compare.Require(diff, required); err != nil {
			return err
		}
	}

	if err := emitDiff(stdout, diff, format, output); err != nil {
		return err
	}

	// Order matters: a refusal outranks a condition. A gate that could not
	// evaluate must never report a pass.
	if !diff.Comparable() {
		return compare.ErrRunsNotComparable
	}
	// Every failed condition is named, in the order given, the way run
	// --assert reports every failed assertion: naming only the first would
	// cost a CI user one re-run per failure to learn the rest.
	failed := make([]string, 0, len(results))
	for _, result := range results {
		if !result.Passed {
			failed = append(failed, fmt.Sprintf("--require %s: %s", result.Name, result.Detail))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%w: %s", ErrAssertionsFailed, strings.Join(failed, "; "))
	}
	// A failure above read a real finding -- a target present in only one run
	// is reported without pairing -- so it stands even when nothing was
	// compared. A pass over zero compared endpoints describes nothing: no
	// condition examined a single paired count, so reporting it as a pass
	// would be a gate that could not evaluate saying everything is fine.
	if len(required) > 0 && diff.Compared == 0 {
		return fmt.Errorf("%w: 0 endpoint(s) compared, so no --require condition can pass (%s)",
			compare.ErrNothingCompared, notComparedSummary(diff))
	}
	return nil
}

// notComparedSummary names why a diff compared no endpoint, counting each
// reason, so a refused gate says what to fix rather than only that it refused.
// With nothing compared the only suppressions are the per-target ones that
// precede pairing, and every remaining target was present in one run only.
func notComparedSummary(diff compare.Diff) string {
	counts := make(map[string]int)
	for _, suppression := range diff.Suppressions {
		counts[suppression.Reason]++
	}
	reasons := make([]string, 0, len(counts))
	for reason := range counts {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	parts := make([]string, 0, len(reasons)+1)
	for _, reason := range reasons {
		parts = append(parts, fmt.Sprintf("%d %s", counts[reason], reason))
	}
	unpaired := 0
	for _, finding := range diff.Findings {
		if finding.Code == "PRESENCE" {
			unpaired++
		}
	}
	if unpaired > 0 {
		parts = append(parts, fmt.Sprintf("%d present in only one run", unpaired))
	}
	if len(parts) == 0 {
		return "neither run has a target"
	}
	return strings.Join(parts, ", ")
}

// emitDiff writes the diff to a file when one was named, and to stdout
// otherwise. The file path goes through the same atomic writer the run command
// uses, so a failed write leaves any previous diff untouched.
func emitDiff(stdout io.Writer, diff compare.Diff, format, output string) error {
	if output == "" {
		return writeDiff(stdout, diff, format)
	}
	writer, finalize, err := outputWriterFunc(output)
	if err != nil {
		return err
	}
	writeErr := writeDiff(writer, diff, format)
	if err := finalize(writeErr == nil); err != nil && writeErr == nil {
		writeErr = err
	}
	return writeErr
}

func writeDiff(writer io.Writer, diff compare.Diff, format string) error {
	if format == "json" {
		return compare.WriteJSON(writer, diff)
	}
	return compare.WriteTable(writer, diff)
}
