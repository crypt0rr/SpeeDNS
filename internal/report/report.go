package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/crypt0rr/dns-speedtest/internal/benchmark"
	"github.com/crypt0rr/dns-speedtest/internal/catalog"
)

type JSONReport struct {
	SchemaVersion int                 `json:"schema_version"`
	Run           JSONRun             `json:"run"`
	Results       []JSONResult        `json:"results"`
	Rankings      []benchmark.Ranking `json:"rankings"`
	Warnings      []string            `json:"warnings,omitempty"`
}

type JSONRun struct {
	StartedAt  string   `json:"started_at"`
	FinishedAt string   `json:"finished_at"`
	Seed       int64    `json:"seed"`
	SampleSize int      `json:"sample_size"`
	Queries    int      `json:"queries_per_target"`
	QueryTypes []uint16 `json:"query_types"`
}

type JSONResult struct {
	Target       JSONTarget                  `json:"target"`
	Stats        benchmark.Statistics        `json:"stats"`
	OpenError    string                      `json:"open_error,omitempty"`
	Observations []benchmark.Observation     `json:"samples,omitempty"`
	Cold         []benchmark.ColdObservation `json:"cold,omitempty"`
}

type JSONTarget struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Owner    string           `json:"owner"`
	Policy   string           `json:"policy"`
	Address  string           `json:"address"`
	Protocol catalog.Protocol `json:"protocol"`
}

type csvWriter interface {
	Write([]string) error
	Flush()
	Error() error
}

var newCSVWriter = func(writer io.Writer) csvWriter {
	return csv.NewWriter(writer)
}

func toJSON(report benchmark.Report, raw bool) JSONReport {
	results := make([]JSONResult, 0, len(report.Targets))
	for _, result := range report.Targets {
		jsonResult := JSONResult{
			Target: JSONTarget{
				ID: result.Target.ID(), Name: result.Target.DisplayName(),
				Owner: result.Target.Resolver.Owner, Policy: result.Target.Resolver.Policy,
				Address: result.Target.Address, Protocol: result.Target.Protocol,
			},
			Stats: result.Stats, OpenError: result.OpenError,
		}
		if raw {
			jsonResult.Observations = result.Observations
			jsonResult.Cold = result.Cold
		}
		results = append(results, jsonResult)
	}
	return JSONReport{
		SchemaVersion: 1,
		Run: JSONRun{
			StartedAt:  report.StartedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			FinishedAt: report.FinishedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			Seed:       report.Seed, SampleSize: report.SampleSize, Queries: report.Queries, QueryTypes: report.QueryTypes,
		},
		Results: results, Rankings: report.Rankings, Warnings: report.Warnings,
	}
}

func WriteJSON(writer io.Writer, report benchmark.Report, raw bool) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(toJSON(report, raw))
}

func WriteCSV(writer io.Writer, report benchmark.Report) error {
	writerCSV := newCSVWriter(writer)
	if err := writerCSV.Write([]string{
		"target_id", "name", "owner", "policy", "address", "protocol", "rank", "recommended", "tie",
		"total", "successes", "failures", "scored", "divergent", "truncated", "success_rate", "median_ms", "p95_ms",
		"min_ms", "max_ms", "mad_ms", "cold_median_ms", "score_ms", "ci_low_ms", "ci_high_ms", "open_error",
	}); err != nil {
		return err
	}
	for _, result := range report.Targets {
		rank := rankFor(report, result.Target.ID())
		stats := result.Stats
		row := []string{
			result.Target.ID(), result.Target.DisplayName(), result.Target.Resolver.Owner, result.Target.Resolver.Policy,
			result.Target.Address, result.Target.Protocol.String(), strconv.Itoa(rank), strconv.FormatBool(stats.Recommended),
			strconv.FormatBool(stats.Tie), strconv.Itoa(stats.Total), strconv.Itoa(stats.Successes), strconv.Itoa(stats.Failures),
			strconv.Itoa(stats.Scored), strconv.Itoa(stats.Divergent), strconv.Itoa(stats.Truncated), formatFloat(stats.SuccessRate), formatFloat(stats.MedianMS),
			formatFloat(stats.P95MS), formatFloat(stats.MinMS), formatFloat(stats.MaxMS), formatFloat(stats.MADMS),
			formatFloat(stats.ColdMedianMS), formatFloat(stats.ScoreMS), formatFloat(stats.CILowMS), formatFloat(stats.CIHighMS), result.OpenError,
		}
		if err := writerCSV.Write(row); err != nil {
			return err
		}
	}
	writerCSV.Flush()
	return writerCSV.Error()
}

func rankFor(report benchmark.Report, targetID string) int {
	for _, ranking := range report.Rankings {
		if ranking.TargetID == targetID {
			return ranking.Rank
		}
	}
	return 0
}

func formatFloat(value float64) string { return strconv.FormatFloat(value, 'f', 3, 64) }

type TableOptions struct {
	Details bool
	Color   bool
}

const (
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiReset  = "\x1b[0m"
)

func rankedResult(report benchmark.Report, protocol catalog.Protocol, rank int) (benchmark.TargetResult, bool) {
	for _, ranking := range report.Rankings {
		if ranking.Protocol != protocol || ranking.Rank != rank {
			continue
		}
		if result, ok := report.ResultFor(ranking.TargetID); ok {
			return result, true
		}
	}
	return benchmark.TargetResult{}, false
}

func recommendedResult(report benchmark.Report, protocol catalog.Protocol) (benchmark.TargetResult, bool) {
	for _, ranking := range report.Rankings {
		if ranking.Protocol != protocol {
			continue
		}
		result, ok := report.ResultFor(ranking.TargetID)
		if ok && result.Stats.Recommended {
			return result, true
		}
	}
	return benchmark.TargetResult{}, false
}

func reportProtocols(report benchmark.Report) []catalog.Protocol {
	seen := make(map[catalog.Protocol]bool)
	for _, result := range report.Targets {
		seen[result.Target.Protocol] = true
	}
	for _, ranking := range report.Rankings {
		seen[ranking.Protocol] = true
	}
	protocols := make([]catalog.Protocol, 0, len(seen))
	for _, protocol := range catalog.AllProtocols {
		if seen[protocol] {
			protocols = append(protocols, protocol)
			delete(seen, protocol)
		}
	}
	remaining := make([]catalog.Protocol, 0, len(seen))
	for protocol := range seen {
		remaining = append(remaining, protocol)
	}
	sort.Slice(remaining, func(i, j int) bool { return remaining[i] < remaining[j] })
	return append(protocols, remaining...)
}

func resultStatus(result benchmark.TargetResult) string {
	if result.Stats.Scored == 0 {
		return "FAILED"
	}
	if result.Stats.Recommended {
		return "QUALIFIED"
	}
	return "INELIGIBLE"
}

func styledStatus(status string, color bool) string {
	if !color {
		return status
	}
	colorCode := ""
	switch status {
	case "RECOMMENDED", "QUALIFIED":
		colorCode = ansiGreen
	case "PROVISIONAL", "INELIGIBLE":
		colorCode = ansiYellow
	case "FAILED":
		colorCode = ansiRed
	default:
		return status
	}
	return colorCode + status + ansiReset
}

func latencyText(value float64) string {
	if value == 0 {
		return "—"
	}
	return fmt.Sprintf("%.2f ms", value)
}

func percentText(value float64) string { return fmt.Sprintf("%.2f%%", value*100) }

func scoreText(result benchmark.TargetResult) string {
	if result.Stats.Scored == 0 {
		return "—"
	}
	return latencyText(result.Stats.ScoreMS)
}

func rankText(report benchmark.Report, targetID string) string {
	rank := rankFor(report, targetID)
	if rank == 0 {
		return "—"
	}
	return strconv.Itoa(rank)
}

func summaryRow(protocol catalog.Protocol, result benchmark.TargetResult, status string, color bool) []string {
	return []string{
		string(protocol), result.Target.Resolver.Owner, result.Target.Address, result.Target.Resolver.Policy,
		latencyText(result.Stats.MedianMS), latencyText(result.Stats.P95MS), percentText(result.Stats.SuccessRate),
		scoreText(result), styledStatus(status, color),
	}
}

func comparisonRow(report benchmark.Report, result benchmark.TargetResult, details bool, color bool) []string {
	row := []string{
		rankText(report, result.Target.ID()), result.Target.Resolver.Owner, result.Target.Address,
		result.Target.Resolver.Policy,
		latencyText(result.Stats.MedianMS), latencyText(result.Stats.P95MS), percentText(result.Stats.SuccessRate),
		scoreText(result),
	}
	if details {
		row = append(row,
			latencyText(result.Stats.ColdMedianMS), latencyText(result.Stats.MADMS),
			strconv.Itoa(result.Stats.Scored), strconv.Itoa(result.Stats.Failures),
			strconv.Itoa(result.Stats.Divergent), strconv.Itoa(result.Stats.Truncated), dialAddressText(result),
		)
	}
	return append(row, styledStatus(resultStatus(result), color))
}

func dialAddressText(result benchmark.TargetResult) string {
	if result.DialAddress == "" {
		return "—"
	}
	return result.DialAddress
}

func sortComparisonResults(report benchmark.Report, results []benchmark.TargetResult) {
	sort.SliceStable(results, func(i, j int) bool {
		leftRank := rankFor(report, results[i].Target.ID())
		rightRank := rankFor(report, results[j].Target.ID())
		if leftRank == 0 && rightRank != 0 {
			return false
		}
		if leftRank != 0 && rightRank == 0 {
			return true
		}
		if leftRank != 0 && rightRank != 0 && leftRank != rightRank {
			return leftRank < rightRank
		}
		if results[i].Target.Resolver.Owner != results[j].Target.Resolver.Owner {
			return results[i].Target.Resolver.Owner < results[j].Target.Resolver.Owner
		}
		return results[i].Target.Address < results[j].Target.Address
	})
}

func comparisonRows(report benchmark.Report, protocol catalog.Protocol, details bool, color bool) [][]string {
	results := make([]benchmark.TargetResult, 0)
	for _, result := range report.Targets {
		if result.Target.Protocol == protocol {
			results = append(results, result)
		}
	}
	sortComparisonResults(report, results)
	rows := make([][]string, 0, len(results))
	for _, result := range results {
		rows = append(rows, comparisonRow(report, result, details, color))
	}
	return rows
}

func writeAlignedTable(writer io.Writer, headers []string, rows [][]string) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	indent := func(values []string) string {
		copyValues := append([]string(nil), values...)
		copyValues[0] = "  " + copyValues[0]
		return strings.Join(copyValues, "\t")
	}
	if _, err := fmt.Fprintln(table, indent(headers)); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintln(table, indent(row)); err != nil {
			return err
		}
	}
	return table.Flush()
}

func summaryHeaders() []string {
	return []string{"Protocol", "Owner", "Address", "Policy", "Median", "P95", "Success", "Score", "Status"}
}

func comparisonHeaders(details bool) []string {
	headers := []string{"Rank", "Owner", "Address", "Policy", "Median", "P95", "Success", "Score"}
	if details {
		headers = append(headers, "Cold", "MAD", "Scored", "Failed", "Divergent", "Truncated", "Dial")
	}
	return append(headers, "Status")
}

func targetWarningLabel(result benchmark.TargetResult) string {
	return fmt.Sprintf("%s %s/%s", result.Target.DisplayName(), result.Target.Address, result.Target.Protocol)
}

func isTargetWarning(warning string, results []benchmark.TargetResult) bool {
	for _, result := range results {
		if strings.HasPrefix(warning, targetWarningLabel(result)) {
			return true
		}
	}
	return false
}

func compactWarnings(report benchmark.Report) []string {
	warnings := make([]string, 0)
	handled := make(map[string]bool)
	for _, protocol := range reportProtocols(report) {
		targets := make([]benchmark.TargetResult, 0)
		for _, result := range report.Targets {
			if result.Target.Protocol == protocol {
				targets = append(targets, result)
			}
		}
		if len(targets) == 0 {
			continue
		}
		allUnavailable := true
		failedQueries := 0
		totalQueries := 0
		for _, result := range targets {
			totalQueries += result.Stats.Total
			failedQueries += result.Stats.Failures
			if result.Stats.Total == 0 || result.Stats.Scored != 0 || result.Stats.Failures != result.Stats.Total {
				allUnavailable = false
			}
		}
		if allUnavailable {
			warnings = append(warnings, fmt.Sprintf("%s: %d/%d endpoints unavailable; %d/%d measured queries failed", protocol, len(targets), len(targets), failedQueries, totalQueries))
			for _, result := range targets {
				handled[result.Target.ID()] = true
			}
		}
	}
	for _, result := range report.Targets {
		if handled[result.Target.ID()] {
			continue
		}
		parts := make([]string, 0, 4)
		if result.OpenError != "" && result.Stats.Scored == 0 {
			parts = append(parts, "unavailable")
		}
		if result.Stats.Failures > 0 {
			parts = append(parts, fmt.Sprintf("%d/%d queries failed", result.Stats.Failures, result.Stats.Total))
		}
		if result.Stats.Divergent > 0 {
			parts = append(parts, fmt.Sprintf("%d divergent responses", result.Stats.Divergent))
		}
		if result.Stats.Truncated > 0 {
			parts = append(parts, fmt.Sprintf("%d truncated responses", result.Stats.Truncated))
		}
		if len(parts) > 0 {
			warnings = append(warnings, fmt.Sprintf("%s: %s", targetWarningLabel(result), strings.Join(parts, "; ")))
		}
	}
	for _, warning := range report.Warnings {
		if !isTargetWarning(warning, report.Targets) {
			warnings = append(warnings, warning)
		}
	}
	return warnings
}

func writeWarnings(writer io.Writer, report benchmark.Report, details bool) error {
	warnings := report.Warnings
	if !details {
		warnings = compactWarnings(report)
	}
	if len(warnings) == 0 {
		return nil
	}
	if _, err := io.WriteString(writer, "\nWarnings\n"); err != nil {
		return err
	}
	for _, warning := range warnings {
		if _, err := fmt.Fprintf(writer, "  - %s\n", warning); err != nil {
			return err
		}
	}
	return nil
}

func WriteTable(writer io.Writer, report benchmark.Report, details bool) error {
	return WriteTableWithOptions(writer, report, TableOptions{Details: details})
}

func WriteTableWithOptions(writer io.Writer, report benchmark.Report, options TableOptions) error {
	if _, err := fmt.Fprintf(writer, "SpeeDNS benchmark\nSeed: %d | sample: %d domains | query types: %s\n\n", report.Seed, report.SampleSize, queryTypes(report.QueryTypes)); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, "Recommendations\n"); err != nil {
		return err
	}
	protocols := reportProtocols(report)
	recommendations := make([][]string, 0, len(protocols))
	provisionals := make([][]string, 0, len(protocols))
	for _, protocol := range protocols {
		if winner, found := recommendedResult(report, protocol); found {
			recommendations = append(recommendations, summaryRow(protocol, winner, "RECOMMENDED", options.Color))
			continue
		}
		if winner, found := rankedResult(report, protocol, 1); found {
			provisionals = append(provisionals, summaryRow(protocol, winner, "PROVISIONAL", options.Color))
		}
	}
	if len(recommendations) == 0 {
		if _, err := fmt.Fprintf(writer, "  none qualified (minimum %d comparable samples and %.0f%% success)\n", benchmark.MinimumRecommendedSamples, benchmark.MinimumRecommendedSuccessRate*100); err != nil {
			return err
		}
	} else if err := writeAlignedTable(writer, summaryHeaders(), recommendations); err != nil {
		return err
	}
	if len(provisionals) > 0 {
		if _, err := io.WriteString(writer, "\nProvisional winners\n"); err != nil {
			return err
		}
		if err := writeAlignedTable(writer, summaryHeaders(), provisionals); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(writer, "\nComparisons\n"); err != nil {
		return err
	}
	for _, protocol := range protocols {
		if _, err := fmt.Fprintf(writer, "\nProtocol %s\n", strings.ToUpper(string(protocol))); err != nil {
			return err
		}
		rows := comparisonRows(report, protocol, options.Details, options.Color)
		if len(rows) == 0 {
			if _, err := io.WriteString(writer, "  no targets\n"); err != nil {
				return err
			}
			continue
		}
		if err := writeAlignedTable(writer, comparisonHeaders(options.Details), rows); err != nil {
			return err
		}
	}
	if err := writeWarnings(writer, report, options.Details); err != nil {
		return err
	}
	return nil
}

func queryTypes(types []uint16) string {
	names := make([]string, 0, len(types))
	for _, qtype := range types {
		names = append(names, benchmark.QueryTypeName(qtype))
	}
	return strings.Join(names, ",")
}
