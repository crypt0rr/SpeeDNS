package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

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

func WriteTable(writer io.Writer, report benchmark.Report, details bool) error {
	if _, err := fmt.Fprintf(writer, "SpeeDNS benchmark\nSeed: %d | sample: %d domains | query types: %s\n\n", report.Seed, report.SampleSize, queryTypes(report.QueryTypes)); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, "Recommendations\n"); err != nil {
		return err
	}
	protocols := make([]catalog.Protocol, 0)
	seen := map[catalog.Protocol]bool{}
	for _, ranking := range report.Rankings {
		if !seen[ranking.Protocol] {
			seen[ranking.Protocol] = true
			protocols = append(protocols, ranking.Protocol)
		}
	}
	sort.Slice(protocols, func(i, j int) bool { return protocols[i] < protocols[j] })
	for _, protocol := range protocols {
		var winner benchmark.TargetResult
		found := false
		for _, ranking := range report.Rankings {
			if ranking.Protocol == protocol && ranking.Rank == 1 {
				winner, found = report.ResultFor(ranking.TargetID)
				break
			}
		}
		if !found {
			continue
		}
		marker := ""
		if winner.Stats.Recommended {
			marker = " *recommended*"
		}
		if _, err := fmt.Fprintf(writer, "  %-4s %-20s %-15s %-22s median %7.2f ms  p95 %7.2f ms  success %6.2f%%%s\n", protocol, winner.Target.DisplayName(), winner.Target.Address, winner.Target.Resolver.Policy, winner.Stats.MedianMS, winner.Stats.P95MS, winner.Stats.SuccessRate*100, marker); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(writer, "\nComparison\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "  Owner                 Address          Policy                         Protocol  Median       P95       Success  Score"); err != nil {
		return err
	}
	for _, result := range report.Targets {
		stats := result.Stats
		if stats.Scored == 0 {
			if _, err := fmt.Fprintf(writer, "  %-20s %-15s %-30s %-8s FAIL\n", result.Target.Resolver.Owner, result.Target.Address, result.Target.Resolver.Policy, result.Target.Protocol); err != nil {
				return err
			}
			continue
		}
		if details {
			if _, err := fmt.Fprintf(writer, "  %-20s %-15s %-30s %-8s %7.2f ms %7.2f ms %7.2f%% %7.2f ms cold %7.2f mad %7.2f\n", result.Target.Resolver.Owner, result.Target.Address, result.Target.Resolver.Policy, result.Target.Protocol, stats.MedianMS, stats.P95MS, stats.SuccessRate*100, stats.ScoreMS, stats.ColdMedianMS, stats.MADMS); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(writer, "  %-20s %-15s %-30s %-8s %7.2f ms %7.2f ms %7.2f%% %7.2f\n", result.Target.Resolver.Owner, result.Target.Address, result.Target.Resolver.Policy, result.Target.Protocol, stats.MedianMS, stats.P95MS, stats.SuccessRate*100, stats.ScoreMS); err != nil {
			return err
		}
	}
	if len(report.Warnings) > 0 {
		if _, err := io.WriteString(writer, "\nWarnings\n"); err != nil {
			return err
		}
		for _, warning := range report.Warnings {
			if _, err := fmt.Fprintf(writer, "  - %s\n", warning); err != nil {
				return err
			}
		}
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
