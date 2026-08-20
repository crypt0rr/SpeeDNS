package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/crypt0rr/SpeeDNS/data"
	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/domains"
	"github.com/crypt0rr/SpeeDNS/internal/report"
	"github.com/crypt0rr/SpeeDNS/internal/systemdns"
	"github.com/crypt0rr/SpeeDNS/internal/version"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"golang.org/x/text/width"
)

type cliConfig struct {
	protocols       string
	resolverFlags   []string
	resolverFile    string
	noDefaults      bool
	domainFile      string
	cacheMiss       bool
	cacheMissSample int
	sample          int
	full            bool
	seed            int64
	queryTypes      string
	timeout         time.Duration
	concurrency     int
	includeSystem   bool
	format          string
	output          string
	details         bool
	profileView     bool
	raw             bool
	noColor         bool
	redactSystem    bool
}

var exit = os.Exit

var runBenchmarkEngine = benchmark.Run

var discoverSystemResolvers = systemdns.Discover

var loadProfilesFunc = loadProfiles

var verifyCorpusFunc = data.VerifyCorpus

var writeTableReport = report.WriteTableWithOptions
var writeJSONReport = report.WriteJSON
var writeCSVReport = report.WriteCSV
var outputWriterFunc = outputWriter

var terminalDetector = fileIsTerminal

var newCacheMissNonceFunc = domains.NewCacheMissNonce

func exitCodeForError(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return 130
	case errors.Is(err, benchmark.ErrNoComparableResults):
		return 3
	default:
		return 2
	}
}

type progressRenderer struct {
	writer        io.Writer
	interactive   bool
	protocols     []catalog.Protocol
	totals        map[catalog.Protocol]int
	completed     map[catalog.Protocol]int
	printed       map[catalog.Protocol]bool
	lastLineWidth int
	rendered      bool
	mu            sync.Mutex
}

func fileIsTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func canonicalProtocols(selected []catalog.Protocol) []catalog.Protocol {
	seen := make(map[catalog.Protocol]bool, len(selected))
	for _, protocol := range selected {
		seen[protocol] = true
	}
	protocols := make([]catalog.Protocol, 0, len(selected))
	for _, protocol := range catalog.AllProtocols {
		if seen[protocol] {
			protocols = append(protocols, protocol)
		}
	}
	return protocols
}

func newProgressRenderer(writer io.Writer, interactive bool, selected []catalog.Protocol, targets []catalog.Target) *progressRenderer {
	progress := &progressRenderer{
		writer:      writer,
		interactive: interactive,
		protocols:   canonicalProtocols(selected),
		totals:      make(map[catalog.Protocol]int),
		completed:   make(map[catalog.Protocol]int),
		printed:     make(map[catalog.Protocol]bool),
	}
	for _, target := range targets {
		progress.totals[target.Protocol]++
	}
	return progress
}

func (p *progressRenderer) Update(update benchmark.Progress) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if update.Completed > p.completed[update.Protocol] {
		p.completed[update.Protocol] = update.Completed
	}
	if update.Total > p.totals[update.Protocol] {
		p.totals[update.Protocol] = update.Total
	}
	if p.interactive {
		line := p.progressLine()
		padding := ""
		lineWidth := displayWidth(line)
		if p.lastLineWidth > lineWidth {
			padding = strings.Repeat(" ", p.lastLineWidth-lineWidth)
		}
		_, _ = fmt.Fprintf(p.writer, "\r%s%s", line, padding)
		p.lastLineWidth = lineWidth
		p.rendered = true
		return
	}
	if update.Completed >= p.totals[update.Protocol] && !p.printed[update.Protocol] {
		_, _ = fmt.Fprintf(p.writer, "tested %s %d/%d targets\n", update.Protocol, update.Completed, update.Total)
		p.printed[update.Protocol] = true
	}
}

func (p *progressRenderer) progressLine() string {
	parts := []string{"testing"}
	for _, protocol := range p.protocols {
		total := p.totals[protocol]
		if total == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %d/%d", protocol, p.completed[protocol], total))
	}
	return strings.Join(parts, " | ")
}

// displayWidth returns the number of terminal cells used by a progress line.
// Resolver metadata can contain Unicode, so byte length is not a safe measure
// when erasing the previous line. Combining marks occupy no cells and common
// wide/full-width characters occupy two.
func displayWidth(value string) int {
	result := 0
	for _, character := range value {
		if unicode.Is(unicode.Mn, character) || unicode.Is(unicode.Me, character) {
			continue
		}
		switch width.LookupRune(character).Kind() {
		case width.EastAsianWide, width.EastAsianFullwidth:
			result += 2
		default:
			result++
		}
	}
	return result
}

func (p *progressRenderer) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.interactive && p.rendered {
		_, _ = fmt.Fprintln(p.writer)
		p.rendered = false
	}
}

func tableColorEnabled(config *cliConfig) bool {
	if config.noColor || (strings.TrimSpace(config.output) != "" && config.output != "-") {
		return false
	}
	return terminalDetector(os.Stdout)
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(exitCodeForError(err))
	}
}

func newRootCommand() *cobra.Command {
	config := &cliConfig{}
	root := &cobra.Command{
		Use:           "speedns",
		Short:         "Compare DNS resolver performance across modern transports",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBenchmark(cmd.Context(), config)
		},
	}
	flags := root.Flags()
	flags.StringVar(&config.protocols, "protocol", "udp,tcp,doh,dot,doq", "comma-separated transports to test")
	flags.StringArrayVar(&config.resolverFlags, "resolver", nil, "custom resolver NAME=URI (repeatable)")
	flags.StringVar(&config.resolverFile, "resolver-file", "", "YAML resolver profile file")
	flags.BoolVar(&config.noDefaults, "no-defaults", false, "do not include bundled public resolvers")
	flags.StringVar(&config.domainFile, "domains", "", "newline-delimited domain list; defaults to the embedded corpus")
	flags.BoolVar(&config.cacheMiss, "cache-miss", false, "opt in to bounded random names below the reserved example.com zone")
	flags.IntVar(&config.cacheMissSample, "cache-miss-sample", domains.CacheMissDefaultSample, "number of unique reserved-zone names for --cache-miss (maximum 20)")
	flags.IntVar(&config.sample, "sample", benchmark.DefaultSample, "number of domains to sample")
	flags.BoolVar(&config.full, "full", false, "test the complete embedded or custom domain list")
	flags.Int64Var(&config.seed, "seed", 0, "random seed (0 chooses and prints a new seed)")
	flags.StringVar(&config.queryTypes, "type", "A,AAAA", "comma-separated DNS record types")
	flags.DurationVar(&config.timeout, "timeout", benchmark.DefaultTimeout, "per-query and connection timeout")
	flags.IntVar(&config.concurrency, "concurrency", benchmark.DefaultConcurrency, "maximum measured DNS exchanges in flight per protocol")
	flags.BoolVar(&config.includeSystem, "include-system", false, "include the configured system resolver as a baseline")
	flags.StringVar(&config.format, "format", "table", "output format: table, json, or csv")
	flags.StringVar(&config.output, "output", "", "write output to a file instead of stdout")
	flags.BoolVar(&config.details, "details", false, "show cold latency, jitter, response outcomes, and expanded metrics")
	flags.BoolVar(&config.profileView, "profile-view", false, "show same-resolver transport comparisons with score confidence intervals")
	flags.BoolVar(&config.raw, "raw", false, "include per-query observations in JSON output")
	flags.BoolVar(&config.noColor, "no-color", false, "disable terminal styling")
	flags.BoolVar(&config.redactSystem, "redact-system", false, "redact local system resolver addresses and labels in reports")

	root.AddCommand(newResolversCommand())
	root.AddCommand(newCorpusCommand())
	root.AddCommand(newVersionCommand())
	return root
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, _ []string) {
			buildVersion, buildCommit, buildDate := version.Values()
			fmt.Fprintf(cmd.OutOrStdout(), "speedns %s\ncommit: %s\nbuilt: %s\n", buildVersion, buildCommit, buildDate)
		},
	}
}

func newResolversCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "resolvers",
		Short: "List bundled resolver profiles and supported transports",
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, resolver := range catalog.DefaultResolvers() {
				protocols := make([]string, 0, len(resolver.Transports))
				for protocol := range resolver.Transports {
					protocols = append(protocols, protocol.String())
				}
				sort.Strings(protocols)
				fmt.Fprintf(cmd.OutOrStdout(), "%-16s %-22s %-24s %-34s %s\n", resolver.ID, resolver.Owner, strings.Join(resolver.Addresses, ","), resolver.Policy, strings.Join(protocols, ","))
			}
			return nil
		},
	}
}

func newCorpusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "corpus",
		Short: "Show the embedded domain corpus provenance and checksum",
		RunE: func(cmd *cobra.Command, _ []string) error {
			metadata, err := verifyCorpusFunc()
			if err != nil {
				return err
			}
			writer := cmd.OutOrStdout()
			fmt.Fprintln(writer, "SpeeDNS domain corpus")
			fmt.Fprintf(writer, "Source: %s\n", metadata.Source)
			fmt.Fprintf(writer, "List ID: %s\n", metadata.ListID)
			fmt.Fprintf(writer, "Retrieved: %s\n", metadata.RetrievedAt)
			fmt.Fprintf(writer, "Entries: %d\n", metadata.Entries)
			fmt.Fprintf(writer, "SHA-256: %s\n", metadata.SHA256)
			if metadata.DownloadURL != "" {
				fmt.Fprintf(writer, "Source URL: %s\n", metadata.DownloadURL)
			}
			return nil
		},
	}
}

func runBenchmark(ctx context.Context, config *cliConfig) error {
	switch strings.ToLower(config.format) {
	case "table", "json", "csv":
	default:
		return fmt.Errorf("unsupported output format %q (choose table, json, or csv)", config.format)
	}
	if config.sample <= 0 && !config.full {
		return errors.New("--sample must be greater than zero")
	}
	if config.timeout <= 0 || config.concurrency <= 0 {
		return errors.New("--timeout and --concurrency must be positive")
	}
	if config.profileView && strings.EqualFold(config.format, "csv") {
		return errors.New("--profile-view requires table or json output")
	}
	selected, err := parseProtocols(config.protocols)
	if err != nil {
		return err
	}
	queryTypes, err := parseQueryTypes(config.queryTypes)
	if err != nil {
		return err
	}
	corpusMode := benchmark.CorpusWarmCache
	corpusZone := ""
	corpusNonce := ""
	var domainList []string
	if config.cacheMiss {
		if strings.TrimSpace(config.domainFile) != "" {
			return errors.New("--cache-miss cannot be combined with --domains")
		}
		if config.full {
			return errors.New("--cache-miss cannot be combined with --full; use --cache-miss-sample")
		}
		corpusNonce, err = newCacheMissNonceFunc()
		if err != nil {
			return err
		}
		domainList, err = domains.CacheMissNames(corpusNonce, config.cacheMissSample)
		if err != nil {
			return err
		}
		corpusMode = benchmark.CorpusCacheMiss
		corpusZone = domains.CacheMissZone
	} else {
		domainList, err = domains.Load(config.domainFile)
		if err != nil {
			return err
		}
	}
	profiles, err := loadProfilesFunc(ctx, config)
	if err != nil {
		return err
	}
	if err := catalog.Validate(profiles); err != nil {
		return err
	}
	targets := catalog.Expand(profiles, selected)
	if len(targets) == 0 {
		return errors.New("no resolver supports the selected protocol(s)")
	}
	seed := config.seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	effectiveConcurrency := config.concurrency
	concurrencyCapped := false
	if config.cacheMiss && effectiveConcurrency > domains.CacheMissMaxConcurrency {
		effectiveConcurrency = domains.CacheMissMaxConcurrency
		concurrencyCapped = true
	}
	var progressView *progressRenderer
	var onProgress func(benchmark.Progress)
	if strings.EqualFold(config.format, "table") {
		progressView = newProgressRenderer(os.Stderr, terminalDetector(os.Stderr), selected, targets)
		onProgress = progressView.Update
	}
	runContext, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, runErr := runBenchmarkEngine(runContext, targets, benchmark.Options{
		Domains: domainList, QueryTypes: queryTypes, Sample: config.sample, Full: config.full,
		Seed: seed, Timeout: config.timeout, Concurrency: effectiveConcurrency, Protocols: selected,
		OnProgress: onProgress,
	})
	if progressView != nil {
		progressView.Finish()
	}
	if runErr != nil && result.FinishedAt.IsZero() {
		return runErr
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) && !errors.Is(runErr, context.DeadlineExceeded) && !errors.Is(runErr, benchmark.ErrNoComparableResults) {
		return runErr
	}
	result.CorpusMode = corpusMode
	result.CorpusZone = corpusZone
	result.CorpusNonce = corpusNonce
	if concurrencyCapped {
		result.Warnings = append(result.Warnings, fmt.Sprintf("cache-miss mode capped concurrency at %d to limit reserved-zone traffic", domains.CacheMissMaxConcurrency))
	}
	writer, finalizeOutput, err := outputWriterFunc(config.output)
	if err != nil {
		return err
	}
	if runErr != nil && (errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded)) {
		result.Warnings = append(result.Warnings, "benchmark interrupted before all targets completed")
	}
	var reportErr error
	switch strings.ToLower(config.format) {
	case "table":
		reportErr = writeTableReport(writer, result, report.TableOptions{
			Details: config.details, Color: tableColorEnabled(config), ProfileView: config.profileView, RedactSystem: config.redactSystem, Profiles: profiles, Protocols: selected,
		})
	case "json":
		if config.redactSystem || config.profileView {
			reportErr = report.WriteJSONWithOptions(writer, result, config.raw, report.JSONOptions{RedactSystem: config.redactSystem, ProfileView: config.profileView})
		} else {
			reportErr = writeJSONReport(writer, result, config.raw)
		}
	case "csv":
		if config.redactSystem {
			reportErr = report.WriteCSVWithOptions(writer, result, report.CSVOptions{RedactSystem: true})
		} else {
			reportErr = writeCSVReport(writer, result)
		}
	}
	if err := finalizeOutput(reportErr == nil); err != nil {
		if reportErr != nil {
			return fmt.Errorf("write report: %v; finalize output: %w", reportErr, err)
		}
		return err
	}
	if reportErr != nil {
		return reportErr
	}
	if runErr != nil {
		return runErr
	}
	return nil
}

func loadProfiles(ctx context.Context, config *cliConfig) ([]catalog.ResolverProfile, error) {
	var profiles []catalog.ResolverProfile
	if !config.noDefaults {
		profiles = append(profiles, catalog.DefaultResolvers()...)
	}
	if config.resolverFile != "" {
		file, err := os.Open(config.resolverFile)
		if err != nil {
			return nil, fmt.Errorf("open resolver file: %w", err)
		}
		fromFile, loadErr := catalog.LoadYAML(file)
		_ = file.Close()
		if loadErr != nil {
			return nil, loadErr
		}
		profiles = append(profiles, fromFile...)
	}
	for _, raw := range config.resolverFlags {
		profile, err := catalog.ParseResolverFlag(raw)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	if config.includeSystem {
		fromSystem, err := discoverSystemResolvers(ctx)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, fromSystem...)
	}
	if len(profiles) == 0 {
		return nil, errors.New("no resolver profiles selected")
	}
	return profiles, nil
}

func parseProtocols(value string) ([]catalog.Protocol, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("--protocol cannot be empty")
	}
	seen := map[catalog.Protocol]bool{}
	var protocols []catalog.Protocol
	for _, item := range strings.Split(value, ",") {
		protocol, err := catalog.ParseProtocol(item)
		if err != nil {
			return nil, err
		}
		if !seen[protocol] {
			seen[protocol] = true
			protocols = append(protocols, protocol)
		}
	}
	return protocols, nil
}

func parseQueryTypes(value string) ([]uint16, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("--type cannot be empty")
	}
	seen := map[uint16]bool{}
	var types []uint16
	for _, item := range strings.Split(value, ",") {
		name := strings.ToUpper(strings.TrimSpace(item))
		qtype, ok := dns.StringToType[name]
		if !ok {
			if numeric, err := strconv.ParseUint(name, 10, 16); err == nil {
				qtype = uint16(numeric)
				ok = true
			}
		}
		if !ok || qtype == dns.TypeANY {
			return nil, fmt.Errorf("unsupported or unsafe DNS query type %q", item)
		}
		if !seen[qtype] {
			seen[qtype] = true
			types = append(types, qtype)
		}
	}
	return types, nil
}

type outputFinalizer func(commit bool) error

type outputFileHandle interface {
	io.Writer
	Sync() error
	Close() error
	Name() string
}

var statOutputPath = os.Stat
var createTempOutputFile = func(directory, pattern string) (outputFileHandle, error) {
	return os.CreateTemp(directory, pattern)
}
var removeOutputFile = os.Remove
var renameOutputFile = os.Rename

func outputWriter(path string) (io.Writer, outputFinalizer, error) {
	if strings.TrimSpace(path) == "" || path == "-" {
		return os.Stdout, func(bool) error { return nil }, nil
	}
	if info, err := statOutputPath(path); err == nil && info.IsDir() {
		return nil, nil, fmt.Errorf("output path is a directory: %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("inspect output path: %w", err)
	}
	directory := filepath.Dir(path)
	base := filepath.Base(path)
	file, err := createTempOutputFile(directory, "."+base+".speedns-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create temporary output file: %w", err)
	}
	temporaryPath := file.Name()
	finalize := func(commit bool) error {
		if !commit {
			closeErr := file.Close()
			removeErr := removeOutputFile(temporaryPath)
			if closeErr != nil {
				return fmt.Errorf("discard output file: %w", closeErr)
			}
			if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return fmt.Errorf("remove temporary output file: %w", removeErr)
			}
			return nil
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			_ = removeOutputFile(temporaryPath)
			return fmt.Errorf("flush output file: %w", err)
		}
		if err := file.Close(); err != nil {
			_ = removeOutputFile(temporaryPath)
			return fmt.Errorf("close output file: %w", err)
		}
		if err := renameOutputFile(temporaryPath, path); err != nil {
			_ = removeOutputFile(temporaryPath)
			return fmt.Errorf("replace output file: %w", err)
		}
		return nil
	}
	return file, finalize, nil
}
