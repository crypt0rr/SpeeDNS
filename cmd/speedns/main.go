package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/crypt0rr/dns-speedtest/internal/benchmark"
	"github.com/crypt0rr/dns-speedtest/internal/catalog"
	"github.com/crypt0rr/dns-speedtest/internal/domains"
	"github.com/crypt0rr/dns-speedtest/internal/report"
	"github.com/crypt0rr/dns-speedtest/internal/systemdns"
	"github.com/crypt0rr/dns-speedtest/internal/version"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

type cliConfig struct {
	protocols     string
	resolverFlags []string
	resolverFile  string
	noDefaults    bool
	domainFile    string
	sample        int
	full          bool
	seed          int64
	queryTypes    string
	timeout       time.Duration
	concurrency   int
	includeSystem bool
	format        string
	output        string
	details       bool
	raw           bool
	noColor       bool
}

var exit = os.Exit

var runBenchmarkEngine = benchmark.Run

var discoverSystemResolvers = systemdns.Discover

var loadProfilesFunc = loadProfiles

var writeTableReport = report.WriteTableWithOptions
var writeJSONReport = report.WriteJSON
var writeCSVReport = report.WriteCSV

var terminalDetector = fileIsTerminal

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
		if p.lastLineWidth > len(line) {
			padding = strings.Repeat(" ", p.lastLineWidth-len(line))
		}
		_, _ = fmt.Fprintf(p.writer, "\r%s%s", line, padding)
		p.lastLineWidth = len(line)
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
	flags.IntVar(&config.sample, "sample", benchmark.DefaultSample, "number of domains to sample")
	flags.BoolVar(&config.full, "full", false, "test the complete embedded or custom domain list")
	flags.Int64Var(&config.seed, "seed", 0, "random seed (0 chooses and prints a new seed)")
	flags.StringVar(&config.queryTypes, "type", "A,AAAA", "comma-separated DNS record types")
	flags.DurationVar(&config.timeout, "timeout", benchmark.DefaultTimeout, "per-query and connection timeout")
	flags.IntVar(&config.concurrency, "concurrency", benchmark.DefaultConcurrency, "maximum resolver targets tested concurrently")
	flags.BoolVar(&config.includeSystem, "include-system", false, "include the configured system resolver as a baseline")
	flags.StringVar(&config.format, "format", "table", "output format: table, json, or csv")
	flags.StringVar(&config.output, "output", "", "write output to a file instead of stdout")
	flags.BoolVar(&config.details, "details", false, "show cold latency, jitter, response outcomes, and expanded metrics")
	flags.BoolVar(&config.raw, "raw", false, "include per-query observations in JSON output")
	flags.BoolVar(&config.noColor, "no-color", false, "disable terminal styling")

	root.AddCommand(newResolversCommand())
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
				sortStrings(protocols)
				fmt.Fprintf(cmd.OutOrStdout(), "%-16s %-22s %-24s %-34s %s\n", resolver.ID, resolver.Owner, strings.Join(resolver.Addresses, ","), resolver.Policy, strings.Join(protocols, ","))
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
	selected, err := parseProtocols(config.protocols)
	if err != nil {
		return err
	}
	queryTypes, err := parseQueryTypes(config.queryTypes)
	if err != nil {
		return err
	}
	domainList, err := domains.Load(config.domainFile)
	if err != nil {
		return err
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
		Seed: seed, Timeout: config.timeout, Concurrency: config.concurrency, Protocols: selected,
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
	writer, closeWriter, err := outputWriter(config.output)
	if err != nil {
		return err
	}
	defer closeWriter()
	if runErr != nil && (errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded)) {
		result.Warnings = append(result.Warnings, "benchmark interrupted before all targets completed")
	}
	switch strings.ToLower(config.format) {
	case "table":
		err = writeTableReport(writer, result, report.TableOptions{Details: config.details, Color: tableColorEnabled(config)})
	case "json":
		err = writeJSONReport(writer, result, config.raw)
	case "csv":
		err = writeCSVReport(writer, result)
	}
	if err != nil {
		return err
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

func outputWriter(path string) (io.Writer, func(), error) {
	if strings.TrimSpace(path) == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("create output file: %w", err)
	}
	return file, func() { _ = file.Close() }, nil
}

func sortStrings(values []string) {
	for i := 0; i < len(values); i++ {
		for j := i + 1; j < len(values); j++ {
			if values[j] < values[i] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
}
