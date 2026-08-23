package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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
	assertions      []string
	family          string
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

var progressWriterFunc = func() io.Writer { return os.Stderr }

var newCacheMissNonceFunc = domains.NewCacheMissNonce

var listProvenanceInterfacesFunc = net.Interfaces
var listNetworkInterfacesFunc = net.Interfaces

var interfaceAddressesFunc = func(iface net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

var detectAddressFamiliesFunc = detectAddressFamilies

// exitCodes lists every status the command can return, so documentation can be
// checked against the contract rather than against a hand-kept list.
func exitCodes() []int { return []int{0, 2, 3, 4, 130} }

func exitCodeForError(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return 130
	case errors.Is(err, benchmark.ErrNoComparableResults):
		return 3
	case errors.Is(err, ErrAssertionsFailed):
		return 4
	default:
		return 2
	}
}

type progressRenderer struct {
	writer          io.Writer
	interactive     bool
	protocols       []catalog.Protocol
	states          map[catalog.Protocol]progressState
	printedPhases   map[catalog.Protocol]map[benchmark.ProgressPhase]bool
	lastLineWidth   int
	rendered        bool
	started         time.Time
	spinner         int
	refreshInterval time.Duration
	stop            chan struct{}
	done            chan struct{}
	finished        bool
	mu              sync.Mutex
}

type progressState struct {
	phase              benchmark.ProgressPhase
	targetsCompleted   int
	targetsTotal       int
	exchangesCompleted int
	exchangesTotal     int
}

// Write keeps diagnostics emitted by dependencies from corrupting an active
// interactive progress line. The benchmark installs the renderer as the
// standard logger's output for table runs; machine-readable runs discard
// dependency log noise so it cannot leak into a pipeline's stderr.
func (p *progressRenderer) Write(value []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.interactive || !p.rendered || p.finished {
		return p.writer.Write(value)
	}
	if _, err := fmt.Fprintf(p.writer, "\r%s\r", strings.Repeat(" ", p.lastLineWidth)); err != nil {
		return 0, err
	}
	n, err := p.writer.Write(value)
	if err != nil {
		return n, err
	}
	if len(value) == 0 || value[len(value)-1] != '\n' {
		if _, err := io.WriteString(p.writer, "\n"); err != nil {
			return n, err
		}
	}
	p.renderLocked(time.Now())
	return n, nil
}

const defaultProgressRefreshInterval = 500 * time.Millisecond

var progressSpinner = []string{"-", "\\", "|", "/"}

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

// measuredProtocols returns the protocol groups the benchmark will actually
// run, in the documented measurement order. It is derived from the expanded
// targets rather than from --protocol so a selected protocol that no resolver
// supports is not counted.
func measuredProtocols(targets []catalog.Target) []catalog.Protocol {
	protocols := make([]catalog.Protocol, 0, len(targets))
	for _, target := range targets {
		protocols = append(protocols, target.Protocol)
	}
	return canonicalProtocols(protocols)
}

func newProgressRenderer(writer io.Writer, interactive bool, selected []catalog.Protocol, targets []catalog.Target) *progressRenderer {
	progress := &progressRenderer{
		writer:          writer,
		interactive:     interactive,
		protocols:       canonicalProtocols(selected),
		states:          make(map[catalog.Protocol]progressState),
		printedPhases:   make(map[catalog.Protocol]map[benchmark.ProgressPhase]bool),
		refreshInterval: defaultProgressRefreshInterval,
	}
	for _, protocol := range progress.protocols {
		progress.states[protocol] = progressState{}
		progress.printedPhases[protocol] = make(map[benchmark.ProgressPhase]bool)
	}
	for _, target := range targets {
		state := progress.states[target.Protocol]
		state.targetsTotal++
		progress.states[target.Protocol] = state
	}
	return progress
}

func (p *progressRenderer) Start() {
	p.mu.Lock()
	if p.finished {
		p.mu.Unlock()
		return
	}
	if p.started.IsZero() {
		p.started = time.Now()
	}
	if p.interactive {
		p.renderLocked(time.Now())
		if p.stop == nil {
			p.stop = make(chan struct{})
			p.done = make(chan struct{})
			stop, done := p.stop, p.done
			interval := p.refreshInterval
			p.mu.Unlock()
			go p.refreshLoop(stop, done, interval)
			return
		}
	}
	p.mu.Unlock()
}

func (p *progressRenderer) refreshLoop(stop <-chan struct{}, done chan<- struct{}, interval time.Duration) {
	defer close(done)
	if interval <= 0 {
		interval = defaultProgressRefreshInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.mu.Lock()
			if !p.finished {
				p.renderLocked(time.Now())
			}
			p.mu.Unlock()
		case <-stop:
			return
		}
	}
}

func (p *progressRenderer) Update(update benchmark.Progress) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	if p.started.IsZero() {
		p.started = time.Now()
	}
	state := p.states[update.Protocol]
	if update.TargetsTotal > state.targetsTotal {
		state.targetsTotal = update.TargetsTotal
	}
	if update.TargetsCompleted > state.targetsCompleted {
		state.targetsCompleted = update.TargetsCompleted
	}
	if update.ExchangesTotal > state.exchangesTotal {
		state.exchangesTotal = update.ExchangesTotal
	}
	if update.ExchangesCompleted > state.exchangesCompleted {
		state.exchangesCompleted = update.ExchangesCompleted
	}
	phaseAccepted := progressPhaseRank(update.Phase) >= progressPhaseRank(state.phase)
	if phaseAccepted {
		state.phase = update.Phase
	}
	p.states[update.Protocol] = state
	if !phaseAccepted {
		return
	}
	p.renderUpdateLocked(update, time.Now())
}

func progressPhaseRank(phase benchmark.ProgressPhase) int {
	switch phase {
	case benchmark.ProgressPreparing:
		return 1
	case benchmark.ProgressMeasuring:
		return 2
	case benchmark.ProgressComplete:
		return 3
	default:
		return 0
	}
}

func (p *progressRenderer) renderUpdateLocked(update benchmark.Progress, now time.Time) {
	if p.interactive {
		p.renderLocked(now)
		return
	}
	if p.printedPhases[update.Protocol] == nil {
		p.printedPhases[update.Protocol] = make(map[benchmark.ProgressPhase]bool)
	}
	if p.printedPhases[update.Protocol][update.Phase] {
		return
	}
	state := p.states[update.Protocol]
	switch update.Phase {
	case benchmark.ProgressPreparing:
		_, _ = fmt.Fprintf(p.writer, "progress %s: preparing %d/%d targets\n", update.Protocol, state.targetsCompleted, state.targetsTotal)
	case benchmark.ProgressMeasuring:
		_, _ = fmt.Fprintf(p.writer, "progress %s: measuring %d/%d exchanges\n", update.Protocol, state.exchangesCompleted, state.exchangesTotal)
	case benchmark.ProgressComplete:
		_, _ = fmt.Fprintf(p.writer, "tested %s %d/%d targets\n", update.Protocol, state.targetsCompleted, state.targetsTotal)
	default:
		return
	}
	p.printedPhases[update.Protocol][update.Phase] = true
}

func (p *progressRenderer) renderLocked(now time.Time) {
	line := p.progressLineLocked(now)
	padding := ""
	lineWidth := displayWidth(line)
	if p.lastLineWidth > lineWidth {
		padding = strings.Repeat(" ", p.lastLineWidth-lineWidth)
	}
	_, _ = fmt.Fprintf(p.writer, "\r%s%s", line, padding)
	p.lastLineWidth = lineWidth
	p.rendered = true
}

// renderAt is a deterministic rendering seam for tests and callers that need
// to drive a refresh without waiting for the live ticker.
func (p *progressRenderer) renderAt(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	if p.started.IsZero() {
		p.started = now
	}
	p.renderLocked(now)
}

func (p *progressRenderer) progressLineLocked(now time.Time) string {
	parts := []string{"testing"}
	for _, protocol := range p.protocols {
		state := p.states[protocol]
		if state.targetsTotal == 0 {
			continue
		}
		switch state.phase {
		case benchmark.ProgressPreparing:
			parts = append(parts, fmt.Sprintf("%s preparing %d/%d", protocol, state.targetsCompleted, state.targetsTotal))
		case benchmark.ProgressMeasuring:
			parts = append(parts, fmt.Sprintf("%s measuring %d/%d", protocol, state.exchangesCompleted, state.exchangesTotal))
		case benchmark.ProgressComplete:
			parts = append(parts, fmt.Sprintf("%s done", protocol))
		default:
			parts = append(parts, fmt.Sprintf("%s queued", protocol))
		}
	}
	parts = append(parts, fmt.Sprintf("elapsed %s", progressElapsed(p.started, now)))
	parts = append(parts, progressSpinner[p.spinner%len(progressSpinner)])
	p.spinner++
	return strings.Join(parts, " | ")
}

func progressElapsed(started, now time.Time) string {
	if started.IsZero() || now.Before(started) {
		return "00:00"
	}
	seconds := int(now.Sub(started) / time.Second)
	hours := seconds / 3600
	minutes := (seconds / 60) % 60
	seconds %= 60
	if hours > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
	}
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
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
	if p.finished {
		p.mu.Unlock()
		return
	}
	p.finished = true
	stop, done := p.stop, p.done
	p.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
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

// activeInterfaceNames returns best-effort names of interfaces currently
// marked up. Names are useful provenance without exposing local addresses;
// an inventory failure must never prevent a DNS benchmark from completing.
func activeInterfaceNames() []string {
	interfaces, err := listProvenanceInterfacesFunc()
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{}, len(interfaces))
	names := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		name := strings.TrimSpace(iface.Name)
		if name == "" || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// detectAddressFamilies reports IP families present on an up interface. It
// deliberately performs no DNS lookup or connection attempt; auto mode uses
// the local interface inventory as a safe, offline bootstrap signal.
func detectAddressFamilies() (map[catalog.AddressFamily]bool, error) {
	interfaces, err := listNetworkInterfacesFunc()
	if err != nil {
		return nil, fmt.Errorf("inspect network interfaces: %w", err)
	}
	available := make(map[catalog.AddressFamily]bool)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := interfaceAddressesFunc(iface)
		if err != nil {
			return nil, fmt.Errorf("inspect addresses for interface %q: %w", iface.Name, err)
		}
		for _, address := range addresses {
			ip, ok := interfaceAddressIP(address)
			if !ok || !ip.IsGlobalUnicast() {
				continue
			}
			if ip.To4() != nil {
				// IPv4 accepts RFC 1918 addresses because NAT makes a
				// private v4 address an ordinary path to the Internet.
				available[catalog.Family4] = true
				continue
			}
			// IPv6 has no NAT equivalent, so a unique-local address
			// (fc00::/7, which covers Tailscale's fd7a::/48 and the ULAs
			// many home routers hand out) is not evidence of a public
			// route even though net.IP.IsGlobalUnicast reports true for
			// it. Requiring a non-private address keeps auto mode from
			// selecting IPv6 targets that cannot be reached.
			if ip.IsPrivate() {
				continue
			}
			available[catalog.Family6] = true
		}
	}
	return available, nil
}

func interfaceAddressIP(address net.Addr) (net.IP, bool) {
	switch value := address.(type) {
	case *net.IPNet:
		return value.IP, value.IP != nil
	case *net.IPAddr:
		return value.IP, value.IP != nil
	default:
		return nil, false
	}
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
	addBenchmarkFlags(root, config)
	root.AddCommand(newRunCommand(config))
	root.AddCommand(newResolversCommand())
	root.AddCommand(newCorpusCommand())
	root.AddCommand(newCompletionCommand())
	root.AddCommand(newVersionCommand())
	return root
}

func addBenchmarkFlags(command *cobra.Command, config *cliConfig) {
	flags := command.Flags()
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
	flags.StringArrayVar(&config.assertions, "assert", nil, "assert a winner metric or profile condition (repeatable)")
	flags.StringVar(&config.family, "family", "auto", "resolver address family: 4, 6, both, or auto")
}

func newRunCommand(config *cliConfig) *cobra.Command {
	command := &cobra.Command{
		Use:          "run",
		Short:        "Run a DNS resolver benchmark explicitly",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBenchmark(cmd.Context(), config)
		},
	}
	addBenchmarkFlags(command, config)
	return command
}

func newCompletionCommand() *cobra.Command {
	return &cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     "Generate shell completion scripts",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch strings.ToLower(strings.TrimSpace(args[0])) {
			case "bash":
				return cmd.Root().GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				return cmd.Root().GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletion(cmd.OutOrStdout())
			default:
				return fmt.Errorf("unsupported shell %q (choose bash, zsh, fish, or powershell)", args[0])
			}
		},
	}
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
	assertions, err := parseAssertions(config.assertions)
	if err != nil {
		return err
	}
	family, err := catalog.ParseAddressFamily(config.family)
	if err != nil {
		return err
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
	selection, err := loadProfilesFunc(ctx, config)
	if err != nil {
		return err
	}
	if err := catalog.Validate(selection.all()); err != nil {
		return err
	}
	availableFamilies := map[catalog.AddressFamily]bool{}
	if family == catalog.FamilyAuto {
		availableFamilies, err = detectAddressFamiliesFunc()
		if err != nil {
			return err
		}
	}
	profiles, err := catalog.FilterProfilesByFamily(selection.bundled(), family, availableFamilies)
	if err != nil {
		return err
	}
	// Auto mode is a heuristic over the local interface inventory, so it only
	// prunes the bundled catalog. Resolvers the operator named explicitly
	// (--resolver, --resolver-file, --include-system) survive auto untouched;
	// an explicit --family 4/6/both is a deliberate instruction and still
	// filters everything.
	explicitProfiles := selection.explicit()
	if family != catalog.FamilyAuto {
		explicitProfiles, err = catalog.FilterProfilesByFamily(selection.explicit(), family, availableFamilies)
		if err != nil {
			return err
		}
	}
	familyWarnings := autoFamilyWarnings(family, availableFamilies, selection.bundled(), profiles)
	profiles = append(profiles, explicitProfiles...)
	if len(profiles) == 0 {
		return fmt.Errorf("no resolver addresses match --family %s", family)
	}
	targets := catalog.Expand(profiles, selected)
	if len(targets) == 0 {
		return errors.New("no resolver supports the selected protocol(s)")
	}
	if err := validateAssertionTargets(assertions, targets); err != nil {
		return err
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
	var restoreLogOutput func()
	if strings.EqualFold(config.format, "table") {
		progressView = newProgressRenderer(progressWriterFunc(), terminalDetector(os.Stderr), selected, targets)
		progressView.Start()
		onProgress = progressView.Update
		previousLogWriter := log.Writer()
		log.SetOutput(progressView)
		restoreLogOutput = func() { log.SetOutput(previousLogWriter) }
	} else {
		previousLogWriter := log.Writer()
		log.SetOutput(io.Discard)
		restoreLogOutput = func() { log.SetOutput(previousLogWriter) }
	}
	defer restoreLogOutput()
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
	buildVersion, buildCommit, buildDate := version.Values()
	result.Provenance = &benchmark.RunProvenance{
		Version:       buildVersion,
		Commit:        buildCommit,
		BuildDate:     buildDate,
		OS:            runtime.GOOS,
		Architecture:  runtime.GOARCH,
		Interfaces:    activeInterfaceNames(),
		Protocols:     append([]catalog.Protocol(nil), canonicalProtocols(selected)...),
		CorpusEntries: len(domainList),
		CorpusSHA256:  domains.CorpusDigest(domainList),
		Timeout:       config.timeout,
		Concurrency:   effectiveConcurrency,
	}
	if concurrencyCapped {
		result.Warnings = append(result.Warnings, fmt.Sprintf("cache-miss mode capped concurrency at %d to limit reserved-zone traffic", domains.CacheMissMaxConcurrency))
	}
	if config.cacheMiss {
		// Every protocol group replays the same generated names against the
		// same resolver cache, so only the first group measured observes a
		// genuine miss; the rest measure a warm cache. Removing the bias,
		// rather than only disclosing it, is tracked as issue #108.
		if measured := measuredProtocols(targets); len(measured) > 1 {
			remaining := make([]string, 0, len(measured)-1)
			for _, protocol := range measured[1:] {
				remaining = append(remaining, protocol.String())
			}
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"cache-miss mode replays one generated name set across every protocol; only the first measured protocol (%s) observes a true cache miss, and later protocols (%s) run against an already warm resolver cache",
				measured[0], strings.Join(remaining, ", ")))
		}
	}
	result.Warnings = append(result.Warnings, familyWarnings...)
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
	return evaluateAssertions(result, assertions)
}

// profileSelection keeps the bundled catalog separate from resolvers the
// operator supplied explicitly so family auto-detection can prune only the
// former. The split lives here rather than in internal/catalog because the
// distinction is a CLI-input concern, not a catalog property.
type profileSelection struct {
	// profiles holds the bundled catalog first, then the explicit profiles.
	// They share one slice so catalog.Validate can normalize every profile in
	// place and still detect duplicate identifiers across both groups; taking
	// a copy here would silently drop the scalar trims Validate applies.
	profiles []catalog.ResolverProfile
	// explicitFrom is the index in profiles where explicit profiles begin.
	explicitFrom int
}

// all returns every selected profile, bundled first, backed by the same array
// the split views use.
func (selection profileSelection) all() []catalog.ResolverProfile {
	return selection.profiles
}

// bundled returns the profiles that came from the built-in catalog.
func (selection profileSelection) bundled() []catalog.ResolverProfile {
	return selection.profiles[:selection.explicitFrom]
}

// explicit returns the profiles the operator named through --resolver,
// --resolver-file or --include-system.
func (selection profileSelection) explicit() []catalog.ResolverProfile {
	return selection.profiles[selection.explicitFrom:]
}

func loadProfiles(ctx context.Context, config *cliConfig) (profileSelection, error) {
	var selection profileSelection
	if !config.noDefaults {
		selection.profiles = append(selection.profiles, catalog.DefaultResolvers()...)
	}
	// Everything appended from here on was named by the operator.
	selection.explicitFrom = len(selection.profiles)
	if config.resolverFile != "" {
		file, err := os.Open(config.resolverFile)
		if err != nil {
			return profileSelection{}, fmt.Errorf("open resolver file: %w", err)
		}
		fromFile, loadErr := catalog.LoadYAML(file)
		_ = file.Close()
		if loadErr != nil {
			return profileSelection{}, loadErr
		}
		selection.profiles = append(selection.profiles, fromFile...)
	}
	for _, raw := range config.resolverFlags {
		profile, err := catalog.ParseResolverFlag(raw)
		if err != nil {
			return profileSelection{}, err
		}
		selection.profiles = append(selection.profiles, profile)
	}
	if config.includeSystem {
		fromSystem, err := discoverSystemResolvers(ctx)
		if err != nil {
			return profileSelection{}, err
		}
		selection.profiles = append(selection.profiles, fromSystem...)
	}
	if len(selection.profiles) == 0 {
		return profileSelection{}, errors.New("no resolver profiles selected")
	}
	return selection, nil
}

// autoFamilyWarnings reports what --family auto pruned from the bundled
// catalog so the reduced comparison table is visible rather than silent.
func autoFamilyWarnings(family catalog.AddressFamily, available map[catalog.AddressFamily]bool, before, after []catalog.ResolverProfile) []string {
	if family != catalog.FamilyAuto {
		return nil
	}
	dropped := countProfileAddresses(before) - countProfileAddresses(after)
	if dropped <= 0 {
		return nil
	}
	return []string{fmt.Sprintf("--family auto detected %s on local interfaces and dropped %d bundled resolver address(es) from other families", describeFamilies(available), dropped)}
}

func countProfileAddresses(profiles []catalog.ResolverProfile) int {
	total := 0
	for _, profile := range profiles {
		total += len(profile.Addresses)
	}
	return total
}

// describeFamilies names the detected families. Callers only reach it once at
// least one family was detected; with none detected auto retains both literal
// families, so nothing is dropped and no warning is produced.
func describeFamilies(available map[catalog.AddressFamily]bool) string {
	var names []string
	if available[catalog.Family4] {
		names = append(names, "IPv4")
	}
	if available[catalog.Family6] {
		names = append(names, "IPv6")
	}
	return strings.Join(names, " and ")
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
