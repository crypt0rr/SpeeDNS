package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

	"github.com/crypt0rr/SpeeDNS/data"
	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/domains"
	"github.com/crypt0rr/SpeeDNS/internal/report"
	"github.com/crypt0rr/SpeeDNS/internal/systemdns"
	"github.com/crypt0rr/SpeeDNS/internal/textwidth"
	"github.com/crypt0rr/SpeeDNS/internal/version"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

type cliConfig struct {
	protocols       string
	resolverFlags   []string
	resolverFile    string
	noDefaults      bool
	domainFile      string
	skipInvalid     bool
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
	dnssec          bool
}

var exit = os.Exit

var runBenchmarkEngine = benchmark.Run

var discoverSystemResolvers = systemdns.Discover

var loadProfilesFunc = loadProfiles

var verifyCorpusFunc = data.VerifyCorpus

var writeTableReport = report.WriteTableWithOptions
var writeJSONReport = report.WriteJSONWithOptions
var writeCSVReport = report.WriteCSVWithOptions
var outputWriterFunc = outputWriter

var terminalDetector = fileIsTerminal

var progressWriterFunc = func() io.Writer { return os.Stderr }

var warningWriterFunc = func() io.Writer { return os.Stderr }

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

// shutdownSignals ask a running benchmark to stop.
var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

var notifySignals = signal.Notify
var stopSignals = signal.Stop

// interruptContext cancels the returned context on the first shutdown signal
// and releases the signal registration straight away, restoring the operating
// system default. A second Ctrl-C therefore terminates SpeeDNS immediately
// instead of being swallowed while the first one is still winding the run
// down. The returned stop function releases the registration and cancels the
// context; the exit status keeps coming from the cancelled run itself.
func interruptContext(ctx context.Context) (context.Context, func()) {
	runContext, cancel := context.WithCancel(ctx)
	signals := make(chan os.Signal, 1)
	notifySignals(signals, shutdownSignals...)
	go func() {
		select {
		case <-signals:
			stopSignals(signals)
			cancel()
		case <-runContext.Done():
		}
	}()
	return runContext, func() {
		stopSignals(signals)
		cancel()
	}
}

type progressRenderer struct {
	writer          io.Writer
	interactive     bool
	protocols       []catalog.Protocol
	states          map[catalog.Protocol]progressState
	phaseMilestones map[catalog.Protocol]map[benchmark.ProgressPhase]int
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

// cacheMissTargets keeps one endpoint per resolver profile and reports the
// endpoints it dropped.
//
// A resolver holds one cache, shared across every transport it offers and every
// address it answers on. So the first measurement of a generated name at a
// resolver is a genuine miss and every later measurement of that name at that
// resolver is a warm read, no matter which transport or address reaches it.
// Measuring a resolver once is what makes "cache miss" true of every query
// rather than only of whichever group happened to run first.
//
// catalog.Expand returns targets in documented protocol order, then by target
// ID, so the endpoint kept for a profile is its earliest declared transport at
// its lowest-sorting address -- deterministic across runs.
//
// The consequence is deliberate: a cache-miss run does not compare transports.
// Comparing transports needs the same name measured twice, which is exactly
// what makes the second measurement warm.
func cacheMissTargets(targets []catalog.Target) ([]catalog.Target, []string) {
	kept := make([]catalog.Target, 0, len(targets))
	dropped := make([]string, 0)
	measured := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if _, seen := measured[target.Resolver.ID]; seen {
			dropped = append(dropped, target.ID())
			continue
		}
		measured[target.Resolver.ID] = struct{}{}
		kept = append(kept, target)
	}
	return kept, dropped
}

func newProgressRenderer(writer io.Writer, interactive bool, selected []catalog.Protocol, targets []catalog.Target) *progressRenderer {
	progress := &progressRenderer{
		writer:          writer,
		interactive:     interactive,
		protocols:       canonicalProtocols(selected),
		states:          make(map[catalog.Protocol]progressState),
		phaseMilestones: make(map[catalog.Protocol]map[benchmark.ProgressPhase]int),
		refreshInterval: defaultProgressRefreshInterval,
	}
	for _, protocol := range progress.protocols {
		progress.states[protocol] = progressState{}
		progress.phaseMilestones[protocol] = make(map[benchmark.ProgressPhase]int)
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

// progressMilestoneSteps divides the work of a non-interactive phase into
// equal milestones, so a redirected run reports roughly every 25 percent of
// that phase instead of a single line that always reads zero. The step count
// keeps the log low-volume: at most five lines per phase and protocol.
const progressMilestoneSteps = 4

// progressPhaseSequence lists the phases in the order they are reached, so a
// superseded phase can be reported before the phase that replaced it.
var progressPhaseSequence = []benchmark.ProgressPhase{
	benchmark.ProgressPreparing,
	benchmark.ProgressMeasuring,
	benchmark.ProgressComplete,
}

// progressMilestone reports how many milestones of a phase are complete. A
// phase whose total is still unknown stays at the first milestone so its
// opening line is not mistaken for completion, and any progress at all past
// the total counts as the final milestone.
func progressMilestone(completed, total int) int {
	if total <= 0 || completed <= 0 {
		return 0
	}
	if completed >= total {
		return progressMilestoneSteps
	}
	return completed * progressMilestoneSteps / total
}

// progressPhaseUnits reports the counters a phase advances: measurement counts
// DNS exchanges, every other phase counts targets.
func progressPhaseUnits(phase benchmark.ProgressPhase, state progressState) (int, int) {
	if phase == benchmark.ProgressMeasuring {
		return state.exchangesCompleted, state.exchangesTotal
	}
	return state.targetsCompleted, state.targetsTotal
}

func (p *progressRenderer) renderUpdateLocked(update benchmark.Progress, now time.Time) {
	if p.interactive {
		p.renderLocked(now)
		return
	}
	if p.phaseMilestones[update.Protocol] == nil {
		p.phaseMilestones[update.Protocol] = make(map[benchmark.ProgressPhase]int)
	}
	// A phase can finish between two updates, so report the final state of
	// every phase this update supersedes before reporting the current one.
	for _, phase := range progressPhaseSequence {
		if progressPhaseRank(phase) >= progressPhaseRank(update.Phase) {
			break
		}
		if _, started := p.phaseMilestones[update.Protocol][phase]; started {
			p.emitPhaseLocked(update.Protocol, phase)
		}
	}
	p.emitPhaseLocked(update.Protocol, update.Phase)
}

// emitPhaseLocked writes one deterministic line for a phase the first time it
// is seen and again whenever it crosses a milestone. Lines carry counters
// only: no ETA and no resolver addresses.
func (p *progressRenderer) emitPhaseLocked(protocol catalog.Protocol, phase benchmark.ProgressPhase) {
	completed, total := progressPhaseUnits(phase, p.states[protocol])
	milestone := progressMilestone(completed, total)
	if reached, started := p.phaseMilestones[protocol][phase]; started && milestone <= reached {
		return
	}
	switch phase {
	case benchmark.ProgressPreparing:
		_, _ = fmt.Fprintf(p.writer, "progress %s: preparing %d/%d targets\n", protocol, completed, total)
	case benchmark.ProgressMeasuring:
		_, _ = fmt.Fprintf(p.writer, "progress %s: measuring %d/%d exchanges\n", protocol, completed, total)
	case benchmark.ProgressComplete:
		_, _ = fmt.Fprintf(p.writer, "tested %s %d/%d targets\n", protocol, completed, total)
	default:
		return
	}
	p.phaseMilestones[protocol][phase] = milestone
}

func (p *progressRenderer) renderLocked(now time.Time) {
	line := p.progressLineLocked(now)
	padding := ""
	lineWidth := textwidth.Display(line)
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
		fmt.Fprintln(os.Stderr, errorMessage(err))
		exit(exitCodeForError(err))
	}
}

// errorMessage renders err in user-facing language. A cancelled run means the
// user or the operating system interrupted SpeeDNS, so report that instead of
// the "context canceled" plumbing. Every other error keeps its own text.
func errorMessage(err error) string {
	if errors.Is(err, context.Canceled) {
		return "interrupted"
	}
	return err.Error()
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
	flags.BoolVar(&config.skipInvalid, "skip-invalid-domains", false, "skip unusable entries in --domains instead of failing the run")
	flags.BoolVar(&config.cacheMiss, "cache-miss", false, "opt in to bounded random names below the reserved example.com zone")
	flags.IntVar(&config.cacheMissSample, "cache-miss-sample", domains.CacheMissDefaultSample, "number of unique reserved-zone names for --cache-miss (maximum 20)")
	flags.IntVar(&config.sample, "sample", benchmark.DefaultSample, "number of domains to sample")
	flags.BoolVar(&config.full, "full", false, "test the complete embedded or custom domain list")
	flags.Int64Var(&config.seed, "seed", 0, "random seed (0 chooses and prints a new seed)")
	flags.StringVar(&config.queryTypes, "type", "A,AAAA", "comma-separated DNS record types; zone-transfer, meta and pseudo-record types are rejected")
	flags.DurationVar(&config.timeout, "timeout", benchmark.DefaultTimeout, "per-query and connection timeout")
	flags.IntVar(&config.concurrency, "concurrency", benchmark.DefaultConcurrency, "maximum concurrent target preparations and measured DNS exchanges per protocol")
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
	flags.BoolVar(&config.dnssec, "dnssec", false, "opt in to DNSSEC probing: set the EDNS(0) DO bit and run two pinned validation probes per target")
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
	var skippedDomains []string
	if config.cacheMiss {
		if strings.TrimSpace(config.domainFile) != "" {
			return errors.New("--cache-miss cannot be combined with --domains")
		}
		if config.full {
			return errors.New("--cache-miss cannot be combined with --full; use --cache-miss-sample")
		}
		if config.skipInvalid {
			return errors.New("--skip-invalid-domains cannot be combined with --cache-miss; generated names are always valid")
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
		corpus, loadErr := domains.LoadTolerant(config.domainFile, config.skipInvalid)
		if loadErr != nil {
			return loadErr
		}
		domainList = corpus.Names
		skippedDomains = corpus.Skipped
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
	var cacheMissDropped []string
	if config.cacheMiss {
		targets, cacheMissDropped = cacheMissTargets(targets)
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
	runContext, stop := interruptContext(ctx)
	defer stop()
	result, runErr := runBenchmarkEngine(runContext, targets, benchmark.Options{
		Domains: domainList, QueryTypes: queryTypes, Sample: config.sample, Full: config.full,
		Seed: seed, Timeout: config.timeout, Concurrency: effectiveConcurrency, Protocols: selected,
		OnProgress: onProgress, DNSSEC: config.dnssec, CacheMiss: config.cacheMiss,
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
	if len(skippedDomains) > 0 {
		// The corpus digest and entry count in provenance describe the names
		// that were measured, so the report must say the file held more.
		result.Warnings = append(result.Warnings, benchmark.RunWarning(fmt.Sprintf(
			"--skip-invalid-domains dropped %d unusable entries from %s: %s",
			len(skippedDomains), config.domainFile, strings.Join(skippedDomains, "; "))))
	}
	if concurrencyCapped {
		result.Warnings = append(result.Warnings, benchmark.RunWarning(fmt.Sprintf("cache-miss mode capped concurrency at %d to limit reserved-zone traffic", domains.CacheMissMaxConcurrency)))
	}
	if config.cacheMiss && config.sample < len(domainList) {
		result.Warnings = append(result.Warnings, benchmark.RunWarning(fmt.Sprintf(
			"effective sample of %d truncated the generated cache-miss corpus of %d names; raise --sample or lower --cache-miss-sample to measure every generated name",
			config.sample, len(domainList))))
	}
	if len(cacheMissDropped) > 0 {
		result.Warnings = append(result.Warnings, benchmark.RunWarning(fmt.Sprintf(
			"cache-miss mode measures each resolver once so every query is a genuine miss; it dropped %d endpoint(s) that share a cache with one already selected: %s",
			len(cacheMissDropped), strings.Join(cacheMissDropped, ", "))))
	}
	result.Warnings = append(result.Warnings, familyWarnings...)
	writer, finalizeOutput, err := outputWriterFunc(config.output)
	if err != nil {
		return err
	}
	if runErr != nil && (errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded)) {
		result.Warnings = append(result.Warnings, benchmark.RunWarning("benchmark interrupted before all targets completed"))
	}
	var reportErr error
	switch strings.ToLower(config.format) {
	case "table":
		reportErr = writeTableReport(writer, result, report.TableOptions{
			Details: config.details, Color: tableColorEnabled(config), ProfileView: config.profileView, RedactSystem: config.redactSystem, Profiles: profiles, Protocols: selected,
		})
	case "json":
		// One path, always through the seam. The former branch called the
		// package directly for redacted and profile-view runs, so every CLI
		// test that injects a report-write failure silently skipped those
		// cases - including the finalizeOutput(false) discard path below.
		reportErr = writeJSONReport(writer, result, config.raw, report.JSONOptions{
			RedactSystem: config.redactSystem, ProfileView: config.profileView,
		})
	case "csv":
		reportErr = writeCSVReport(writer, result, report.CSVOptions{RedactSystem: config.redactSystem})
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
		switch {
		case err == nil:
			selection.profiles = append(selection.profiles, fromSystem...)
		case len(selection.profiles) == 0:
			return profileSelection{}, err
		default:
			// Discovery can fail for reasons the run does not depend on, such
			// as an unsupported platform. Aborting would discard every other
			// selected resolver, so report it and continue.
			fmt.Fprintf(warningWriterFunc(), "warning: system resolver discovery failed: %v\n", err)
		}
	}
	if len(selection.profiles) == 0 {
		return profileSelection{}, errors.New("no resolver profiles selected")
	}
	return selection, nil
}

// autoFamilyWarnings reports what --family auto pruned from the bundled
// catalog so the reduced comparison table is visible rather than silent.
func autoFamilyWarnings(family catalog.AddressFamily, available map[catalog.AddressFamily]bool, before, after []catalog.ResolverProfile) []benchmark.Warning {
	if family != catalog.FamilyAuto {
		return nil
	}
	dropped := countProfileAddresses(before) - countProfileAddresses(after)
	if dropped <= 0 {
		return nil
	}
	return []benchmark.Warning{benchmark.RunWarning(fmt.Sprintf("--family auto detected %s on local interfaces and dropped %d bundled resolver address(es) from other families", describeFamilies(available), dropped))}
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

// rejectedQueryType explains why a DNS type may never be used as a QTYPE by
// the benchmark. "invalid" types are meta or pseudo records that cannot legally
// appear in a question section at all; "unsafe" types are syntactically valid
// questions that must not be aimed at a resolver under test.
type rejectedQueryType struct {
	kind   string
	reason string
}

// rejectedQueryTypes is a deny-list, not an allow-list: benchmarking an unusual
// but legitimate record type stays supported.
var rejectedQueryTypes = map[uint16]rejectedQueryType{
	dns.TypeOPT: {
		kind:   "invalid",
		reason: "OPT is an EDNS(0) pseudo-record that belongs in the additional section, and every query already carries its own",
	},
	dns.TypeTKEY: {
		kind:   "invalid",
		reason: "TKEY is a key-establishment meta-record, not a queryable type",
	},
	dns.TypeTSIG: {
		kind:   "invalid",
		reason: "TSIG is a transaction-signature meta-record, not a queryable type",
	},
	dns.TypeAXFR: {
		kind:   "unsafe",
		reason: "AXFR requests a full zone transfer, which recursive resolvers refuse",
	},
	dns.TypeIXFR: {
		kind:   "unsafe",
		reason: "IXFR requests an incremental zone transfer, which recursive resolvers refuse",
	},
	dns.TypeANY: {
		kind:   "unsafe",
		reason: "ANY is an obsolete meta-query that resolvers answer inconsistently or refuse",
	},
	dns.TypeMAILB: {
		kind:   "unsafe",
		reason: "MAILB is an obsolete meta-query with no defined resolver behaviour",
	},
	dns.TypeMAILA: {
		kind:   "unsafe",
		reason: "MAILA is an obsolete meta-query with no defined resolver behaviour",
	},
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
		if !ok {
			return nil, fmt.Errorf("unknown DNS query type %q", item)
		}
		if rejected, found := rejectedQueryTypes[qtype]; found {
			return nil, fmt.Errorf("%s DNS query type %q: %s", rejected.kind, item, rejected.reason)
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
var openOutputFile = func(path string) (outputFileHandle, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
}
var removeOutputFile = os.Remove
var renameOutputFile = os.Rename
var chmodOutputFile = os.Chmod
var createOutputProbeFile = func(path string) (io.Closer, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, ordinaryFileMode)
}

// ordinaryFileMode is the permission set an ordinary file creation asks for
// before the process umask narrows it. os.CreateTemp instead forces 0600, so a
// report written with --output would stay unreadable to everyone but its owner
// while the same bytes redirected by a shell would not.
const ordinaryFileMode fs.FileMode = 0o666

// outputProbeSuffix names the umask probe next to the temporary report file.
const outputProbeSuffix = ".mode"

// probeOrdinaryFileMode reports the permissions an ordinary file creation would
// receive at path, which is ordinaryFileMode narrowed by the process umask. Go
// exposes no portable way to read the umask, so create a throwaway file next to
// the report and observe what the operating system granted. A failed probe
// simply leaves the temporary file mode untouched.
func probeOrdinaryFileMode(path string) (fs.FileMode, bool) {
	probe, err := createOutputProbeFile(path)
	if err != nil {
		return 0, false
	}
	closeErr := probe.Close()
	info, statErr := os.Stat(path)
	_ = os.Remove(path)
	if closeErr != nil || statErr != nil {
		return 0, false
	}
	return info.Mode().Perm(), true
}

// directOutputWriter writes the report straight into the destination. It is
// used for destinations that cannot be replaced atomically, so a failed run
// can leave a partial report behind. Syncing is limited to regular files
// because flushing a device or a pipe is not meaningful.
func directOutputWriter(path string, syncOnCommit bool) (io.Writer, outputFinalizer, error) {
	file, err := openOutputFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open output file: %w", err)
	}
	finalize := func(commit bool) error {
		if !commit {
			if err := file.Close(); err != nil {
				return fmt.Errorf("discard output file: %w", err)
			}
			return nil
		}
		if syncOnCommit {
			if err := file.Sync(); err != nil {
				_ = file.Close()
				return fmt.Errorf("flush output file: %w", err)
			}
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close output file: %w", err)
		}
		return nil
	}
	return file, finalize, nil
}

// outputWriter replaces a regular destination atomically: the report is
// written to a temporary file in the destination directory and renamed over
// the target only after a successful run. Destinations that cannot be
// replaced that way are written in place instead. That covers non-regular
// files such as /dev/null, named pipes, and /proc file descriptors, plus a
// writable regular file inside a directory that rejects new entries.
func outputWriter(path string) (io.Writer, outputFinalizer, error) {
	if strings.TrimSpace(path) == "" || path == "-" {
		return os.Stdout, func(bool) error { return nil }, nil
	}
	info, err := statOutputPath(path)
	switch {
	case err == nil && info.IsDir():
		return nil, nil, fmt.Errorf("output path is a directory: %s", path)
	case err == nil && !info.Mode().IsRegular():
		return directOutputWriter(path, false)
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return nil, nil, fmt.Errorf("inspect output path: %w", err)
	}
	directory := filepath.Dir(path)
	base := filepath.Base(path)
	file, err := createTempOutputFile(directory, "."+base+".speedns-*")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return directOutputWriter(path, true)
		}
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
		// Permissions are best effort: a platform that refuses the change
		// still leaves a complete report behind, just with the restrictive
		// temporary-file mode.
		if mode, ok := probeOrdinaryFileMode(temporaryPath + outputProbeSuffix); ok {
			_ = chmodOutputFile(temporaryPath, mode)
		}
		if err := renameOutputFile(temporaryPath, path); err != nil {
			_ = removeOutputFile(temporaryPath)
			return fmt.Errorf("replace output file: %w", err)
		}
		return nil
	}
	return file, finalize, nil
}
