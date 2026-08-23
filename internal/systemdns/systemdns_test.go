package systemdns

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

type testReadCloser struct {
	io.Reader
	closed bool
}

var originalOpenResolvConf = openResolvConf
var originalRunScutil = runScutil

func (r *testReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestDiscoverLinuxResolverProfiles(t *testing.T) {
	oldOS := currentOS
	oldOpen := openResolvConf
	t.Cleanup(func() {
		currentOS = oldOS
		openResolvConf = oldOpen
	})
	currentOS = "linux"
	openResolvConf = func() (io.ReadCloser, error) {
		return &testReadCloser{Reader: strings.NewReader("# comment\nnameserver 192.0.2.1\nnameserver 192.0.2.1\nnameserver   2001:0DB8::1\nnameserver not-an-ip\nsearch example\n")}, nil
	}
	profiles, err := Discover(context.Background())
	if err != nil || len(profiles) != 2 {
		t.Fatalf("Discover profiles = %#v/%v", profiles, err)
	}
	if profiles[0].ID != "system-192-0-2-1" || profiles[1].ID != "system-2001-db8--1" {
		t.Fatalf("system profile IDs = %#v", profiles)
	}
	if profiles[1].Addresses[0] != "2001:db8::1" {
		t.Fatalf("IPv6 address normalization = %#v", profiles[1].Addresses)
	}
	if profiles[0].Transports["udp"].Port != 53 || profiles[0].Owner != "configured locally" {
		t.Fatalf("system profile metadata = %#v", profiles[0])
	}

	openResolvConf = func() (io.ReadCloser, error) {
		return &testReadCloser{Reader: strings.NewReader("# no nameservers\n")}, nil
	}
	if _, err := Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "no system nameservers") {
		t.Fatalf("empty discovery error = %v", err)
	}
	openResolvConf = func() (io.ReadCloser, error) { return nil, errors.New("open failed") }
	if _, err := Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "open failed") {
		t.Fatalf("open discovery error = %v", err)
	}
}

func TestDiscoverMacOSPreservesResolverBlocks(t *testing.T) {
	oldOS := currentOS
	oldOpen := openResolvConf
	oldRun := runScutil
	t.Cleanup(func() {
		currentOS = oldOS
		openResolvConf = oldOpen
		runScutil = oldRun
	})
	currentOS = "darwin"
	runScutil = func(context.Context) ([]byte, error) {
		return []byte(`DNS configuration

resolver #1
  search domain[0] : example.test
  search domain[1] : example.test
  nameserver[0] : 192.0.2.1
  nameserver[1] : 2001:db8::1
  nameserver[2] : not-an-ip
  nameserver[3] : 192.0.2.1
  if_index : 4 (en0)

resolver #2
  domain : corp.test
  nameserver[0] : 192.0.2.1
  if_index : 12 (utun3)

resolver #3
  domain : vpn.test
  nameserver[0] : 2001:db8::1
  if_index : 12

resolver #4
  nameserver[0] : 192.0.2.5
`), nil
	}
	profiles, err := Discover(context.Background())
	if err != nil || len(profiles) != 5 {
		t.Fatalf("macOS Discover profiles = %#v/%v", profiles, err)
	}
	if profiles[0].ID != "system-resolver-1-192-0-2-1" || profiles[2].ID != "system-resolver-2-192-0-2-1" {
		t.Fatalf("resolver block IDs = %#v", profiles)
	}
	if profiles[0].Scope != "example.test" || profiles[0].Interface != "en0" || !strings.Contains(profiles[0].Name, "scope: example.test") || !strings.Contains(profiles[0].Owner, "interface: en0") {
		t.Fatalf("global resolver metadata = %#v", profiles[0])
	}
	if profiles[2].Scope != "corp.test" || profiles[2].Interface != "utun3" {
		t.Fatalf("scoped resolver metadata = %#v", profiles[2])
	}
	if profiles[3].Scope != "vpn.test" || profiles[3].Interface != "if-index-12" {
		t.Fatalf("interface-index metadata = %#v", profiles[3])
	}
	if profiles[4].Scope != "global" || !strings.Contains(profiles[4].Name, "scope: global") {
		t.Fatalf("global scope metadata = %#v", profiles[4])
	}
}

func TestDiscoverMacOSFallbacks(t *testing.T) {
	oldOS := currentOS
	oldOpen := openResolvConf
	oldRun := runScutil
	oldTimeout := scutilTimeout
	t.Cleanup(func() {
		currentOS = oldOS
		openResolvConf = oldOpen
		runScutil = oldRun
		scutilTimeout = oldTimeout
	})
	currentOS = "darwin"
	openResolvConf = func() (io.ReadCloser, error) {
		return &testReadCloser{Reader: strings.NewReader("nameserver 192.0.2.9\n")}, nil
	}
	runScutil = func(context.Context) ([]byte, error) { return []byte("no resolver records\n"), nil }
	profiles, err := Discover(context.Background())
	if err != nil || len(profiles) != 1 || profiles[0].Addresses[0] != "192.0.2.9" {
		t.Fatalf("no-match fallback = %#v/%v", profiles, err)
	}
	runScutil = func(context.Context) ([]byte, error) { return nil, errors.New("scutil failed") }
	if profiles, err = Discover(context.Background()); err != nil || len(profiles) != 1 {
		t.Fatalf("command-error fallback = %#v/%v", profiles, err)
	}
	openResolvConf = func() (io.ReadCloser, error) { return nil, errors.New("fallback failed") }
	if _, err := Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "fallback failed") {
		t.Fatalf("fallback error = %v", err)
	}
}

func TestDiscoverMacOSScutilTimeoutFallsBack(t *testing.T) {
	oldOS := currentOS
	oldOpen := openResolvConf
	oldRun := runScutil
	oldTimeout := scutilTimeout
	t.Cleanup(func() {
		currentOS = oldOS
		openResolvConf = oldOpen
		runScutil = oldRun
		scutilTimeout = oldTimeout
	})
	currentOS = "darwin"
	scutilTimeout = 10 * time.Millisecond
	deadlineSeen := false
	runScutil = func(ctx context.Context) ([]byte, error) {
		_, deadlineSeen = ctx.Deadline()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	openResolvConf = func() (io.ReadCloser, error) {
		return &testReadCloser{Reader: strings.NewReader("nameserver 192.0.2.10\n")}, nil
	}
	profiles, err := Discover(context.Background())
	if err != nil || len(profiles) != 1 || profiles[0].Addresses[0] != "192.0.2.10" || !deadlineSeen {
		t.Fatalf("bounded scutil fallback = %#v/%v, deadline=%v", profiles, err, deadlineSeen)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	openResolvConf = func() (io.ReadCloser, error) { return nil, errors.New("fallback must not run") }
	runScutil = func(ctx context.Context) ([]byte, error) { return nil, ctx.Err() }
	if _, err := Discover(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled scutil discovery error = %v", err)
	}
}

func TestOpenResolvConfReadsTheConfiguredPath(t *testing.T) {
	oldPath := resolvConfPath
	oldOpen := openResolvConf
	t.Cleanup(func() {
		resolvConfPath = oldPath
		openResolvConf = oldOpen
	})
	path := filepath.Join(t.TempDir(), "resolv.conf")
	contents := "# fixture\nnameserver 192.0.2.42\nnameserver 2001:db8::42\noptions edns0\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	resolvConfPath = path

	reader, err := originalOpenResolvConf()
	if err != nil {
		t.Fatalf("open fixture resolv.conf = %v", err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read fixture resolv.conf = %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close fixture resolv.conf = %v", err)
	}
	if string(raw) != contents {
		t.Fatalf("fixture resolv.conf contents = %q", string(raw))
	}

	openResolvConf = originalOpenResolvConf
	addresses, err := discoverResolvConf()
	if err != nil || len(addresses) != 2 || addresses[0] != "192.0.2.42" || addresses[1] != "2001:db8::42" {
		t.Fatalf("discoverResolvConf over the fixture = %#v/%v", addresses, err)
	}

	missing := filepath.Join(t.TempDir(), "absent.conf")
	resolvConfPath = missing
	if _, err := discoverResolvConf(); err == nil || !strings.Contains(err.Error(), "open "+missing) {
		t.Fatalf("missing resolv.conf error = %v", err)
	}
}

func TestScutilCommandQueriesDNSConfiguration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := scutilCommand(ctx)
	if base := filepath.Base(command.Path); base != "scutil" {
		t.Fatalf("scutil command path = %q", command.Path)
	}
	if len(command.Args) != 2 || command.Args[0] != "scutil" || command.Args[1] != "--dns" {
		t.Fatalf("scutil command args = %#v", command.Args)
	}
}

func TestRunScutilReportsCommandFailures(t *testing.T) {
	oldCommand := scutilCommand
	t.Cleanup(func() { scutilCommand = oldCommand })
	absent := filepath.Join(t.TempDir(), "absent-scutil")
	scutilCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, absent, "--dns")
	}
	output, err := originalRunScutil(context.Background())
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("runScutil over a missing binary = %q/%v", output, err)
	}
	if output != nil {
		t.Fatalf("runScutil output on failure = %q", output)
	}
}

func TestSystemSourceHelpers(t *testing.T) {
	if got, ok := normalizeAddress(" 192.0.2.1 "); !ok || got != "192.0.2.1" {
		t.Fatalf("normalized IPv4 = %q/%v", got, ok)
	}
	if got, ok := normalizeAddress("not-an-ip"); ok || got != "" {
		t.Fatalf("invalid IP = %q/%v", got, ok)
	}
	if got, ok := normalizeAddress(" FE80::1%en0 "); !ok || got != "fe80::1%en0" {
		t.Fatalf("normalized zoned IPv6 = %q/%v", got, ok)
	}
	if got, ok := normalizeAddress("::ffff:192.0.2.1"); !ok || got != "192.0.2.1" {
		t.Fatalf("normalized IPv4-mapped IPv6 = %q/%v", got, ok)
	}
	if isLocalStub("fe80::1%en0") {
		t.Fatal("link-local nameserver must not be labeled a local stub")
	}
	if got := uniqueStrings([]string{"", "scope", "scope", "other"}); strings.Join(got, ",") != "scope,other" {
		t.Fatalf("unique strings = %#v", got)
	}
	if got := sourceLabel(resolverSource{Block: 1}); got != "resolver block" {
		t.Fatalf("empty source label = %q", got)
	}
	if !isLocalStub("127.0.0.53") || !isLocalStub("::1") || isLocalStub("192.0.2.1") {
		t.Fatal("local stub detection is incorrect")
	}
	sources := []resolverSource{
		{Address: "192.0.2.1"},
		{Address: "192.0.2.1"},
		{Address: "bad"},
		{Address: "192.0.2.1", Block: 2, Scope: "vpn", Interface: "utun0"},
		{Address: "192.0.2.1", Block: 2, Scope: "vpn", Interface: "utun0"},
	}
	profiles := profilesFromSources(sources)
	if len(profiles) != 2 || profiles[0].ID != "system-192-0-2-1" || profiles[1].ID != "system-resolver-2-192-0-2-1" {
		t.Fatalf("source profiles = %#v", profiles)
	}
	stubProfiles := profilesFromSources([]resolverSource{{Address: "127.0.0.53"}, {Address: "::1"}})
	if len(stubProfiles) != 2 || stubProfiles[0].ID != "system-stub-127-0-0-53" || stubProfiles[0].Owner != "local stub/forwarder" || stubProfiles[0].Policy != "local forwarding (upstream unknown)" {
		t.Fatalf("stub profiles = %#v", stubProfiles)
	}
}

// TestLoopbackSourcesAreMarkedLocal keeps the stub classification available to
// the reporting layer. Without the flag the loopback stub is only labeled in
// prose, and ranking cannot tell it apart from a network resolver.
func TestLoopbackSourcesAreMarkedLocal(t *testing.T) {
	profiles := profilesFromSources([]resolverSource{
		{Address: "127.0.0.53"},
		{Address: "::1"},
		{Address: "192.0.2.1"},
		{Address: "127.0.0.1", Block: 3, Scope: "vpn", Interface: "utun0"},
	})
	if len(profiles) != 4 {
		t.Fatalf("profiles = %#v", profiles)
	}
	for index, wantLocal := range []bool{true, true, false, true} {
		if profiles[index].Local != wantLocal {
			t.Fatalf("profile %d (%s) Local = %v, want %v", index, profiles[index].ID, profiles[index].Local, wantLocal)
		}
	}
	if profiles[3].ID != "system-resolver-3-127-0-0-1" {
		t.Fatalf("scoped loopback profile ID = %q", profiles[3].ID)
	}
}

func TestDiscoverResolvConfReaderErrors(t *testing.T) {
	oldOpen := openResolvConf
	t.Cleanup(func() { openResolvConf = oldOpen })
	openResolvConf = func() (io.ReadCloser, error) { return nil, errors.New("cannot open") }
	if _, err := discoverResolvConf(); err == nil || !strings.Contains(err.Error(), "open /etc/resolv.conf") {
		t.Fatalf("open error = %v", err)
	}
	openResolvConf = func() (io.ReadCloser, error) {
		return &testReadCloser{Reader: errorReader{}}, nil
	}
	if _, err := discoverResolvConf(); err == nil || !strings.Contains(err.Error(), "read /etc/resolv.conf") {
		t.Fatalf("read error = %v", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// A link-local nameserver is the only resolver on a host whose router
// advertises one, so discovery must keep the zone instead of parsing the
// literal away.
func TestDiscoverKeepsZonedIPv6Nameserver(t *testing.T) {
	oldOS := currentOS
	oldOpen := openResolvConf
	oldScutil := runScutil
	t.Cleanup(func() {
		currentOS = oldOS
		openResolvConf = oldOpen
		runScutil = oldScutil
	})

	currentOS = "linux"
	openResolvConf = func() (io.ReadCloser, error) {
		return &testReadCloser{Reader: strings.NewReader("nameserver fe80::1%en0\n")}, nil
	}
	profiles, err := Discover(context.Background())
	if err != nil || len(profiles) != 1 {
		t.Fatalf("zoned discovery = %#v/%v", profiles, err)
	}
	if profiles[0].Addresses[0] != "fe80::1%en0" {
		t.Fatalf("zoned address = %#v", profiles[0].Addresses)
	}
	if profiles[0].ID != "system-fe80--1-en0" {
		t.Fatalf("zoned profile ID = %q", profiles[0].ID)
	}
	if family, ok := catalog.AddressFamilyForAddress(profiles[0].Addresses[0]); !ok || family != catalog.Family6 {
		t.Fatalf("zoned address family = %q/%v", family, ok)
	}

	currentOS = "darwin"
	runScutil = func(context.Context) ([]byte, error) {
		return []byte("resolver #1\n  nameserver[0] : fe80::1%en0\n  if_index : 4 (en0)\n"), nil
	}
	macProfiles, err := Discover(context.Background())
	if err != nil || len(macProfiles) != 1 || macProfiles[0].Addresses[0] != "fe80::1%en0" {
		t.Fatalf("macOS zoned discovery = %#v/%v", macProfiles, err)
	}
}

// A platform with no discovery implementation must tell the caller which
// platform is unsupported instead of handing back a missing Unix path.
func TestDiscoverUnsupportedPlatform(t *testing.T) {
	oldOS := currentOS
	oldOpen := openResolvConf
	t.Cleanup(func() {
		currentOS = oldOS
		openResolvConf = oldOpen
	})
	currentOS = "plan9"
	openResolvConf = func() (io.ReadCloser, error) {
		t.Error("resolv.conf must not be opened on an unsupported platform")
		return nil, errors.New("unexpected open")
	}

	profiles, err := Discover(context.Background())
	if profiles != nil || err == nil {
		t.Fatalf("unsupported discovery = %#v/%v", profiles, err)
	}
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("unsupported sentinel = %v", err)
	}
	var unsupported *UnsupportedPlatformError
	if !errors.As(err, &unsupported) || unsupported.OS != "plan9" {
		t.Fatalf("unsupported platform error = %v", err)
	}
	if !strings.Contains(err.Error(), "plan9") || strings.Contains(err.Error(), "resolv.conf") {
		t.Fatalf("unsupported platform message = %q", err.Error())
	}
}

// withWindowsAdapters points discovery at a fixed adapter table so the Windows
// path can be exercised on any host, the way the macOS path is exercised
// through recorded scutil output.
func withWindowsAdapters(t *testing.T, adapters []windowsAdapter, err error) {
	t.Helper()
	oldOS, oldDiscover, oldOpen := currentOS, discoverWindowsAdapters, openResolvConf
	t.Cleanup(func() {
		currentOS, discoverWindowsAdapters, openResolvConf = oldOS, oldDiscover, oldOpen
	})
	currentOS = "windows"
	discoverWindowsAdapters = func() ([]windowsAdapter, error) { return adapters, err }
	openResolvConf = func() (io.ReadCloser, error) {
		t.Error("resolv.conf must not be read on Windows")
		return nil, errors.New("unexpected open")
	}
}

// TestDiscoverWindowsKeepsAdaptersSeparate is the shape that matters on a
// Windows laptop: Wi-Fi and a VPN each configure their own resolvers, and a
// benchmark that folded them together would hide exactly the comparison the
// operator is running. Each adapter becomes its own numbered block, labeled
// with the name Windows itself shows.
func TestDiscoverWindowsKeepsAdaptersSeparate(t *testing.T) {
	withWindowsAdapters(t, []windowsAdapter{
		{Index: 12, Name: "Wi-Fi", Nameservers: []string{"192.168.1.1", "192.168.1.1", "fe80::1%12"}},
		{Index: 30, Name: "Corp VPN", Nameservers: []string{"192.168.1.1"}},
	}, nil)

	profiles, err := Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 3 {
		t.Fatalf("windows profiles = %#v", profiles)
	}
	// The duplicate within the Wi-Fi adapter is dropped; the same address on
	// a different adapter is a genuinely different resolver path and stays.
	got := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		got = append(got, profile.ID+" | "+profile.Name+" | "+profile.Addresses[0])
	}
	want := []string{
		"system-resolver-1-192-168-1-1 | System DNS (interface: Wi-Fi) | 192.168.1.1",
		"system-resolver-1-fe80--1-12 | System DNS (interface: Wi-Fi) | fe80::1%12",
		"system-resolver-2-192-168-1-1 | System DNS (interface: Corp VPN) | 192.168.1.1",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("profile %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestWindowsSourcesDropsUnusableEntries covers what must never reach a
// ranking: the site-local placeholders Windows lists on adapters with no IPv6
// DNS at all, and anything that is not an address. An adapter left with
// nothing does not consume a block number, so the report has no gaps.
func TestWindowsSourcesDropsUnusableEntries(t *testing.T) {
	sources := windowsSources([]windowsAdapter{
		{Index: 3, Name: "Ethernet", Nameservers: []string{"fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"}},
		{Index: 4, Name: "  ", Nameservers: []string{"not-an-address", "9.9.9.9"}},
		{Index: 0, Name: "", Nameservers: []string{"1.1.1.1"}},
	})
	if len(sources) != 2 {
		t.Fatalf("windows sources = %#v", sources)
	}
	if sources[0].Block != 1 || sources[0].Address != "9.9.9.9" || sources[0].Interface != "if-index-4" {
		t.Fatalf("first usable source = %#v", sources[0])
	}
	if sources[1].Block != 2 || sources[1].Address != "1.1.1.1" || sources[1].Interface != "" {
		t.Fatalf("unnamed source = %#v", sources[1])
	}
}

// TestWindowsInterfaceLabelFlattensAdapterNames guards the aligned report
// table: adapter names are user-editable in Windows, so a name carrying a
// newline or a run of tabs must not break the column layout downstream.
func TestWindowsInterfaceLabelFlattensAdapterNames(t *testing.T) {
	label := windowsInterfaceLabel(windowsAdapter{Index: 7, Name: "  Wi-Fi\n\t 5GHz  "})
	if label != "Wi-Fi 5GHz" {
		t.Fatalf("adapter label = %q", label)
	}
}

// TestDiscoverWindowsReportsFailures keeps the two failure modes distinct: the
// adapter table could not be read at all, and it was read but configured no
// usable resolver. The second is not an error from the API, so the package
// must produce the message itself.
func TestDiscoverWindowsReportsFailures(t *testing.T) {
	withWindowsAdapters(t, nil, errors.New("read Windows adapter addresses: access denied"))
	if _, err := Discover(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "access denied") {
		t.Fatalf("adapter read failure = %v", err)
	}

	withWindowsAdapters(t, []windowsAdapter{{Index: 9, Name: "Ethernet"}}, nil)
	if _, err := Discover(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "no system nameservers found") {
		t.Fatalf("empty adapter table = %v", err)
	}
}

// TestPlatformWindowsAdaptersIsBuildGated documents the seam: on a build that
// is not Windows the real reader is absent, and the placeholder says so rather
// than pretending the host has no resolvers. Discover never routes here in
// production because currentOS mirrors runtime.GOOS.
func TestPlatformWindowsAdaptersIsBuildGated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this build has the real adapter reader")
	}
	adapters, err := platformWindowsAdapters()
	if adapters != nil || err == nil || !strings.Contains(err.Error(), "not built for Windows") {
		t.Fatalf("placeholder reader = %#v/%v", adapters, err)
	}
}
