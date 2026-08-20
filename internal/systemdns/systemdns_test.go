package systemdns

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type testReadCloser struct {
	io.Reader
	closed bool
}

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

func TestSystemSourceHelpers(t *testing.T) {
	if got, ok := normalizeAddress(" 192.0.2.1 "); !ok || got != "192.0.2.1" {
		t.Fatalf("normalized IPv4 = %q/%v", got, ok)
	}
	if got, ok := normalizeAddress("not-an-ip"); ok || got != "" {
		t.Fatalf("invalid IP = %q/%v", got, ok)
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
