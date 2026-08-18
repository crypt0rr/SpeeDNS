package systemdns

import (
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
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
		return &testReadCloser{Reader: strings.NewReader("# comment\nnameserver 192.0.2.1\nnameserver 192.0.2.1\nnameserver   2001:db8::1\nsearch example\n")}, nil
	}
	profiles, err := Discover(context.Background())
	if err != nil || len(profiles) != 2 {
		t.Fatalf("Discover profiles = %#v/%v", profiles, err)
	}
	if profiles[0].ID != "system-192-0-2-1" || profiles[1].ID != "system-2001-db8--1" {
		t.Fatalf("system profile IDs = %#v", profiles)
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

func TestDiscoverMacOSAndFallbacks(t *testing.T) {
	oldOS := currentOS
	oldOpen := openResolvConf
	oldRun := runScutil
	oldPattern := macOSNameServer
	t.Cleanup(func() {
		currentOS = oldOS
		openResolvConf = oldOpen
		runScutil = oldRun
		macOSNameServer = oldPattern
	})
	currentOS = "darwin"
	runScutil = func(context.Context) ([]byte, error) {
		return []byte("nameserver[0] : 192.0.2.1\nnameserver[1] : 2001:db8::1\n"), nil
	}
	profiles, err := Discover(context.Background())
	if err != nil || len(profiles) != 2 {
		t.Fatalf("macOS Discover profiles = %#v/%v", profiles, err)
	}
	addresses, err := discoverMacOS(context.Background())
	if err != nil || len(addresses) != 2 || addresses[0] != "192.0.2.1" || addresses[1] != "2001:db8::1" {
		t.Fatalf("macOS addresses = %#v/%v", addresses, err)
	}
	macOSNameServer = regexp.MustCompile(`nameserver\[[0-9]+\] *: *(\S*)`)
	runScutil = func(context.Context) ([]byte, error) {
		return []byte("nameserver[0] : \nnameserver[1] : 192.0.2.2\n"), nil
	}
	profiles, err = Discover(context.Background())
	if err != nil || len(profiles) != 1 || profiles[0].Addresses[0] != "192.0.2.2" {
		t.Fatalf("blank macOS address filtering = %#v/%v", profiles, err)
	}

	macOSNameServer = oldPattern
	openResolvConf = func() (io.ReadCloser, error) {
		return &testReadCloser{Reader: strings.NewReader("nameserver 192.0.2.9\n")}, nil
	}
	runScutil = func(context.Context) ([]byte, error) { return []byte("no nameserver records\n"), nil }
	addresses, err = discoverMacOS(context.Background())
	if err != nil || len(addresses) != 1 || addresses[0] != "192.0.2.9" {
		t.Fatalf("no-match fallback = %#v/%v", addresses, err)
	}
	runScutil = func(context.Context) ([]byte, error) { return nil, errors.New("scutil failed") }
	if addresses, err = discoverMacOS(context.Background()); err != nil || len(addresses) != 1 {
		t.Fatalf("command-error fallback = %#v/%v", addresses, err)
	}

	macOSNameServer = regexp.MustCompile(`nameserver`)
	runScutil = func(context.Context) ([]byte, error) { return []byte("nameserver\n"), nil }
	addresses, err = discoverMacOS(context.Background())
	if err != nil || len(addresses) != 1 || addresses[0] != "192.0.2.9" {
		t.Fatalf("defensive match fallback = %#v/%v", addresses, err)
	}
	openResolvConf = func() (io.ReadCloser, error) { return nil, errors.New("fallback failed") }
	if _, err := discoverMacOS(context.Background()); err == nil || !strings.Contains(err.Error(), "fallback failed") {
		t.Fatalf("fallback error = %v", err)
	}
}

func TestDiscoverResolvConfReaderErrors(t *testing.T) {
	defaultOpen := openResolvConf
	defaultRun := runScutil
	file, _ := defaultOpen()
	if file != nil {
		_ = file.Close()
	}
	_, _ = defaultRun(context.Background())
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
