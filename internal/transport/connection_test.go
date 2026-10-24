package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// connectionOf reads the optional Connection method every session offers.
func connectionOf(t *testing.T, session Session) ConnectionInfo {
	t.Helper()
	described, ok := session.(interface{ Connection() ConnectionInfo })
	if !ok {
		t.Fatalf("%T does not describe its connection", session)
	}
	return described.Connection()
}

// stubLookup answers every hostname lookup with addresses, in that order.
func stubLookup(t *testing.T, addresses ...string) {
	t.Helper()
	old := lookupNetIP
	t.Cleanup(func() { lookupNetIP = old })
	lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		resolved := make([]netip.Addr, 0, len(addresses))
		for _, address := range addresses {
			resolved = append(resolved, netip.MustParseAddr(address))
		}
		return resolved, nil
	}
}

// TestEveryTransportReportsThePeerItReached pins #242: dial_address is the
// configured candidate, which for a hostname endpoint is the hostname:port on
// every transport but UDP, so the peer a connection actually reached -- and
// with it the address family -- has to be recorded separately, for every
// transport.
func TestEveryTransportReportsThePeerItReached(t *testing.T) {
	const serverName = "dns.example"
	certificate, roots := testServerCertificate(t, serverName)

	t.Run("udp", func(t *testing.T) {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		t.Cleanup(func() { close(stop); _ = conn.Close() })
		go serveUDP(conn, stop)
		// LookupNetIP hands IPv4 back mapped; the reported peer is the
		// unmapped literal the session sends to.
		stubLookup(t, "::ffff:127.0.0.1")
		port := strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port)
		session, err := (&udpFactory{address: net.JoinHostPort(serverName, port), timeout: time.Second}).Open(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
			t.Fatal(err)
		}
		want := ConnectionInfo{RemoteAddress: net.JoinHostPort("127.0.0.1", port)}
		if got := connectionOf(t, session); got != want {
			t.Fatalf("UDP connection = %#v, want %#v", got, want)
		}
	})

	t.Run("tcp", func(t *testing.T) {
		listener := listenLoopback(t)
		stop := make(chan struct{})
		t.Cleanup(func() { close(stop); _ = listener.Close() })
		go serveTCPCounting(listener, stop, nil)
		session, err := (&streamFactory{address: listener.Addr().String(), timeout: time.Second}).Open(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		want := ConnectionInfo{RemoteAddress: listener.Addr().String()}
		if got := connectionOf(t, session); got != want {
			t.Fatalf("TCP connection = %#v, want %#v", got, want)
		}
	})

	t.Run("dot", func(t *testing.T) {
		listener := listenLoopback(t)
		serveDoTCandidate(t, listener, &tls.Config{Certificates: []tls.Certificate{certificate}}, func(int32) candidateMode {
			return candidateAnswers
		})
		session, err := dotFixtureFactory(roots, time.Second, listener.Addr().String()).Open(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		want := ConnectionInfo{RemoteAddress: listener.Addr().String(), TLSVersion: "TLS 1.3"}
		if got := connectionOf(t, session); got != want {
			t.Fatalf("DoT connection = %#v, want %#v", got, want)
		}
	})

	t.Run("doq", func(t *testing.T) {
		listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"doq"},
		}, &quic.Config{MaxIdleTimeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		serveDoQCandidate(t, listener, func(int32) candidateMode { return candidateAnswers })
		// A hostname candidate goes through the same lookup UDP uses rather
		// than quic-go's own IPv4-first resolution.
		stubLookup(t, "127.0.0.1")
		port := strconv.Itoa(listener.Addr().(*net.UDPAddr).Port)
		hostname := net.JoinHostPort(serverName, port)
		factory := &doqFactory{
			connectionPlan: dialPlan{addresses: []string{hostname}, timeout: time.Second},
			timeout:        time.Second,
			tlsConfig:      &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots, NextProtos: []string{"doq"}},
		}
		session, err := factory.Open(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
			t.Fatal(err)
		}
		if got := session.(*doqSession).DialAddress(); got != hostname {
			t.Fatalf("DoQ dial address = %q, want the configured candidate %q", got, hostname)
		}
		want := ConnectionInfo{RemoteAddress: net.JoinHostPort("127.0.0.1", port), TLSVersion: "TLS 1.3"}
		if got := connectionOf(t, session); got != want {
			t.Fatalf("DoQ connection = %#v, want %#v", got, want)
		}
	})
}

// TestUDPReportsItsLiteralPeerAsASocketWould pins that a UDP target configured
// by literal reports remote_address in the form the connection-based
// transports read from their socket, so the same configured address does not
// read differently over UDP than over TCP, DoT, DoH or DoQ.
func TestUDPReportsItsLiteralPeerAsASocketWould(t *testing.T) {
	for address, want := range map[string]string{
		"192.0.2.1:53":          "192.0.2.1:53",
		"[::ffff:192.0.2.1]:53": "192.0.2.1:53",
		"[2001:DB8::1]:53":      "[2001:db8::1]:53",
		"[fe80::1%eth0]:53":     "[fe80::1%eth0]:53",
		"not-a-literal":         "not-a-literal",
	} {
		if got := (&udpSession{address: address}).Connection(); got != (ConnectionInfo{RemoteAddress: want}) {
			t.Errorf("UDP session to %q reports %#v, want remote address %q", address, got, want)
		}
	}
	// The same spelling over TCP, read from the connected socket.
	listener := listenLoopback(t)
	t.Cleanup(func() { _ = listener.Close() })
	port := listener.Addr().(*net.TCPAddr).Port
	conn, err := net.Dial("tcp", net.JoinHostPort("::ffff:127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("no IPv4-mapped dialing on this host: %v", err)
	}
	defer conn.Close()
	if got, want := (&udpSession{address: net.JoinHostPort("::ffff:127.0.0.1", strconv.Itoa(port))}).Connection().RemoteAddress, conn.RemoteAddr().String(); got != want {
		t.Fatalf("UDP reports %q where a TCP socket to the same literal reports %q", got, want)
	}
}

// TestDoTReportsTheNegotiatedTLSVersion covers a server capped below TLS 1.3,
// which DoT accepts down to TLS 1.2 without saying so anywhere else.
func TestDoTReportsTheNegotiatedTLSVersion(t *testing.T) {
	certificate, roots := testServerCertificate(t, "dns.example")
	listener := listenLoopback(t)
	serveDoTCandidate(t, listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MaxVersion: tls.VersionTLS12}, func(int32) candidateMode {
		return candidateAnswers
	})
	session, err := dotFixtureFactory(roots, time.Second, listener.Addr().String()).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if got := connectionOf(t, session).TLSVersion; got != "TLS 1.2" {
		t.Fatalf("DoT TLS version = %q, want TLS 1.2", got)
	}
}

// startDoHServer runs an RFC 8484 endpoint for dns.example on loopback with
// the given HTTP/2 and TLS settings, and makes DoH sessions trust it for the
// length of the test.
func startDoHServer(t *testing.T, http2 bool, maxVersion uint16) string {
	t.Helper()
	certificate, roots := testServerCertificate(t, "dns.example")
	server := httptest.NewUnstartedServer(http.HandlerFunc(answerDoH))
	server.EnableHTTP2 = http2
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MaxVersion: maxVersion}
	server.StartTLS()
	t.Cleanup(server.Close)
	trustDoHRoots(t, roots)
	return server.Listener.Addr().String()
}

func trustDoHRoots(t *testing.T, roots *x509.CertPool) {
	t.Helper()
	old := newDoHTLSConfig
	t.Cleanup(func() { newDoHTLSConfig = old })
	newDoHTLSConfig = func(name string) *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name, RootCAs: roots}
	}
}

// TestDoHReportsTheNegotiatedProtocols pins #258. DoH offers h2 first and
// accepts http/1.1, and README promised HTTP/2, so an endpoint that speaks
// only HTTP/1.1, or only TLS 1.2, was benchmarked with nothing in the report
// saying so.
func TestDoHReportsTheNegotiatedProtocols(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		http2      bool
		maxVersion uint16
		want       ConnectionInfo
	}{
		{name: "h2 over TLS 1.3", http2: true, want: ConnectionInfo{TLSVersion: "TLS 1.3", HTTPProtocol: "h2"}},
		{name: "h2 not offered", want: ConnectionInfo{TLSVersion: "TLS 1.3", HTTPProtocol: "http/1.1"}},
		{name: "capped at TLS 1.2", http2: true, maxVersion: tls.VersionTLS12, want: ConnectionInfo{TLSVersion: "TLS 1.2", HTTPProtocol: "h2"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			address := startDoHServer(t, testCase.http2, testCase.maxVersion)
			session, err := dohFixtureFactory(time.Second, address).Open(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
				t.Fatal(err)
			}
			want := testCase.want
			want.RemoteAddress = address
			if got := connectionOf(t, session); got != want {
				t.Fatalf("DoH connection = %#v, want %#v", got, want)
			}
		})
	}
}

// TestDoHWithoutALPNSpeaksHTTP1 covers a server that negotiates no ALPN
// protocol at all: net/http then speaks HTTP/1.1, and the report says so
// rather than leaving the protocol blank.
func TestDoHWithoutALPNSpeaksHTTP1(t *testing.T) {
	certificate, roots := testServerCertificate(t, "dns.example")
	listener := listenLoopback(t)
	server := &http.Server{Handler: http.HandlerFunc(answerDoH), ReadHeaderTimeout: time.Second}
	go func() {
		_ = server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}}))
	}()
	t.Cleanup(func() { _ = server.Close() })
	trustDoHRoots(t, roots)
	session, err := dohFixtureFactory(time.Second, listener.Addr().String()).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if got := connectionOf(t, session).HTTPProtocol; got != "http/1.1" {
		t.Fatalf("DoH protocol without ALPN = %q, want http/1.1", got)
	}
}

// TestDoHConnectionFollowsAReconnect checks the dial hook: net/http re-dials
// transparently, and the description must move to the new connection.
func TestDoHConnectionFollowsAReconnect(t *testing.T) {
	address := startDoHServer(t, true, 0)
	session, err := dohFixtureFactory(time.Second, address).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	doh := session.(*doHSession)
	doh.mu.Lock()
	doh.connection = ConnectionInfo{}
	doh.mu.Unlock()
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	doh.transport.CloseIdleConnections()
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if !doh.LastQueryReconnected() {
		t.Fatal("the query after the pooled connection closed did not reconnect")
	}
	want := ConnectionInfo{RemoteAddress: address, TLSVersion: "TLS 1.3", HTTPProtocol: "h2"}
	if got := connectionOf(t, session); got != want {
		t.Fatalf("DoH connection after a reconnect = %#v, want %#v", got, want)
	}
}

// TestDoQDialsResolvedAddressesInResolverOrder is the DoQ half of #242.
// quic-go's own resolution preferred IPv4, so a dual-stack hostname reached
// DoQ over IPv4 while every other transport followed the resolver's order.
// Each address now gets its own attempt, in that order, so a family without a
// route falls through to the next one.
func TestDoQDialsResolvedAddressesInResolverOrder(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		resolved []string
		want     string
	}{
		{name: "IPv6 first", resolved: []string{"::1", "::ffff:127.0.0.1"}, want: "[::1]:853,127.0.0.1:853"},
		{name: "IPv4 first", resolved: []string{"127.0.0.1", "::1"}, want: "127.0.0.1:853,[::1]:853"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			stubLookup(t, testCase.resolved...)
			oldDial := dialDoQ
			t.Cleanup(func() { dialDoQ = oldDial })
			var dialed []string
			dialDoQ = func(_ context.Context, address string, config *tls.Config, _ *quic.Config) (doqConn, error) {
				dialed = append(dialed, address)
				if config.ServerName != "dns.example" {
					t.Fatalf("DoQ dialled %s with TLS name %q", address, config.ServerName)
				}
				if len(dialed) == 1 {
					return nil, errors.New("sendmsg: network is unreachable")
				}
				_, conn := newFakeDoQStream()
				conn.remote = address
				return conn, nil
			}
			factory := &doqFactory{
				connectionPlan: dialPlan{addresses: []string{"dns.example:853"}, timeout: time.Second},
				timeout:        time.Second,
				tlsConfig:      &tls.Config{ServerName: "dns.example", NextProtos: []string{"doq"}},
			}
			session, err := factory.Open(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if got := strings.Join(dialed, ","); got != testCase.want {
				t.Fatalf("DoQ dial order = %s, want %s", got, testCase.want)
			}
			if got := session.(*doqSession).DialAddress(); got != "dns.example:853" {
				t.Fatalf("DoQ dial address = %q, want the configured candidate", got)
			}
			if got := connectionOf(t, session).RemoteAddress; got != dialed[1] {
				t.Fatalf("DoQ remote address = %q, want %q", got, dialed[1])
			}
		})
	}
}

// TestDoQCandidateFailuresNameEveryAttempt covers the error paths of resolving
// a DoQ candidate: a failed lookup moves on to the next candidate unless the
// caller has given up, and every dialled address is named.
func TestDoQCandidateFailuresNameEveryAttempt(t *testing.T) {
	oldLookup, oldDial := lookupNetIP, dialDoQ
	t.Cleanup(func() { lookupNetIP, dialDoQ = oldLookup, oldDial })
	factory := func(addresses ...string) *doqFactory {
		return &doqFactory{
			connectionPlan: dialPlan{addresses: addresses, timeout: time.Second},
			timeout:        time.Second,
			tlsConfig:      &tls.Config{ServerName: "dns.example", NextProtos: []string{"doq"}},
		}
	}
	lookupNetIP = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host == "broken.example" {
			return nil, errors.New("no such host")
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.6"), netip.MustParseAddr("192.0.2.4")}, nil
	}
	dialDoQ = func(_ context.Context, address string, _ *tls.Config, _ *quic.Config) (doqConn, error) {
		if address == "192.0.2.9:853" {
			_, conn := newFakeDoQStream()
			return conn, nil
		}
		return nil, errors.New("timeout")
	}

	session, err := factory("broken.example:853", "192.0.2.9:853").Open(context.Background())
	if err != nil {
		t.Fatalf("a failed lookup must move on to the next candidate: %v", err)
	}
	_ = session.Close()

	_, err = factory("dns.example:853", "no-port").Open(context.Background())
	want := `all connection candidates failed: dns.example:853 via 192.0.2.6:853: timeout; ` +
		`dns.example:853 via 192.0.2.4:853: timeout; no-port: address no-port: missing port in address`
	if err == nil || err.Error() != want {
		t.Fatalf("DoQ error = %v\nwant %s", err, want)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	lookupNetIP = func(ctx context.Context, _, _ string) ([]netip.Addr, error) { return nil, ctx.Err() }
	_, err = factory("dns.example:853", "192.0.2.9:853").Open(canceled)
	if err == nil || strings.Contains(err.Error(), "192.0.2.9") {
		t.Fatalf("a canceled lookup must stop before the next candidate: %v", err)
	}

	lookupNetIP = oldLookup
	dialDoQ = func(context.Context, string, *tls.Config, *quic.Config) (doqConn, error) {
		return nil, context.Canceled
	}
	stubLookup(t, "192.0.2.6", "192.0.2.4")
	_, err = factory("dns.example:853").Open(canceled)
	if err == nil || strings.Contains(err.Error(), "192.0.2.4") {
		t.Fatalf("a canceled dial must stop before the next address: %v", err)
	}
}
