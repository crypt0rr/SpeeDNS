package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// answerDoH is a minimal RFC 8484 POST handler that answers every query.
func answerDoH(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	query := new(dns.Msg)
	if err != nil || query.Unpack(body) != nil || len(query.Question) != 1 {
		http.Error(writer, "bad DoH query", http.StatusBadRequest)
		return
	}
	response, err := replyFor(query.Question[0].Name, query.Question[0].Qtype, 0).Pack()
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/dns-message")
	_, _ = writer.Write(response)
}

// dohFixture is a loopback HTTPS server presenting a certificate for
// dns.example, which DoH sessions trust for the length of the test only. It
// counts the connections the server holds open.
type dohFixture struct {
	server *httptest.Server
	open   atomic.Int32
}

func startDoHFixture(t *testing.T, handler http.HandlerFunc) *dohFixture {
	t.Helper()
	certificate, roots := testServerCertificate(t, "dns.example")
	fixture := &dohFixture{server: httptest.NewUnstartedServer(handler)}
	fixture.server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			fixture.open.Add(1)
		case http.StateClosed, http.StateHijacked:
			fixture.open.Add(-1)
		}
	}
	fixture.server.EnableHTTP2 = true
	fixture.server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	fixture.server.StartTLS()
	t.Cleanup(fixture.server.Close)

	oldTLSConfig := newDoHTLSConfig
	newDoHTLSConfig = func(name string) *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name, RootCAs: roots}
	}
	t.Cleanup(func() { newDoHTLSConfig = oldTLSConfig })
	return fixture
}

func (f *dohFixture) address() string { return f.server.Listener.Addr().String() }

func dohFixtureFactory(timeout time.Duration, addresses ...string) *doHFactory {
	return &doHFactory{
		url:            "https://dns.example/dns-query",
		connectionPlan: dialPlan{addresses: addresses, timeout: timeout},
		serverName:     "dns.example",
		timeout:        timeout,
	}
}

// waitFor polls condition until it holds, failing the test once a generous
// deadline passes. Connection teardown is asynchronous on both ends, so a
// fixed sleep would be either flaky or slow.
func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDoHColdProbesSurviveAStalledFirstCandidate runs the cold-probe sequence
// (Open, one query under the transport timeout, Close) against a bootstrap
// list whose first candidate accepts TCP and never speaks TLS. DoH used to
// dial inside that first query, so the stall spent the query's whole budget
// and every cold probe failed while DoT and DoQ, which dial in Open, passed.
func TestDoHColdProbesSurviveAStalledFirstCandidate(t *testing.T) {
	const timeout = 300 * time.Millisecond
	fixture := startDoHFixture(t, answerDoH)
	stall := listenLoopback(t)
	serveDoTCandidate(t, stall, nil, func(int32) candidateMode { return candidateSilent })
	factory := dohFixtureFactory(timeout, stall.Addr().String(), fixture.address())
	for probe := 0; probe < 3; probe++ {
		session, err := factory.Open(context.Background())
		if err != nil {
			t.Fatalf("cold probe %d open: %v", probe, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_, err = session.Query(ctx, "example.com", dns.TypeA)
		cancel()
		doh := session.(*doHSession)
		if err != nil {
			t.Fatalf("cold probe %d: %v", probe, err)
		}
		if doh.LastQueryReconnected() {
			t.Fatalf("cold probe %d counted the connection Open made as a reconnect", probe)
		}
		if got := doh.DialAddress(); got != fixture.address() {
			t.Fatalf("cold probe %d dial address = %q, want %q", probe, got, fixture.address())
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// freezingProxy forwards TCP connections on 127.0.0.1 to upstream. freeze
// makes every connection open at that moment go silent in both directions
// while staying open, as a path that dies without a FIN or RST does;
// connections accepted afterwards forward normally.
type freezingProxy struct {
	listener net.Listener
	mu       sync.Mutex
	frozen   []*atomic.Bool
	conns    []net.Conn
}

func newFreezingProxy(t *testing.T, upstream string) *freezingProxy {
	t.Helper()
	proxy := &freezingProxy{listener: listenLoopback(t)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			client, err := proxy.listener.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp", upstream)
			if err != nil {
				_ = client.Close()
				continue
			}
			frozen := new(atomic.Bool)
			proxy.mu.Lock()
			proxy.frozen = append(proxy.frozen, frozen)
			proxy.conns = append(proxy.conns, client, server)
			proxy.mu.Unlock()
			go forwardUnlessFrozen(server, client, frozen)
			go forwardUnlessFrozen(client, server, frozen)
		}
	}()
	t.Cleanup(func() {
		_ = proxy.listener.Close()
		<-done
		proxy.mu.Lock()
		defer proxy.mu.Unlock()
		for _, conn := range proxy.conns {
			_ = conn.Close()
		}
	})
	return proxy
}

func (p *freezingProxy) freeze() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, frozen := range p.frozen {
		frozen.Store(true)
	}
}

func forwardUnlessFrozen(dst, src net.Conn, frozen *atomic.Bool) {
	buffer := make([]byte, 32<<10)
	for {
		n, err := src.Read(buffer)
		if n > 0 && !frozen.Load() {
			if _, writeErr := dst.Write(buffer[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// TestDoHRetiresASilentlyDeadHTTP2Connection freezes the path under a pooled
// HTTP/2 connection. Without a health check the session kept sending queries
// on it, one timeout per stream slot the server allows (hundreds), while TCP,
// DoT and DoQ reconnect after their first failure. With it, the connection is
// closed after one timeout of silence and one unanswered ping, and the next
// query is a flagged reconnect.
func TestDoHRetiresASilentlyDeadHTTP2Connection(t *testing.T) {
	const timeout = 200 * time.Millisecond
	var http2Requests atomic.Int32
	fixture := startDoHFixture(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.ProtoMajor == 2 {
			http2Requests.Add(1)
		}
		answerDoH(writer, request)
	})
	proxy := newFreezingProxy(t, fixture.address())
	session, err := dohFixtureFactory(timeout, proxy.listener.Addr().String()).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if got := strings.Join(queryOutcomes(t, session, 1, timeout), ","); got != "ok" {
		t.Fatalf("DoH query before the freeze = %s", got)
	}
	if http2Requests.Load() != 1 {
		t.Fatal("the DoH fixture is not speaking HTTP/2, so it cannot exercise the stream-slot behaviour")
	}

	proxy.freeze()
	const budget = 10
	outcomes := queryOutcomes(t, session, budget, timeout)
	failures := 0
	for failures < len(outcomes) && outcomes[failures] != "reconnected" {
		if outcomes[failures] != "failed" {
			t.Fatalf("DoH queries after the freeze = %v", outcomes)
		}
		failures++
	}
	if failures == budget {
		t.Fatalf("DoH never left the dead connection within %d queries", budget)
	}
	// TCP fails once. The health check needs one timeout of silence and one
	// unanswered ping, so one more query can still land on the connection.
	if failures > 3 {
		t.Fatalf("DoH failed %d queries on a dead connection, want at most 3", failures)
	}
	for index, outcome := range outcomes[failures+1:] {
		if outcome != "ok" {
			t.Fatalf("DoH query %d after the reconnect = %s (%v)", failures+1+index, outcome, outcomes)
		}
	}
}

// TestDoHCloseReleasesConnectionsOfTimedOutExchanges reproduces a cold probe
// against a server that never answers in time. Close used to call only
// CloseIdleConnections, which skips a connection whose timed-out stream
// net/http has not released yet, and the private transport was then dropped:
// the connection and its read loop stayed until the server gave up.
func TestDoHCloseReleasesConnectionsOfTimedOutExchanges(t *testing.T) {
	const timeout = 200 * time.Millisecond
	fixture := startDoHFixture(t, func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	})
	baseline := runtime.NumGoroutine()
	factory := dohFixtureFactory(timeout, fixture.address())
	for probe := 0; probe < 3; probe++ {
		session, err := factory.Open(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(queryOutcomes(t, session, 1, timeout), ","); got != "failed" {
			t.Fatalf("probe %d against a silent handler = %s", probe, got)
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "the server to see every DoH connection closed", func() bool { return fixture.open.Load() == 0 })
	waitFor(t, "goroutines to return to the baseline", func() bool { return runtime.NumGoroutine() <= baseline })
}

// The connection Open dials belongs to the session until the first exchange
// takes it over; closing an unused session must not strand it.
func TestDoHCloseBeforeTheFirstQueryClosesTheOpenConnection(t *testing.T) {
	fixture := startDoHFixture(t, answerDoH)
	session, err := dohFixtureFactory(time.Second, fixture.address()).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the server to accept the connection Open dialled", func() bool { return fixture.open.Load() == 1 })
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the server to see the unused connection closed", func() bool { return fixture.open.Load() == 0 })
}

// net/http finishes a dial even after the request that started it is gone,
// so one can complete after Close. The session refuses it rather than hand the
// transport a connection nothing will ever close.
func TestDoHSessionRefusesADialThatFinishesAfterClose(t *testing.T) {
	fixture := startDoHFixture(t, answerDoH)
	session, err := dohFixtureFactory(time.Second, fixture.address()).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	doh := session.(*doHSession)
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	conn, err := doh.transport.DialTLSContext(context.Background(), "tcp", "ignored")
	if err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("dial after Close = %v/%v", conn, err)
	}
	doh.mu.RLock()
	connections := doh.connections
	doh.mu.RUnlock()
	if connections != 1 {
		t.Fatalf("connections after a refused dial = %d, want 1", connections)
	}
	waitFor(t, "the refused connection to be closed", func() bool {
		doh.mu.RLock()
		defer doh.mu.RUnlock()
		return len(doh.conns) == 0 && fixture.open.Load() == 0
	})
}
