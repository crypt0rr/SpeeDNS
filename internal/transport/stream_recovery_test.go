package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type streamTimeoutError struct{}

func (streamTimeoutError) Error() string   { return "stream read timed out" }
func (streamTimeoutError) Timeout() bool   { return true }
func (streamTimeoutError) Temporary() bool { return true }

type delayedStreamConn struct {
	*scriptedConn
	timedOut bool
}

func (c *delayedStreamConn) Read(p []byte) (int, error) {
	if !c.timedOut {
		c.timedOut = true
		return 0, streamTimeoutError{}
	}
	return c.scriptedConn.Read(p)
}

func mismatchedResponseConn() *scriptedConn {
	conn := &scriptedConn{}
	conn.onWrite = func(p []byte) {
		query, ok := unframeQuery(p)
		if !ok {
			return
		}
		conn.readBuf.Write(frameMessage(replyFor("other.example", query.Question[0].Qtype, query.Id)))
	}
	return conn
}

func TestStreamSessionReconnectsAfterFatalErrors(t *testing.T) {
	cases := []struct {
		name  string
		first func() net.Conn
	}{
		{name: "deadline", first: func() net.Conn { return &scriptedConn{setDeadlineErr: errors.New("deadline failed")} }},
		{name: "write", first: func() net.Conn { return &scriptedConn{writeErrAt: 1} }},
		{name: "prefix read", first: func() net.Conn { return &scriptedConn{readErr: errors.New("prefix read failed")} }},
		{name: "empty response", first: func() net.Conn {
			conn := &scriptedConn{}
			conn.readBuf.Write([]byte{0, 0})
			return conn
		}},
		{name: "short response", first: func() net.Conn {
			conn := &scriptedConn{}
			conn.readBuf.Write([]byte{0, 3, 1})
			return conn
		}},
		{name: "unpack", first: func() net.Conn {
			conn := &scriptedConn{}
			conn.readBuf.Write([]byte{0, 1, 1})
			return conn
		}},
		{name: "response validation", first: func() net.Conn { return mismatchedResponseConn() }},
		{name: "timeout leaves stale response unread", first: func() net.Conn {
			stale := &scriptedConn{}
			stale.readBuf.Write(frameMessage(replyFor("stale.example", dns.TypeA, 1)))
			return &delayedStreamConn{scriptedConn: stale}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := tc.first()
			second := newScriptedStreamConn()
			opens := 0
			session := &streamSession{
				conn:    first,
				timeout: time.Second,
				reopen: func(context.Context) (net.Conn, string, error) {
					opens++
					return second, "reconnected:853", nil
				},
			}

			if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err == nil {
				t.Fatal("fatal exchange unexpectedly succeeded")
			}
			if opens != 0 {
				t.Fatalf("failed query was retried through reconnect: opens=%d", opens)
			}
			if session.LastQueryReconnected() {
				t.Fatal("failed initial query was marked as a reconnect")
			}
			if got := closeCalls(first); got != 1 {
				t.Fatalf("failed connection close calls = %d, want 1", got)
			}
			if tc.name == "timeout leaves stale response unread" {
				delayed := first.(*delayedStreamConn)
				if delayed.readBuf.Len() == 0 {
					t.Fatal("stale response was consumed after the timeout")
				}
			}

			response, err := session.Query(context.Background(), "example.com", dns.TypeA)
			if err != nil || response == nil {
				t.Fatalf("reconnected query = %#v/%v", response, err)
			}
			if opens != 1 {
				t.Fatalf("reconnect attempts = %d, want 1", opens)
			}
			if !session.LastQueryReconnected() {
				t.Fatal("recovered query did not report a reconnect")
			}
			if got := session.DialAddress(); got != "reconnected:853" {
				t.Fatalf("reconnected dial address = %q", got)
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func closeCalls(conn net.Conn) int {
	if scripted, ok := conn.(*scriptedConn); ok {
		return scripted.closeCalls
	}
	if delayed, ok := conn.(*delayedStreamConn); ok {
		return delayed.closeCalls
	}
	return 0
}

func TestStreamSessionReconnectFailureCanRecoverLater(t *testing.T) {
	first := &scriptedConn{readErr: errors.New("connection failed")}
	second := newScriptedStreamConn()
	opens := 0
	session := &streamSession{
		conn:    first,
		timeout: time.Second,
		reopen: func(context.Context) (net.Conn, string, error) {
			opens++
			if opens == 1 {
				return nil, "", errors.New("reconnect failed")
			}
			return second, "later:853", nil
		},
	}
	defer session.Close()

	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err == nil {
		t.Fatal("expected initial exchange failure")
	}
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err == nil || !strings.Contains(err.Error(), "reconnect failed") {
		t.Fatalf("reconnect failure = %v", err)
	}
	if opens != 1 {
		t.Fatalf("reconnect attempts after failed open = %d, want 1", opens)
	}
	if !session.LastQueryReconnected() {
		t.Fatal("reconnect failure did not report a reconnect attempt")
	}
	response, err := session.Query(context.Background(), "example.com", dns.TypeA)
	if err != nil || response == nil {
		t.Fatalf("later reconnect = %#v/%v", response, err)
	}
	if opens != 2 || session.DialAddress() != "later:853" {
		t.Fatalf("later reconnect state = attempts %d, address %q", opens, session.DialAddress())
	}
	if !session.LastQueryReconnected() {
		t.Fatal("later recovery did not report a reconnect")
	}
}

func TestStreamSessionDoesNotInvalidateForLocalErrors(t *testing.T) {
	cases := []struct {
		name string
		pack func(*dns.Msg) ([]byte, error)
	}{
		{name: "pack", pack: func(*dns.Msg) ([]byte, error) { return nil, errors.New("pack failed") }},
		{name: "oversize", pack: func(*dns.Msg) ([]byte, error) { return make([]byte, 65536), nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := newScriptedStreamConn()
			opens := 0
			session := &streamSession{
				conn:    conn,
				timeout: time.Second,
				reopen: func(context.Context) (net.Conn, string, error) {
					opens++
					return nil, "", errors.New("must not reopen")
				},
			}
			withPackSession(t, tc.pack)
			if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err == nil {
				t.Fatal("expected local query error")
			}
			if session.conn != conn || conn.closeCalls != 0 || opens != 0 {
				t.Fatalf("local error changed session state: conn=%p/%p closes=%d opens=%d", session.conn, conn, conn.closeCalls, opens)
			}
		})
	}
}

func TestStreamSessionCloseIsIdempotentAndPreventsReconnect(t *testing.T) {
	conn := newScriptedStreamConn()
	opens := 0
	session := &streamSession{
		conn:    conn,
		timeout: time.Second,
		reopen: func(context.Context) (net.Conn, string, error) {
			opens++
			return newScriptedStreamConn(), "unexpected", nil
		},
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if conn.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", conn.closeCalls)
	}
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("query after close = %v", err)
	}
	if opens != 0 {
		t.Fatalf("query reopened explicitly closed session: opens=%d", opens)
	}

	var empty streamSession
	if err := empty.ensureConn(context.Background()); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("unavailable connection error = %v", err)
	}
	if err := empty.Close(); err != nil {
		t.Fatal(err)
	}
	closed := &streamSession{closed: true}
	if err := closed.ensureConn(context.Background()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed connection error = %v", err)
	}
	nilConn := &streamSession{
		reopen: func(context.Context) (net.Conn, string, error) { return nil, "", nil },
	}
	if _, err := nilConn.Query(context.Background(), "example.com", dns.TypeA); err == nil || !strings.Contains(err.Error(), "nil connection") {
		t.Fatalf("nil reconnect connection error = %v", err)
	}
}

type streamFixtureResult struct {
	connections int
	queries     int
	err         error
}

func serveClosingStreamFixture(listener net.Listener, connectionCount int) <-chan streamFixtureResult {
	done := make(chan streamFixtureResult, 1)
	go func() {
		result := streamFixtureResult{}
		for result.connections < connectionCount {
			conn, err := listener.Accept()
			if err != nil {
				result.err = err
				done <- result
				return
			}
			result.connections++
			queries, err := serveOneStreamQuery(conn)
			result.queries += queries
			if err != nil {
				result.err = err
				done <- result
				return
			}
		}
		done <- result
	}()
	return done
}

func serveOneStreamQuery(conn net.Conn) (int, error) {
	defer conn.Close()
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return 0, err
	}
	requestBytes := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(conn, requestBytes); err != nil {
		return 0, err
	}
	query := new(dns.Msg)
	if err := query.Unpack(requestBytes); err != nil {
		return 0, err
	}
	if len(query.Question) != 1 {
		return 0, errors.New("fixture query has no single question")
	}
	response, err := replyFor(query.Question[0].Name, query.Question[0].Qtype, query.Id).Pack()
	if err != nil {
		return 0, err
	}
	binary.BigEndian.PutUint16(prefix[:], uint16(len(response)))
	if _, err := conn.Write(prefix[:]); err != nil {
		return 0, err
	}
	if _, err := conn.Write(response); err != nil {
		return 0, err
	}
	return 1, nil
}

func TestTCPSessionRecoversAfterServerClosesConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := serveClosingStreamFixture(listener, 2)

	factory := &streamFactory{
		connectionPlan: dialPlan{addresses: []string{listener.Addr().String()}, timeout: time.Second},
		timeout:        time.Second,
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err == nil {
		t.Fatal("expected the query on the closed connection to fail")
	}
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}

	result := <-done
	if result.err != nil || result.connections != 2 || result.queries != 2 {
		t.Fatalf("TCP recovery fixture = %#v, want two connections and two queries", result)
	}
}

func TestDoTSessionRecoversAfterServerClosesConnection(t *testing.T) {
	const serverName = "dns.example"
	certificate, roots := testServerCertificate(t, serverName)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}})
	defer tlsListener.Close()
	done := serveClosingStreamFixture(tlsListener, 2)

	factory := &streamFactory{
		connectionPlan: dialPlan{addresses: []string{listener.Addr().String()}, timeout: time.Second},
		timeout:        time.Second,
		tlsConfig:      &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, RootCAs: roots},
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err == nil {
		t.Fatal("expected the query on the closed DoT connection to fail")
	}
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}

	result := <-done
	if result.err != nil || result.connections != 2 || result.queries != 2 {
		t.Fatalf("DoT recovery fixture = %#v, want two connections and two queries", result)
	}
}

// candidateMode is what a connection candidate fixture does with one
// accepted connection.
type candidateMode int

const (
	// candidateAnswers answers every query until the client goes away.
	candidateAnswers candidateMode = iota
	// candidateDropsSecond answers one query, then reads the next and drops
	// the connection without answering, as a mid-session loss does.
	candidateDropsSecond
	// candidateSilent accepts and never speaks, like a path that drops
	// traffic: a TLS handshake against it spends the whole budget.
	candidateSilent
)

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

// serveDoTCandidate runs a DoT connection candidate on listener. mode picks
// the behaviour of each accepted connection by its 1-based index; the counter
// reports how many connections the candidate accepted.
func serveDoTCandidate(t *testing.T, listener net.Listener, config *tls.Config, mode func(connection int32) candidateMode) *atomic.Int32 {
	t.Helper()
	accepts := new(atomic.Int32)
	var mu sync.Mutex
	var held []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
			switch mode(accepts.Add(1)) {
			case candidateSilent:
			case candidateDropsSecond:
				go answerThenDrop(tls.Server(conn, config))
			default:
				go serveFramedQueries(tls.Server(conn, config))
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			_ = conn.Close()
		}
	})
	return accepts
}

func answerThenDrop(conn net.Conn) {
	defer conn.Close()
	query, err := readFramedQuery(conn)
	if err != nil {
		return
	}
	if _, err := conn.Write(frameMessage(replyFor(query.Question[0].Name, query.Question[0].Qtype, query.Id))); err != nil {
		return
	}
	_, _ = readFramedQuery(conn)
}

// queryOutcomes runs count queries, each under its own deadline as the
// benchmark does, and describes each one as ok, failed, reconnected (a
// reconnect that answered) or reconnect-failed.
func queryOutcomes(t *testing.T, session Session, count int, timeout time.Duration) []string {
	t.Helper()
	reconnects, ok := session.(interface{ LastQueryReconnected() bool })
	if !ok {
		t.Fatalf("%T does not report reconnects", session)
	}
	outcomes := make([]string, 0, count)
	for index := 0; index < count; index++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_, err := session.Query(ctx, "example.com", dns.TypeA)
		cancel()
		switch reconnected := reconnects.LastQueryReconnected(); {
		case err == nil && reconnected:
			outcomes = append(outcomes, "reconnected")
		case err == nil:
			outcomes = append(outcomes, "ok")
		case reconnected:
			outcomes = append(outcomes, "reconnect-failed")
		default:
			outcomes = append(outcomes, "failed")
		}
	}
	return outcomes
}

func dotFixtureFactory(roots *x509.CertPool, timeout time.Duration, addresses ...string) *streamFactory {
	return &streamFactory{
		connectionPlan: dialPlan{addresses: addresses, timeout: timeout},
		timeout:        timeout,
		tlsConfig:      &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "dns.example", RootCAs: roots},
	}
}

// TestDoTReconnectReturnsToTheCandidateThatConnected pins sticky reconnects.
// The first bootstrap candidate is a black hole that Open gets past with its
// own budget. After a mid-session loss the reconnect runs inside one query's
// deadline, and starting again at the black hole spent all of it, so every
// remaining query failed although the second candidate was healthy.
func TestDoTReconnectReturnsToTheCandidateThatConnected(t *testing.T) {
	const timeout = 300 * time.Millisecond
	certificate, roots := testServerCertificate(t, "dns.example")
	serverConfig := &tls.Config{Certificates: []tls.Certificate{certificate}}
	blackhole, good := listenLoopback(t), listenLoopback(t)
	blackholeAccepts := serveDoTCandidate(t, blackhole, serverConfig, func(int32) candidateMode { return candidateSilent })
	serveDoTCandidate(t, good, serverConfig, func(connection int32) candidateMode {
		if connection == 1 {
			return candidateDropsSecond
		}
		return candidateAnswers
	})

	session, err := dotFixtureFactory(roots, timeout, blackhole.Addr().String(), good.Addr().String()).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	got := strings.Join(queryOutcomes(t, session, 4, timeout), ",")
	if want := "ok,failed,reconnected,ok"; got != want {
		t.Fatalf("DoT queries after a mid-session loss = %s, want %s", got, want)
	}
	if address := session.(*streamSession).DialAddress(); address != good.Addr().String() {
		t.Fatalf("DoT reconnected to %q, want %q", address, good.Addr().String())
	}
	if accepts := blackholeAccepts.Load(); accepts != 1 {
		t.Fatalf("the black-hole candidate was dialled %d times, want only by Open", accepts)
	}
}

// TestDoTReconnectMovesOnWhenTheLastGoodCandidateGoesSilent covers the other
// half: when the address that last connected is the one that stopped
// answering, its reconnect fails once and the next one starts at the
// following candidate instead of spending every later budget on it again.
func TestDoTReconnectMovesOnWhenTheLastGoodCandidateGoesSilent(t *testing.T) {
	const timeout = 300 * time.Millisecond
	certificate, roots := testServerCertificate(t, "dns.example")
	serverConfig := &tls.Config{Certificates: []tls.Certificate{certificate}}
	first, second := listenLoopback(t), listenLoopback(t)
	firstAccepts := serveDoTCandidate(t, first, serverConfig, func(connection int32) candidateMode {
		if connection == 1 {
			return candidateDropsSecond
		}
		return candidateSilent
	})
	secondAccepts := serveDoTCandidate(t, second, serverConfig, func(int32) candidateMode { return candidateAnswers })

	session, err := dotFixtureFactory(roots, timeout, first.Addr().String(), second.Addr().String()).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	got := strings.Join(queryOutcomes(t, session, 5, timeout), ",")
	if want := "ok,failed,reconnect-failed,reconnected,ok"; got != want {
		t.Fatalf("DoT queries after the last good candidate went silent = %s, want %s", got, want)
	}
	if address := session.(*streamSession).DialAddress(); address != second.Addr().String() {
		t.Fatalf("DoT reconnected to %q, want %q", address, second.Addr().String())
	}
	if firstDials, secondDials := firstAccepts.Load(), secondAccepts.Load(); firstDials != 2 || secondDials != 1 {
		t.Fatalf("candidate dials = %d/%d, want 2/1", firstDials, secondDials)
	}
}
