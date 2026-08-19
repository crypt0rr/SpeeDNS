package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
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
		if len(p) <= 2 {
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(p); err != nil || len(query.Question) != 1 {
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
		{name: "prefix write", first: func() net.Conn { return &scriptedConn{writeErrAt: 1} }},
		{name: "payload write", first: func() net.Conn { return &scriptedConn{writeErrAt: 2} }},
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
	response, err := session.Query(context.Background(), "example.com", dns.TypeA)
	if err != nil || response == nil {
		t.Fatalf("later reconnect = %#v/%v", response, err)
	}
	if opens != 2 || session.DialAddress() != "later:853" {
		t.Fatalf("later reconnect state = attempts %d, address %q", opens, session.DialAddress())
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
