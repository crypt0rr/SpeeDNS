package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func TestDoQSessionRecoversAfterConnectionAndIdleFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{name: "connection close", err: errors.New("DoQ connection closed")},
		{name: "idle timeout", err: streamTimeoutError{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := &fakeDoQConn{openErr: tc.err, remote: "192.0.2.1:853"}
			_, second := newFakeDoQStream()
			second.remote = "192.0.2.2:853"
			opens := 0
			session := &doqSession{
				conn:       first,
				timeout:    time.Second,
				connection: doqConnectionInfo(first),
				reopen: func(context.Context) (doqConn, string, error) {
					opens++
					return second, "reconnected:853", nil
				},
			}

			if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err == nil {
				t.Fatal("failed DoQ exchange unexpectedly succeeded")
			}
			if opens != 0 {
				t.Fatalf("failed query was retried through reconnect: opens=%d", opens)
			}
			if session.LastQueryReconnected() {
				t.Fatal("failed initial query was marked as a reconnect")
			}
			if first.closeCalls != 1 {
				t.Fatalf("failed DoQ connection close calls = %d, want 1", first.closeCalls)
			}

			response, err := session.Query(context.Background(), "example.com", dns.TypeA)
			if err != nil || response == nil {
				t.Fatalf("reconnected DoQ query = %#v/%v", response, err)
			}
			if opens != 1 || !session.LastQueryReconnected() {
				t.Fatalf("DoQ reconnect state = attempts %d, reconnected %v", opens, session.LastQueryReconnected())
			}
			if session.DialAddress() != "reconnected:853" {
				t.Fatalf("reconnected DoQ address = %q", session.DialAddress())
			}
			// The session began with the first connection's description, as
			// Open leaves it, so only a reconnect that replaced it reports
			// the peer the session now talks to.
			want := ConnectionInfo{RemoteAddress: "192.0.2.2:853", TLSVersion: "TLS 1.3"}
			if got := session.Connection(); got != want {
				t.Fatalf("DoQ connection after the reconnect = %#v, want %#v", got, want)
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDoQSessionReconnectFailureCanRecoverLater(t *testing.T) {
	first := &fakeDoQConn{openErr: errors.New("DoQ connection closed")}
	_, second := newFakeDoQStream()
	opens := 0
	session := &doqSession{
		conn:    first,
		timeout: time.Second,
		reopen: func(context.Context) (doqConn, string, error) {
			opens++
			if opens == 1 {
				return nil, "", errors.New("DoQ reconnect failed")
			}
			return second, "later:853", nil
		},
	}

	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err == nil {
		t.Fatal("expected initial DoQ exchange failure")
	}
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err == nil || !strings.Contains(err.Error(), "reconnect failed") {
		t.Fatalf("DoQ reconnect failure = %v", err)
	}
	if opens != 1 || !session.LastQueryReconnected() {
		t.Fatalf("DoQ failed reconnect state = attempts %d, reconnected %v", opens, session.LastQueryReconnected())
	}
	response, err := session.Query(context.Background(), "example.com", dns.TypeA)
	if err != nil || response == nil {
		t.Fatalf("later DoQ reconnect = %#v/%v", response, err)
	}
	if opens != 2 || !session.LastQueryReconnected() || session.DialAddress() != "later:853" {
		t.Fatalf("later DoQ recovery state = attempts %d, reconnected %v, address %q", opens, session.LastQueryReconnected(), session.DialAddress())
	}
	_ = session.Close()
}

func TestDoQSessionCloseIsIdempotentAndPreventsReconnect(t *testing.T) {
	conn := &fakeDoQConn{}
	opens := 0
	session := &doqSession{
		conn:    conn,
		timeout: time.Second,
		reopen: func(context.Context) (doqConn, string, error) {
			opens++
			return newFakeDoQStreamConn(), "unexpected:853", nil
		},
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if conn.closeCalls != 1 {
		t.Fatalf("DoQ close calls = %d, want 1", conn.closeCalls)
	}
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("DoQ query after close = %v", err)
	}
	if opens != 0 {
		t.Fatalf("DoQ query reopened explicitly closed session: opens=%d", opens)
	}

	var empty doqSession
	if err := empty.ensureConn(context.Background()); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("unavailable DoQ connection error = %v", err)
	}
	if err := empty.Close(); err != nil {
		t.Fatal(err)
	}
	closed := &doqSession{closed: true}
	if err := closed.ensureConn(context.Background()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed DoQ connection error = %v", err)
	}
	var nilConn doqSession
	nilConn.reopen = func(context.Context) (doqConn, string, error) { return nil, "", nil }
	if _, err := nilConn.Query(context.Background(), "example.com", dns.TypeA); err == nil || !strings.Contains(err.Error(), "nil connection") {
		t.Fatalf("nil DoQ reconnect connection error = %v", err)
	}
}

func TestDoQFactoryRecoversWithLocalFixtureAfterConnectionClose(t *testing.T) {
	const serverName = "dns.example"
	certificate, roots := testServerCertificate(t, serverName)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"doq"},
	}, &quic.Config{MaxIdleTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	firstClosed := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		for connectionIndex := 0; connectionIndex < 2; connectionIndex++ {
			conn, acceptErr := listener.Accept(context.Background())
			if acceptErr != nil {
				serverDone <- acceptErr
				return
			}
			stream, streamErr := conn.AcceptStream(context.Background())
			if streamErr != nil {
				serverDone <- streamErr
				return
			}
			var prefix [2]byte
			if _, readErr := io.ReadFull(stream, prefix[:]); readErr != nil {
				serverDone <- readErr
				return
			}
			requestBytes := make([]byte, binary.BigEndian.Uint16(prefix[:]))
			if _, readErr := io.ReadFull(stream, requestBytes); readErr != nil {
				serverDone <- readErr
				return
			}
			query := new(dns.Msg)
			if unpackErr := query.Unpack(requestBytes); unpackErr != nil {
				serverDone <- unpackErr
				return
			}
			if connectionIndex == 0 {
				_ = conn.CloseWithError(0, "idle timeout fixture")
				close(firstClosed)
				continue
			}
			response, packErr := replyFor(query.Question[0].Name, query.Question[0].Qtype, 0).Pack()
			if packErr != nil {
				serverDone <- packErr
				return
			}
			binary.BigEndian.PutUint16(prefix[:], uint16(len(response)))
			if _, writeErr := stream.Write(prefix[:]); writeErr != nil {
				serverDone <- writeErr
				return
			}
			if _, writeErr := stream.Write(response); writeErr != nil {
				serverDone <- writeErr
				return
			}
			// Leave the second connection open until the client has consumed
			// the response; the test closes it after the fixture reports done.
			serverDone <- nil
			return
		}
	}()

	factory := &doqFactory{
		connectionPlan: dialPlan{addresses: []string{listener.Addr().String()}, timeout: time.Second},
		timeout:        time.Second,
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: serverName,
			RootCAs:    roots,
			NextProtos: []string{"doq"},
		},
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	doqSession := session.(*doqSession)
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err == nil {
		t.Fatal("expected the first DoQ query to fail after the fixture closes the connection")
	}
	if doqSession.LastQueryReconnected() {
		t.Fatal("failed initial DoQ query was marked as a reconnect")
	}
	select {
	case <-firstClosed:
	case <-time.After(time.Second):
		t.Fatal("DoQ close fixture did not close the first connection")
	}
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if !doqSession.LastQueryReconnected() {
		t.Fatal("successful DoQ recovery query did not report reconnect state")
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("DoQ recovery fixture did not finish")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func newFakeDoQStreamConn() doqConn {
	_, conn := newFakeDoQStream()
	return conn
}

// serveDoQCandidate answers DoQ queries on listener. mode picks the behaviour
// of each accepted connection by its 1-based index; candidateDropsSecond
// closes the connection on its second query instead of answering it.
func serveDoQCandidate(t *testing.T, listener *quic.Listener, mode func(connection int32) candidateMode) {
	t.Helper()
	var accepts atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go serveDoQConnection(conn, mode(accepts.Add(1)))
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
}

func serveDoQConnection(conn *quic.Conn, mode candidateMode) {
	defer conn.CloseWithError(0, "")
	for answered := 0; ; answered++ {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		query, err := readFramedQuery(stream)
		if err != nil {
			return
		}
		if mode == candidateDropsSecond && answered == 1 {
			_ = conn.CloseWithError(0, "fixture drops the connection")
			return
		}
		if _, err := stream.Write(frameMessage(replyFor(query.Question[0].Name, query.Question[0].Qtype, 0))); err != nil {
			return
		}
		_ = stream.Close()
	}
}

// TestDoQReconnectReturnsToTheCandidateThatConnected is the DoQ half of the
// sticky-reconnect fixture: a UDP black hole is the first bootstrap
// candidate, Open gets past it with its own budget, and the reconnect after a
// mid-session loss must go straight back to the server that answered.
func TestDoQReconnectReturnsToTheCandidateThatConnected(t *testing.T) {
	const serverName = "dns.example"
	const timeout = 300 * time.Millisecond
	certificate, roots := testServerCertificate(t, serverName)
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blackhole.Close() })
	good, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"doq"},
	}, &quic.Config{MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	serveDoQCandidate(t, good, func(connection int32) candidateMode {
		if connection == 1 {
			return candidateDropsSecond
		}
		return candidateAnswers
	})

	factory := &doqFactory{
		connectionPlan: dialPlan{addresses: []string{blackhole.LocalAddr().String(), good.Addr().String()}, timeout: timeout},
		timeout:        timeout,
		tlsConfig:      &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots, NextProtos: []string{"doq"}},
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	// Open reached the same server, so its description is cleared: only the
	// reconnect can restore it, from the new QUIC connection.
	doq := session.(*doqSession)
	doq.mu.Lock()
	doq.connection = ConnectionInfo{}
	doq.mu.Unlock()
	got := strings.Join(queryOutcomes(t, session, 4, timeout), ",")
	if want := "ok,failed,reconnected,ok"; got != want {
		t.Fatalf("DoQ queries after a mid-session loss = %s, want %s", got, want)
	}
	if address := doq.DialAddress(); address != good.Addr().String() {
		t.Fatalf("DoQ reconnected to %q, want %q", address, good.Addr().String())
	}
	want := ConnectionInfo{RemoteAddress: good.Addr().String(), TLSVersion: "TLS 1.3"}
	if got := connectionOf(t, session); got != want {
		t.Fatalf("DoQ connection after a reconnect = %#v, want %#v", got, want)
	}
}

// TestDoQReconnectReturnsToTheAddressItReached covers a hostname candidate
// whose resolved addresses DoQ dials one after another. When the first one
// silently drops packets, such as an IPv6 path that is routed but broken,
// Open waits it out and reaches the next. A reconnect has to fit in one
// query's deadline, and starting again at the resolver's first address spent
// all of it there: after one lost connection every later query of the
// session failed, although the address it had been using still answered.
func TestDoQReconnectReturnsToTheAddressItReached(t *testing.T) {
	const timeout = 250 * time.Millisecond
	for _, testCase := range []struct {
		name     string
		resolved []string
		// silentAtOpen drop packets while the session opens and
		// silentLater replace them once the first connection is lost;
		// from then on the refusedLater addresses fail at once.
		silentAtOpen, silentLater, refusedLater []string
		want, wantDials, wantRemote             string
	}{
		{
			name:     "the address it reached still answers",
			resolved: []string{"2001:db8::1", "192.0.2.1"}, silentAtOpen: []string{"[2001:db8::1]:853"}, silentLater: []string{"[2001:db8::1]:853"},
			want:       "failed,reconnected,ok",
			wantDials:  "[2001:db8::1]:853,192.0.2.1:853,192.0.2.1:853",
			wantRemote: "192.0.2.1:853",
		},
		{
			// An address that used up the budget of a reconnect it started
			// is not tried first again: the next reconnect starts at the
			// address after it, as a candidate's reconnects do.
			name:     "the resolver's first address goes silent",
			resolved: []string{"192.0.2.1", "192.0.2.2"}, silentLater: []string{"192.0.2.1:853"},
			want:       "failed,reconnect-failed,reconnected,ok",
			wantDials:  "192.0.2.1:853,192.0.2.1:853,192.0.2.2:853",
			wantRemote: "192.0.2.2:853",
		},
		{
			name:     "the address it reached goes silent",
			resolved: []string{"192.0.2.1", "192.0.2.2"}, silentAtOpen: []string{"192.0.2.1:853"}, silentLater: []string{"192.0.2.2:853"},
			want:       "failed,reconnect-failed,reconnected,ok",
			wantDials:  "192.0.2.1:853,192.0.2.2:853,192.0.2.2:853,192.0.2.1:853",
			wantRemote: "192.0.2.1:853",
		},
		{
			// The address after the one a timed-out reconnect started at
			// is taken in the resolver's order. Taking it in the order
			// that reconnect had dialled, which put the preferred address
			// first, sent the next reconnect back to the first silent
			// address, so the reconnects alternated between the two and
			// never reached the third.
			name:     "the first two of three addresses go silent",
			resolved: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, silentLater: []string{"192.0.2.1:853", "192.0.2.2:853"},
			want:       "failed,reconnect-failed,reconnect-failed,reconnected,ok",
			wantDials:  "192.0.2.1:853,192.0.2.1:853,192.0.2.2:853,192.0.2.3:853",
			wantRemote: "192.0.2.3:853",
		},
		{
			// A reconnect dials the preferred address first and then the
			// others in the resolver's order. When the preferred one fails
			// at once and an earlier one uses up the budget, the next
			// reconnect starts after the preferred address. Starting after
			// the one that used up the budget came back to the preferred
			// address, so the reconnects repeated the same two dials and
			// never reached the third.
			name:     "the address it reached fails at once and an earlier one is silent",
			resolved: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, silentAtOpen: []string{"192.0.2.1:853"}, silentLater: []string{"192.0.2.1:853"}, refusedLater: []string{"192.0.2.2:853"},
			want:       "failed,reconnect-failed,reconnected,ok",
			wantDials:  "192.0.2.1:853,192.0.2.2:853,192.0.2.2:853,192.0.2.1:853,192.0.2.3:853",
			wantRemote: "192.0.2.3:853",
		},
		{
			// The dns.google shape on a host whose IPv6 is routed but
			// broken: Open waits out both IPv6 addresses, and once the
			// IPv4 address it reached fails at once, the other IPv4
			// address is the next reconnect's first.
			name:         "both IPv6 addresses are silent and the IPv4 address it reached fails at once",
			resolved:     []string{"2001:4860:4860::8888", "2001:4860:4860::8844", "8.8.8.8", "8.8.4.4"},
			silentAtOpen: []string{"[2001:4860:4860::8888]:853", "[2001:4860:4860::8844]:853"},
			silentLater:  []string{"[2001:4860:4860::8888]:853", "[2001:4860:4860::8844]:853"},
			refusedLater: []string{"8.8.8.8:853"},
			want:         "failed,reconnect-failed,reconnected,ok",
			wantDials:    "[2001:4860:4860::8888]:853,[2001:4860:4860::8844]:853,8.8.8.8:853,8.8.8.8:853,[2001:4860:4860::8888]:853,8.8.4.4:853",
			wantRemote:   "8.8.4.4:853",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			stubLookup(t, testCase.resolved...)
			oldDial := dialDoQ
			t.Cleanup(func() { dialDoQ = oldDial })
			silent := testCase.silentAtOpen
			var refused []string
			var dialed []string
			connected := 0
			dialDoQ = func(ctx context.Context, address string, _ *tls.Config, _ *quic.Config) (doqConn, error) {
				dialed = append(dialed, address)
				if slices.Contains(silent, address) {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				if slices.Contains(refused, address) {
					return nil, errors.New("CRYPTO_ERROR 0x128 (remote): tls: handshake failure")
				}
				connected++
				_, conn := newFakeDoQStream()
				conn.remote = address
				if connected == 1 {
					// The connection Open made is lost on its first query.
					conn.openErr = errors.New("DoQ connection closed")
				}
				return conn, nil
			}
			factory := &doqFactory{
				connectionPlan: dialPlan{addresses: []string{"dns.example:853"}, timeout: timeout},
				timeout:        timeout,
				tlsConfig:      &tls.Config{ServerName: "dns.example", NextProtos: []string{"doq"}},
			}
			session, err := factory.Open(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			silent, refused = testCase.silentLater, testCase.refusedLater
			got := strings.Join(queryOutcomes(t, session, strings.Count(testCase.want, ",")+1, timeout), ",")
			if got != testCase.want {
				t.Fatalf("DoQ queries after the connection was lost = %s, want %s", got, testCase.want)
			}
			if got := strings.Join(dialed, ","); got != testCase.wantDials {
				t.Fatalf("DoQ dials = %s, want %s", got, testCase.wantDials)
			}
			if got := connectionOf(t, session).RemoteAddress; got != testCase.wantRemote {
				t.Fatalf("DoQ remote address = %q, want %q", got, testCase.wantRemote)
			}
			if got := session.(*doqSession).DialAddress(); got != "dns.example:853" {
				t.Fatalf("DoQ dial address = %q, want the configured candidate", got)
			}
		})
	}
}
