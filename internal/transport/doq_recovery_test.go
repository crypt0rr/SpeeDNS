package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"strings"
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
			first := &fakeDoQConn{openErr: tc.err}
			_, second := newFakeDoQStream()
			opens := 0
			session := &doqSession{
				conn:    first,
				timeout: time.Second,
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
