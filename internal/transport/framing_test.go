package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func packedQuery(t *testing.T, name string, qtype, id uint16, padded bool) []byte {
	t.Helper()
	packed, err := packQuery(newQuery(name, qtype, id, padded, QueryOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

// The connection-oriented transports and DoQ share one framing implementation
// but keep their stream lifecycles: a reused TCP or DoT connection must stay
// writable, while DoQ closes the send side of its per-query stream.
func TestFramedStreamLifecycleDiffers(t *testing.T) {
	conn := newScriptedStreamConn()
	response, err := framedStream{stream: conn, label: "DNS"}.query(packedQuery(t, "example.com", dns.TypeA, 7, false), "example.com", dns.TypeA, 7, false)
	if err != nil {
		t.Fatal(err)
	}
	if response.Id != 7 {
		t.Fatalf("stream response ID = %d, want 7", response.Id)
	}
	if conn.closeCalls != 0 {
		t.Fatalf("stream framing closed the connection %d times", conn.closeCalls)
	}

	stream, _ := newFakeDoQStream()
	closes := 0
	closeSend := func() error {
		closes++
		return stream.Close()
	}
	response, err = framedStream{stream: stream, closeSend: closeSend, label: "DoQ"}.query(packedQuery(t, "example.com", dns.TypeA, 0, true), "example.com", dns.TypeA, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if response.Id != 0 {
		t.Fatalf("DoQ response ID = %d, want 0", response.Id)
	}
	if closes != 1 {
		t.Fatalf("DoQ framing closed the send side %d times, want 1", closes)
	}
}

func TestFramedStreamErrorsCarryTransportLabel(t *testing.T) {
	for _, label := range []string{"DNS", "DoQ"} {
		t.Run(label, func(t *testing.T) {
			empty := &fakeDoQStream{}
			empty.readBuf.Write([]byte{0, 0})
			_, err := framedStream{stream: empty, label: label}.query(packedQuery(t, "example.com", dns.TypeA, 0, false), "example.com", dns.TypeA, 0, false)
			if err == nil || err.Error() != "empty "+label+" response" {
				t.Fatalf("empty response error = %v", err)
			}

			malformed := &fakeDoQStream{}
			malformed.readBuf.Write([]byte{0, 1, 1})
			_, err = framedStream{stream: malformed, label: label}.query(packedQuery(t, "example.com", dns.TypeA, 0, false), "example.com", dns.TypeA, 0, false)
			if err == nil || !strings.HasPrefix(err.Error(), "unpack "+label+" response: ") {
				t.Fatalf("unpack error = %v", err)
			}
		})
	}

	failing := &fakeDoQStream{}
	closeSend := func() error { return errors.New("close send failed") }
	if _, err := (framedStream{stream: failing, closeSend: closeSend, label: "DoQ"}).query(packedQuery(t, "example.com", dns.TypeA, 0, true), "example.com", dns.TypeA, 0, true); err == nil {
		t.Fatal("expected close-send error")
	}
}

// Both session types must bound one query by the transport timeout, even when
// the caller deadline is further away. The deadline target differs (the reused
// connection versus the per-query DoQ stream); the computation must not.
func TestStreamAndDoQShareQueryDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	const timeout = 50 * time.Millisecond

	conn := newScriptedStreamConn()
	if _, err := (&streamSession{conn: conn, timeout: timeout}).Query(ctx, "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if len(conn.deadlines) != 1 {
		t.Fatalf("stream deadlines = %v", conn.deadlines)
	}
	if conn.deadlines[0].After(time.Now().Add(time.Minute)) {
		t.Fatalf("stream deadline %v ignored the %v timeout", conn.deadlines[0], timeout)
	}

	stream, doqConn := newFakeDoQStream()
	if _, err := (&doqSession{conn: doqConn, timeout: timeout}).Query(ctx, "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if len(stream.deadlines) != 1 {
		t.Fatalf("DoQ deadlines = %v", stream.deadlines)
	}
	if stream.deadlines[0].After(time.Now().Add(time.Minute)) {
		t.Fatalf("DoQ deadline %v ignored the %v timeout", stream.deadlines[0], timeout)
	}
}

// richReply is a valid answer with records in every section, so name
// compression has something to point at and the RR walk crosses each section.
func richReply(name string, qtype, id uint16) *dns.Msg {
	reply := replyFor(name, qtype, id)
	owner := dns.Fqdn(name)
	reply.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "edge." + owner},
		&dns.A{Hdr: dns.RR_Header{Name: "edge." + owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)},
	}
	reply.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns." + owner, Mbox: "hostmaster." + owner, Serial: 1}}
	reply.Extra = []dns.RR{&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: ednsUDPSize}}}
	return reply
}

func packReply(t *testing.T, reply *dns.Msg, compress bool) []byte {
	t.Helper()
	reply.Compress = compress
	packed, err := reply.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

// wireLength must find the end of a valid message whatever its encoding: a
// re-pack is no reference, because compression changes the length.
func TestWireLengthMeasuresCompressedAndUncompressedReplies(t *testing.T) {
	compressed := packReply(t, richReply("example.com", dns.TypeA, 7), true)
	uncompressed := packReply(t, richReply("example.com", dns.TypeA, 7), false)
	if len(compressed) >= len(uncompressed) {
		t.Fatalf("fixture is not compressed: %d >= %d bytes", len(compressed), len(uncompressed))
	}
	header := uncompressed[:dnsHeaderLength]
	empty := append([]byte(nil), header...)
	clear(empty[4:])
	for _, wire := range [][]byte{compressed, uncompressed, empty} {
		if got, err := wireLength(wire); err != nil || got != len(wire) {
			t.Fatalf("wireLength(%d bytes) = %d/%v", len(wire), got, err)
		}
		if err := rejectTrailingBytes(wire, "DNS"); err != nil {
			t.Fatal(err)
		}
		extended := append(append([]byte(nil), wire...), 0)
		if err := rejectTrailingBytes(extended, "DNS"); err == nil || !strings.Contains(err.Error(), "DNS response has trailing data") {
			t.Fatalf("one trailing byte = %v", err)
		}
	}
	// A header that claims more records than the message holds ends where the
	// message does, as miekg/dns reads it.
	short := append([]byte(nil), empty...)
	binary.BigEndian.PutUint16(short[6:], 3)
	if got, err := wireLength(short); err != nil || got != len(short) {
		t.Fatalf("over-counted header = %d/%v", got, err)
	}

	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"short header", uncompressed[:dnsHeaderLength-1]},
		{"bad question name", append(append([]byte(nil), header...), 0xc0)},
		{"truncated question", append(append([]byte(nil), header...), 0, 0, 1)},
		{"bad record", append(append([]byte(nil), compressed...), 0xc0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := tc.wire
			if tc.name == "bad record" {
				binary.BigEndian.PutUint16(wire[10:], binary.BigEndian.Uint16(wire[10:])+1)
			}
			if _, err := wireLength(wire); err == nil {
				t.Fatal("expected a wire length error")
			}
			if err := rejectTrailingBytes(wire, "DoQ"); err == nil || !strings.HasPrefix(err.Error(), "measure DoQ response: ") {
				t.Fatalf("rejectTrailingBytes = %v", err)
			}
		})
	}
}

// replyStream returns a scripted stream whose read side holds one frame
// carrying body, whatever the request was.
func replyStream(body []byte) *fakeDoQStream {
	stream := &fakeDoQStream{}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(body)))
	stream.readBuf.Write(prefix[:])
	stream.readBuf.Write(body)
	return stream
}

// A frame longer than the DNS message inside it is a protocol error on every
// framed transport, and on DoH a body longer than its message is too. Valid
// replies are accepted compressed or not.
func TestRepliesWithTrailingBytesAreRejected(t *testing.T) {
	for _, compress := range []bool{true, false} {
		valid := packReply(t, richReply("example.com", dns.TypeA, 0), compress)
		extended := append(append([]byte(nil), valid...), 0)
		for _, label := range []string{"DNS", "DoQ"} {
			if _, err := (framedStream{stream: replyStream(valid), label: label}).query(packedQuery(t, "example.com", dns.TypeA, 0, true), "example.com", dns.TypeA, 0, true); err != nil {
				t.Fatalf("%s compress=%v valid frame: %v", label, compress, err)
			}
			_, err := (framedStream{stream: replyStream(extended), label: label}).query(packedQuery(t, "example.com", dns.TypeA, 0, true), "example.com", dns.TypeA, 0, true)
			if err == nil || !strings.HasPrefix(err.Error(), label+" response has trailing data") {
				t.Fatalf("%s compress=%v trailing frame = %v", label, compress, err)
			}
		}
		for _, tc := range []struct {
			body []byte
			ok   bool
		}{{valid, true}, {extended, false}} {
			session := doHTestSession(roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": []string{"application/dns-message"}}, Body: io.NopCloser(bytes.NewReader(tc.body)), Request: request}, nil
			}))
			_, err := session.Query(context.Background(), "example.com", dns.TypeA)
			if tc.ok != (err == nil) || (!tc.ok && !strings.HasPrefix(err.Error(), "DoH response has trailing data")) {
				t.Fatalf("DoH compress=%v body of %d bytes = %v", compress, len(tc.body), err)
			}
		}
	}
}

// The zero-ID rule applies to DoH as much as to DoQ, so its error must not
// blame DoQ for a DoH reply.
func TestZeroIDErrorNamesNeitherTransport(t *testing.T) {
	session := doHTestSession(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := replyFor("example.com", dns.TypeA, 7).Pack()
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": []string{"application/dns-message"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
	}))
	_, err := session.Query(context.Background(), "example.com", dns.TypeA)
	if err == nil || err.Error() != "DNS transaction ID must be zero, got 7" {
		t.Fatalf("DoH non-zero ID error = %v", err)
	}
	stream := replyStream(packReply(t, replyFor("example.com", dns.TypeA, 7), true))
	if _, err := (&doqSession{conn: &fakeDoQConn{stream: stream}, timeout: time.Second}).Query(context.Background(), "example.com", dns.TypeA); err == nil || !strings.Contains(err.Error(), "must be zero") {
		t.Fatalf("DoQ non-zero ID error = %v", err)
	}
}

type writeCountingConn struct {
	net.Conn
	writes atomic.Int32
}

func (c *writeCountingConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

// serveFramedQueries answers length-prefixed queries on conn until it closes.
func serveFramedQueries(conn net.Conn) {
	defer conn.Close()
	for {
		query, err := readFramedQuery(conn)
		if err != nil {
			return
		}
		if _, err := conn.Write(frameMessage(replyFor(query.Question[0].Name, query.Question[0].Qtype, query.Id))); err != nil {
			return
		}
	}
}

func readFramedQuery(reader io.Reader) (*dns.Msg, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	request := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(reader, request); err != nil {
		return nil, err
	}
	query := new(dns.Msg)
	if err := query.Unpack(request); err != nil {
		return nil, err
	}
	if len(query.Question) != 1 {
		return nil, errors.New("fixture query has no single question")
	}
	return query, nil
}

// TestDoTQuerySealsOneTLSRecord counts writes underneath TLS, where each one
// is a record: writing the length prefix on its own cost every DoT query a
// second record for two bytes.
func TestDoTQuerySealsOneTLSRecord(t *testing.T) {
	const serverName = "dns.example"
	certificate, roots := testServerCertificate(t, serverName)
	clientSide, serverSide := net.Pipe()
	go serveFramedQueries(tls.Server(serverSide, &tls.Config{Certificates: []tls.Certificate{certificate}}))
	counting := &writeCountingConn{Conn: clientSide}
	tlsConn := tls.Client(counting, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, RootCAs: roots})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	session := &streamSession{conn: tlsConn, timeout: time.Second, secure: true}
	defer session.Close()
	const queries = 3
	before := counting.writes.Load()
	for index := 0; index < queries; index++ {
		if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
			t.Fatal(err)
		}
	}
	if got := counting.writes.Load() - before; got != queries {
		t.Fatalf("%d DoT queries sealed %d TLS records, want %d", queries, got, queries)
	}
}

// A DoQ query cancels the read side of its stream once the answer is in, so
// quic-go can forget the stream even when the server's FIN is late.
func TestDoQQueryCancelsReadAfterTheAnswer(t *testing.T) {
	stream, conn := newFakeDoQStream()
	if _, err := (&doqSession{conn: conn, timeout: time.Second}).Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if len(stream.cancelReads) != 1 || stream.cancelReads[0] != doqNoError {
		t.Fatalf("CancelRead calls = %v, want one with DOQ_NO_ERROR", stream.cancelReads)
	}
	failing := &fakeDoQStream{}
	if _, err := (&doqSession{conn: &fakeDoQConn{stream: failing}, timeout: time.Second}).Query(context.Background(), "example.com", dns.TypeA); err == nil {
		t.Fatal("expected the unanswered DoQ query to fail")
	}
	if len(failing.cancelReads) != 0 {
		t.Fatalf("a failed query cancelled its read side %d times; the connection is dropped instead", len(failing.cancelReads))
	}
}

// TestDoQLateFINServerSeesStopSending uses a real quic-go server that writes
// the answer but holds back its FIN. The client must stop reading the stream
// with DOQ_NO_ERROR, which the server observes as STOP_SENDING, rather than
// leave the stream open until the connection closes.
func TestDoQLateFINServerSeesStopSending(t *testing.T) {
	const serverName = "dns.example"
	certificate, roots := testServerCertificate(t, serverName)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"doq"},
	}, &quic.Config{MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			observed <- err
			return
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			observed <- err
			return
		}
		query, err := readFramedQuery(stream)
		if err != nil {
			observed <- err
			return
		}
		if _, err := stream.Write(frameMessage(replyFor(query.Question[0].Name, query.Question[0].Qtype, 0))); err != nil {
			observed <- err
			return
		}
		select {
		case <-stream.Context().Done():
			observed <- context.Cause(stream.Context())
		case <-time.After(5 * time.Second):
			observed <- errors.New("the client never stopped reading the stream")
		}
	}()

	factory := &doqFactory{address: listener.Addr().String(), timeout: 5 * time.Second, tlsConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots, NextProtos: []string{"doq"},
	}}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	var streamErr *quic.StreamError
	if err := <-observed; !errors.As(err, &streamErr) || !streamErr.Remote || streamErr.ErrorCode != doqNoError {
		t.Fatalf("server stream ended with %v, want STOP_SENDING with DOQ_NO_ERROR", err)
	}
}
