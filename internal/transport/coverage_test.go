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
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/dns-speedtest/internal/catalog"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

type scriptedConn struct {
	readBuf        bytes.Buffer
	readErr        error
	writeErrAt     int
	setDeadlineErr error
	closeErr       error
	writeCalls     int
	deadlines      []time.Time
	lastWrite      []byte
	onWrite        func([]byte)
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	if c.readBuf.Len() == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		return 0, io.EOF
	}
	return c.readBuf.Read(p)
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	c.writeCalls++
	if c.writeErrAt == c.writeCalls {
		return 0, errors.New("write failed")
	}
	if c.onWrite != nil {
		c.onWrite(append([]byte(nil), p...))
	}
	return len(p), nil
}

func (c *scriptedConn) Close() error         { return c.closeErr }
func (c *scriptedConn) LocalAddr() net.Addr  { return fakeAddr("local") }
func (c *scriptedConn) RemoteAddr() net.Addr { return fakeAddr("remote") }
func (c *scriptedConn) SetDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	return c.setDeadlineErr
}
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

func replyFor(name string, qtype, id uint16) *dns.Msg {
	return &dns.Msg{MsgHdr: dns.MsgHdr{Id: id, Response: true}, Question: []dns.Question{{Name: dns.Fqdn(name), Qtype: qtype, Qclass: dns.ClassINET}}}
}

func frameMessage(message *dns.Msg) []byte {
	packed, err := message.Pack()
	if err != nil {
		panic(err)
	}
	framed := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(packed)))
	copy(framed[2:], packed)
	return framed
}

func queueReplyAfterQuery(c *scriptedConn) {
	if c.writeCalls != 2 {
		return
	}
	query := new(dns.Msg)
	if err := query.Unpack(c.lastWrite); err != nil {
		return
	}
	c.readBuf.Write(frameMessage(replyFor(query.Question[0].Name, query.Question[0].Qtype, query.Id)))
}

func (c *scriptedConn) rememberWrite(p []byte) {
	c.lastWrite = append([]byte(nil), p...)
	queueReplyAfterQuery(c)
}

func withPackSession(t *testing.T, fn func(*dns.Msg) ([]byte, error)) {
	old := packSessionQuery
	packSessionQuery = fn
	t.Cleanup(func() { packSessionQuery = old })
}

func newScriptedStreamConn() *scriptedConn {
	c := &scriptedConn{}
	c.onWrite = c.rememberWrite
	return c
}

func TestFactorySelectionAndAddressHelpers(t *testing.T) {
	if _, err := NewFactory(catalog.Target{Protocol: catalog.UDP}, 0); err == nil {
		t.Fatal("expected nonpositive timeout error")
	}
	tests := []struct {
		protocol catalog.Protocol
		wantType string
	}{
		{catalog.UDP, "*transport.udpFactory"}, {catalog.TCP, "*transport.streamFactory"}, {catalog.DoH, "*transport.doHFactory"}, {catalog.DoT, "*transport.streamFactory"}, {catalog.DoQ, "*transport.doqFactory"},
	}
	for _, tc := range tests {
		target := catalog.Target{Protocol: tc.protocol, Address: "192.0.2.1", Spec: catalog.TransportSpec{Port: 53, URL: "https://dns.example/dns-query", ServerName: "dns.example"}}
		factory, err := NewFactory(target, time.Second)
		if err != nil {
			t.Fatalf("NewFactory(%s): %v", tc.protocol, err)
		}
		if got := typeName(factory); got != tc.wantType {
			t.Fatalf("factory type = %s, want %s", got, tc.wantType)
		}
	}
	if _, err := NewFactory(catalog.Target{Protocol: "unknown", Address: "192.0.2.1", Spec: catalog.TransportSpec{Port: 53}}, time.Second); err == nil {
		t.Fatal("expected unsupported protocol error")
	}
	dot, _ := NewFactory(catalog.Target{Protocol: catalog.DoT, Address: "192.0.2.2", Spec: catalog.TransportSpec{Port: 853}}, time.Second)
	if dot.(*streamFactory).tlsConfig.ServerName != "192.0.2.2" {
		t.Fatalf("DoT fallback server name = %q", dot.(*streamFactory).tlsConfig.ServerName)
	}
	doq, _ := NewFactory(catalog.Target{Protocol: catalog.DoQ, Address: "192.0.2.3", Spec: catalog.TransportSpec{Port: 853}}, time.Second)
	if doq.(*doqFactory).tlsConfig.NextProtos[0] != "doq" || doq.(*doqFactory).tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("DoQ TLS config = %#v", doq.(*doqFactory).tlsConfig)
	}
	if joinAddress(" 192.0.2.1 ", 53) != "192.0.2.1:53" || joinAddress("[2001:db8::1]", 853) != "[2001:db8::1]:853" {
		t.Fatal("unexpected joined addresses")
	}
	left, _ := url.Parse("https://DNS.Example/a")
	right, _ := url.Parse("https://dns.example/b")
	other, _ := url.Parse("https://other.example/b")
	if !sameHost(left, right) || sameHost(left, other) {
		t.Fatal("sameHost comparison failed")
	}
}

func typeName(value any) string {
	switch value.(type) {
	case *udpFactory:
		return "*transport.udpFactory"
	case *streamFactory:
		return "*transport.streamFactory"
	case *doHFactory:
		return "*transport.doHFactory"
	case *doqFactory:
		return "*transport.doqFactory"
	default:
		return "unknown"
	}
}

func TestStreamFactoryPlainTLSAndFailurePaths(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
		_ = listener.Close()
	}()
	if _, err := (&streamFactory{address: address, timeout: time.Second, tlsConfig: &tls.Config{ServerName: "localhost"}}).Open(context.Background()); err == nil {
		t.Fatal("expected TLS handshake failure")
	}

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddress := closed.Addr().String()
	_ = closed.Close()
	if _, err := (&streamFactory{address: closedAddress, timeout: 20 * time.Millisecond}).Open(context.Background()); err == nil {
		t.Fatal("expected TCP dial failure")
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsFactory := &streamFactory{address: strings.TrimPrefix(server.URL, "https://"), timeout: time.Second, tlsConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}}
	session, err := tlsFactory.Open(context.Background())
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	if !session.(*streamSession).secure {
		t.Fatal("TLS stream was not marked secure")
	}
	_ = session.Close()
	server.Close()
}

func TestUDPSessionFailureAndFactoryOpen(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buffer := make([]byte, 4096)
		n, address, readErr := conn.ReadFromUDP(buffer)
		if readErr != nil {
			return
		}
		query := new(dns.Msg)
		if query.Unpack(buffer[:n]) != nil {
			return
		}
		response := replyFor("other.example", query.Question[0].Qtype, query.Id)
		packed, _ := response.Pack()
		_, _ = conn.WriteToUDP(packed, address)
	}()
	session, err := (&udpFactory{address: conn.LocalAddr().String(), timeout: time.Second}).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err == nil {
		t.Fatal("expected UDP validation error")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	unused, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	unusedAddress := unused.LocalAddr().String()
	_ = unused.Close()
	if _, err := (&udpSession{address: unusedAddress, timeout: 10 * time.Millisecond}).Query(context.Background(), "example.com", dns.TypeA); err == nil {
		t.Fatal("expected UDP exchange failure")
	}
}

func TestStreamSessionFramingAndAllErrors(t *testing.T) {
	valid := func() (*streamSession, *scriptedConn) {
		conn := newScriptedStreamConn()
		return &streamSession{conn: conn, timeout: time.Second}, conn
	}
	session, conn := valid()
	response, err := session.Query(context.Background(), "example.com", dns.TypeA)
	if err != nil || response == nil || conn.writeCalls != 2 {
		t.Fatalf("stream success = %#v/%v, writes=%d", response, err, conn.writeCalls)
	}

	cases := []struct {
		name string
		make func() *streamSession
	}{
		{"pack", func() *streamSession {
			withPackSession(t, func(*dns.Msg) ([]byte, error) { return nil, errors.New("pack failed") })
			return &streamSession{conn: &scriptedConn{}, timeout: time.Second}
		}},
		{"deadline", func() *streamSession {
			return &streamSession{conn: &scriptedConn{setDeadlineErr: errors.New("deadline failed")}, timeout: time.Second}
		}},
		{"oversize", func() *streamSession {
			withPackSession(t, func(*dns.Msg) ([]byte, error) { return make([]byte, 65536), nil })
			return &streamSession{conn: &scriptedConn{}, timeout: time.Second}
		}},
		{"prefix write", func() *streamSession { return &streamSession{conn: &scriptedConn{writeErrAt: 1}, timeout: time.Second} }},
		{"payload write", func() *streamSession { return &streamSession{conn: &scriptedConn{writeErrAt: 2}, timeout: time.Second} }},
		{"prefix read", func() *streamSession {
			return &streamSession{conn: &scriptedConn{readErr: errors.New("prefix read failed")}, timeout: time.Second}
		}},
		{"empty response", func() *streamSession {
			conn := &scriptedConn{}
			conn.readBuf.Write([]byte{0, 0})
			return &streamSession{conn: conn, timeout: time.Second}
		}},
		{"short body", func() *streamSession {
			conn := &scriptedConn{}
			conn.readBuf.Write([]byte{0, 3, 1})
			return &streamSession{conn: conn, timeout: time.Second}
		}},
		{"unpack", func() *streamSession {
			conn := &scriptedConn{}
			conn.readBuf.Write([]byte{0, 1, 1})
			return &streamSession{conn: conn, timeout: time.Second}
		}},
		{"validation", func() *streamSession {
			conn := &scriptedConn{}
			conn.readBuf.Write(frameMessage(replyFor("other.example", dns.TypeA, 1)))
			return &streamSession{conn: conn, timeout: time.Second}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := packSessionQuery
			s := tc.make()
			defer func() { packSessionQuery = before }()
			if _, err := s.Query(context.Background(), "example.com", dns.TypeA); err == nil {
				t.Fatal("expected stream query error")
			}
		})
	}
	closeConn := &scriptedConn{closeErr: errors.New("close failed")}
	if err := (&streamSession{conn: closeConn}).Close(); err == nil {
		t.Fatal("expected stream close error")
	}
}

func TestDeadlineAndResponseValidation(t *testing.T) {
	conn := &scriptedConn{}
	if err := setConnDeadline(conn, context.Background(), time.Second); err != nil || len(conn.deadlines) != 1 {
		t.Fatal("background deadline failed")
	}
	early, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := setConnDeadline(conn, early, time.Hour); err != nil {
		t.Fatal(err)
	}
	later, cancelLater := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	defer cancelLater()
	if err := setConnDeadline(conn, later, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := setConnDeadline(&scriptedConn{setDeadlineErr: errors.New("deadline")}, context.Background(), time.Second); err == nil {
		t.Fatal("expected SetDeadline error")
	}

	valid := replyFor("example.com", dns.TypeA, 7)
	cases := []struct {
		name    string
		message *dns.Msg
		id      uint16
		zeroID  bool
	}{
		{"nil", nil, 7, false},
		{"missing response", &dns.Msg{MsgHdr: dns.MsgHdr{Id: 7}, Question: valid.Question}, 7, false},
		{"id mismatch", replyFor("example.com", dns.TypeA, 8), 7, false},
		{"zero id mismatch", replyFor("example.com", dns.TypeA, 8), 0, true},
		{"no questions", &dns.Msg{MsgHdr: dns.MsgHdr{Id: 7, Response: true}}, 7, false},
		{"two questions", &dns.Msg{MsgHdr: dns.MsgHdr{Id: 7, Response: true}, Question: []dns.Question{valid.Question[0], valid.Question[0]}}, 7, false},
		{"wrong type", replyFor("example.com", dns.TypeAAAA, 7), 7, false},
		{"wrong class", &dns.Msg{MsgHdr: dns.MsgHdr{Id: 7, Response: true}, Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassCHAOS}}}, 7, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateResponse(tc.message, "example.com", dns.TypeA, tc.id, tc.zeroID); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if err := validateResponse(valid, "EXAMPLE.COM", dns.TypeA, 7, false); err != nil {
		t.Fatal(err)
	}
	zero := replyFor("example.com", dns.TypeA, 0)
	if err := validateResponse(zero, "example.com", dns.TypeA, 0, true); err != nil {
		t.Fatal(err)
	}
}

func TestDoHFactorySessionAndRedirects(t *testing.T) {
	for _, raw := range []string{"https://", "http://dns.example/dns-query", "https:///dns-query"} {
		if _, err := newDoHFactory(catalog.Target{Spec: catalog.TransportSpec{URL: raw}}, time.Second); err == nil {
			t.Fatalf("expected invalid DoH URL %q", raw)
		}
	}
	factory, err := newDoHFactory(catalog.Target{Address: "192.0.2.53", Spec: catalog.TransportSpec{URL: "https://dns.example/dns-query", Port: 8443, ServerName: "tls.example"}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	dohFactory := factory.(*doHFactory)
	if dohFactory.dialAddr != "192.0.2.53:8443" || dohFactory.serverName != "tls.example" {
		t.Fatalf("DoH factory = %#v", dohFactory)
	}
	fallback, err := newDoHFactory(catalog.Target{Spec: catalog.TransportSpec{URL: "https://dns.example/dns-query"}}, time.Second)
	if err != nil || fallback.(*doHFactory).dialAddr != "dns.example:443" || fallback.(*doHFactory).serverName != "dns.example" {
		t.Fatalf("DoH fallback factory = %#v/%v", fallback, err)
	}
	legacy := &doHFactory{url: "https://dns.example/dns-query", dialAddr: "dns.example:443", timeout: time.Second}
	legacySession, err := legacy.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = legacySession.Close()
	session, err := dohFactory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	doh := session.(*doHSession)
	if doh.client.Timeout != time.Second || !doh.client.Transport.(*http.Transport).ForceAttemptHTTP2 {
		t.Fatal("DoH client configuration missing")
	}
	dialCtx, cancelDial := context.WithCancel(context.Background())
	cancelDial()
	if _, err := doh.client.Transport.(*http.Transport).DialContext(dialCtx, "tcp", "ignored"); err == nil {
		t.Fatal("expected cancelled DoH dial")
	}
	first, _ := url.Parse("https://dns.example/a")
	same, _ := url.Parse("https://DNS.EXAMPLE/b")
	other, _ := url.Parse("https://other.example/b")
	if err := doh.client.CheckRedirect(&http.Request{URL: same}, nil); err != nil {
		t.Fatal(err)
	}
	if err := doh.client.CheckRedirect(&http.Request{URL: same}, []*http.Request{{URL: first}}); err != nil {
		t.Fatal(err)
	}
	if err := doh.client.CheckRedirect(&http.Request{URL: other}, []*http.Request{{URL: first}}); err == nil {
		t.Fatal("expected cross-host redirect rejection")
	}
	if err := doh.Close(); err != nil {
		t.Fatal(err)
	}
	if sameHTTPSOrigin(nil, first) || sameHTTPSOrigin(first, other) {
		t.Fatal("invalid HTTPS origin was accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

type errorBody struct{}

func (errorBody) Read([]byte) (int, error) { return 0, errors.New("body read failed") }
func (errorBody) Close() error             { return nil }

func doHTestSession(rt roundTripFunc) *doHSession {
	return &doHSession{client: &http.Client{Transport: rt}, transport: &http.Transport{}, endpoint: "https://dns.example/dns-query"}
}

func TestDoHQueryAllResponseBranches(t *testing.T) {
	validTransport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		query := new(dns.Msg)
		if err := query.Unpack(body); err != nil {
			return nil, err
		}
		response, _ := replyFor(query.Question[0].Name, query.Question[0].Qtype, 0).Pack()
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(response)), Request: request}, nil
	})
	session := doHTestSession(validTransport)
	response, err := session.Query(context.Background(), "example.com", dns.TypeA)
	if err != nil || response == nil {
		t.Fatalf("DoH valid query = %#v/%v", response, err)
	}
	cases := []struct {
		name string
		rt   roundTripFunc
	}{
		{"client error", func(*http.Request) (*http.Response, error) { return nil, errors.New("client failed") }},
		{"status", func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 500, Status: "500 Server Error", Header: make(http.Header), Body: io.NopCloser(strings.NewReader("error")), Request: request}, nil
		}},
		{"content type", func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Status: "200 OK", Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader("x")), Request: request}, nil
		}},
		{"body read", func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: errorBody{}, Request: request}, nil
		}},
		{"unpack", func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader("bad")), Request: request}, nil
		}},
		{"validation", func(request *http.Request) (*http.Response, error) {
			body, _ := replyFor("other.example", dns.TypeA, 0).Pack()
			return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := doHTestSession(tc.rt).Query(context.Background(), "example.com", dns.TypeA); err == nil {
				t.Fatal("expected DoH error")
			}
		})
	}
	withPackSession(t, func(*dns.Msg) ([]byte, error) { return nil, errors.New("pack failed") })
	if _, err := doHTestSession(validTransport).Query(context.Background(), "example.com", dns.TypeA); err == nil {
		t.Fatal("expected DoH pack error")
	}
	packSessionQuery = packQuery
	if _, err := (&doHSession{client: &http.Client{}, transport: &http.Transport{}, endpoint: "://bad"}).Query(context.Background(), "example.com", dns.TypeA); err == nil {
		t.Fatal("expected DoH request construction error")
	}
}

type fakeDoQStream struct {
	readBuf     bytes.Buffer
	writeErrAt  int
	writeCalls  int
	closeErr    error
	deadlineErr error
	deadlines   []time.Time
	onWrite     func([]byte)
}

func (s *fakeDoQStream) Read(p []byte) (int, error) {
	if s.readBuf.Len() == 0 {
		return 0, io.EOF
	}
	return s.readBuf.Read(p)
}
func (s *fakeDoQStream) Write(p []byte) (int, error) {
	s.writeCalls++
	if s.writeErrAt == s.writeCalls {
		return 0, errors.New("DoQ write failed")
	}
	if s.onWrite != nil {
		s.onWrite(append([]byte(nil), p...))
	}
	return len(p), nil
}
func (s *fakeDoQStream) Close() error { return s.closeErr }
func (s *fakeDoQStream) SetDeadline(deadline time.Time) error {
	s.deadlines = append(s.deadlines, deadline)
	return s.deadlineErr
}

type fakeDoQConn struct {
	stream   doqStream
	openErr  error
	closeErr error
}

func (c *fakeDoQConn) OpenStreamSync(context.Context) (doqStream, error)      { return c.stream, c.openErr }
func (c *fakeDoQConn) CloseWithError(quic.ApplicationErrorCode, string) error { return c.closeErr }

func newFakeDoQStream() (*fakeDoQStream, *fakeDoQConn) {
	stream := &fakeDoQStream{}
	stream.onWrite = func(p []byte) {
		if stream.writeCalls != 2 {
			return
		}
		query := new(dns.Msg)
		if query.Unpack(p) != nil {
			return
		}
		stream.readBuf.Write(frameMessage(replyFor(query.Question[0].Name, query.Question[0].Qtype, 0)))
	}
	return stream, &fakeDoQConn{stream: stream}
}

func TestDoQFactoryAndSessionAllBranches(t *testing.T) {
	oldDial := dialDoQ
	t.Cleanup(func() { dialDoQ = oldDial })
	oldPack := packSessionQuery
	t.Cleanup(func() { packSessionQuery = oldPack })
	if _, err := oldDial(context.Background(), "127.0.0.1:1", &tls.Config{NextProtos: []string{"doq"}}, &quic.Config{HandshakeIdleTimeout: 10 * time.Millisecond}); err == nil {
		t.Fatal("expected default DoQ dial failure")
	}
	fakeStream, fakeConn := newFakeDoQStream()
	var dialedAddress string
	dialDoQ = func(_ context.Context, address string, config *tls.Config, _ *quic.Config) (doqConn, error) {
		dialedAddress = address
		if config.NextProtos[0] != "doq" {
			t.Fatalf("DoQ ALPN = %#v", config.NextProtos)
		}
		return fakeConn, nil
	}
	factory := &doqFactory{address: "192.0.2.1:853", timeout: time.Second, tlsConfig: &tls.Config{NextProtos: []string{"doq"}}}
	session, err := factory.Open(context.Background())
	if err != nil || dialedAddress != factory.address {
		t.Fatalf("DoQ factory open = %#v/%v", session, err)
	}
	if _, err := session.(*doqSession).Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if len(fakeStream.deadlines) != 1 {
		t.Fatal("DoQ fallback deadline was not set")
	}
	deadlineContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	fakeStream, fakeConn = newFakeDoQStream()
	if _, err := (&doqSession{conn: fakeConn, timeout: time.Second}).Query(deadlineContext, "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if err := (&doqSession{conn: &fakeDoQConn{closeErr: errors.New("close")}}).Close(); err == nil {
		t.Fatal("expected DoQ close error")
	}

	dialDoQ = func(context.Context, string, *tls.Config, *quic.Config) (doqConn, error) {
		return nil, errors.New("dial failed")
	}
	if _, err := factory.Open(context.Background()); err == nil {
		t.Fatal("expected DoQ factory dial error")
	}

	cases := []struct {
		name string
		make func() *doqSession
	}{
		{"pack", func() *doqSession {
			packSessionQuery = func(*dns.Msg) ([]byte, error) { return nil, errors.New("pack") }
			return &doqSession{conn: &fakeDoQConn{}, timeout: time.Second}
		}},
		{"oversize", func() *doqSession {
			packSessionQuery = func(*dns.Msg) ([]byte, error) { return make([]byte, 65536), nil }
			return &doqSession{conn: &fakeDoQConn{}, timeout: time.Second}
		}},
		{"open stream", func() *doqSession {
			return &doqSession{conn: &fakeDoQConn{openErr: errors.New("open stream")}, timeout: time.Second}
		}},
		{"prefix write", func() *doqSession {
			return &doqSession{conn: &fakeDoQConn{stream: &fakeDoQStream{writeErrAt: 1}}, timeout: time.Second}
		}},
		{"payload write", func() *doqSession {
			return &doqSession{conn: &fakeDoQConn{stream: &fakeDoQStream{writeErrAt: 2}}, timeout: time.Second}
		}},
		{"close", func() *doqSession {
			return &doqSession{conn: &fakeDoQConn{stream: &fakeDoQStream{closeErr: errors.New("close stream")}}, timeout: time.Second}
		}},
		{"read prefix", func() *doqSession {
			return &doqSession{conn: &fakeDoQConn{stream: &fakeDoQStream{}}, timeout: time.Second}
		}},
		{"empty", func() *doqSession {
			stream := &fakeDoQStream{}
			stream.readBuf.Write([]byte{0, 0})
			return &doqSession{conn: &fakeDoQConn{stream: stream}, timeout: time.Second}
		}},
		{"short body", func() *doqSession {
			stream := &fakeDoQStream{}
			stream.readBuf.Write([]byte{0, 3, 1})
			return &doqSession{conn: &fakeDoQConn{stream: stream}, timeout: time.Second}
		}},
		{"unpack", func() *doqSession {
			stream := &fakeDoQStream{}
			stream.readBuf.Write([]byte{0, 1, 1})
			return &doqSession{conn: &fakeDoQConn{stream: stream}, timeout: time.Second}
		}},
		{"validation", func() *doqSession {
			stream := &fakeDoQStream{}
			stream.readBuf.Write(frameMessage(replyFor("other.example", dns.TypeA, 0)))
			return &doqSession{conn: &fakeDoQConn{stream: stream}, timeout: time.Second}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			packSessionQuery = packQuery
			if _, err := tc.make().Query(context.Background(), "example.com", dns.TypeA); err == nil {
				t.Fatal("expected DoQ query error")
			}
		})
	}
}

func TestQueryPackingAndClassification(t *testing.T) {
	plain := newQuery("example.com", dns.TypeA, 7, false)
	if plain.Id != 7 || !plain.RecursionDesired || len(plain.Question) != 1 || len(plain.Extra) != 1 {
		t.Fatalf("plain query = %#v", plain)
	}
	if opt, ok := plain.Extra[0].(*dns.OPT); !ok || len(opt.Option) != 0 {
		t.Fatalf("plain OPT = %#v", plain.Extra)
	}
	bad := &dns.Msg{Question: []dns.Question{{Name: strings.Repeat("a", 64) + ".example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	if _, err := packQuery(bad); err == nil {
		t.Fatal("expected DNS packing error")
	}
	withExtra := newQuery("example.com", dns.TypeA, 1, false)
	withExtra.Extra = append(withExtra.Extra, &dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET}})
	if _, err := packQuery(withExtra); err != nil {
		t.Fatal(err)
	}
	withOption := newQuery("example.com", dns.TypeA, 1, false)
	withOption.Extra[0].(*dns.OPT).Option = []dns.EDNS0{&dns.EDNS0_NSID{}}
	if _, err := packQuery(withOption); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		message *dns.Msg
		want    string
	}{
		{nil, "invalid"},
		{&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}, "nodata"},
		{&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}, Answer: []dns.RR{&dns.A{}}}, "answer"},
		{&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}, "nxdomain"},
		{&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}, "rcode-2"},
	} {
		if got := ResponseClass(tc.message); got != tc.want {
			t.Fatalf("ResponseClass = %q, want %q", got, tc.want)
		}
	}
}

func TestResponseCodeSemantics(t *testing.T) {
	usable := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}
	nxdomain := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
	servfail := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}
	if !IsUsableResponse(usable) || !IsUsableResponse(nxdomain) {
		t.Fatal("NOERROR and NXDOMAIN should be usable DNS outcomes")
	}
	if IsUsableResponse(servfail) || IsUsableResponse(nil) {
		t.Fatal("resolver errors and nil responses should not be usable")
	}
	if got := ResponseCodeName(dns.RcodeServerFailure); got != "SERVFAIL" {
		t.Fatalf("ResponseCodeName(SERVFAIL) = %q", got)
	}
	if got := ResponseCodeName(999); got != "RCODE999" {
		t.Fatalf("ResponseCodeName(999) = %q", got)
	}
}

func TestLocalDoQFactoryExercisesAdapter(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificates := server.TLS.Certificates
	server.Close()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: certificates, NextProtos: []string{"doq"}}, &quic.Config{MaxIdleTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.CloseWithError(0, "")
		stream, streamErr := conn.AcceptStream(context.Background())
		if streamErr != nil {
			serverDone <- streamErr
			return
		}
		var prefix [2]byte
		if _, err := io.ReadFull(stream, prefix[:]); err != nil {
			serverDone <- err
			return
		}
		requestBytes := make([]byte, binary.BigEndian.Uint16(prefix[:]))
		if _, err := io.ReadFull(stream, requestBytes); err != nil {
			serverDone <- err
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(requestBytes); err != nil {
			serverDone <- err
			return
		}
		response, _ := replyFor(query.Question[0].Name, query.Question[0].Qtype, 0).Pack()
		binary.BigEndian.PutUint16(prefix[:], uint16(len(response)))
		if _, err := stream.Write(prefix[:]); err != nil {
			serverDone <- err
			return
		}
		_, writeErr := stream.Write(response)
		serverDone <- writeErr
		time.Sleep(100 * time.Millisecond)
	}()
	factory := &doqFactory{address: listener.Addr().String(), timeout: time.Second, tlsConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"doq"}}}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	_ = session.Close()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("DoQ fixture did not finish")
	}
}
