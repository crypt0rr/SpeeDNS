package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func TestDialPlanUsesOrderedBootstrapCandidates(t *testing.T) {
	plan := newDialPlan("dns.example", []string{"192.0.2.1", "[2001:db8::1]"}, 853, time.Second)
	want := []string{"192.0.2.1:853", "[2001:db8::1]:853"}
	if len(plan.addresses) != len(want) || plan.addresses[0] != want[0] || plan.addresses[1] != want[1] {
		t.Fatalf("dial plan addresses = %#v, want %#v", plan.addresses, want)
	}

	fallback := newDialPlan("dns.example", nil, 853, time.Second)
	if len(fallback.addresses) != 1 || fallback.addresses[0] != "dns.example:853" {
		t.Fatalf("dial plan fallback = %#v", fallback.addresses)
	}
}

func TestDialPlanDefensiveBranches(t *testing.T) {
	if got := singleDialPlan("", time.Second).addresses; len(got) != 0 {
		t.Fatalf("empty single dial plan = %#v", got)
	}
	if got := newDialPlan("", []string{""}, 853, time.Second).addresses; len(got) != 0 {
		t.Fatalf("empty candidate dial plan = %#v", got)
	}
	if got := firstAddress(dialPlan{}); got != "" {
		t.Fatalf("empty first address = %q", got)
	}
	if err := (dialPlan{}).failed(nil); err == nil || !strings.Contains(err.Error(), "no connection candidates") {
		t.Fatalf("empty candidate error = %v", err)
	}
	zeroContext, zeroCancel := (dialPlan{}).openContext(context.Background())
	zeroCancel()
	if zeroContext == nil {
		t.Fatal("zero-timeout context is nil")
	}
	shortContext, shortCancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer shortCancel()
	shortPlan := dialPlan{timeout: time.Hour}
	boundedContext, boundedCancel := shortPlan.openContext(shortContext)
	boundedCancel()
	if boundedContext == nil {
		t.Fatal("bounded context is nil")
	}
}

func TestOpenStreamStopsAfterCanceledCandidate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	plan := dialPlan{addresses: []string{"127.0.0.1:1", "127.0.0.1:2"}, timeout: time.Second}
	if _, _, err := plan.openStream(ctx, nil); err == nil {
		t.Fatal("expected canceled stream open error")
	}
}

func TestOpenStreamReportsTLSHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- nil
			return
		}
		accepted <- conn
	}()
	plan := dialPlan{addresses: []string{listener.Addr().String()}, timeout: 20 * time.Millisecond}
	if _, _, err := plan.openStream(context.Background(), &tls.Config{InsecureSkipVerify: true}); err == nil {
		t.Fatal("expected TLS handshake timeout")
	}
	if conn := <-accepted; conn != nil {
		_ = conn.Close()
	}
}

func TestOpenStreamStopsAfterCanceledTLSCandidate(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- nil
			return
		}
		accepted <- conn
		cancel()
	}()

	plan := dialPlan{addresses: []string{listener.Addr().String(), "127.0.0.1:1"}, timeout: time.Second}
	if _, _, err := plan.openStream(ctx, &tls.Config{InsecureSkipVerify: true}); err == nil {
		t.Fatal("expected canceled TLS handshake error")
	}
	if conn := <-accepted; conn != nil {
		_ = conn.Close()
	}
}

func TestOpenStreamStopsAfterTLSContextExpires(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- nil
			return
		}
		accepted <- conn
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	plan := dialPlan{addresses: []string{listener.Addr().String()}, timeout: time.Second}
	if _, _, err := plan.openStream(ctx, &tls.Config{InsecureSkipVerify: true}); err == nil {
		t.Fatal("expected TLS context expiry")
	}
	if conn := <-accepted; conn != nil {
		_ = conn.Close()
	}
}

func TestOpenStreamRetriesAfterCandidateTimeout(t *testing.T) {
	const serverName = "dns.example"
	certificate, roots := testServerCertificate(t, serverName)

	firstListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer firstListener.Close()
	firstAccepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := firstListener.Accept()
		if acceptErr != nil {
			firstAccepted <- nil
			return
		}
		firstAccepted <- conn
	}()

	secondListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(secondListener, &tls.Config{Certificates: []tls.Certificate{certificate}})
	defer tlsListener.Close()
	secondResult := make(chan error, 1)
	go func() {
		conn, acceptErr := tlsListener.Accept()
		if acceptErr != nil {
			secondResult <- acceptErr
			return
		}
		tlsConn := conn.(*tls.Conn)
		handshakeErr := tlsConn.Handshake()
		_ = conn.Close()
		secondResult <- handshakeErr
	}()

	plan := dialPlan{
		addresses: []string{firstListener.Addr().String(), secondListener.Addr().String()},
		timeout:   100 * time.Millisecond,
	}
	conn, address, err := plan.openStream(context.Background(), &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		RootCAs:    roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	if address != secondListener.Addr().String() {
		t.Fatalf("selected address = %q, want %q", address, secondListener.Addr().String())
	}
	_ = conn.Close()

	if firstConn := <-firstAccepted; firstConn != nil {
		_ = firstConn.Close()
	}
	if err := <-secondResult; err != nil {
		t.Fatalf("second candidate TLS handshake = %v", err)
	}
}

func TestStreamFactoryFallsBackToNextCandidate(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	first := closed.Addr().String()
	_ = closed.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
		accepted <- acceptErr
	}()

	factory := &streamFactory{
		connectionPlan: dialPlan{addresses: []string{first, listener.Addr().String()}, timeout: time.Second},
		timeout:        time.Second,
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := session.(*streamSession).DialAddress(); got != listener.Addr().String() {
		t.Fatalf("selected dial address = %q, want %q", got, listener.Addr().String())
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}

	secondClosed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	second := secondClosed.Addr().String()
	_ = secondClosed.Close()
	failedFactory := &streamFactory{
		connectionPlan: dialPlan{addresses: []string{first, second}, timeout: 100 * time.Millisecond},
		timeout:        100 * time.Millisecond,
	}
	if _, err := failedFactory.Open(context.Background()); err == nil || !strings.Contains(err.Error(), first) || !strings.Contains(err.Error(), second) {
		t.Fatalf("all-candidate error = %v", err)
	}
}

func TestDoHFactoryUsesBootstrapCandidates(t *testing.T) {
	const port = 443
	factory, err := newDoHFactory(catalog.Target{
		Address: "192.0.2.53",
		Spec: catalog.TransportSpec{
			URL:                "https://dns.example/dns-query",
			Port:               port,
			ServerName:         "dns.example",
			BootstrapAddresses: []string{"127.0.0.2", "127.0.0.1"},
		},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	dohFactory := factory.(*doHFactory)
	if got := dohFactory.connectionPlan.addresses; len(got) != 2 || got[0] != "127.0.0.2:443" || got[1] != "127.0.0.1:443" {
		t.Fatalf("DoH bootstrap plan = %#v", got)
	}
	session, err := dohFactory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	transport := session.(*doHSession).client.Transport.(*http.Transport)
	if transport.MaxResponseHeaderBytes != doHMaxResponseHeaderBytes {
		t.Fatalf("DoH response header limit = %d, want %d", transport.MaxResponseHeaderBytes, doHMaxResponseHeaderBytes)
	}
}

func TestDoHQueryUsesBootstrapIPWithHostnameTLSIdentity(t *testing.T) {
	const serverName = "dns.example"
	certificate, roots := testServerCertificate(t, serverName)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}})
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(body); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		response, err := replyFor(query.Question[0].Name, query.Question[0].Qtype, 0).Pack()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(response)
	})}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(tlsListener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = tlsListener.Close()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
			t.Error("DoH TLS fixture did not stop")
		}
	})

	oldTLSConfig := newDoHTLSConfig
	newDoHTLSConfig = func(name string) *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name, RootCAs: roots}
	}
	t.Cleanup(func() { newDoHTLSConfig = oldTLSConfig })

	port := listener.Addr().(*net.TCPAddr).Port
	factory, err := newDoHFactory(catalog.Target{Address: "192.0.2.53", Spec: catalog.TransportSpec{
		URL:                "https://dns.example/dns-query",
		Port:               port,
		ServerName:         serverName,
		BootstrapAddresses: []string{"127.0.0.1"},
	}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if got := session.(*doHSession).DialAddress(); got != listener.Addr().String() {
		t.Fatalf("DoH selected dial address = %q, want %q", got, listener.Addr().String())
	}
}

func TestDoTUsesBootstrapIPAndServerName(t *testing.T) {
	const serverName = "dns.example"
	certificate, roots := testServerCertificate(t, serverName)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}})
	serverDone := make(chan struct {
		err        error
		serverName string
	}, 1)
	go func() {
		conn, acceptErr := tlsListener.Accept()
		if acceptErr != nil {
			serverDone <- struct {
				err        error
				serverName string
			}{err: acceptErr}
			return
		}
		tlsConn := conn.(*tls.Conn)
		handshakeErr := tlsConn.Handshake()
		name := ""
		if handshakeErr == nil {
			name = tlsConn.ConnectionState().ServerName
		}
		_ = conn.Close()
		serverDone <- struct {
			err        error
			serverName string
		}{err: handshakeErr, serverName: name}
	}()
	t.Cleanup(func() { _ = tlsListener.Close() })

	factory := &streamFactory{
		connectionPlan: dialPlan{addresses: []string{listener.Addr().String()}, timeout: time.Second},
		timeout:        time.Second,
		tlsConfig:      &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, RootCAs: roots},
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := session.(*streamSession).DialAddress(); got != listener.Addr().String() {
		t.Fatalf("DoT selected dial address = %q", got)
	}
	_ = session.Close()
	result := <-serverDone
	if result.err != nil || result.serverName != serverName {
		t.Fatalf("DoT TLS handshake = %v, SNI = %q", result.err, result.serverName)
	}
}

func testServerCertificate(t *testing.T, serverName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: serverName},
		DNSNames:              []string{serverName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return certificate, roots
}

func TestDoQFactoryFallsBackToNextCandidate(t *testing.T) {
	oldDial := dialDoQ
	t.Cleanup(func() { dialDoQ = oldDial })
	_, fakeConn := newFakeDoQStream()
	var addresses []string
	dialDoQ = func(_ context.Context, address string, _ *tls.Config, _ *quic.Config) (doqConn, error) {
		addresses = append(addresses, address)
		if len(addresses) == 1 {
			return nil, errors.New("first candidate unavailable")
		}
		return fakeConn, nil
	}
	factory := &doqFactory{
		connectionPlan: dialPlan{addresses: []string{"192.0.2.1:853", "192.0.2.2:853"}, timeout: time.Second},
		timeout:        time.Second,
		tlsConfig:      &tls.Config{NextProtos: []string{"doq"}},
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := session.(*doqSession).DialAddress(); got != "192.0.2.2:853" {
		t.Fatalf("DoQ selected dial address = %q", got)
	}
	if strings.Join(addresses, ",") != "192.0.2.1:853,192.0.2.2:853" {
		t.Fatalf("DoQ dial order = %#v", addresses)
	}
	_ = session.Close()
}

func TestDoQFactoryStopsWhenOpenContextExpires(t *testing.T) {
	oldDial := dialDoQ
	t.Cleanup(func() { dialDoQ = oldDial })
	called := 0
	dialDoQ = func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (doqConn, error) {
		called++
		return nil, ctx.Err()
	}
	factory := &doqFactory{
		connectionPlan: dialPlan{addresses: []string{"192.0.2.1:853", "192.0.2.2:853"}, timeout: time.Second},
		timeout:        time.Second,
		tlsConfig:      &tls.Config{NextProtos: []string{"doq"}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := factory.Open(ctx); err == nil {
		t.Fatal("expected expired DoQ open error")
	}
	if called != 1 {
		t.Fatalf("expired DoQ candidates attempted = %d, want 1", called)
	}
}

func TestDoQFactoryRetriesAfterCandidateTimeout(t *testing.T) {
	oldDial := dialDoQ
	t.Cleanup(func() { dialDoQ = oldDial })
	_, fakeConn := newFakeDoQStream()
	addresses := make([]string, 0, 2)
	dialDoQ = func(ctx context.Context, address string, _ *tls.Config, _ *quic.Config) (doqConn, error) {
		addresses = append(addresses, address)
		if len(addresses) == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return fakeConn, nil
	}
	factory := &doqFactory{
		connectionPlan: dialPlan{addresses: []string{"192.0.2.1:853", "192.0.2.2:853"}, timeout: 20 * time.Millisecond},
		timeout:        20 * time.Millisecond,
		tlsConfig:      &tls.Config{NextProtos: []string{"doq"}},
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := session.(*doqSession).DialAddress(); got != "192.0.2.2:853" {
		t.Fatalf("DoQ selected address = %q", got)
	}
	if strings.Join(addresses, ",") != "192.0.2.1:853,192.0.2.2:853" {
		t.Fatalf("DoQ dial order = %#v", addresses)
	}
	_ = session.Close()
}

func TestDoHRedirectLoopStopsAtHopLimit(t *testing.T) {
	const serverName = "dns.example"
	certificate, roots := testServerCertificate(t, serverName)
	var hits atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		hits.Add(1)
		http.Redirect(writer, request, "/dns-query", http.StatusFound)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)

	oldTLSConfig := newDoHTLSConfig
	newDoHTLSConfig = func(name string) *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name, RootCAs: roots}
	}
	t.Cleanup(func() { newDoHTLSConfig = oldTLSConfig })

	factory, err := newDoHFactory(catalog.Target{Address: "192.0.2.53", Spec: catalog.TransportSpec{
		URL:                "https://dns.example/dns-query",
		Port:               server.Listener.Addr().(*net.TCPAddr).Port,
		ServerName:         serverName,
		BootstrapAddresses: []string{"127.0.0.1"},
	}}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	_, err = session.Query(context.Background(), "example.com", dns.TypeA)
	if err == nil {
		t.Fatal("redirect loop unexpectedly produced a response")
	}
	want := fmt.Sprintf("DoH stopped after %d redirects", doHMaxRedirects)
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("redirect loop error = %v, want one containing %q", err, want)
	}
	if got := hits.Load(); got != int64(doHMaxRedirects) {
		t.Fatalf("redirect loop server hits = %d, want %d", got, doHMaxRedirects)
	}
}

func TestDoHRedirectRequiresHTTPSOrigin(t *testing.T) {
	factory, err := newDoHFactory(catalog.Target{Spec: catalog.TransportSpec{URL: "https://dns.example/dns-query"}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	doh := session.(*doHSession)
	origin, _ := url.Parse("https://dns.example/dns-query")
	cases := []struct {
		name string
		url  string
		ok   bool
	}{
		{"same origin", "https://DNS.EXAMPLE/other", true},
		{"explicit default port", "https://dns.example:443/other", true},
		{"http downgrade", "http://dns.example/other", false},
		{"port change", "https://dns.example:444/other", false},
		{"host change", "https://other.example/other", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			redirect, _ := url.Parse(tc.url)
			err := doh.client.CheckRedirect(&http.Request{URL: redirect}, []*http.Request{{URL: origin}})
			if (err == nil) != tc.ok {
				t.Fatalf("redirect %s error = %v", tc.url, err)
			}
		})
	}
}
