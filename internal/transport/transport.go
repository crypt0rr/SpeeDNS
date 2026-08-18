package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/dns-speedtest/internal/catalog"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// Session represents a transport connection used by a single benchmark
// worker. A worker serializes calls, which makes TCP and encrypted stream
// framing deterministic while still allowing different targets to run in
// parallel.
type Session interface {
	Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)
	Close() error
}

// Factory creates fresh sessions for cold measurements and one reusable
// session for warm measurements.
type Factory interface {
	Open(context.Context) (Session, error)
}

type doqStream interface {
	io.ReadWriter
	Close() error
	SetDeadline(time.Time) error
}

type doqConn interface {
	OpenStreamSync(context.Context) (doqStream, error)
	CloseWithError(quic.ApplicationErrorCode, string) error
}

type quicConnAdapter struct{ conn *quic.Conn }

func (c quicConnAdapter) OpenStreamSync(ctx context.Context) (doqStream, error) {
	return c.conn.OpenStreamSync(ctx)
}

func (c quicConnAdapter) CloseWithError(code quic.ApplicationErrorCode, message string) error {
	return c.conn.CloseWithError(code, message)
}

var dialDoQ = func(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (doqConn, error) {
	conn, err := quic.DialAddr(ctx, address, tlsConfig, config)
	if err != nil {
		return nil, err
	}
	return quicConnAdapter{conn: conn}, nil
}

var packSessionQuery = packQuery

func NewFactory(target catalog.Target, timeout time.Duration) (Factory, error) {
	if timeout <= 0 {
		return nil, errors.New("transport timeout must be positive")
	}
	address := joinAddress(target.Address, target.Spec.Port)
	switch target.Protocol {
	case catalog.UDP:
		return &udpFactory{address: address, timeout: timeout}, nil
	case catalog.TCP:
		return &streamFactory{address: address, timeout: timeout}, nil
	case catalog.DoT:
		serverName := target.Spec.ServerName
		if serverName == "" {
			serverName = target.Address
		}
		return &streamFactory{
			address: address,
			timeout: timeout,
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: serverName,
			},
		}, nil
	case catalog.DoH:
		return newDoHFactory(target, timeout)
	case catalog.DoQ:
		serverName := target.Spec.ServerName
		if serverName == "" {
			serverName = target.Address
		}
		return &doqFactory{
			address: address,
			timeout: timeout,
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				ServerName: serverName,
				NextProtos: []string{"doq"},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol %q", target.Protocol)
	}
}

type udpFactory struct {
	address string
	timeout time.Duration
}

func (f *udpFactory) Open(context.Context) (Session, error) {
	return &udpSession{address: f.address, timeout: f.timeout}, nil
}

type streamFactory struct {
	address   string
	timeout   time.Duration
	tlsConfig *tls.Config
}

func (f *streamFactory) Open(ctx context.Context) (Session, error) {
	dialer := net.Dialer{Timeout: f.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", f.address)
	if err != nil {
		return nil, err
	}
	if f.tlsConfig != nil {
		tlsConn := tls.Client(conn, f.tlsConfig.Clone())
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = tlsConn
	}
	return &streamSession{conn: conn, timeout: f.timeout, secure: f.tlsConfig != nil}, nil
}

type udpSession struct {
	address string
	timeout time.Duration
}

func (s *udpSession) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	query := newQuery(name, qtype, dns.Id(), false)
	client := &dns.Client{Net: "udp", Timeout: s.timeout}
	response, _, err := client.ExchangeContext(ctx, query, s.address)
	if err != nil {
		return nil, err
	}
	if err := validateResponse(response, name, qtype, query.Id, false); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *udpSession) Close() error { return nil }

type streamSession struct {
	conn    net.Conn
	mu      sync.Mutex
	timeout time.Duration
	secure  bool
}

func (s *streamSession) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query := newQuery(name, qtype, dns.Id(), s.secure)
	packed, err := packSessionQuery(query)
	if err != nil {
		return nil, err
	}
	if err := setConnDeadline(s.conn, ctx, s.timeout); err != nil {
		return nil, err
	}
	var prefix [2]byte
	if len(packed) > 65535 {
		return nil, errors.New("DNS query exceeds TCP message limit")
	}
	binary.BigEndian.PutUint16(prefix[:], uint16(len(packed)))
	if _, err := s.conn.Write(prefix[:]); err != nil {
		return nil, err
	}
	if _, err := s.conn.Write(packed); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(s.conn, prefix[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(prefix[:]))
	if length == 0 {
		return nil, errors.New("empty DNS response")
	}
	responseBytes := make([]byte, length)
	if _, err := io.ReadFull(s.conn, responseBytes); err != nil {
		return nil, err
	}
	response := new(dns.Msg)
	if err := response.Unpack(responseBytes); err != nil {
		return nil, fmt.Errorf("unpack DNS response: %w", err)
	}
	if err := validateResponse(response, name, qtype, query.Id, false); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *streamSession) Close() error { return s.conn.Close() }

type doHFactory struct {
	url        string
	dialAddr   string
	serverName string
	timeout    time.Duration
}

func newDoHFactory(target catalog.Target, timeout time.Duration) (Factory, error) {
	u, err := url.Parse(target.Spec.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("invalid DoH URL %q", target.Spec.URL)
	}
	serverName := target.Spec.ServerName
	if serverName == "" {
		serverName = u.Hostname()
	}
	port := target.Spec.Port
	if port == 0 {
		port = 443
	}
	dialAddress := target.Address
	if dialAddress == "" {
		dialAddress = u.Hostname()
	}
	return &doHFactory{
		url:        target.Spec.URL,
		dialAddr:   joinAddress(dialAddress, port),
		serverName: serverName,
		timeout:    timeout,
	}, nil
}

func (f *doHFactory) Open(context.Context) (Session, error) {
	dialer := &net.Dialer{Timeout: f.timeout}
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: f.serverName,
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, f.dialAddr)
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   f.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && !sameHost(via[0].URL, req.URL) {
				return errors.New("DoH redirect changed host")
			}
			return nil
		},
	}
	return &doHSession{client: client, transport: transport, endpoint: f.url}, nil
}

func sameHost(a, b *url.URL) bool { return strings.EqualFold(a.Hostname(), b.Hostname()) }

func joinAddress(host string, port int) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

type doHSession struct {
	client    *http.Client
	transport *http.Transport
	endpoint  string
}

func (s *doHSession) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	query := newQuery(name, qtype, 0, true)
	packed, err := packSessionQuery(query)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")
	response, err := s.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP status %s", response.Status)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "" && !strings.Contains(strings.ToLower(contentType), "application/dns-message") {
		return nil, fmt.Errorf("DoH returned content type %q", contentType)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	message := new(dns.Msg)
	if err := message.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack DoH response: %w", err)
	}
	if err := validateResponse(message, name, qtype, 0, true); err != nil {
		return nil, err
	}
	return message, nil
}

func (s *doHSession) Close() error {
	s.transport.CloseIdleConnections()
	return nil
}

type doqFactory struct {
	address   string
	timeout   time.Duration
	tlsConfig *tls.Config
}

func (f *doqFactory) Open(ctx context.Context) (Session, error) {
	conn, err := dialDoQ(ctx, f.address, f.tlsConfig.Clone(), &quic.Config{
		HandshakeIdleTimeout: f.timeout,
		MaxIdleTimeout:       f.timeout * 2,
	})
	if err != nil {
		return nil, err
	}
	return &doqSession{conn: conn, timeout: f.timeout}, nil
}

type doqSession struct {
	conn    doqConn
	timeout time.Duration
}

func (s *doqSession) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	query := newQuery(name, qtype, 0, true)
	packed, err := packSessionQuery(query)
	if err != nil {
		return nil, err
	}
	if len(packed) > 65535 {
		return nil, errors.New("DNS query exceeds DoQ message limit")
	}
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	} else {
		_ = stream.SetDeadline(time.Now().Add(s.timeout))
	}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(packed)))
	if _, err := stream.Write(prefix[:]); err != nil {
		return nil, err
	}
	if _, err := stream.Write(packed); err != nil {
		return nil, err
	}
	if err := stream.Close(); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(stream, prefix[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(prefix[:]))
	if length == 0 {
		return nil, errors.New("empty DoQ response")
	}
	responseBytes := make([]byte, length)
	if _, err := io.ReadFull(stream, responseBytes); err != nil {
		return nil, err
	}
	response := new(dns.Msg)
	if err := response.Unpack(responseBytes); err != nil {
		return nil, fmt.Errorf("unpack DoQ response: %w", err)
	}
	if err := validateResponse(response, name, qtype, 0, true); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *doqSession) Close() error { return s.conn.CloseWithError(0, "") }

func newQuery(name string, qtype, id uint16, padded bool) *dns.Msg {
	query := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               id,
			RecursionDesired: true,
			Opcode:           dns.OpcodeQuery,
		},
		Question: []dns.Question{{Name: dns.Fqdn(name), Qtype: qtype, Qclass: dns.ClassINET}},
	}
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}}
	if padded {
		// RFC 9250 requires padding when the QUIC implementation does not
		// provide a packet-padding policy. The same stable padding policy is
		// used for DoH and DoT so encrypted wire requests stay comparable.
		opt.Option = []dns.EDNS0{&dns.EDNS0_PADDING{}}
	}
	query.Extra = []dns.RR{opt}
	return query
}

func packQuery(query *dns.Msg) ([]byte, error) {
	packed, err := query.Pack()
	if err != nil {
		return nil, err
	}
	for _, extra := range query.Extra {
		opt, ok := extra.(*dns.OPT)
		if !ok {
			continue
		}
		for _, option := range opt.Option {
			padding, ok := option.(*dns.EDNS0_PADDING)
			if !ok {
				continue
			}
			padding.Padding = make([]byte, (128-len(packed)%128)%128)
			return query.Pack()
		}
	}
	return packed, nil
}

func setConnDeadline(conn net.Conn, ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return conn.SetDeadline(deadline)
}

func validateResponse(response *dns.Msg, name string, qtype uint16, queryID uint16, zeroID bool) error {
	if response == nil {
		return errors.New("empty DNS response")
	}
	if !response.Response {
		return errors.New("DNS response is missing the response flag")
	}
	if !zeroID && response.Id != queryID {
		return fmt.Errorf("DNS transaction ID mismatch: got %d, want %d", response.Id, queryID)
	}
	if zeroID && response.Id != 0 {
		return fmt.Errorf("DoQ transaction ID must be zero, got %d", response.Id)
	}
	if len(response.Question) != 1 {
		return fmt.Errorf("DNS response has %d questions, want 1", len(response.Question))
	}
	question := response.Question[0]
	if !strings.EqualFold(dns.Fqdn(question.Name), dns.Fqdn(name)) || question.Qtype != qtype || question.Qclass != dns.ClassINET {
		return errors.New("DNS response question does not match request")
	}
	return nil
}

// ResponseClass is deliberately based on DNS response semantics rather than
// answer count alone. It lets the benchmark identify filtered/divergent
// responses without declaring valid NODATA responses to be transport errors.
func ResponseClass(message *dns.Msg) string {
	if message == nil {
		return "invalid"
	}
	switch message.Rcode {
	case dns.RcodeSuccess:
		if len(message.Answer) == 0 && len(message.Ns) == 0 {
			return "nodata"
		}
		return "answer"
	case dns.RcodeNameError:
		return "nxdomain"
	default:
		return fmt.Sprintf("rcode-%d", message.Rcode)
	}
}
