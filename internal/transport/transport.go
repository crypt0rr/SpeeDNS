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

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
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

// dialPlan contains the ordered network addresses used to open one logical
// endpoint. Bootstrap addresses are connection candidates, not separately
// ranked resolver targets. Once one candidate succeeds, the resulting session
// is reused by the benchmark worker.
type dialPlan struct {
	addresses []string
	timeout   time.Duration
}

func newDialPlan(targetAddress string, bootstrapAddresses []string, port int, timeout time.Duration) dialPlan {
	candidates := bootstrapAddresses
	if len(candidates) == 0 {
		candidates = []string{targetAddress}
	}
	addresses := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		addresses = append(addresses, joinAddress(candidate, port))
	}
	return dialPlan{addresses: addresses, timeout: timeout}
}

func singleDialPlan(address string, timeout time.Duration) dialPlan {
	if strings.TrimSpace(address) == "" {
		return dialPlan{timeout: timeout}
	}
	return dialPlan{addresses: []string{address}, timeout: timeout}
}

// openContext returns a fresh timeout budget for one ordered candidate
// attempt. The caller context remains authoritative, so a candidate timeout
// does not consume the budget of later candidates.
func (p dialPlan) openContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if p.timeout <= 0 {
		return ctx, func() {}
	}
	deadline := time.Now().Add(p.timeout)
	if existing, hasDeadline := ctx.Deadline(); hasDeadline && existing.Before(deadline) {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, deadline)
}

func (p dialPlan) failed(errs []error) error {
	if len(errs) == 0 {
		return errors.New("no connection candidates configured")
	}
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		parts = append(parts, err.Error())
	}
	return fmt.Errorf("all connection candidates failed: %s", strings.Join(parts, "; "))
}

func (p dialPlan) openStream(ctx context.Context, tlsConfig *tls.Config) (net.Conn, string, error) {
	dialer := &net.Dialer{Timeout: p.timeout}
	errs := make([]error, 0, len(p.addresses))
	for _, address := range p.addresses {
		openCtx, cancel := p.openContext(ctx)
		conn, err := dialer.DialContext(openCtx, "tcp", address)
		if err != nil {
			cancel()
			errs = append(errs, fmt.Errorf("%s: %w", address, err))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if tlsConfig != nil {
			tlsConn := tls.Client(conn, tlsConfig.Clone())
			if err := tlsConn.HandshakeContext(openCtx); err != nil {
				_ = conn.Close()
				cancel()
				errs = append(errs, fmt.Errorf("%s: TLS handshake: %w", address, err))
				if ctx.Err() != nil {
					break
				}
				continue
			}
			conn = tlsConn
		}
		cancel()
		return conn, address, nil
	}
	return nil, "", p.failed(errs)
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
	connectionPlan := newDialPlan(target.Address, target.Spec.BootstrapAddresses, target.Spec.Port, timeout)
	address := firstAddress(connectionPlan)
	switch target.Protocol {
	case catalog.UDP:
		return &udpFactory{address: joinAddress(target.Address, target.Spec.Port), timeout: timeout}, nil
	case catalog.TCP:
		return &streamFactory{address: address, connectionPlan: connectionPlan, timeout: timeout}, nil
	case catalog.DoT:
		serverName := target.Spec.ServerName
		if serverName == "" {
			serverName = target.Address
		}
		return &streamFactory{
			address:        address,
			connectionPlan: connectionPlan,
			timeout:        timeout,
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
			address:        address,
			connectionPlan: connectionPlan,
			timeout:        timeout,
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
	address        string
	connectionPlan dialPlan
	timeout        time.Duration
	tlsConfig      *tls.Config
}

func (f *streamFactory) Open(ctx context.Context) (Session, error) {
	plan := f.connectionPlan
	if len(plan.addresses) == 0 {
		plan = singleDialPlan(f.address, f.timeout)
	}
	conn, dialAddress, err := plan.openStream(ctx, f.tlsConfig)
	if err != nil {
		return nil, err
	}
	return &streamSession{
		conn:        conn,
		reopen:      func(ctx context.Context) (net.Conn, string, error) { return plan.openStream(ctx, f.tlsConfig) },
		timeout:     f.timeout,
		secure:      f.tlsConfig != nil,
		dialAddress: dialAddress,
	}, nil
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
	conn            net.Conn
	reopen          func(context.Context) (net.Conn, string, error)
	mu              sync.Mutex
	timeout         time.Duration
	secure          bool
	dialAddress     string
	lastReconnected bool
	closed          bool
}

func (s *streamSession) DialAddress() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dialAddress
}

// LastQueryReconnected reports whether the most recent Query had to open a
// fresh connection after the previous one was invalidated.
func (s *streamSession) LastQueryReconnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastReconnected
}

func (s *streamSession) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastReconnected = false
	if s.closed {
		return nil, errors.New("stream session is closed")
	}
	query := newQuery(name, qtype, dns.Id(), s.secure)
	packed, err := packSessionQuery(query)
	if err != nil {
		return nil, err
	}
	if len(packed) > maxFramedMessage {
		return nil, errors.New("DNS query exceeds TCP message limit")
	}
	reconnecting := s.conn == nil
	if err := s.ensureConn(ctx); err != nil {
		s.lastReconnected = reconnecting
		return nil, err
	}
	s.lastReconnected = reconnecting
	// The connection is reused across queries, so the deadline is set on the
	// connection itself and the send side stays open.
	if err := s.conn.SetDeadline(queryDeadline(ctx, s.timeout)); err != nil {
		return nil, s.fatal(err)
	}
	framing := framedStream{stream: s.conn, label: "DNS"}
	response, err := framing.query(packed, name, qtype, query.Id, false)
	if err != nil {
		return nil, s.fatal(err)
	}
	return response, nil
}

func (s *streamSession) ensureConn(ctx context.Context) error {
	if s.conn != nil {
		return nil
	}
	if s.closed {
		return errors.New("stream session is closed")
	}
	if s.reopen == nil {
		return errors.New("stream session connection is unavailable")
	}
	conn, dialAddress, err := s.reopen(ctx)
	if err != nil {
		return err
	}
	if conn == nil {
		return errors.New("stream session reconnect returned nil connection")
	}
	s.conn = conn
	s.dialAddress = dialAddress
	return nil
}

func (s *streamSession) fatal(err error) error {
	s.invalidate()
	return err
}

func (s *streamSession) invalidate() {
	conn := s.conn
	s.conn = nil
	if conn != nil {
		_ = conn.Close()
	}
}

func (s *streamSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

type doHFactory struct {
	url            string
	dialAddr       string
	connectionPlan dialPlan
	serverName     string
	timeout        time.Duration
}

var newDoHTLSConfig = func(serverName string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
}

// DNS-over-HTTPS responses are small DNS messages. Keep response headers
// bounded independently from the already bounded response body so a hostile
// endpoint cannot force an unnecessarily large header allocation per query.
const doHMaxResponseHeaderBytes = 64 << 10

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
		if rawPort := u.Port(); rawPort != "" {
			port, err = net.LookupPort("tcp", rawPort)
			if err != nil {
				return nil, fmt.Errorf("invalid DoH URL port %q: %w", rawPort, err)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid DoH URL port %q", rawPort)
			}
		}
	}
	dialAddress := target.Address
	if dialAddress == "" {
		dialAddress = u.Hostname()
	}
	connectionPlan := newDialPlan(dialAddress, target.Spec.BootstrapAddresses, port, timeout)
	return &doHFactory{
		url:            target.Spec.URL,
		dialAddr:       joinAddress(dialAddress, port),
		connectionPlan: connectionPlan,
		serverName:     serverName,
		timeout:        timeout,
	}, nil
}

func (f *doHFactory) Open(context.Context) (Session, error) {
	plan := f.connectionPlan
	if len(plan.addresses) == 0 {
		plan = singleDialPlan(f.dialAddr, f.timeout)
	}
	session := &doHSession{endpoint: f.url}
	tlsConfig := newDoHTLSConfig(f.serverName)
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}
	transport := &http.Transport{
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        tlsConfig,
		MaxResponseHeaderBytes: doHMaxResponseHeaderBytes,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, address, err := plan.openStream(ctx, tlsConfig)
			if err == nil {
				session.setDialAddress(address)
			}
			return conn, err
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   f.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && !sameHTTPSOrigin(via[0].URL, req.URL) {
				return errors.New("DoH redirect changed HTTPS origin")
			}
			return nil
		},
	}
	session.client = client
	session.transport = transport
	return session, nil
}

func sameHost(a, b *url.URL) bool { return strings.EqualFold(a.Hostname(), b.Hostname()) }

func sameHTTPSOrigin(a, b *url.URL) bool {
	if a == nil || b == nil || !strings.EqualFold(a.Scheme, "https") || !strings.EqualFold(b.Scheme, "https") {
		return false
	}
	return sameHost(a, b) && effectivePort(a) == effectivePort(b)
}

func effectivePort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	return "443"
}

func firstAddress(plan dialPlan) string {
	if len(plan.addresses) == 0 {
		return ""
	}
	return plan.addresses[0]
}

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
	mu        sync.RWMutex
	dialAddr  string
}

func (s *doHSession) setDialAddress(address string) {
	s.mu.Lock()
	s.dialAddr = address
	s.mu.Unlock()
}

func (s *doHSession) DialAddress() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dialAddr
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
	address        string
	connectionPlan dialPlan
	timeout        time.Duration
	tlsConfig      *tls.Config
}

func (f *doqFactory) dialConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: f.timeout,
		MaxIdleTimeout:       f.timeout * 2,
		// Keep the reusable session alive between benchmark queries. If the
		// peer or network still closes it, the next query reconnects lazily.
		KeepAlivePeriod: f.timeout,
	}
}

func (f *doqFactory) open(ctx context.Context) (doqConn, string, error) {
	plan := f.connectionPlan
	if len(plan.addresses) == 0 {
		plan = singleDialPlan(f.address, f.timeout)
	}
	errs := make([]error, 0, len(plan.addresses))
	for _, address := range plan.addresses {
		openCtx, cancel := plan.openContext(ctx)
		conn, err := dialDoQ(openCtx, address, f.tlsConfig.Clone(), f.dialConfig())
		cancel()
		if err == nil {
			return conn, address, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", address, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, "", plan.failed(errs)
}

func (f *doqFactory) Open(ctx context.Context) (Session, error) {
	conn, dialAddress, err := f.open(ctx)
	if err != nil {
		return nil, err
	}
	return &doqSession{
		conn:        conn,
		reopen:      f.open,
		timeout:     f.timeout,
		dialAddress: dialAddress,
	}, nil
}

type doqSession struct {
	conn            doqConn
	reopen          func(context.Context) (doqConn, string, error)
	mu              sync.Mutex
	timeout         time.Duration
	dialAddress     string
	lastReconnected bool
	closed          bool
}

func (s *doqSession) DialAddress() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dialAddress
}

// LastQueryReconnected reports whether the most recent Query had to open a
// fresh QUIC connection after the previous one was invalidated.
func (s *doqSession) LastQueryReconnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastReconnected
}

func (s *doqSession) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastReconnected = false
	if s.closed {
		return nil, errors.New("DoQ session is closed")
	}
	query := newQuery(name, qtype, 0, true)
	packed, err := packSessionQuery(query)
	if err != nil {
		return nil, err
	}
	if len(packed) > maxFramedMessage {
		return nil, errors.New("DNS query exceeds DoQ message limit")
	}
	reconnecting := s.conn == nil
	if err := s.ensureConn(ctx); err != nil {
		s.lastReconnected = reconnecting
		return nil, err
	}
	s.lastReconnected = reconnecting
	// RFC 9250 gives every DoQ query its own stream, so the deadline belongs
	// to the stream and the send side is closed once the request is written.
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, s.fatal(err)
	}
	defer stream.Close()
	if err := stream.SetDeadline(queryDeadline(ctx, s.timeout)); err != nil {
		return nil, s.fatal(err)
	}
	framing := framedStream{stream: stream, closeSend: stream.Close, label: "DoQ"}
	response, err := framing.query(packed, name, qtype, 0, true)
	if err != nil {
		return nil, s.fatal(err)
	}
	return response, nil
}

func (s *doqSession) ensureConn(ctx context.Context) error {
	if s.conn != nil {
		return nil
	}
	if s.closed {
		return errors.New("DoQ session is closed")
	}
	if s.reopen == nil {
		return errors.New("DoQ session connection is unavailable")
	}
	conn, dialAddress, err := s.reopen(ctx)
	if err != nil {
		return err
	}
	if conn == nil {
		return errors.New("DoQ session reconnect returned nil connection")
	}
	s.conn = conn
	s.dialAddress = dialAddress
	return nil
}

func (s *doqSession) fatal(err error) error {
	s.invalidate()
	return err
}

func (s *doqSession) invalidate() {
	conn := s.conn
	s.conn = nil
	if conn != nil {
		_ = conn.CloseWithError(0, "")
	}
}

func (s *doqSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.CloseWithError(0, "")
}

// maxFramedMessage is the largest DNS message the two-byte length prefix can
// describe, and therefore the size limit shared by TCP, DoT and DoQ framing.
const maxFramedMessage = 65535

// framedStream carries out the length-prefixed DNS exchange that TCP and DoT
// (RFC 1035 section 4.2.2) and DoQ (RFC 9250 section 4.2) all use. Only the
// framing lives here: connection lifecycle, deadlines and transaction ID
// rules stay with the sessions, which handle them differently.
type framedStream struct {
	stream io.ReadWriter
	// closeSend ends the client side of the stream once the request has been
	// written. DoQ requires it; a reused TCP or DoT connection must leave the
	// send side open for the next query, and so leaves this nil.
	closeSend func() error
	// label names the transport in framing errors.
	label string
}

// query performs one framed exchange and returns the validated response.
func (f framedStream) query(packed []byte, name string, qtype, queryID uint16, zeroID bool) (*dns.Msg, error) {
	responseBytes, err := f.exchange(packed)
	if err != nil {
		return nil, err
	}
	response := new(dns.Msg)
	if err := response.Unpack(responseBytes); err != nil {
		return nil, fmt.Errorf("unpack %s response: %w", f.label, err)
	}
	if err := validateResponse(response, name, qtype, queryID, zeroID); err != nil {
		return nil, err
	}
	return response, nil
}

// exchange writes one length-prefixed request and reads the length-prefixed
// response bytes.
func (f framedStream) exchange(packed []byte) ([]byte, error) {
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(packed)))
	if _, err := f.stream.Write(prefix[:]); err != nil {
		return nil, err
	}
	if _, err := f.stream.Write(packed); err != nil {
		return nil, err
	}
	if f.closeSend != nil {
		if err := f.closeSend(); err != nil {
			return nil, err
		}
	}
	if _, err := io.ReadFull(f.stream, prefix[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(prefix[:]))
	if length == 0 {
		return nil, fmt.Errorf("empty %s response", f.label)
	}
	responseBytes := make([]byte, length)
	if _, err := io.ReadFull(f.stream, responseBytes); err != nil {
		return nil, err
	}
	return responseBytes, nil
}

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

// queryDeadline bounds one framed exchange by the transport timeout, and by
// the caller deadline when that is nearer. Stream and DoQ sessions share the
// computation so a per-query budget cannot mean two different things.
func queryDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return deadline
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

// ResponseCodeName returns the conventional DNS response-code name used in
// reports. Unknown extended or future codes retain their numeric value.
func ResponseCodeName(rcode int) string {
	if name, ok := dns.RcodeToString[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", rcode)
}

// IsUsableResponse reports whether a validated DNS response represents a
// normal resolver outcome. NOERROR includes both answers and valid NODATA;
// NXDOMAIN is also a useful, authoritative outcome. Resolver errors such as
// SERVFAIL and REFUSED are transport-valid, but must not win latency scoring.
func IsUsableResponse(message *dns.Msg) bool {
	if message == nil {
		return false
	}
	return message.Rcode == dns.RcodeSuccess || message.Rcode == dns.RcodeNameError
}
