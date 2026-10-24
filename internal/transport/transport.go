package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
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
	CancelRead(quic.StreamErrorCode)
	SetDeadline(time.Time) error
}

type doqConn interface {
	OpenStreamSync(context.Context) (doqStream, error)
	CloseWithError(quic.ApplicationErrorCode, string) error
	RemoteAddr() net.Addr
	ConnectionState() quic.ConnectionState
}

// ConnectionInfo describes the connection a session holds, or held last: the
// peer it actually reached and what its handshake negotiated. A session
// reports it through an optional Connection method, as it reports its dial
// address through DialAddress.
//
// The dial address is the configured candidate. For a hostname endpoint
// without bootstrap addresses that is the hostname:port on every transport but
// UDP, so it cannot say which address family a transport used: a hostname with
// both an IPv4 and an IPv6 address let one report mix families with nothing
// showing which. The remote address is the literal the connection reached.
type ConnectionInfo struct {
	// RemoteAddress is the IP address and port of the peer: the resolved
	// literal for UDP, the connected socket's peer for every other transport.
	RemoteAddress string
	// TLSVersion is the negotiated TLS version, such as "TLS 1.3", for DoT,
	// DoH and DoQ, and empty for UDP and TCP.
	TLSVersion string
	// HTTPProtocol is the HTTP version a DoH connection speaks, as its ALPN
	// negotiation decided it: "h2", or "http/1.1" when the server chose it or
	// negotiated no protocol at all. It is empty for every other transport.
	HTTPProtocol string
}

// streamConnectionInfo describes a TCP or TLS stream. Every stream comes from
// net.Dialer, so its peer is always known.
func streamConnectionInfo(conn net.Conn) ConnectionInfo {
	info := ConnectionInfo{RemoteAddress: conn.RemoteAddr().String()}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		info.TLSVersion = tls.VersionName(tlsConn.ConnectionState().Version)
	}
	return info
}

// doHConnectionInfo adds the HTTP version to a DoH connection's description.
// DoH offers h2 first and accepts http/1.1, and net/http speaks HTTP/2 over a
// connection only when ALPN settled on h2, so the negotiated protocol is the
// one every exchange on that connection used. A server that negotiates no
// ALPN protocol gets HTTP/1.1.
func doHConnectionInfo(conn net.Conn) ConnectionInfo {
	info := streamConnectionInfo(conn)
	info.HTTPProtocol = "http/1.1"
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if protocol := tlsConn.ConnectionState().NegotiatedProtocol; protocol != "" {
			info.HTTPProtocol = protocol
		}
	}
	return info
}

func doqConnectionInfo(conn doqConn) ConnectionInfo {
	return ConnectionInfo{
		RemoteAddress: conn.RemoteAddr().String(),
		TLSVersion:    tls.VersionName(conn.ConnectionState().TLS.Version),
	}
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

// preferring returns the plan with address moved to the front and the other
// candidates kept in their configured order. An address that is not one of
// the candidates leaves the order unchanged.
func (p dialPlan) preferring(address string) dialPlan {
	for index, candidate := range p.addresses {
		if candidate != address {
			continue
		}
		ordered := make([]string, 0, len(p.addresses))
		ordered = append(ordered, candidate)
		ordered = append(ordered, p.addresses[:index]...)
		ordered = append(ordered, p.addresses[index+1:]...)
		return dialPlan{addresses: ordered, timeout: p.timeout}
	}
	return p
}

// after returns the candidate that follows address in configured order,
// wrapping around at the end. An address that is not one of the candidates
// is returned unchanged.
func (p dialPlan) after(address string) string {
	for index, candidate := range p.addresses {
		if candidate == address {
			return p.addresses[(index+1)%len(p.addresses)]
		}
	}
	return address
}

// stickyReopen returns the reconnect function of a session whose first
// connection went to start. Unlike Open, a reconnect runs inside one query's
// deadline, so starting again at the first configured candidate let one that
// silently drops traffic spend the whole budget of every later query, and the
// address the session had actually reached was never tried in time. A
// reconnect therefore tries the address that last connected first and the
// others in configured order. When the budget runs out regardless, the next
// reconnect starts at the following candidate, so successive queries work
// through the list rather than all failing on the same address. Sessions call
// the result with their mutex held, which is what serialises start.
func stickyReopen[C any](plan dialPlan, start string, open func(context.Context, dialPlan) (C, string, error)) func(context.Context) (C, string, error) {
	return func(ctx context.Context) (C, string, error) {
		conn, address, err := open(ctx, plan.preferring(start))
		if err == nil {
			start = address
		} else if ctx.Err() != nil {
			start = plan.after(start)
		}
		return conn, address, err
	}
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
	return p.openTrackedStream(ctx, tlsConfig, nil)
}

// openTrackedStream is openStream with a hook that sees every TCP connection
// before TLS runs over it. DoH uses it to keep hold of connections owned by
// the HTTP transport; wrapping underneath TLS leaves net/http the *tls.Conn it
// needs to negotiate HTTP/2.
func (p dialPlan) openTrackedStream(ctx context.Context, tlsConfig *tls.Config, track func(net.Conn) net.Conn) (net.Conn, string, error) {
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
		if track != nil {
			conn = track(conn)
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

func (c quicConnAdapter) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c quicConnAdapter) ConnectionState() quic.ConnectionState { return c.conn.ConnectionState() }

var dialDoQ = func(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (doqConn, error) {
	conn, err := quic.DialAddr(ctx, address, tlsConfig, config)
	if err != nil {
		return nil, err
	}
	return quicConnAdapter{conn: conn}, nil
}

var packSessionQuery = packQuery

// QueryOptions carries per-run DNS query settings. The zero value reproduces
// the queries SpeeDNS has always sent, so a default run stays byte-identical
// on the wire and remains comparable with previously published reports.
type QueryOptions struct {
	// DNSSEC sets the EDNS(0) DO bit. It is opt-in because it changes the
	// request the resolver sees. The CD (checking disabled) bit is never set:
	// SpeeDNS wants the resolver to validate, not to skip validation.
	DNSSEC bool
}

// NewFactory creates a factory that sends the default query form.
func NewFactory(target catalog.Target, timeout time.Duration) (Factory, error) {
	return NewFactoryWithOptions(target, timeout, QueryOptions{})
}

// NewFactoryWithOptions creates a factory whose sessions apply the supplied
// per-run query options to every query they send.
func NewFactoryWithOptions(target catalog.Target, timeout time.Duration, options QueryOptions) (Factory, error) {
	if timeout <= 0 {
		return nil, errors.New("transport timeout must be positive")
	}
	connectionPlan := newDialPlan(target.Address, target.Spec.BootstrapAddresses, target.Spec.Port, timeout)
	address := firstAddress(connectionPlan)
	switch target.Protocol {
	case catalog.UDP:
		return &udpFactory{address: joinAddress(target.Address, target.Spec.Port), timeout: timeout, queryOptions: options}, nil
	case catalog.TCP:
		return &streamFactory{address: address, connectionPlan: connectionPlan, timeout: timeout, queryOptions: options}, nil
	case catalog.DoT:
		serverName := target.Spec.ServerName
		if serverName == "" {
			serverName = target.Address
		}
		return &streamFactory{
			address:        address,
			connectionPlan: connectionPlan,
			timeout:        timeout,
			queryOptions:   options,
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: serverName,
				// RFC 7858 registers the "dot" ALPN token and RFC 8310 says a
				// DNS-over-TLS client SHOULD offer it. DoQ and DoH already
				// negotiate their own tokens here; without one, a server or
				// middlebox that routes by ALPN cannot tell what this
				// connection carries.
				NextProtos: []string{"dot"},
			},
		}, nil
	case catalog.DoH:
		return newDoHFactory(target, timeout, options)
	case catalog.DoQ:
		serverName := target.Spec.ServerName
		if serverName == "" {
			serverName = target.Address
		}
		return &doqFactory{
			address:        address,
			connectionPlan: connectionPlan,
			timeout:        timeout,
			queryOptions:   options,
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
	address      string
	timeout      time.Duration
	queryOptions QueryOptions
}

// lookupNetIP is the resolver call itself, kept separate from
// resolveUDPAddress so the "succeeded but returned nothing" contract below can
// be exercised. The real resolver never pairs a nil error with an empty slice,
// but udpFactory.Open depends on that case producing an error rather than an
// empty address, and an untested branch there would dial "":port.
var lookupNetIP = net.DefaultResolver.LookupNetIP

// resolveHost looks a hostname up once and returns its addresses in the order
// the resolver gave them, which for the system resolver is the RFC 6724
// destination order the stream transports' net.Dialer follows as well.
func resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	resolved, err := lookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(resolved) == 0 {
		return nil, fmt.Errorf("no addresses for %q", host)
	}
	// LookupNetIP reports IPv4 results as IPv4-mapped IPv6 ("::ffff:8.8.8.8").
	// Dialing that literal needs an AF_INET6 socket, so an IPv4-only host
	// cannot reach a hostname target that resolves to IPv4 at all. Unmap
	// restores the family the address actually belongs to.
	addresses := make([]netip.Addr, 0, len(resolved))
	for _, address := range resolved {
		addresses = append(addresses, address.Unmap())
	}
	return addresses, nil
}

// resolveUDPAddress is a seam so the bootstrap lookup can be exercised without
// a real system resolver.
var resolveUDPAddress = func(ctx context.Context, address string) (string, error) {
	resolved, err := resolveHost(ctx, address)
	if err != nil {
		return "", err
	}
	return resolved[0].String(), nil
}

// Open resolves a hostname endpoint once, here, rather than leaving it to every
// exchange. dns.Client.ExchangeContext dials the address it is given, so a
// hostname target sent the benchmark through the system resolver inside the
// timed region on every single query, measuring the local resolver's latency
// as if it were the target's. METHODOLOGY.md states that UDP reports the DNS
// transaction time only, and a bootstrap lookup is not part of that
// transaction. An address that is already a literal costs nothing here. That
// includes a zoned link-local literal such as fe80::1%en0: net.ParseIP rejects
// the zone, and the resolver it used to fall through to returns the address
// without it, so every query went to an undialable fe80:: destination.
func (f *udpFactory) Open(ctx context.Context) (Session, error) {
	address := f.address
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid UDP endpoint %q: %w", address, err)
	}
	if _, literalErr := netip.ParseAddr(host); literalErr != nil {
		resolvedHost, resolveErr := resolveUDPAddress(ctx, host)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve UDP endpoint %q: %w", host, resolveErr)
		}
		address = net.JoinHostPort(resolvedHost, port)
	}
	return &udpSession{address: address, timeout: f.timeout, queryOptions: f.queryOptions}, nil
}

type streamFactory struct {
	address        string
	connectionPlan dialPlan
	timeout        time.Duration
	tlsConfig      *tls.Config
	queryOptions   QueryOptions
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
		conn: conn,
		reopen: stickyReopen(plan, dialAddress, func(ctx context.Context, order dialPlan) (net.Conn, string, error) {
			return order.openStream(ctx, f.tlsConfig)
		}),
		timeout:      f.timeout,
		secure:       f.tlsConfig != nil,
		dialAddress:  dialAddress,
		connection:   streamConnectionInfo(conn),
		queryOptions: f.queryOptions,
	}, nil
}

type udpSession struct {
	address      string
	timeout      time.Duration
	queryOptions QueryOptions
}

// DialAddress reports the literal endpoint the session exchanges with, which
// for a hostname target is the address resolved once when the session opened.
func (s *udpSession) DialAddress() string { return s.address }

// Connection reports that same literal as the peer: UDP has no connection to
// ask, and every datagram goes to the address resolved when the session
// opened. The literal is written the way the other transports' sockets write
// their peer, unmapped and in canonical case, so one address configured as
// ::ffff:192.0.2.1 or 2001:DB8::1 reads the same remote_address on every
// transport.
func (s *udpSession) Connection() ConnectionInfo {
	return ConnectionInfo{RemoteAddress: canonicalPeer(s.address)}
}

// canonicalPeer writes an IP:port literal as net.Addr.String does for a
// connected socket. Anything that does not parse as one is returned as given.
func canonicalPeer(address string) string {
	peer, err := netip.ParseAddrPort(address)
	if err != nil {
		return address
	}
	return netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()).String()
}

func (s *udpSession) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	query := newQuery(name, qtype, dns.Id(), false, s.queryOptions)
	client := &dns.Client{Net: "udp", Timeout: s.timeout}
	conn, err := client.DialContext(ctx, s.address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// This is the exchange dns.Client.ExchangeContext performs, written out
	// so the reply's datagram stays available: miekg/dns ignores bytes after
	// a complete message, and only the wire form shows them. The receive
	// buffer, the deadline and the handling of stale replies are unchanged.
	conn.UDPSize = ednsUDPSize
	_ = conn.SetDeadline(queryDeadline(ctx, s.timeout))
	if err := conn.WriteMsg(query); err != nil {
		return nil, err
	}
	for {
		wire, err := conn.ReadMsgHeader(nil)
		if err != nil {
			return nil, err
		}
		response := new(dns.Msg)
		if err := response.Unpack(wire); err != nil {
			return nil, err
		}
		// ExchangeContext verified a TSIG record against the client's key
		// set, which is empty because SpeeDNS never signs a query, so every
		// signed reply failed with this error. That stays so.
		if response.IsTsig() != nil {
			return nil, dns.ErrSecret
		}
		// A reply with another ID can be the late answer to an earlier query
		// that timed out, so it is skipped rather than failing this one.
		if response.Id != query.Id {
			continue
		}
		if err := validateResponse(response, name, qtype, query.Id, false); err != nil {
			return nil, err
		}
		if err := rejectTrailingBytes(wire, "UDP"); err != nil {
			return nil, err
		}
		return response, nil
	}
}

func (s *udpSession) Close() error { return nil }

type streamSession struct {
	conn            net.Conn
	reopen          func(context.Context) (net.Conn, string, error)
	mu              sync.Mutex
	timeout         time.Duration
	secure          bool
	dialAddress     string
	connection      ConnectionInfo
	queryOptions    QueryOptions
	lastReconnected bool
	closed          bool
}

func (s *streamSession) DialAddress() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dialAddress
}

// Connection describes the session's most recent connection, which a
// reconnect replaces, so it stays readable after the connection is gone.
func (s *streamSession) Connection() ConnectionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connection
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
	query := newQuery(name, qtype, dns.Id(), s.secure, s.queryOptions)
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
	s.connection = streamConnectionInfo(conn)
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
	queryOptions   QueryOptions
}

var newDoHTLSConfig = func(serverName string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
}

// DNS-over-HTTPS responses are small DNS messages. Keep response headers
// bounded independently from the already bounded response body so a hostile
// endpoint cannot force an unnecessarily large header allocation per query.
const doHMaxResponseHeaderBytes = 64 << 10

// doHMaxResponseBodyBytes bounds every DoH body read, parsed or discarded.
const doHMaxResponseBodyBytes = 1 << 20

// Go applies its ten hop redirect cap inside net/http's own CheckRedirect,
// so installing a custom callback removes the cap entirely. A legitimate DoH
// endpoint needs at most one or two hops, so keep a small budget of our own
// to stop a hostile or misconfigured endpoint from expanding a single query
// into an unbounded request burst. Like the net/http default, the budget
// counts the requests in one chain, so at most doHMaxRedirects requests are
// issued per query.
const doHMaxRedirects = 5

func newDoHFactory(target catalog.Target, timeout time.Duration, options QueryOptions) (Factory, error) {
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
		queryOptions:   options,
	}, nil
}

// Open dials the session's first connection here, under the caller's context,
// as the stream and DoQ factories do. Left to the first exchange, that dial
// ran inside the query's deadline, so a first candidate that stalled spent the
// whole budget and the request failed before a later candidate was tried; here
// every candidate gets its own timeout. A cold probe's clock starts before
// Open, so it still covers this handshake.
func (f *doHFactory) Open(ctx context.Context) (Session, error) {
	session := f.newSession()
	conn, address, err := session.dial(ctx)
	if err != nil {
		return nil, err
	}
	// The connection is recorded once, here, so the exchange that takes it
	// over is not counted as a reconnect.
	session.pending = conn
	session.dialAddr = address
	session.connection = doHConnectionInfo(conn)
	session.connections = 1
	return session, nil
}

// newSession builds a session and its private HTTP client without touching
// the network.
func (f *doHFactory) newSession() *doHSession {
	plan := f.connectionPlan
	if len(plan.addresses) == 0 {
		plan = singleDialPlan(f.dialAddr, f.timeout)
	}
	tlsConfig := newDoHTLSConfig(f.serverName)
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}
	session := &doHSession{
		endpoint:     f.url,
		queryOptions: f.queryOptions,
		plan:         plan,
		tlsConfig:    tlsConfig,
		conns:        make(map[*doHConn]struct{}),
	}
	transport := &http.Transport{
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        tlsConfig,
		MaxResponseHeaderBytes: doHMaxResponseHeaderBytes,
		// Without a health check, an HTTP/2 connection that dies without a
		// FIN or RST stays pooled: each timed-out request resets its stream,
		// but net/http keeps counting the slot until a PING is answered, so
		// the session failed once per stream slot the server allows before
		// it opened a new connection. With one, a connection silent for a
		// timeout is pinged and closed when the ping goes unanswered for
		// another, and the next query reconnects, about as soon as TCP, DoT
		// and DoQ do after their first failure. The interval is never shorter
		// than the query timeout, so a ping only rarely overlaps a measured exchange.
		HTTP2: &http.HTTP2Config{SendPingTimeout: f.timeout, PingTimeout: f.timeout},
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if conn := session.takePending(); conn != nil {
				return conn, nil
			}
			conn, address, err := session.dial(ctx)
			if err != nil {
				return nil, err
			}
			// http.Transport re-dials transparently when a pooled
			// connection is gone, so this hook is the only place a new
			// TCP+TLS(+HTTP/2) handshake becomes observable, and the only
			// place its peer and negotiated protocols can be read.
			if err := session.recordConnection(address, doHConnectionInfo(conn)); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   f.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= doHMaxRedirects {
				return fmt.Errorf("DoH stopped after %d redirects", doHMaxRedirects)
			}
			if len(via) > 0 && !sameHTTPSOrigin(via[0].URL, req.URL) {
				return errors.New("DoH redirect changed HTTPS origin")
			}
			return nil
		},
	}
	session.client = client
	session.transport = transport
	return session
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
	client          *http.Client
	transport       *http.Transport
	endpoint        string
	queryOptions    QueryOptions
	plan            dialPlan
	tlsConfig       *tls.Config
	mu              sync.RWMutex
	dialAddr        string
	connection      ConnectionInfo
	connections     uint64
	lastReconnected bool
	// pending is the connection Open dialled, until the transport's first
	// dial takes it over.
	pending net.Conn
	// conns holds the TCP connection under every TLS connection the session
	// dialled that has not been closed yet.
	conns  map[*doHConn]struct{}
	closed bool
}

// doHConn is the TCP connection under one of a session's TLS connections. It
// removes itself from the session when the HTTP transport, or the session,
// closes it.
type doHConn struct {
	net.Conn
	session *doHSession
}

func (c *doHConn) Close() error {
	c.session.mu.Lock()
	delete(c.session.conns, c)
	c.session.mu.Unlock()
	return c.Conn.Close()
}

// dial opens one connection through the session's ordered candidates and
// tracks the TCP connection under it.
func (s *doHSession) dial(ctx context.Context) (net.Conn, string, error) {
	return s.plan.openTrackedStream(ctx, s.tlsConfig, s.track)
}

func (s *doHSession) track(conn net.Conn) net.Conn {
	tracked := &doHConn{Conn: conn, session: s}
	s.mu.Lock()
	s.conns[tracked] = struct{}{}
	s.mu.Unlock()
	return tracked
}

// takePending hands the connection Open dialled to the transport, once.
func (s *doHSession) takePending() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	conn := s.pending
	s.pending = nil
	return conn
}

// recordConnection is called from the transport dial hook, which runs on the
// http.Transport's own goroutines, once per newly opened HTTPS connection.
// net/http finishes a dial even after the request that started it has gone,
// so one can complete after Close; it is refused, because nothing would ever
// close it.
func (s *doHSession) recordConnection(address string, connection ConnectionInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("DoH session is closed")
	}
	s.dialAddr = address
	s.connection = connection
	s.connections++
	return nil
}

// beginQuery resets the per-query reconnect state and returns the number of
// connections opened so far, so the query can tell whether it had to open one.
func (s *doHSession) beginQuery() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastReconnected = false
	return s.connections
}

// endQuery records whether the exchange had to open a connection. Open has
// already recorded the session's first connection, as the stream transports
// do, so only a connection dialled during an exchange is a reconnect.
func (s *doHSession) endQuery(connectionsBefore uint64) {
	s.mu.Lock()
	s.lastReconnected = s.connections > connectionsBefore
	s.mu.Unlock()
}

// LastQueryReconnected reports whether the most recent Query had to open a
// fresh HTTPS connection after the previous one was dropped.
func (s *doHSession) LastQueryReconnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastReconnected
}

func (s *doHSession) DialAddress() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dialAddr
}

// Connection describes the HTTPS connection the session opened last. Requests
// can still be served by an older pooled one until it is dropped, but a
// session opens a new connection only when the previous one is gone.
func (s *doHSession) Connection() ConnectionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.connection
}

func (s *doHSession) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	connectionsBefore := s.beginQuery()
	query := newQuery(name, qtype, 0, true, s.queryOptions)
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
	s.endQuery(connectionsBefore)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		drainHTTPBody(response.Body)
		return nil, fmt.Errorf("DoH HTTP status %s", response.Status)
	}
	contentType := response.Header.Get("Content-Type")
	mediaType, _, contentTypeErr := mime.ParseMediaType(contentType)
	if contentTypeErr != nil || !strings.EqualFold(mediaType, "application/dns-message") {
		drainHTTPBody(response.Body)
		return nil, fmt.Errorf("DoH returned content type %q", contentType)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, doHMaxResponseBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > doHMaxResponseBodyBytes {
		return nil, fmt.Errorf("DoH response body exceeds %d bytes", doHMaxResponseBodyBytes)
	}
	message := new(dns.Msg)
	if err := message.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack DoH response: %w", err)
	}
	if err := validateResponse(message, name, qtype, 0, true); err != nil {
		return nil, err
	}
	if err := rejectTrailingBytes(body, "DoH"); err != nil {
		return nil, err
	}
	return message, nil
}

// drainHTTPBody consumes a bounded amount of a response body that the caller
// will not parse, so the keep-alive connection stays reusable instead of being
// torn down after every rejected reply. The bound matches the parsed-body limit
// so a hostile endpoint cannot make an error path read without end.
func drainHTTPBody(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, doHMaxResponseBodyBytes))
}

// Close tears down every connection the session opened. Closing the idle ones
// is not enough: when the last exchange timed out, net/http has not released
// that request's stream at the moment Close runs, so its connection is not
// idle yet, and with the private transport dropped it stayed open, read loop
// and all, until the server gave up on it.
func (s *doHSession) Close() error {
	s.transport.CloseIdleConnections()
	s.mu.Lock()
	s.closed = true
	s.pending = nil
	conns := s.conns
	s.conns = make(map[*doHConn]struct{})
	s.mu.Unlock()
	for conn := range conns {
		_ = conn.Close()
	}
	return nil
}

type doqFactory struct {
	address        string
	connectionPlan dialPlan
	timeout        time.Duration
	tlsConfig      *tls.Config
	queryOptions   QueryOptions
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

// open dials the plan's candidates in order. A hostname candidate is resolved
// first and its addresses dialled in the order the resolver returned them,
// each with its own timeout budget, so an address family without a route
// fails over to the next address rather than failing the candidate. The
// returned address is still the configured candidate: dial_address keeps its
// meaning, and the peer actually reached is the connection's remote address.
//
// reached is the session's own address preference, which open both reads and
// updates; Open starts it empty and the session's reconnects share it. A
// resolved address equal to it is dialled first. Reconnects need that because
// they have to fit in one query's deadline: starting again at the resolver's
// first address spent all of it there when that address silently drops
// packets, the one Open had waited out before reaching the next, so after one
// lost connection every later query of the session failed. A connection moves
// the preference to the address it reached. An attempt that runs out of time
// moves it to the address after the one that attempt started at, in the
// resolver's order, as stickyReopen moves its start through the candidates,
// so each reconnect that runs out of time starts one address further on and
// within as many reconnects as there are addresses every one has been dialled
// first. Rotating from the address that used up the budget instead came back
// to the preferred address whenever that one failed at once and an earlier
// one was silent, and rotating over the reordered list bounced between the
// first two addresses; either way a later address was never reached.
func (f *doqFactory) open(ctx context.Context, plan dialPlan, reached *string) (doqConn, string, error) {
	errs := make([]error, 0, len(plan.addresses))
candidates:
	for _, address := range plan.addresses {
		resolveCtx, cancel := plan.openContext(ctx)
		literals, err := doqDialAddresses(resolveCtx, address)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", address, err))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		resolverOrder := dialPlan{addresses: literals}
		ordered := resolverOrder.preferring(*reached)
		for _, literal := range ordered.addresses {
			openCtx, cancel := plan.openContext(ctx)
			conn, err := dialDoQ(openCtx, literal, f.tlsConfig.Clone(), f.dialConfig())
			cancel()
			if err == nil {
				*reached = literal
				return conn, address, nil
			}
			attempt := address
			if literal != address {
				attempt = address + " via " + literal
			}
			errs = append(errs, fmt.Errorf("%s: %w", attempt, err))
			if ctx.Err() != nil {
				*reached = resolverOrder.after(ordered.addresses[0])
				break candidates
			}
		}
	}
	return nil, "", plan.failed(errs)
}

// doqDialAddresses returns the literal addresses to dial for one DoQ candidate.
//
// quic.DialAddr resolves a hostname itself, through net.ResolveUDPAddr, which
// prefers an IPv4 address and ignores the context. On a dual-stack host DoQ
// alone therefore reached a hostname endpoint over IPv4 while UDP, TCP, DoT and
// DoH followed the resolver's RFC 6724 order, usually to IPv6, and on a host
// with no IPv4 route it failed with "network is unreachable" where they
// succeeded. Resolving here, with the lookup UDP uses, keeps every transport on
// the same order. A literal, including a zoned link-local one, is dialled as
// given; the TLS server name is configured separately, so dialling a resolved
// literal verifies the same certificate identity the hostname would.
func doqDialAddresses(ctx context.Context, address string) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, literalErr := netip.ParseAddr(host); literalErr == nil {
		return []string{address}, nil
	}
	resolved, err := resolveHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve DoQ endpoint %q: %w", host, err)
	}
	literals := make([]string, 0, len(resolved))
	for _, ip := range resolved {
		literals = append(literals, net.JoinHostPort(ip.String(), port))
	}
	return literals, nil
}

func (f *doqFactory) Open(ctx context.Context) (Session, error) {
	plan := f.connectionPlan
	if len(plan.addresses) == 0 {
		plan = singleDialPlan(f.address, f.timeout)
	}
	// reached is shared by this Open and the session's reconnects, which run
	// with the session's mutex held, as stickyReopen's start is.
	var reached string
	open := func(ctx context.Context, plan dialPlan) (doqConn, string, error) {
		return f.open(ctx, plan, &reached)
	}
	conn, dialAddress, err := open(ctx, plan)
	if err != nil {
		return nil, err
	}
	return &doqSession{
		conn:         conn,
		reopen:       stickyReopen(plan, dialAddress, open),
		timeout:      f.timeout,
		dialAddress:  dialAddress,
		connection:   doqConnectionInfo(conn),
		queryOptions: f.queryOptions,
	}, nil
}

type doqSession struct {
	conn            doqConn
	reopen          func(context.Context) (doqConn, string, error)
	mu              sync.Mutex
	timeout         time.Duration
	dialAddress     string
	connection      ConnectionInfo
	queryOptions    QueryOptions
	lastReconnected bool
	closed          bool
}

func (s *doqSession) DialAddress() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dialAddress
}

// Connection describes the session's most recent QUIC connection.
func (s *doqSession) Connection() ConnectionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connection
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
	query := newQuery(name, qtype, 0, true, s.queryOptions)
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
	// The response has been read in full, but quic-go forgets a stream only
	// once its receive side is finished as well. A server that sends its FIN
	// in a later frame, or never, left the state of every answered query's
	// stream behind until the connection closed. CancelRead does not block,
	// so it adds nothing to the measured exchange, and it does nothing once
	// the FIN has been read.
	stream.CancelRead(doqNoError)
	return response, nil
}

// doqNoError is DOQ_NO_ERROR (RFC 9250 section 4.3), the code for closing a
// stream when there is no error to signal.
const doqNoError quic.StreamErrorCode = 0

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
	s.connection = doqConnectionInfo(conn)
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
	if err := rejectTrailingBytes(responseBytes, f.label); err != nil {
		return nil, err
	}
	return response, nil
}

// exchange writes one length-prefixed request and reads the length-prefixed
// response bytes. The prefix and the message go out in a single write, as RFC
// 7766 section 8 asks: Go disables Nagle's algorithm, so two writes could put
// the prefix in a TCP segment of its own, and they cost DoT a separate TLS
// record for two bytes on every query.
func (f framedStream) exchange(packed []byte) ([]byte, error) {
	request := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(request, uint16(len(packed)))
	copy(request[2:], packed)
	if _, err := f.stream.Write(request); err != nil {
		return nil, err
	}
	if f.closeSend != nil {
		if err := f.closeSend(); err != nil {
			return nil, err
		}
	}
	var prefix [2]byte
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

// dnsHeaderLength is the fixed size of a DNS message header (RFC 1035 section
// 4.1.1).
const dnsHeaderLength = 12

// wireLength returns how many leading bytes of wire the DNS message occupies,
// found by walking the sections its header counts describe. miekg/dns stops
// unpacking once those sections are read and ignores whatever follows, so the
// wire form is the only place appended bytes show. Comparing with a re-pack
// would not work: name compression lets a valid reply be shorter or longer
// than its re-encoding. Like the unpacker, the walk ends where the message
// does when the counts claim more records than it holds.
func wireLength(wire []byte) (int, error) {
	if len(wire) < dnsHeaderLength {
		return 0, dns.ErrShortRead
	}
	questions := int(binary.BigEndian.Uint16(wire[4:]))
	records := int(binary.BigEndian.Uint16(wire[6:])) + int(binary.BigEndian.Uint16(wire[8:])) + int(binary.BigEndian.Uint16(wire[10:]))
	offset := dnsHeaderLength
	var err error
	for index := 0; index < questions && offset < len(wire); index++ {
		if _, offset, err = dns.UnpackDomainName(wire, offset); err != nil {
			return 0, err
		}
		// QTYPE and QCLASS follow the name.
		if offset += 4; offset > len(wire) {
			return 0, dns.ErrBuf
		}
	}
	for index := 0; index < records && offset < len(wire); index++ {
		if _, offset, err = dns.UnpackRR(wire, offset); err != nil {
			return 0, err
		}
	}
	return offset, nil
}

// rejectTrailingBytes fails a reply whose wire form carries bytes after the
// DNS message. miekg/dns accepts such a reply as the message alone, so a body,
// frame or datagram that a broken proxy or middlebox extended was scored as a
// clean answer; it is a protocol error instead. Callers run it after
// validateResponse, so a reply that was rejected before keeps its reason.
func rejectTrailingBytes(wire []byte, label string) error {
	length, err := wireLength(wire)
	if err != nil {
		return fmt.Errorf("measure %s response: %w", label, err)
	}
	if length < len(wire) {
		return fmt.Errorf("%s response has trailing data after the DNS message (%d of %d bytes)", label, length, len(wire))
	}
	return nil
}

// ednsUDPSize is the EDNS(0) UDP payload size every query advertises, and so
// the size of the buffer a UDP reply is read into.
const ednsUDPSize = 1232

func newQuery(name string, qtype, id uint16, padded bool, options QueryOptions) *dns.Msg {
	query := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               id,
			RecursionDesired: true,
			Opcode:           dns.OpcodeQuery,
		},
		Question: []dns.Question{{Name: dns.Fqdn(name), Qtype: qtype, Qclass: dns.ClassINET}},
	}
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: ednsUDPSize}}
	if options.DNSSEC {
		// RFC 4035: the DO bit asks the resolver for DNSSEC records and, for a
		// validating resolver, for validated answers with the AD flag. It is
		// set only for an opt-in --dnssec run; the default query form is
		// unchanged so default results stay comparable across releases.
		opt.SetDo()
	}
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
		// DoH and DoQ both send ID 0 (RFC 8484 section 4.1, RFC 9250
		// section 4.2.1), so the message names neither.
		return fmt.Errorf("DNS transaction ID must be zero, got %d", response.Id)
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
		if !answersQuestion(message) {
			return "nodata"
		}
		return "answer"
	case dns.RcodeNameError:
		return "nxdomain"
	default:
		return fmt.Sprintf("rcode-%d", message.Rcode)
	}
}

// answersQuestion reports whether the answer section carries a record of the
// requested type. A canonical NODATA response is NOERROR with an empty answer
// section and an SOA in the authority section, so authority records must never
// be read as an answer: doing so collapses "this name has no such record" and
// "here is the address" into one response class.
func answersQuestion(message *dns.Msg) bool {
	if len(message.Question) != 1 {
		// validateResponse rejects any other shape before scoring, so this is
		// only reachable for synthetic messages; fall back to answer presence.
		return len(message.Answer) > 0
	}
	qtype := message.Question[0].Qtype
	for _, answer := range message.Answer {
		if answer.Header().Rrtype == qtype {
			return true
		}
	}
	return false
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
