package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// peekConn replays already-read ClientHello bytes before reading from the underlying conn.
type peekConn struct {
	net.Conn
	buf *bytes.Reader
}

func (c *peekConn) Read(p []byte) (int, error) {
	if c.buf != nil && c.buf.Len() > 0 {
		return c.buf.Read(p)
	}
	return c.Conn.Read(p)
}

// PeekClientHelloSNI reads the initial TLS record from conn without consuming it,
// returning the SNI server_name (lowercased) and a wrapped net.Conn that replays
// the peeked bytes verbatim for either TLS passthrough or internal termination.
func PeekClientHelloSNI(conn net.Conn) (string, net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var header [5]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", conn, err
	}

	// TLS Handshake record type is 0x16 (22).
	if header[0] != 0x16 {
		return "", &peekConn{Conn: conn, buf: bytes.NewReader(header[:])}, errors.New("not a TLS handshake record")
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen <= 0 || recordLen > 16384 {
		return "", &peekConn{Conn: conn, buf: bytes.NewReader(header[:])}, errors.New("invalid TLS record length")
	}

	payload := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		raw := append(header[:], payload...)
		return "", &peekConn{Conn: conn, buf: bytes.NewReader(raw)}, err
	}

	raw := make([]byte, 5+recordLen)
	copy(raw[:5], header[:])
	copy(raw[5:], payload)

	sni := extractSNIFromHandshake(payload)
	return strings.ToLower(sni), &peekConn{Conn: conn, buf: bytes.NewReader(raw)}, nil
}

// extractSNIFromHandshake parses a TLS ClientHello handshake message for the
// server_name extension (type 0x0000).
func extractSNIFromHandshake(data []byte) string {
	// Handshake header: 1 byte type (0x01 = ClientHello) + 3 bytes length.
	if len(data) < 4 || data[0] != 0x01 {
		return ""
	}
	pos := 4

	// ClientVersion (2) + Random (32) = 34 bytes.
	if len(data) < pos+34 {
		return ""
	}
	pos += 34

	// SessionID length (1) + SessionID.
	if len(data) < pos+1 {
		return ""
	}
	sessLen := int(data[pos])
	pos += 1 + sessLen

	// CipherSuites length (2) + CipherSuites.
	if len(data) < pos+2 {
		return ""
	}
	cipherLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherLen

	// CompressionMethods length (1) + CompressionMethods.
	if len(data) < pos+1 {
		return ""
	}
	compLen := int(data[pos])
	pos += 1 + compLen

	// Extensions length (2).
	if len(data) < pos+2 {
		return ""
	}
	extTotalLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	end := pos + extTotalLen
	if end > len(data) {
		end = len(data)
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			break
		}
		if extType == 0x0000 && extLen >= 5 { // server_name extension
			listLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
			listEnd := pos + 2 + listLen
			if listEnd > pos+extLen {
				listEnd = pos + extLen
			}
			p := pos + 2
			for p+3 <= listEnd {
				nameType := data[p]
				nameLen := int(binary.BigEndian.Uint16(data[p+1 : p+3]))
				p += 3
				if p+nameLen > listEnd {
					break
				}
				if nameType == 0x00 { // host_name
					return string(data[p : p+nameLen])
				}
				p += nameLen
			}
		}
		pos += extLen
	}
	return ""
}

// TLSPassthroughRule maps SNI hostnames (exact or wildcard like *.example.com)
// to a raw TCP backend address (e.g. "my-tls-svc.default.svc.cluster.local:8443").
type TLSPassthroughRule struct {
	Hostnames []string
	Backend   string
}

// TLSPassthroughRouter matches ClientHello SNI and forwards raw encrypted TLS
// bytes directly to the backend Service without terminating TLS.
type TLSPassthroughRouter struct {
	mu    sync.RWMutex
	rules []TLSPassthroughRule
}

// NewTLSPassthroughRouter creates an empty TLSPassthroughRouter.
func NewTLSPassthroughRouter() *TLSPassthroughRouter {
	return &TLSPassthroughRouter{}
}

// Update atomically replaces the active TLSRoute passthrough rules.
func (r *TLSPassthroughRouter) Update(rules []TLSPassthroughRule) {
	norm := make([]TLSPassthroughRule, 0, len(rules))
	for _, rule := range rules {
		hosts := make([]string, 0, len(rule.Hostnames))
		for _, h := range rule.Hostnames {
			h = strings.ToLower(strings.TrimSpace(h))
			if h != "" {
				hosts = append(hosts, h)
			}
		}
		norm = append(norm, TLSPassthroughRule{
			Hostnames: hosts,
			Backend:   rule.Backend,
		})
	}
	r.mu.Lock()
	r.rules = norm
	r.mu.Unlock()
}

// Match returns the backend address for a given SNI hostname, preferring exact
// matches over wildcard matches.
func (r *TLSPassthroughRouter) Match(sni string) (string, bool) {
	r.mu.RLock()
	rules := r.rules
	r.mu.RUnlock()

	sni = strings.ToLower(strings.TrimSuffix(sni, "."))

	// Pass 1: exact hostname match.
	for _, rule := range rules {
		for _, h := range rule.Hostnames {
			if h == sni {
				return rule.Backend, true
			}
		}
	}
	// Pass 2: wildcard or catch-all match.
	for _, rule := range rules {
		if matchesHost(rule.Hostnames, sni) {
			return rule.Backend, true
		}
	}
	return "", false
}

// TCPRouter forwards raw L4 TCP connections to a hot-reloadable backend address.
type TCPRouter struct {
	mu      sync.RWMutex
	backend string
}

// NewTCPRouter creates a new TCPRouter.
func NewTCPRouter() *TCPRouter {
	return &TCPRouter{}
}

// Update sets the active backend Service host:port (e.g. "pg.default.svc.cluster.local:5432").
func (r *TCPRouter) Update(backend string) {
	r.mu.Lock()
	r.backend = backend
	r.mu.Unlock()
}

// Handle proxies a raw TCP connection bidirectionally to the configured backend.
func (r *TCPRouter) Handle(clientConn net.Conn) {
	defer clientConn.Close()

	r.mu.RLock()
	backend := r.backend
	r.mu.RUnlock()

	if backend == "" {
		return
	}
	ProxyTCP(clientConn, backend)
}

// ProxyTCP dials backend and copies bytes bidirectionally until either side closes.
func ProxyTCP(clientConn net.Conn, backendAddr string) {
	upstream, err := net.DialTimeout("tcp", backendAddr, 10*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, clientConn)
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, upstream)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// ChannelListener implements net.Listener backed by a channel of net.Conn.
// Used by the SNI demultiplexer to feed internally terminated TLS connections
// into http.Server.Serve without extra TCP hops.
type ChannelListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func NewChannelListener(addr net.Addr) *ChannelListener {
	return &ChannelListener{
		addr:   addr,
		conns:  make(chan net.Conn, 128),
		closed: make(chan struct{}),
	}
}

func (l *ChannelListener) Enqueue(c net.Conn) bool {
	select {
	case <-l.closed:
		return false
	case l.conns <- c:
		return true
	}
}

func (l *ChannelListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case c := <-l.conns:
		return c, nil
	}
}

func (l *ChannelListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *ChannelListener) Addr() net.Addr { return l.addr }

// ServeTLSMultiplexed reads raw TLS connections from remoteLn (e.g., an SSH
// reverse tunnel in TLS tunneling mode), peeks ClientHello SNI, and routes:
//   - Matching TLSRoute passthrough rules -> raw encrypted stream to backend Service
//   - Everything else -> internal TLS termination (tls.Server) -> HTTP Router
func ServeTLSMultiplexed(
	remoteLn net.Listener,
	passthrough *TLSPassthroughRouter,
	tlsStore *TLSStore,
	httpLn *ChannelListener,
) error {
	defer httpLn.Close()

	for {
		conn, err := remoteLn.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			sni, wrapped, peekErr := PeekClientHelloSNI(c)
			if peekErr != nil {
				_ = wrapped.Close()
				return
			}

			// 1. Check L4 TLSRoute passthrough rules first (e.g. *.tls.example.com).
			if passthrough != nil {
				if backend, ok := passthrough.Match(sni); ok {
					defer wrapped.Close()
					ProxyTCP(wrapped, backend)
					return
				}
			}

			// 2. Otherwise terminate TLS internally and hand off to http.Server.
			tlsConn := tls.Server(wrapped, tlsStore.TLSConfig())
			if !httpLn.Enqueue(tlsConn) {
				_ = tlsConn.Close()
			}
		}(conn)
	}
}
