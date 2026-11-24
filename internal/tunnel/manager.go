package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/example/ssh-tunnel-gateway/internal/config"
	"github.com/example/ssh-tunnel-gateway/internal/proxy"
)

// TunnelConfig bundles an SSH tunnel specification with its hot-reloadable
// data-plane state (HTTP routes, TLS passthrough rules, TLS certs, TCP backend).
type TunnelConfig struct {
	Spec           TunnelSpec
	HTTPRoutes     []proxy.RouteRule
	TLSPassthrough []proxy.TLSPassthroughRule
	TLSCerts       []proxy.CertEntry
	TCPBackend     string
}

// TunnelStatus reports the live state of a managed tunnel.
type TunnelStatus struct {
	TunnelKey    string
	Mode         TunnelMode
	AssignedHost string
	Connected    bool
}

// StatusCallback is invoked when a tunnel connects or discovers its assigned public host.
type StatusCallback func(gatewayKey string, tunnelKey string, assignedHost string, connected bool, lastErr error)

type managedTunnel struct {
	spec           TunnelSpec
	router         *proxy.Router
	tls            *proxy.TLSStore
	tlsPassthrough *proxy.TLSPassthroughRouter
	tcpRouter      *proxy.TCPRouter
	cancel         context.CancelFunc
	done           chan struct{}

	mu           sync.RWMutex
	assignedHost string
	connected    bool
}

// Manager supervises resilient outbound SSH reverse tunnels for all Gateway
// listeners (HTTP, HTTPS, TLS, TCP). Routes, TLS certificates, and TCP backends
// hot-reload in-place without dropping active SSH sessions.
type Manager struct {
	cfg    config.Config
	log    logr.Logger
	onStat StatusCallback

	mu      sync.Mutex
	tunnels map[string]*managedTunnel // keyed by TunnelSpec.TunnelKey
}

// NewManager creates a new SSH reverse-tunnel Manager.
func NewManager(cfg config.Config, log logr.Logger) *Manager {
	return &Manager{
		cfg:     cfg,
		log:     log,
		tunnels: make(map[string]*managedTunnel),
	}
}

// SetStatusCallback registers a callback invoked on tunnel state transitions.
func (m *Manager) SetStatusCallback(cb StatusCallback) {
	m.mu.Lock()
	m.onStat = cb
	m.mu.Unlock()
}

// ReconcileGatewayTunnels reconciles the full set of desired tunnels for a
// Gateway (e.g. HTTP on 80, shared wildcard HTTPS+TLS on 443, TCP on 5432),
// hot-reloading unchanged tunnels and pruning removed ones.
func (m *Manager) ReconcileGatewayTunnels(
	parentCtx context.Context,
	gatewayKey string,
	desired []TunnelConfig,
) ([]TunnelStatus, error) {
	desiredKeys := make(map[string]struct{}, len(desired))
	for _, tc := range desired {
		desiredKeys[tc.Spec.TunnelKey] = struct{}{}
	}

	// Prune tunnels belonging to this Gateway that are no longer desired.
	m.mu.Lock()
	var toStop []*managedTunnel
	for k, mt := range m.tunnels {
		if mt.spec.GatewayKey == gatewayKey {
			if _, keep := desiredKeys[k]; !keep {
				toStop = append(toStop, mt)
				delete(m.tunnels, k)
			}
		}
	}
	m.mu.Unlock()
	for _, mt := range toStop {
		mt.cancel()
		<-mt.done
	}

	statuses := make([]TunnelStatus, 0, len(desired))
	for _, tc := range desired {
		st, err := m.reconcileSingle(parentCtx, tc)
		if err != nil {
			return statuses, err
		}
		statuses = append(statuses, st)
	}
	return statuses, nil
}

func (m *Manager) reconcileSingle(parentCtx context.Context, tc TunnelConfig) (TunnelStatus, error) {
	m.mu.Lock()
	existing, ok := m.tunnels[tc.Spec.TunnelKey]
	if ok && existing.spec == tc.Spec {
		m.mu.Unlock()
		if err := existing.router.Update(tc.HTTPRoutes); err != nil {
			return TunnelStatus{}, fmt.Errorf("hot-reload http routes: %w", err)
		}
		if err := existing.tls.Reload(tc.TLSCerts); err != nil {
			return TunnelStatus{}, fmt.Errorf("hot-reload tls certs: %w", err)
		}
		existing.tlsPassthrough.Update(tc.TLSPassthrough)
		existing.tcpRouter.Update(tc.TCPBackend)

		existing.mu.RLock()
		st := TunnelStatus{
			TunnelKey:    tc.Spec.TunnelKey,
			Mode:         tc.Spec.Mode,
			AssignedHost: existing.assignedHost,
			Connected:    existing.connected,
		}
		existing.mu.RUnlock()
		return st, nil
	}

	if ok {
		existing.cancel()
		delete(m.tunnels, tc.Spec.TunnelKey)
	}

	router := proxy.NewRouter()
	if err := router.Update(tc.HTTPRoutes); err != nil {
		m.mu.Unlock()
		return TunnelStatus{}, fmt.Errorf("init http routes: %w", err)
	}
	tlsStore := proxy.NewTLSStore()
	if err := tlsStore.Reload(tc.TLSCerts); err != nil {
		m.mu.Unlock()
		return TunnelStatus{}, fmt.Errorf("init tls certs: %w", err)
	}
	tlsPassthrough := proxy.NewTLSPassthroughRouter()
	tlsPassthrough.Update(tc.TLSPassthrough)
	tcpRouter := proxy.NewTCPRouter()
	tcpRouter.Update(tc.TCPBackend)

	ctx, cancel := context.WithCancel(parentCtx)
	mt := &managedTunnel{
		spec:           tc.Spec,
		router:         router,
		tls:            tlsStore,
		tlsPassthrough: tlsPassthrough,
		tcpRouter:      tcpRouter,
		cancel:         cancel,
		done:           make(chan struct{}),
		assignedHost:   tc.Spec.Hostname,
	}
	m.tunnels[tc.Spec.TunnelKey] = mt
	m.mu.Unlock()

	go m.runLoop(ctx, mt)
	return TunnelStatus{
		TunnelKey:    tc.Spec.TunnelKey,
		Mode:         tc.Spec.Mode,
		AssignedHost: mt.assignedHost,
		Connected:    false,
	}, nil
}

// RemoveGateway stops and removes all SSH tunnels belonging to a deleted Gateway.
func (m *Manager) RemoveGateway(gatewayKey string) {
	m.mu.Lock()
	var toStop []*managedTunnel
	for k, mt := range m.tunnels {
		if mt.spec.GatewayKey == gatewayKey {
			toStop = append(toStop, mt)
			delete(m.tunnels, k)
		}
	}
	m.mu.Unlock()

	for _, mt := range toStop {
		mt.cancel()
		<-mt.done
	}
}

// Shutdown gracefully terminates all active SSH tunnels.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	all := make([]*managedTunnel, 0, len(m.tunnels))
	for k, mt := range m.tunnels {
		all = append(all, mt)
		delete(m.tunnels, k)
	}
	m.mu.Unlock()

	for _, mt := range all {
		mt.cancel()
		<-mt.done
	}
}

func (m *Manager) runLoop(ctx context.Context, mt *managedTunnel) {
	defer close(mt.done)
	backoff := m.cfg.BackoffInitial

	for {
		if ctx.Err() != nil {
			return
		}

		err := m.runOnce(ctx, mt)
		mt.mu.Lock()
		mt.connected = false
		host := mt.assignedHost
		mt.mu.Unlock()
		m.notify(mt.spec.GatewayKey, mt.spec.TunnelKey, host, false, err)

		if ctx.Err() != nil {
			return
		}

		m.log.Error(err, "SSH tunnel disconnected, reconnecting",
			"tunnel", mt.spec.TunnelKey,
			"mode", mt.spec.Mode,
			"backoff", backoff.String(),
		)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > m.cfg.BackoffMax {
			backoff = m.cfg.BackoffMax
		}
	}
}

func (m *Manager) runOnce(ctx context.Context, mt *managedTunnel) error {
	plan := BuildSSHPlan(mt.spec)
	sshCfg, err := m.buildSSHClientConfig(plan.Username)
	if err != nil {
		return fmt.Errorf("build ssh config: %w", err)
	}

	m.log.Info("dialing SSH reverse tunnel",
		"tunnel", mt.spec.TunnelKey,
		"mode", mt.spec.Mode,
		"provider", mt.spec.Provider,
		"server", plan.ServerAddr,
		"user", plan.Username,
		"remoteBind", plan.RemoteBindAddr,
		"tlsTunnelMode", mt.spec.TLSTunnelMode,
	)

	dialer := &net.Dialer{Timeout: m.cfg.ConnectTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", plan.ServerAddr)
	if err != nil {
		return fmt.Errorf("tcp dial %s: %w", plan.ServerAddr, err)
	}

	c, chans, reqs, err := ssh.NewClientConn(rawConn, plan.ServerAddr, sshCfg)
	if err != nil {
		_ = rawConn.Close()
		return fmt.Errorf("ssh handshake %s: %w", plan.ServerAddr, err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	remoteLn, err := client.Listen("tcp", plan.RemoteBindAddr)
	if err != nil {
		return fmt.Errorf("ssh remote listen %s: %w", plan.RemoteBindAddr, err)
	}
	defer remoteLn.Close()

	if plan.SessionCommand != "" || plan.RequestPTY {
		go m.runSession(ctx, client, mt, plan)
	}
	go m.keepAlive(ctx, client)

	mt.mu.Lock()
	mt.connected = true
	host := mt.assignedHost
	mt.mu.Unlock()
	m.notify(mt.spec.GatewayKey, mt.spec.TunnelKey, host, true, nil)

	switch mt.spec.Mode {
	case ModeTCP:
		return m.serveTCP(ctx, remoteLn, mt.tcpRouter)
	case ModeHTTPS, ModeTLS:
		if mt.spec.TLSTunnelMode {
			return m.serveTLSTunnel(ctx, remoteLn, mt, host)
		}
		return m.serveHTTP(ctx, remoteLn, mt.router)
	default:
		return m.serveHTTP(ctx, remoteLn, mt.router)
	}
}

func (m *Manager) serveTCP(ctx context.Context, remoteLn net.Listener, tcpRouter *proxy.TCPRouter) error {
	go func() {
		<-ctx.Done()
		_ = remoteLn.Close()
	}()
	for {
		conn, err := remoteLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go tcpRouter.Handle(conn)
	}
}

func (m *Manager) serveHTTP(ctx context.Context, remoteLn net.Listener, router *proxy.Router) error {
	srv := &http.Server{
		Handler:           router,
		ReadHeaderTimeout: 15 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(remoteLn) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// serveTLSTunnel handles TLS Tunneling Mode: raw encrypted TLS streams arrive
// over the SSH reverse tunnel, ClientHello SNI is peeked, matching TLSRoutes
// pass through untouched to backend pods, and HTTPS traffic terminates TLS
// internally using Gateway Secrets before routing to HTTPRoutes.
func (m *Manager) serveTLSTunnel(ctx context.Context, remoteLn net.Listener, mt *managedTunnel, host string) error {
	if !mt.tls.HasCertificates() {
		fallbackHost := host
		if fallbackHost == "" {
			fallbackHost = "localhost"
		}
		if selfSigned, err := proxy.GenerateSelfSignedCert([]string{fallbackHost}); err == nil {
			_ = mt.tls.Reload([]proxy.CertEntry{selfSigned})
			m.log.Info("no Gateway TLS Secret attached yet; loaded temporary self-signed certificate",
				"tunnel", mt.spec.TunnelKey,
				"cn", fallbackHost,
			)
		}
	}

	httpChLn := proxy.NewChannelListener(remoteLn.Addr())
	srv := &http.Server{
		Handler:           mt.router,
		ReadHeaderTimeout: 15 * time.Second,
	}
	go func() { _ = srv.Serve(httpChLn) }()

	go func() {
		<-ctx.Done()
		_ = remoteLn.Close()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	err := proxy.ServeTLSMultiplexed(remoteLn, mt.tlsPassthrough, mt.tls, httpChLn)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (m *Manager) runSession(ctx context.Context, client *ssh.Client, mt *managedTunnel, plan ResolvedSSHPlan) {
	sess, err := client.NewSession()
	if err != nil {
		m.log.Error(err, "failed to open SSH session", "tunnel", mt.spec.TunnelKey)
		return
	}
	defer sess.Close()

	stdout, err := sess.StdoutPipe()
	if err != nil {
		return
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return
	}

	if plan.RequestPTY {
		_ = sess.RequestPty("xterm", 40, 80, ssh.TerminalModes{})
	}

	if plan.SessionCommand != "" {
		if err := sess.Start(plan.SessionCommand); err != nil {
			m.log.Error(err, "failed to start SSH session command",
				"tunnel", mt.spec.TunnelKey,
				"command", plan.SessionCommand,
			)
			return
		}
	} else {
		if err := sess.Shell(); err != nil {
			m.log.Error(err, "failed to start SSH shell", "tunnel", mt.spec.TunnelKey)
			return
		}
	}

	scan := func(r io.Reader) {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			if host := ExtractAssignedHost(line); host != "" {
				mt.mu.Lock()
				changed := mt.assignedHost != host
				mt.assignedHost = host
				connected := mt.connected
				mt.mu.Unlock()
				if changed {
					m.log.Info("discovered public tunnel endpoint",
						"tunnel", mt.spec.TunnelKey,
						"mode", mt.spec.Mode,
						"endpoint", host,
					)
					m.notify(mt.spec.GatewayKey, mt.spec.TunnelKey, host, connected, nil)
				}
			}
		}
	}

	go scan(stdout)
	go scan(stderr)

	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	select {
	case <-ctx.Done():
		_ = sess.Close()
	case <-done:
	}
}

func (m *Manager) keepAlive(ctx context.Context, client *ssh.Client) {
	ticker := time.NewTicker(m.cfg.KeepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				_ = client.Close()
				return
			}
		}
	}
}

func (m *Manager) buildSSHClientConfig(username string) (*ssh.ClientConfig, error) {
	var authMethods []ssh.AuthMethod

	if m.cfg.SSHPrivateKeyPath != "" {
		keyBytes, err := os.ReadFile(m.cfg.SSHPrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read SSH private key %s: %w", m.cfg.SSHPrivateKeyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse SSH private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if m.cfg.SSHPassword != "" {
		authMethods = append(authMethods, ssh.Password(m.cfg.SSHPassword))
	}

	var hostKeyCB ssh.HostKeyCallback
	if m.cfg.SSHKnownHostsPath != "" {
		cb, err := knownhosts.New(m.cfg.SSHKnownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("load known_hosts %s: %w", m.cfg.SSHKnownHostsPath, err)
		}
		hostKeyCB = cb
	} else if m.cfg.InsecureHostKey {
		hostKeyCB = ssh.InsecureIgnoreHostKey()
	} else {
		return nil, errors.New("SSH_KNOWN_HOSTS_PATH must be set when SSH_INSECURE_IGNORE_HOST_KEY=false")
	}

	return &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCB,
		Timeout:         m.cfg.ConnectTimeout,
	}, nil
}

func (m *Manager) notify(gatewayKey, tunnelKey, host string, connected bool, err error) {
	m.mu.Lock()
	cb := m.onStat
	m.mu.Unlock()
	if cb != nil {
		cb(gatewayKey, tunnelKey, host, connected, err)
	}
}
