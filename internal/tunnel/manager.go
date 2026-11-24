package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
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

// StatusCallback is invoked when a tunnel connects or discovers its assigned public host.
type StatusCallback func(gatewayKey string, assignedHost string, connected bool, lastErr error)

type managedTunnel struct {
	spec   TunnelSpec
	router *proxy.Router
	tls    *proxy.TLSStore
	cancel context.CancelFunc
	done   chan struct{}

	mu           sync.RWMutex
	assignedHost string
	connected    bool
}

// Manager supervises one resilient SSH reverse tunnel per Kubernetes Gateway.
// Routes and TLS certificates are updated in-place via hot reload without
// tearing down active SSH sessions.
type Manager struct {
	cfg    config.Config
	log    logr.Logger
	onStat StatusCallback

	mu      sync.Mutex
	tunnels map[string]*managedTunnel
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

// ReconcileGateway ensures a tunnel exists for the given Gateway with the
// latest routes and TLS certificates. If the SSH connection parameters did not
// change, only the in-memory router and TLS store are hot-reloaded.
func (m *Manager) ReconcileGateway(
	parentCtx context.Context,
	spec TunnelSpec,
	routes []proxy.RouteRule,
	certs []proxy.CertEntry,
) (assignedHost string, connected bool, err error) {
	m.mu.Lock()
	existing, ok := m.tunnels[spec.GatewayKey]
	if ok && existing.spec == spec {
		m.mu.Unlock()
		if err := existing.router.Update(routes); err != nil {
			return "", false, fmt.Errorf("hot-reload routes: %w", err)
		}
		if err := existing.tls.Reload(certs); err != nil {
			return "", false, fmt.Errorf("hot-reload tls certs: %w", err)
		}
		existing.mu.RLock()
		defer existing.mu.RUnlock()
		return existing.assignedHost, existing.connected, nil
	}

	// Stop superseded tunnel if SSH connection parameters changed.
	if ok {
		existing.cancel()
		delete(m.tunnels, spec.GatewayKey)
	}

	router := proxy.NewRouter()
	if err := router.Update(routes); err != nil {
		m.mu.Unlock()
		return "", false, fmt.Errorf("init routes: %w", err)
	}
	tlsStore := proxy.NewTLSStore()
	if err := tlsStore.Reload(certs); err != nil {
		m.mu.Unlock()
		return "", false, fmt.Errorf("init tls certs: %w", err)
	}

	ctx, cancel := context.WithCancel(parentCtx)
	mt := &managedTunnel{
		spec:         spec,
		router:       router,
		tls:          tlsStore,
		cancel:       cancel,
		done:         make(chan struct{}),
		assignedHost: spec.Hostname,
	}
	m.tunnels[spec.GatewayKey] = mt
	m.mu.Unlock()

	go m.runLoop(ctx, mt)
	return mt.assignedHost, false, nil
}

// RemoveGateway stops and removes the SSH tunnel for a deleted Gateway.
func (m *Manager) RemoveGateway(gatewayKey string) {
	m.mu.Lock()
	mt, ok := m.tunnels[gatewayKey]
	if ok {
		delete(m.tunnels, gatewayKey)
	}
	m.mu.Unlock()

	if ok {
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
		m.notify(mt.spec.GatewayKey, host, false, err)

		if ctx.Err() != nil {
			return
		}

		m.log.Error(err, "SSH tunnel disconnected, reconnecting",
			"gateway", mt.spec.GatewayKey,
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
		"gateway", mt.spec.GatewayKey,
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

	// Request reverse port forwarding on the remote SSH tunnel server.
	remoteLn, err := client.Listen("tcp", plan.RemoteBindAddr)
	if err != nil {
		return fmt.Errorf("ssh remote listen %s: %w", plan.RemoteBindAddr, err)
	}
	defer remoteLn.Close()

	// Open an SSH session for providers that take session commands (e.g. tuns.sh
	// `sni-proxy=true`) or emit the assigned public URL over stdout (Pinggy / localhost.run).
	if plan.SessionCommand != "" || plan.RequestPTY {
		go m.runSession(ctx, client, mt, plan)
	}

	// Keepalive loop to detect dead NAT/firewall connections promptly.
	go m.keepAlive(ctx, client)

	mt.mu.Lock()
	mt.connected = true
	host := mt.assignedHost
	mt.mu.Unlock()
	m.notify(mt.spec.GatewayKey, host, true, nil)

	// In TLS Tunneling Mode, the SaaS provider forwards raw encrypted TLS bytes
	// without decrypting them. We wrap the SSH-forwarded net.Listener directly
	// with tls.NewListener so TLS is terminated internally inside our cluster.
	var serveLn net.Listener = remoteLn
	if mt.spec.TLSTunnelMode {
		if !mt.tls.HasCertificates() {
			fallbackHost := host
			if fallbackHost == "" {
				fallbackHost = "localhost"
			}
			selfSigned, genErr := proxy.GenerateSelfSignedCert([]string{fallbackHost})
			if genErr == nil {
				_ = mt.tls.Reload([]proxy.CertEntry{selfSigned})
				m.log.Info("no Gateway TLS Secret attached yet; loaded temporary self-signed certificate",
					"gateway", mt.spec.GatewayKey,
					"cn", fallbackHost,
				)
			}
		}
		serveLn = tls.NewListener(remoteLn, mt.tls.TLSConfig())
	}

	srv := &http.Server{
		Handler:           mt.router,
		ReadHeaderTimeout: 15 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(serveLn)
	}()

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

func (m *Manager) runSession(ctx context.Context, client *ssh.Client, mt *managedTunnel, plan ResolvedSSHPlan) {
	sess, err := client.NewSession()
	if err != nil {
		m.log.Error(err, "failed to open SSH session", "gateway", mt.spec.GatewayKey)
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
				"gateway", mt.spec.GatewayKey,
				"command", plan.SessionCommand,
			)
			return
		}
	} else {
		if err := sess.Shell(); err != nil {
			m.log.Error(err, "failed to start SSH shell", "gateway", mt.spec.GatewayKey)
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
					m.log.Info("discovered public tunnel hostname",
						"gateway", mt.spec.GatewayKey,
						"hostname", host,
					)
					m.notify(mt.spec.GatewayKey, host, connected, nil)
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

func (m *Manager) notify(gatewayKey, host string, connected bool, err error) {
	m.mu.Lock()
	cb := m.onStat
	m.mu.Unlock()
	if cb != nil {
		cb(gatewayKey, host, connected, err)
	}
}
