package tunnel

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/example/ssh-tunnel-gateway/internal/config"
)

// TunnelMode represents the listener protocol mode served over an SSH reverse tunnel.
type TunnelMode string

const (
	// ModeHTTP serves plaintext HTTP over the SSH tunnel (provider terminates TLS or serves HTTP).
	ModeHTTP TunnelMode = "http"
	// ModeHTTPS receives raw TLS over the SSH tunnel (TLS tunneling mode) and
	// terminates TLS internally using Gateway Secrets before routing HTTPRoutes.
	ModeHTTPS TunnelMode = "https"
	// ModeTLS receives raw TLS over the SSH tunnel (TLS tunneling mode) and
	// supports SNI-based TLSRoute passthrough (and/or internal HTTPS termination
	// when sharing port 443 on a wildcard tunnel).
	ModeTLS TunnelMode = "tls"
	// ModeTCP forwards raw L4 TCP streams over the SSH tunnel to TCPRoute backends.
	ModeTCP TunnelMode = "tcp"
)

// TunnelSpec captures the resolved SSH tunnel parameters for a Gateway listener
// (or a shared wildcard listener group).
type TunnelSpec struct {
	TunnelKey      string // Unique key: "<ns>/<gw>/<mode>/<port>"
	GatewayKey     string
	Mode           TunnelMode
	Port           int32
	Provider       config.ProviderType
	SSHServer      string
	SSHUsername    string
	Hostname       string // Exact or wildcard hostname (e.g. "*.example.com" or "app.example.com")
	TLSTunnelMode  bool   // When true, SaaS forwards raw TLS via SNI without decrypting
	RemoteBindAddr string // Explicit override for ssh.Client.Listen("tcp", addr)
	SessionCommand string // Optional command executed on SSH session (e.g., sni-proxy=true)
}

// ResolvedSSHPlan contains the exact SSH dial, remote-forward, and session
// parameters derived from a TunnelSpec for a specific provider.
type ResolvedSSHPlan struct {
	ServerAddr     string
	Username       string
	RemoteBindAddr string
	SessionCommand string
	RequestPTY     bool
}

var (
	httpsURLRegex = regexp.MustCompile(`https://([a-zA-Z0-9.*-]+)`)
	tlsURLRegex   = regexp.MustCompile(`tls://([a-zA-Z0-9.*-]+)`)
	tcpURLRegex   = regexp.MustCompile(`tcp://([a-zA-Z0-9.-]+:[0-9]+)`)
)

// BuildSSHPlan translates a provider-agnostic TunnelSpec into concrete SSH
// reverse-tunnel parameters for HTTP, HTTPS, TLS, and TCP modes—including
// wildcard subdomain tunnels and TLS tunneling (passthrough) flags.
func BuildSSHPlan(spec TunnelSpec) ResolvedSSHPlan {
	plan := ResolvedSSHPlan{
		ServerAddr:     spec.SSHServer,
		Username:       spec.SSHUsername,
		RemoteBindAddr: spec.RemoteBindAddr,
		SessionCommand: spec.SessionCommand,
	}

	isTLSMode := spec.Mode == ModeHTTPS || spec.Mode == ModeTLS || spec.TLSTunnelMode
	isTCPMode := spec.Mode == ModeTCP

	switch spec.Provider {
	case config.ProviderPinggy:
		// Pinggy supports:
		//   HTTP: ssh -p 443 -R0:localhost:<port> <token>@a.pinggy.io
		//   TLS:  ssh -p 443 -R0:localhost:<port> <token>+tls@a.pinggy.io (or tls@free.pinggy.io)
		//   TCP:  ssh -p 443 -R0:localhost:<port> <token>+tcp@a.pinggy.io (or tcp@free.pinggy.io)
		if plan.ServerAddr == "" {
			plan.ServerAddr = "free.pinggy.io:443"
		}
		switch {
		case isTCPMode:
			plan.Username = ensurePinggyFlag(plan.Username, "tcp")
		case isTLSMode:
			plan.Username = ensurePinggyFlag(plan.Username, "tls")
		}
		if plan.RemoteBindAddr == "" {
			plan.RemoteBindAddr = "0.0.0.0:0"
		}
		plan.RequestPTY = true

	case config.ProviderPico:
		// Pico.sh tuns.sh (sish-based) supports wildcard custom domains (*.example.com):
		//   HTTP: ssh -R *.example.com:80:localhost:<port> tuns.sh
		//   TLS:  ssh -R *.example.com:443:localhost:<port> tuns.sh sni-proxy=true
		//   TCP:  ssh -R 0:localhost:<port> tuns.sh (or explicit remote port)
		if plan.ServerAddr == "" {
			plan.ServerAddr = "tuns.sh:22"
		}
		if plan.RemoteBindAddr == "" {
			switch {
			case isTCPMode:
				plan.RemoteBindAddr = "0.0.0.0:0"
			case isTLSMode:
				host := spec.Hostname
				if host == "" {
					host = "0.0.0.0"
				}
				plan.RemoteBindAddr = fmt.Sprintf("%s:443", host)
			default:
				host := spec.Hostname
				if host == "" {
					host = "0.0.0.0"
				}
				plan.RemoteBindAddr = fmt.Sprintf("%s:80", host)
			}
		}
		if isTLSMode && !isTCPMode && plan.SessionCommand == "" {
			plan.SessionCommand = "sni-proxy=true"
		}

	case config.ProviderLocalhostRun:
		// localhost.run supports HTTP and custom-domain TLS passthrough over SSH.
		if plan.ServerAddr == "" {
			plan.ServerAddr = "localhost.run:22"
		}
		if plan.Username == "" {
			plan.Username = "nokey"
		}
		if plan.RemoteBindAddr == "" {
			if isTLSMode && spec.Hostname != "" {
				plan.RemoteBindAddr = fmt.Sprintf("%s:443", spec.Hostname)
			} else if isTCPMode && spec.Port > 0 {
				plan.RemoteBindAddr = fmt.Sprintf("0.0.0.0:%d", spec.Port)
			} else {
				plan.RemoteBindAddr = "0.0.0.0:80"
			}
		}
		plan.RequestPTY = true

	default:
		// Plain OpenSSH server (requires AllowTcpForwarding yes & GatewayPorts yes).
		if plan.RemoteBindAddr == "" {
			port := spec.Port
			if port <= 0 {
				if isTLSMode {
					port = 443
				} else {
					port = 80
				}
			}
			plan.RemoteBindAddr = fmt.Sprintf("0.0.0.0:%d", port)
		}
	}

	return plan
}

// ensurePinggyFlag appends `+<flag>` (or uses `<flag>` on the free tier) if not already present.
func ensurePinggyFlag(user, flag string) string {
	user = strings.TrimSpace(user)
	if user == "" {
		return flag
	}
	parts := strings.Split(user, "+")
	for _, p := range parts {
		if strings.EqualFold(p, flag) {
			return user
		}
	}
	return user + "+" + flag
}

// ExtractAssignedHost parses a public hostname or host:port from SSH tunnel banner output.
func ExtractAssignedHost(line string) string {
	if m := tcpURLRegex.FindStringSubmatch(line); len(m) == 2 {
		return m[1]
	}
	if m := tlsURLRegex.FindStringSubmatch(line); len(m) == 2 {
		return m[1]
	}
	if m := httpsURLRegex.FindStringSubmatch(line); len(m) == 2 {
		return m[1]
	}
	return ""
}
