package tunnel

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/example/ssh-tunnel-gateway/internal/config"
)

// TunnelSpec captures the resolved SSH tunnel parameters for a single Gateway.
type TunnelSpec struct {
	GatewayKey     string
	Provider       config.ProviderType
	SSHServer      string
	SSHUsername    string
	Hostname       string // Optional custom domain / subdomain requested on the Gateway listener
	TLSTunnelMode  bool   // When true, SaaS forwards raw TLS via SNI and we terminate TLS internally
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
	httpsURLRegex = regexp.MustCompile(`https://([a-zA-Z0-9.-]+)`)
	tlsURLRegex   = regexp.MustCompile(`tls://([a-zA-Z0-9.-]+)`)
)

// BuildSSHPlan translates a provider-agnostic TunnelSpec into concrete SSH
// reverse-tunnel parameters, including TLS passthrough / TLS tunneling mode
// flags for compatible SaaS providers.
func BuildSSHPlan(spec TunnelSpec) ResolvedSSHPlan {
	plan := ResolvedSSHPlan{
		ServerAddr:     spec.SSHServer,
		Username:       spec.SSHUsername,
		RemoteBindAddr: spec.RemoteBindAddr,
		SessionCommand: spec.SessionCommand,
	}

	switch spec.Provider {
	case config.ProviderPinggy:
		// Pinggy TLS tunneling mode:
		//   ssh -p 443 -R0:localhost:<port> tls@free.pinggy.io
		//   or <token>+tls@a.pinggy.io for persistent/custom domains.
		// Pinggy routes by SNI on port 443 and forwards raw TLS as-is.
		if plan.ServerAddr == "" {
			plan.ServerAddr = "free.pinggy.io:443"
		}
		if spec.TLSTunnelMode {
			plan.Username = ensurePinggyTLSUser(plan.Username)
		}
		if plan.RemoteBindAddr == "" {
			plan.RemoteBindAddr = "0.0.0.0:0"
		}
		// Pinggy prints the assigned tunnel URL on an interactive session.
		plan.RequestPTY = true

	case config.ProviderPico:
		// Pico.sh tuns.sh (sish-based) SNI / TLS tunneling mode:
		//   ssh -R <hostname>:443:localhost:<port> tuns.sh sni-proxy=true
		// tuns.sh routes port 443 by SNI without terminating TLS.
		if plan.ServerAddr == "" {
			plan.ServerAddr = "tuns.sh:22"
		}
		if plan.RemoteBindAddr == "" {
			host := spec.Hostname
			if host == "" {
				host = "0.0.0.0"
			}
			if spec.TLSTunnelMode {
				plan.RemoteBindAddr = fmt.Sprintf("%s:443", host)
			} else {
				plan.RemoteBindAddr = fmt.Sprintf("%s:80", host)
			}
		}
		if spec.TLSTunnelMode && plan.SessionCommand == "" {
			plan.SessionCommand = "sni-proxy=true"
		}

	case config.ProviderLocalhostRun:
		// localhost.run uses SSH remote port forwarding (nokey@localhost.run or
		// authenticated SSH key for custom domains).
		if plan.ServerAddr == "" {
			plan.ServerAddr = "localhost.run:22"
		}
		if plan.Username == "" {
			plan.Username = "nokey"
		}
		if plan.RemoteBindAddr == "" {
			if spec.TLSTunnelMode && spec.Hostname != "" {
				plan.RemoteBindAddr = fmt.Sprintf("%s:443", spec.Hostname)
			} else {
				plan.RemoteBindAddr = "0.0.0.0:80"
			}
		}
		plan.RequestPTY = true

	default:
		// Plain OpenSSH server (requires AllowTcpForwarding yes & GatewayPorts yes).
		if plan.RemoteBindAddr == "" {
			if spec.TLSTunnelMode {
				plan.RemoteBindAddr = "0.0.0.0:443"
			} else {
				plan.RemoteBindAddr = "0.0.0.0:80"
			}
		}
	}

	return plan
}

// ensurePinggyTLSUser appends the `+tls` mode flag (or uses `tls` on the free tier)
// so Pinggy operates in zero-trust TLS tunneling mode without terminating TLS.
func ensurePinggyTLSUser(user string) string {
	user = strings.TrimSpace(user)
	if user == "" {
		return "tls"
	}
	parts := strings.Split(user, "+")
	for _, p := range parts {
		if strings.EqualFold(p, "tls") {
			return user
		}
	}
	return user + "+tls"
}

// ExtractAssignedHost parses a public hostname from SSH tunnel banner output
// (used by providers like Pinggy, tuns.sh, and localhost.run that assign URLs
// dynamically on connection).
func ExtractAssignedHost(line string) string {
	if m := tlsURLRegex.FindStringSubmatch(line); len(m) == 2 {
		return m[1]
	}
	if m := httpsURLRegex.FindStringSubmatch(line); len(m) == 2 {
		return m[1]
	}
	return ""
}
