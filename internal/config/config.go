package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultControllerName = "ssh-tunnel.gateway.networking.k8s.io/controller"

	// Gateway annotations that override global defaults per Gateway resource.
	AnnotationProvider          = "ssh-tunnel.io/provider"
	AnnotationSSHServer         = "ssh-tunnel.io/ssh-server"
	AnnotationSSHUsername       = "ssh-tunnel.io/ssh-username"
	AnnotationTLSTunnelMode     = "ssh-tunnel.io/tls-tunnel-mode"
	AnnotationRemoteBindAddress = "ssh-tunnel.io/remote-bind-address"
	AnnotationSessionCommand    = "ssh-tunnel.io/session-command"
)

// ProviderType identifies the upstream SSH reverse-tunnel service.
type ProviderType string

const (
	ProviderPinggy       ProviderType = "pinggy"
	ProviderPico         ProviderType = "pico"
	ProviderLocalhostRun ProviderType = "localhostrun"
	ProviderOpenSSH      ProviderType = "openssh"
)

// Config holds process-wide defaults loaded from environment variables.
type Config struct {
	ControllerName    string
	Provider          ProviderType
	SSHServer         string
	SSHUsername       string
	SSHPassword       string
	SSHPrivateKeyPath string
	SSHKnownHostsPath string
	InsecureHostKey   bool
	TLSTunnelMode     bool
	SessionCommand    string
	ConnectTimeout    time.Duration
	KeepAliveInterval time.Duration
	BackoffInitial    time.Duration
	BackoffMax        time.Duration
	MetricsBindAddr   string
	HealthProbeAddr   string
}

// LoadFromEnv loads controller configuration from environment variables.
func LoadFromEnv() Config {
	provider := ProviderType(strings.ToLower(envOrDefault("SSH_PROVIDER", string(ProviderPinggy))))

	defaultServer := defaultServerForProvider(provider)
	defaultUser := defaultUserForProvider(provider)

	return Config{
		ControllerName:    envOrDefault("GATEWAY_CONTROLLER_NAME", DefaultControllerName),
		Provider:          provider,
		SSHServer:         envOrDefault("SSH_SERVER", defaultServer),
		SSHUsername:       envOrDefault("SSH_USERNAME", defaultUser),
		SSHPassword:       os.Getenv("SSH_PASSWORD"),
		SSHPrivateKeyPath: os.Getenv("SSH_PRIVATE_KEY_PATH"),
		SSHKnownHostsPath: os.Getenv("SSH_KNOWN_HOSTS_PATH"),
		InsecureHostKey:   envBool("SSH_INSECURE_IGNORE_HOST_KEY", true),
		TLSTunnelMode:     envBool("TLS_TUNNEL_MODE", true),
		SessionCommand:    os.Getenv("SSH_SESSION_COMMAND"),
		ConnectTimeout:    envDuration("SSH_CONNECT_TIMEOUT", 15*time.Second),
		KeepAliveInterval: envDuration("SSH_KEEPALIVE_INTERVAL", 15*time.Second),
		BackoffInitial:    envDuration("SSH_BACKOFF_INITIAL", 3*time.Second),
		BackoffMax:        envDuration("SSH_BACKOFF_MAX", 60*time.Second),
		MetricsBindAddr:   envOrDefault("METRICS_BIND_ADDRESS", ":8080"),
		HealthProbeAddr:   envOrDefault("HEALTH_PROBE_ADDRESS", ":8081"),
	}
}

// Validate checks that required fields are structurally valid.
func (c Config) Validate() error {
	if c.ControllerName == "" {
		return fmt.Errorf("GATEWAY_CONTROLLER_NAME must not be empty")
	}
	if c.SSHServer == "" {
		return fmt.Errorf("SSH_SERVER must not be empty")
	}
	return nil
}

func defaultServerForProvider(p ProviderType) string {
	switch p {
	case ProviderPinggy:
		return "free.pinggy.io:443"
	case ProviderPico:
		return "tuns.sh:22"
	case ProviderLocalhostRun:
		return "localhost.run:22"
	default:
		return "127.0.0.1:22"
	}
}

func defaultUserForProvider(p ProviderType) string {
	switch p {
	case ProviderPinggy:
		return ""
	case ProviderLocalhostRun:
		return "nokey"
	default:
		return "tunnel"
	}
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
