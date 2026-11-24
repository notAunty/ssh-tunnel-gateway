package tunnel

import (
	"testing"

	"github.com/example/ssh-tunnel-gateway/internal/config"
)

func TestBuildSSHPlan_PinggyAllModes(t *testing.T) {
	tlsPlan := BuildSSHPlan(TunnelSpec{
		Mode:          ModeHTTPS,
		Provider:      config.ProviderPinggy,
		SSHUsername:   "my-token",
		Hostname:      "*.example.com",
		TLSTunnelMode: true,
	})
	if tlsPlan.Username != "my-token+tls" {
		t.Fatalf("expected Pinggy TLS user 'my-token+tls', got %q", tlsPlan.Username)
	}

	tcpPlan := BuildSSHPlan(TunnelSpec{
		Mode:        ModeTCP,
		Port:        5432,
		Provider:    config.ProviderPinggy,
		SSHUsername: "my-token",
	})
	if tcpPlan.Username != "my-token+tcp" {
		t.Fatalf("expected Pinggy TCP user 'my-token+tcp', got %q", tcpPlan.Username)
	}

	httpPlan := BuildSSHPlan(TunnelSpec{
		Mode:        ModeHTTP,
		Port:        80,
		Provider:    config.ProviderPinggy,
		SSHUsername: "my-token",
	})
	if httpPlan.Username != "my-token" {
		t.Fatalf("expected Pinggy HTTP user 'my-token', got %q", httpPlan.Username)
	}
}

func TestBuildSSHPlan_PicoWildcardAllModes(t *testing.T) {
	httpsPlan := BuildSSHPlan(TunnelSpec{
		Mode:          ModeHTTPS,
		Provider:      config.ProviderPico,
		SSHUsername:   "alice",
		Hostname:      "*.example.com",
		TLSTunnelMode: true,
	})
	if httpsPlan.RemoteBindAddr != "*.example.com:443" {
		t.Fatalf("expected '*.example.com:443', got %q", httpsPlan.RemoteBindAddr)
	}
	if httpsPlan.SessionCommand != "sni-proxy=true" {
		t.Fatalf("expected 'sni-proxy=true', got %q", httpsPlan.SessionCommand)
	}

	httpPlan := BuildSSHPlan(TunnelSpec{
		Mode:        ModeHTTP,
		Provider:    config.ProviderPico,
		SSHUsername: "alice",
		Hostname:    "*.example.com",
	})
	if httpPlan.RemoteBindAddr != "*.example.com:80" {
		t.Fatalf("expected '*.example.com:80', got %q", httpPlan.RemoteBindAddr)
	}
	if httpPlan.SessionCommand != "" {
		t.Fatalf("expected empty session command for HTTP, got %q", httpPlan.SessionCommand)
	}

	tcpPlan := BuildSSHPlan(TunnelSpec{
		Mode:        ModeTCP,
		Port:        5432,
		Provider:    config.ProviderPico,
		SSHUsername: "alice",
	})
	if tcpPlan.RemoteBindAddr != "0.0.0.0:0" {
		t.Fatalf("expected '0.0.0.0:0' for Pico TCP, got %q", tcpPlan.RemoteBindAddr)
	}
}

func TestExtractAssignedHost(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{"Your tunnel is live at tls://abc123.a.pinggy.link", "abc123.a.pinggy.link"},
		{"Forwarding https://alice-demo.tuns.sh -> localhost:8443", "alice-demo.tuns.sh"},
		{"TCP endpoint ready at tcp://a.pinggy.io:41234", "a.pinggy.io:41234"},
		{"no url here", ""},
	}
	for _, tc := range cases {
		if got := ExtractAssignedHost(tc.line); got != tc.want {
			t.Errorf("ExtractAssignedHost(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}
