package tunnel

import (
	"testing"

	"github.com/example/ssh-tunnel-gateway/internal/config"
)

func TestBuildSSHPlan_PinggyTLSTunnelMode(t *testing.T) {
	plan := BuildSSHPlan(TunnelSpec{
		Provider:      config.ProviderPinggy,
		SSHUsername:   "my-token",
		TLSTunnelMode: true,
	})
	if plan.Username != "my-token+tls" {
		t.Fatalf("expected Pinggy TLS user 'my-token+tls', got %q", plan.Username)
	}
	if plan.ServerAddr != "free.pinggy.io:443" {
		t.Fatalf("unexpected default Pinggy server: %q", plan.ServerAddr)
	}
	if plan.RemoteBindAddr != "0.0.0.0:0" {
		t.Fatalf("unexpected remote bind addr: %q", plan.RemoteBindAddr)
	}
}

func TestBuildSSHPlan_PicoTunsSNIProxy(t *testing.T) {
	plan := BuildSSHPlan(TunnelSpec{
		Provider:      config.ProviderPico,
		SSHUsername:   "alice",
		Hostname:      "app.example.com",
		TLSTunnelMode: true,
	})
	if plan.ServerAddr != "tuns.sh:22" {
		t.Fatalf("unexpected default Pico server: %q", plan.ServerAddr)
	}
	if plan.RemoteBindAddr != "app.example.com:443" {
		t.Fatalf("expected 'app.example.com:443', got %q", plan.RemoteBindAddr)
	}
	if plan.SessionCommand != "sni-proxy=true" {
		t.Fatalf("expected session command 'sni-proxy=true', got %q", plan.SessionCommand)
	}
}

func TestExtractAssignedHost(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{"Your tunnel is live at tls://abc123.a.pinggy.link", "abc123.a.pinggy.link"},
		{"Forwarding https://alice-demo.tuns.sh -> localhost:8443", "alice-demo.tuns.sh"},
		{"no url here", ""},
	}
	for _, tc := range cases {
		if got := ExtractAssignedHost(tc.line); got != tc.want {
			t.Errorf("ExtractAssignedHost(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}
