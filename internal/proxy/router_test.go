package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouterPathAndHostPrecedence(t *testing.T) {
	backendAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api:" + r.URL.Path))
	}))
	defer backendAPI.Close()

	backendRoot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("root:" + r.URL.Path))
	}))
	defer backendRoot.Close()

	router := NewRouter()
	err := router.Update([]RouteRule{
		{
			Hostnames: []string{"*.example.com"},
			MatchType: PathMatchPrefix,
			Path:      "/",
			Backend:   backendRoot.URL,
		},
		{
			Hostnames: []string{"app.example.com"},
			MatchType: PathMatchPrefix,
			Path:      "/api",
			Backend:   backendAPI.URL,
		},
	})
	if err != nil {
		t.Fatalf("router.Update failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/api/v1/items", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "api:/api/v1/items" {
		t.Fatalf("unexpected response: status=%d body=%q", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "https://blog.example.com/posts", nil)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK || rec2.Body.String() != "root:/posts" {
		t.Fatalf("unexpected response: status=%d body=%q", rec2.Code, rec2.Body.String())
	}
}

// TestInternalTLSTerminationOverRawListener verifies the core TLS tunneling mode
// path: wrapping a raw net.Listener (like ssh.Client.Listen) with tls.NewListener
// so TLS is terminated internally using certificates from TLSStore.
func TestInternalTLSTerminationOverRawListener(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("terminated-internally"))
	}))
	defer backend.Close()

	router := NewRouter()
	if err := router.Update([]RouteRule{{
		Hostnames: []string{"tunnel.local"},
		MatchType: PathMatchPrefix,
		Path:      "/",
		Backend:   backend.URL,
	}}); err != nil {
		t.Fatalf("router.Update: %v", err)
	}

	entry, err := GenerateSelfSignedCert([]string{"tunnel.local"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	store := NewTLSStore()
	if err := store.Reload([]CertEntry{entry}); err != nil {
		t.Fatalf("store.Reload: %v", err)
	}

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer rawLn.Close()

	tlsLn := tls.NewListener(rawLn, store.TLSConfig())
	srv := &http.Server{Handler: router}
	go func() { _ = srv.Serve(tlsLn) }()
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "tunnel.local",
				InsecureSkipVerify: true, // self-signed test cert
			},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+rawLn.Addr().String()+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = "tunnel.local"

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "terminated-internally" {
		t.Fatalf("expected 'terminated-internally', got %q", string(body))
	}
}
