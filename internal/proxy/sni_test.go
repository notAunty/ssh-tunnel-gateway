package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSNIMultiplexedHTTPSAndTLSPassthrough verifies that a single wildcard
// TLS-tunnel listener can simultaneously:
//  1. Terminate TLS internally for HTTPS HTTPRoute traffic (app.wild.local)
//  2. Pass raw encrypted TLS through untouched for TLSRoute traffic (db.wild.local)
func TestSNIMultiplexedHTTPSAndTLSPassthrough(t *testing.T) {
	// Plaintext HTTP backend (gateway terminates TLS internally).
	httpBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("https-terminated-at-gateway"))
	}))
	defer httpBackend.Close()

	// End-to-end TLS backend (gateway passes raw TLS through via SNI).
	backendCertEntry, err := GenerateSelfSignedCert([]string{"db.wild.local"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert backend: %v", err)
	}
	backendKeyPair, err := tls.X509KeyPair(backendCertEntry.CertPEM, backendCertEntry.KeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair backend: %v", err)
	}
	tlsBackendLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{backendKeyPair},
	})
	if err != nil {
		t.Fatalf("tls.Listen backend: %v", err)
	}
	defer tlsBackendLn.Close()
	go func() {
		for {
			c, err := tlsBackendLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("tls-passthrough-backend"))
			}(c)
		}
	}()

	// Gateway wildcard TLS cert for internal HTTPS termination (*.wild.local).
	gwCertEntry, err := GenerateSelfSignedCert([]string{"*.wild.local"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert gateway: %v", err)
	}
	tlsStore := NewTLSStore()
	if err := tlsStore.Reload([]CertEntry{gwCertEntry}); err != nil {
		t.Fatalf("tlsStore.Reload: %v", err)
	}

	httpRouter := NewRouter()
	if err := httpRouter.Update([]RouteRule{{
		Hostnames: []string{"*.wild.local"},
		MatchType: PathMatchPrefix,
		Path:      "/",
		Backend:   httpBackend.URL,
	}}); err != nil {
		t.Fatalf("httpRouter.Update: %v", err)
	}

	tlsPassthrough := NewTLSPassthroughRouter()
	tlsPassthrough.Update([]TLSPassthroughRule{{
		Hostnames: []string{"db.wild.local"},
		Backend:   tlsBackendLn.Addr().String(),
	}})

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer rawLn.Close()

	httpChLn := NewChannelListener(rawLn.Addr())
	srv := &http.Server{Handler: httpRouter}
	go func() { _ = srv.Serve(httpChLn) }()
	defer srv.Close()

	go func() { _ = ServeTLSMultiplexed(rawLn, tlsPassthrough, tlsStore, httpChLn) }()

	// 1. Test HTTPS internal termination on wildcard subdomain app.wild.local.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "app.wild.local",
				InsecureSkipVerify: true,
			},
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+rawLn.Addr().String()+"/", nil)
	req.Host = "app.wild.local"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "https-terminated-at-gateway" {
		t.Fatalf("HTTPS mode mismatch: got %q", string(body))
	}

	// 2. Test L4 TLS passthrough on db.wild.local (backend terminates TLS).
	tlsConn, err := tls.Dial("tcp", rawLn.Addr().String(), &tls.Config{
		ServerName:         "db.wild.local",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("TLS passthrough dial failed: %v", err)
	}
	defer tlsConn.Close()
	passthroughBytes, _ := io.ReadAll(tlsConn)
	if string(passthroughBytes) != "tls-passthrough-backend" {
		t.Fatalf("TLS passthrough mismatch: got %q", string(passthroughBytes))
	}
}

func TestTCPRouter(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen backend: %v", err)
	}
	defer backendLn.Close()

	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	tcpRouter := NewTCPRouter()
	tcpRouter.Update(backendLn.Addr().String())

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen proxy: %v", err)
	}
	defer proxyLn.Close()
	go func() {
		for {
			c, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go tcpRouter.Handle(c)
		}
	}()

	c, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer c.Close()

	_, _ = c.Write([]byte("ping-tcp"))
	buf := make([]byte, 8)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != "ping-tcp" {
		t.Fatalf("expected 'ping-tcp', got %q", string(buf))
	}
}
