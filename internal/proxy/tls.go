package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// CertEntry represents a TLS keypair associated with one or more hostnames.
type CertEntry struct {
	Hostnames []string
	CertPEM   []byte
	KeyPEM    []byte
}

// TLSStore holds hot-reloadable TLS certificates for internal TLS termination.
// When TLS tunneling mode is enabled, the SSH tunnel provider forwards raw
// encrypted TLS traffic (routing only by SNI) and this store supplies the
// matching certificate during the internal TLS handshake.
type TLSStore struct {
	mu       sync.RWMutex
	exact    map[string]*tls.Certificate
	wildcard map[string]*tls.Certificate
	fallback *tls.Certificate
}

// NewTLSStore creates an empty TLSStore.
func NewTLSStore() *TLSStore {
	return &TLSStore{
		exact:    make(map[string]*tls.Certificate),
		wildcard: make(map[string]*tls.Certificate),
	}
}

// Reload atomically replaces the active certificate set without restarting
// the underlying SSH tunnel or TLS listener.
func (s *TLSStore) Reload(entries []CertEntry) error {
	exact := make(map[string]*tls.Certificate)
	wildcard := make(map[string]*tls.Certificate)
	var fallback *tls.Certificate

	for _, e := range entries {
		cert, err := tls.X509KeyPair(e.CertPEM, e.KeyPEM)
		if err != nil {
			return fmt.Errorf("parse x509 keypair: %w", err)
		}
		if len(cert.Certificate) > 0 {
			if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
				cert.Leaf = leaf
			}
		}

		c := cert
		if fallback == nil {
			fallback = &c
		}

		hosts := e.Hostnames
		if len(hosts) == 0 && cert.Leaf != nil {
			hosts = append(hosts, cert.Leaf.DNSNames...)
			if cert.Leaf.Subject.CommonName != "" {
				hosts = append(hosts, cert.Leaf.Subject.CommonName)
			}
		}

		for _, h := range hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			if strings.HasPrefix(h, "*.") {
				wildcard[strings.TrimPrefix(h, "*.")] = &c
			} else {
				exact[h] = &c
			}
		}
	}

	s.mu.Lock()
	s.exact = exact
	s.wildcard = wildcard
	s.fallback = fallback
	s.mu.Unlock()
	return nil
}

// HasCertificates reports whether at least one certificate is loaded.
func (s *TLSStore) HasCertificates() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fallback != nil || len(s.exact) > 0 || len(s.wildcard) > 0
}

// GetCertificate implements tls.Config.GetCertificate with SNI matching:
// exact match -> single-label wildcard match -> fallback certificate.
func (s *TLSStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sni := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if sni != "" {
		if cert, ok := s.exact[sni]; ok {
			return cert, nil
		}
		if dot := strings.IndexByte(sni, '.'); dot > 0 && dot < len(sni)-1 {
			parent := sni[dot+1:]
			if cert, ok := s.wildcard[parent]; ok {
				return cert, nil
			}
		}
	}

	if s.fallback != nil {
		return s.fallback, nil
	}
	return nil, errors.New("no TLS certificate configured for SNI " + hello.ServerName)
}

// TLSConfig returns a hardened *tls.Config backed by this dynamic store.
func (s *TLSStore) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: s.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}

// GenerateSelfSignedCert creates an in-memory ECDSA certificate for local
// development or testing when no Secret is attached yet.
func GenerateSelfSignedCert(hostnames []string) (CertEntry, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CertEntry{}, fmt.Errorf("generate ecdsa key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return CertEntry{}, fmt.Errorf("generate serial: %w", err)
	}

	if len(hostnames) == 0 {
		hostnames = []string{"localhost"}
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: hostnames[0],
		},
		DNSNames:              hostnames,
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return CertEntry{}, fmt.Errorf("create certificate: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return CertEntry{}, fmt.Errorf("marshal private key: %w", err)
	}

	return CertEntry{
		Hostnames: hostnames,
		CertPEM:   encodePEM("CERTIFICATE", derBytes),
		KeyPEM:    encodePEM("EC PRIVATE KEY", keyBytes),
	}, nil
}
