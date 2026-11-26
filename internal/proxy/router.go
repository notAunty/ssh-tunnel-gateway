package proxy

import (
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
)

func encodePEM(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// PathMatchType mirrors Gateway API HTTPPathMatch types.
type PathMatchType string

const (
	PathMatchExact  PathMatchType = "Exact"
	PathMatchPrefix PathMatchType = "PathPrefix"
)

// RouteRule represents a compiled HTTP routing rule from an HTTPRoute resource.
type RouteRule struct {
	Hostnames []string
	MatchType PathMatchType
	Path      string
	Backend   string // e.g. "http://my-svc.default.svc.cluster.local:8080"
	proxy     *httputil.ReverseProxy
}

// Router swaps HTTP routing tables independently of the SSH listener.
type Router struct {
	mu    sync.RWMutex
	rules []RouteRule
}

// NewRouter creates an empty Router.
func NewRouter() *Router {
	return &Router{}
}

// Update compiles and atomically swaps the active routing table.
// Rules are sorted with Exact matches first, then longest PathPrefix first,
// following Gateway API precedence semantics.
func (r *Router) Update(rules []RouteRule) error {
	compiled := make([]RouteRule, 0, len(rules))
	for _, rule := range rules {
		target, err := url.Parse(rule.Backend)
		if err != nil {
			return fmt.Errorf("invalid backend URL %q: %w", rule.Backend, err)
		}
		if rule.Path == "" {
			rule.Path = "/"
		}
		if rule.MatchType == "" {
			rule.MatchType = PathMatchPrefix
		}

		rp := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.SetXForwarded()
				// Preserve the original Host header for virtual-hosted backends.
				pr.Out.Host = pr.In.Host
			},
			ErrorHandler: func(w http.ResponseWriter, req *http.Request, proxyErr error) {
				http.Error(w, fmt.Sprintf("upstream unavailable: %v", proxyErr), http.StatusBadGateway)
			},
		}

		normHosts := make([]string, 0, len(rule.Hostnames))
		for _, h := range rule.Hostnames {
			h = strings.ToLower(strings.TrimSpace(h))
			if h != "" {
				normHosts = append(normHosts, h)
			}
		}

		rule.Hostnames = normHosts
		rule.proxy = rp
		compiled = append(compiled, rule)
	}

	sort.SliceStable(compiled, func(i, j int) bool {
		if compiled[i].MatchType != compiled[j].MatchType {
			return compiled[i].MatchType == PathMatchExact
		}
		if len(compiled[i].Path) != len(compiled[j].Path) {
			return len(compiled[i].Path) > len(compiled[j].Path)
		}
		// Prefer rules with explicit hostnames over catch-all rules.
		return len(compiled[i].Hostnames) > len(compiled[j].Hostnames)
	})

	r.mu.Lock()
	r.rules = compiled
	r.mu.Unlock()
	return nil
}

// ServeHTTP matches incoming requests against the compiled Gateway API routes
// and proxies them to the target Kubernetes Service.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	rules := r.rules
	r.mu.RUnlock()

	host := stripPort(strings.ToLower(req.Host))
	reqPath := req.URL.Path

	for i := range rules {
		if !matchesHost(rules[i].Hostnames, host) {
			continue
		}
		if !matchesPath(rules[i].MatchType, rules[i].Path, reqPath) {
			continue
		}
		rules[i].proxy.ServeHTTP(w, req)
		return
	}

	http.NotFound(w, req)
}

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func matchesHost(patterns []string, host string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if p == "*" || p == host {
			return true
		}
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
		}
	}
	return false
}

func matchesPath(matchType PathMatchType, rulePath, reqPath string) bool {
	switch matchType {
	case PathMatchExact:
		return reqPath == rulePath
	case PathMatchPrefix:
		if rulePath == "/" {
			return true
		}
		if reqPath == rulePath {
			return true
		}
		prefix := strings.TrimRight(rulePath, "/") + "/"
		return strings.HasPrefix(reqPath, prefix)
	default:
		return false
	}
}
