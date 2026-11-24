package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/example/ssh-tunnel-gateway/internal/config"
	"github.com/example/ssh-tunnel-gateway/internal/proxy"
	"github.com/example/ssh-tunnel-gateway/internal/tunnel"
)

// GatewayReconciler watches Gateways, HTTPRoutes, TLSRoutes, TCPRoutes, and
// TLS Secrets, compiling them into hot-reloaded multi-mode SSH reverse tunnels:
//   - HTTP  (HTTPRoute)
//   - HTTPS (HTTPRoute + internal TLS termination via TLS tunneling mode)
//   - TLS   (TLSRoute L4 SNI passthrough, shareable on port 443 with HTTPS)
//   - TCP   (TCPRoute raw L4 TCP forwarding)
type GatewayReconciler struct {
	client.Client
	Config        config.Config
	TunnelManager *tunnel.Manager
}

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var gw gatewayv1.Gateway
	if err := r.Get(ctx, req.NamespacedName, &gw); err != nil {
		if client.IgnoreNotFound(err) == nil {
			r.TunnelManager.RemoveGateway(req.NamespacedName.String())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	var gc gatewayv1.GatewayClass
	if err := r.Get(ctx, types.NamespacedName{Name: string(gw.Spec.GatewayClassName)}, &gc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if string(gc.Spec.ControllerName) != r.Config.ControllerName {
		return ctrl.Result{}, nil
	}

	// 1. Load TLS Secrets referenced by Gateway listeners.
	certs, certErr := r.loadGatewayCerts(ctx, &gw)
	if certErr != nil {
		logger.Error(certErr, "failed to load Gateway TLS certificates", "gateway", req.NamespacedName)
	}

	// 2. Collect HTTPRoutes, TLSRoutes, and TCPRoutes attached to this Gateway.
	httpRules, httpCount, err := r.collectHTTPRoutes(ctx, &gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	tlsRules, tlsCount, err := r.collectTLSRoutes(ctx, &gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	tcpBackendsBySection, tcpCount, err := r.collectTCPRoutes(ctx, &gw)
	if err != nil {
		return ctrl.Result{}, err
	}

	// 3. Group listeners into desired SSH tunnels.
	//    HTTPS and TLS listeners sharing the same port (e.g. wildcard *.example.com:443)
	//    share a single SNI-multiplexed TLS tunnel so internal HTTPS termination and
	//    L4 TLS passthrough coexist seamlessly on one SSH session.
	desired := r.buildDesiredTunnels(&gw, httpRules, tlsRules, certs, tcpBackendsBySection)

	// 4. Reconcile tunnels and hot-reload data plane state.
	gwKey := req.NamespacedName.String()
	statuses, err := r.TunnelManager.ReconcileGatewayTunnels(context.Background(), gwKey, desired)
	if err != nil {
		return ctrl.Result{}, err
	}

	// 5. Update Gateway.status.
	r.updateGatewayStatus(&gw, statuses, httpCount, tlsCount, tcpCount, certErr)
	if err := r.Status().Update(ctx, &gw); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *GatewayReconciler) buildDesiredTunnels(
	gw *gatewayv1.Gateway,
	httpRules []proxy.RouteRule,
	tlsRules []proxy.TLSPassthroughRule,
	certs []proxy.CertEntry,
	tcpBackends map[string]string,
) []tunnel.TunnelConfig {
	ann := gw.Annotations
	if ann == nil {
		ann = map[string]string{}
	}

	provider := r.Config.Provider
	if v := strings.TrimSpace(ann[config.AnnotationProvider]); v != "" {
		provider = config.ProviderType(strings.ToLower(v))
	}
	server := r.Config.SSHServer
	if v := strings.TrimSpace(ann[config.AnnotationSSHServer]); v != "" {
		server = v
	}
	username := r.Config.SSHUsername
	if v := strings.TrimSpace(ann[config.AnnotationSSHUsername]); v != "" {
		username = v
	}
	sessionCmd := r.Config.SessionCommand
	if v := strings.TrimSpace(ann[config.AnnotationSessionCommand]); v != "" {
		sessionCmd = v
	}
	explicitTLSMode := r.Config.TLSTunnelMode
	hasExplicitTLS := false
	if v := strings.TrimSpace(ann[config.AnnotationTLSTunnelMode]); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			explicitTLSMode = parsed
			hasExplicitTLS = true
		}
	}

	gwKey := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}.String()

	// Deduplicate shared tunnels by (modeGroup, port).
	// HTTPS and TLS on the same port share a single TLS-multiplexed tunnel.
	byKey := make(map[string]tunnel.TunnelConfig)
	var order []string

	for _, l := range gw.Spec.Listeners {
		var hostname string
		if l.Hostname != nil {
			hostname = string(*l.Hostname)
		}

		var mode tunnel.TunnelMode
		var tlsTunnel bool
		var keyGroup string

		switch l.Protocol {
		case gatewayv1.HTTPProtocolType:
			mode = tunnel.ModeHTTP
			tlsTunnel = false
			keyGroup = "http"
		case gatewayv1.HTTPSProtocolType:
			mode = tunnel.ModeHTTPS
			tlsTunnel = true
			if hasExplicitTLS {
				tlsTunnel = explicitTLSMode
			}
			keyGroup = "tls"
		case gatewayv1.TLSProtocolType:
			mode = tunnel.ModeTLS
			tlsTunnel = true
			keyGroup = "tls"
		case gatewayv1.TCPProtocolType:
			mode = tunnel.ModeTCP
			tlsTunnel = false
			keyGroup = fmt.Sprintf("tcp-%s", l.Name)
		default:
			continue
		}

		tKey := fmt.Sprintf("%s/%s/%d", gwKey, keyGroup, l.Port)
		if existing, exists := byKey[tKey]; exists {
			// Prefer wildcard hostname (e.g. *.example.com) if a shared port-443
			// tunnel has both exact and wildcard listeners.
			if strings.HasPrefix(hostname, "*.") && !strings.HasPrefix(existing.Spec.Hostname, "*.") {
				existing.Spec.Hostname = hostname
			}
			byKey[tKey] = existing
			continue
		}

		tc := tunnel.TunnelConfig{
			Spec: tunnel.TunnelSpec{
				TunnelKey:      tKey,
				GatewayKey:     gwKey,
				Mode:           mode,
				Port:           int32(l.Port),
				Provider:       provider,
				SSHServer:      server,
				SSHUsername:    username,
				Hostname:       hostname,
				TLSTunnelMode:  tlsTunnel,
				RemoteBindAddr: strings.TrimSpace(ann[config.AnnotationRemoteBindAddress]),
				SessionCommand: sessionCmd,
			},
		}

		switch mode {
		case tunnel.ModeHTTP:
			tc.HTTPRoutes = httpRules
		case tunnel.ModeHTTPS, tunnel.ModeTLS:
			tc.HTTPRoutes = httpRules
			tc.TLSPassthrough = tlsRules
			tc.TLSCerts = certs
		case tunnel.ModeTCP:
			if b, ok := tcpBackends[string(l.Name)]; ok {
				tc.TCPBackend = b
			} else if b, ok := tcpBackends[""]; ok {
				tc.TCPBackend = b
			}
		}

		byKey[tKey] = tc
		order = append(order, tKey)
	}

	desired := make([]tunnel.TunnelConfig, 0, len(order))
	for _, k := range order {
		desired = append(desired, byKey[k])
	}
	return desired
}

func (r *GatewayReconciler) loadGatewayCerts(ctx context.Context, gw *gatewayv1.Gateway) ([]proxy.CertEntry, error) {
	var entries []proxy.CertEntry
	for _, listener := range gw.Spec.Listeners {
		if listener.TLS == nil {
			continue
		}
		for _, ref := range listener.TLS.CertificateRefs {
			if ref.Kind != nil && *ref.Kind != "Secret" {
				continue
			}
			ns := gw.Namespace
			if ref.Namespace != nil && *ref.Namespace != "" {
				ns = string(*ref.Namespace)
			}
			var secret corev1.Secret
			if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: string(ref.Name)}, &secret); err != nil {
				return entries, fmt.Errorf("get TLS secret %s/%s: %w", ns, ref.Name, err)
			}
			certPEM := secret.Data[corev1.TLSCertKey]
			keyPEM := secret.Data[corev1.TLSPrivateKeyKey]
			if len(certPEM) == 0 || len(keyPEM) == 0 {
				return entries, fmt.Errorf("secret %s/%s missing %q or %q", ns, ref.Name, corev1.TLSCertKey, corev1.TLSPrivateKeyKey)
			}

			var hosts []string
			if listener.Hostname != nil && *listener.Hostname != "" {
				hosts = append(hosts, string(*listener.Hostname))
			}
			entries = append(entries, proxy.CertEntry{
				Hostnames: hosts,
				CertPEM:   certPEM,
				KeyPEM:    keyPEM,
			})
		}
	}
	return entries, nil
}

func (r *GatewayReconciler) collectHTTPRoutes(ctx context.Context, gw *gatewayv1.Gateway) ([]proxy.RouteRule, int32, error) {
	var list gatewayv1.HTTPRouteList
	if err := r.List(ctx, &list); err != nil {
		return nil, 0, fmt.Errorf("list HTTPRoutes: %w", err)
	}

	var rules []proxy.RouteRule
	var attached int32

	for i := range list.Items {
		route := &list.Items[i]
		if !parentRefsTargetGateway(route.Spec.ParentRefs, route.Namespace, gw) {
			continue
		}
		attached++

		hostnames := make([]string, 0, len(route.Spec.Hostnames))
		for _, h := range route.Spec.Hostnames {
			hostnames = append(hostnames, string(h))
		}

		for _, rule := range route.Spec.Rules {
			if len(rule.BackendRefs) == 0 {
				continue
			}
			bref := rule.BackendRefs[0]
			svcNS := route.Namespace
			if bref.Namespace != nil && *bref.Namespace != "" {
				svcNS = string(*bref.Namespace)
			}
			port := int32(80)
			if bref.Port != nil {
				port = int32(*bref.Port)
			}
			backendURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", bref.Name, svcNS, port)

			if len(rule.Matches) == 0 {
				rules = append(rules, proxy.RouteRule{
					Hostnames: hostnames,
					MatchType: proxy.PathMatchPrefix,
					Path:      "/",
					Backend:   backendURL,
				})
				continue
			}

			for _, m := range rule.Matches {
				matchType := proxy.PathMatchPrefix
				pathVal := "/"
				if m.Path != nil {
					if m.Path.Type != nil && *m.Path.Type == gatewayv1.PathMatchExact {
						matchType = proxy.PathMatchExact
					}
					if m.Path.Value != nil && *m.Path.Value != "" {
						pathVal = *m.Path.Value
					}
				}
				rules = append(rules, proxy.RouteRule{
					Hostnames: hostnames,
					MatchType: matchType,
					Path:      pathVal,
					Backend:   backendURL,
				})
			}
		}

		r.updateHTTPRouteStatus(ctx, route, gw)
	}

	return rules, attached, nil
}

func (r *GatewayReconciler) collectTLSRoutes(ctx context.Context, gw *gatewayv1.Gateway) ([]proxy.TLSPassthroughRule, int32, error) {
	var list gatewayv1alpha2.TLSRouteList
	if err := r.List(ctx, &list); err != nil {
		// Gracefully allow clusters where experimental TLSRoute CRD is not installed.
		if meta.IsNoMatchError(err) {
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("list TLSRoutes: %w", err)
	}

	var rules []proxy.TLSPassthroughRule
	var attached int32

	for i := range list.Items {
		route := &list.Items[i]
		if !parentRefsTargetGateway(route.Spec.ParentRefs, route.Namespace, gw) {
			continue
		}
		attached++

		hostnames := make([]string, 0, len(route.Spec.Hostnames))
		for _, h := range route.Spec.Hostnames {
			hostnames = append(hostnames, string(h))
		}

		for _, rule := range route.Spec.Rules {
			if len(rule.BackendRefs) == 0 {
				continue
			}
			bref := rule.BackendRefs[0]
			svcNS := route.Namespace
			if bref.Namespace != nil && *bref.Namespace != "" {
				svcNS = string(*bref.Namespace)
			}
			port := int32(443)
			if bref.Port != nil {
				port = int32(*bref.Port)
			}
			rules = append(rules, proxy.TLSPassthroughRule{
				Hostnames: hostnames,
				Backend:   fmt.Sprintf("%s.%s.svc.cluster.local:%d", bref.Name, svcNS, port),
			})
		}
	}

	return rules, attached, nil
}

func (r *GatewayReconciler) collectTCPRoutes(ctx context.Context, gw *gatewayv1.Gateway) (map[string]string, int32, error) {
	var list gatewayv1alpha2.TCPRouteList
	if err := r.List(ctx, &list); err != nil {
		// Gracefully allow clusters where experimental TCPRoute CRD is not installed.
		if meta.IsNoMatchError(err) {
			return map[string]string{}, 0, nil
		}
		return nil, 0, fmt.Errorf("list TCPRoutes: %w", err)
	}

	backends := make(map[string]string)
	var attached int32

	for i := range list.Items {
		route := &list.Items[i]
		matchedSections := matchingSectionsForGateway(route.Spec.ParentRefs, route.Namespace, gw)
		if len(matchedSections) == 0 {
			continue
		}
		attached++

		for _, rule := range route.Spec.Rules {
			if len(rule.BackendRefs) == 0 {
				continue
			}
			bref := rule.BackendRefs[0]
			svcNS := route.Namespace
			if bref.Namespace != nil && *bref.Namespace != "" {
				svcNS = string(*bref.Namespace)
			}
			port := int32(80)
			if bref.Port != nil {
				port = int32(*bref.Port)
			}
			addr := fmt.Sprintf("%s.%s.svc.cluster.local:%d", bref.Name, svcNS, port)
			for _, sec := range matchedSections {
				backends[sec] = addr
			}
		}
	}

	return backends, attached, nil
}

func parentRefsTargetGateway(refs []gatewayv1.ParentReference, routeNS string, gw *gatewayv1.Gateway) bool {
	return len(matchingSectionsForGateway(refs, routeNS, gw)) > 0
}

func matchingSectionsForGateway(refs []gatewayv1.ParentReference, routeNS string, gw *gatewayv1.Gateway) []string {
	var sections []string
	for _, ref := range refs {
		if ref.Kind != nil && *ref.Kind != "Gateway" {
			continue
		}
		refNS := routeNS
		if ref.Namespace != nil && *ref.Namespace != "" {
			refNS = string(*ref.Namespace)
		}
		if refNS == gw.Namespace && string(ref.Name) == gw.Name {
			sec := ""
			if ref.SectionName != nil {
				sec = string(*ref.SectionName)
			}
			sections = append(sections, sec)
		}
	}
	return sections
}

func (r *GatewayReconciler) updateHTTPRouteStatus(ctx context.Context, route *gatewayv1.HTTPRoute, gw *gatewayv1.Gateway) {
	ns := gatewayv1.Namespace(gw.Namespace)
	parentStatus := gatewayv1.RouteParentStatus{
		ParentRef: gatewayv1.ParentReference{
			Namespace: &ns,
			Name:      gatewayv1.ObjectName(gw.Name),
		},
		ControllerName: gatewayv1.GatewayController(r.Config.ControllerName),
		Conditions: []metav1.Condition{
			{
				Type:               string(gatewayv1.RouteConditionAccepted),
				Status:             metav1.ConditionTrue,
				ObservedGeneration: route.Generation,
				Reason:             string(gatewayv1.RouteReasonAccepted),
				Message:            "HTTPRoute accepted by ssh-tunnel-gateway",
				LastTransitionTime: metav1.Now(),
			},
			{
				Type:               string(gatewayv1.RouteConditionResolvedRefs),
				Status:             metav1.ConditionTrue,
				ObservedGeneration: route.Generation,
				Reason:             string(gatewayv1.RouteReasonResolvedRefs),
				Message:            "Backend Service references resolved",
				LastTransitionTime: metav1.Now(),
			},
		},
	}

	route.Status.Parents = []gatewayv1.RouteParentStatus{parentStatus}
	_ = r.Status().Update(ctx, route)
}

func (r *GatewayReconciler) updateGatewayStatus(
	gw *gatewayv1.Gateway,
	statuses []tunnel.TunnelStatus,
	httpCount, tlsCount, tcpCount int32,
	certErr error,
) {
	meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.GatewayConditionAccepted),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: gw.Generation,
		Reason:             string(gatewayv1.GatewayReasonAccepted),
		Message:            "Gateway accepted by ssh-tunnel-gateway",
	})

	allConnected := len(statuses) > 0
	var addrs []gatewayv1.GatewayStatusAddress
	seenAddr := make(map[string]struct{})
	addrType := gatewayv1.HostnameAddressType

	for _, st := range statuses {
		if !st.Connected {
			allConnected = false
		}
		if st.AssignedHost != "" {
			if _, dup := seenAddr[st.AssignedHost]; !dup {
				seenAddr[st.AssignedHost] = struct{}{}
				addrs = append(addrs, gatewayv1.GatewayStatusAddress{
					Type:  &addrType,
					Value: st.AssignedHost,
				})
			}
		}
	}

	progStatus := metav1.ConditionTrue
	progReason := string(gatewayv1.GatewayReasonProgrammed)
	progMsg := "All SSH reverse tunnels active and serving traffic"
	if !allConnected {
		progStatus = metav1.ConditionFalse
		progReason = string(gatewayv1.GatewayReasonPending)
		progMsg = "Establishing SSH reverse tunnel(s)"
	}
	if certErr != nil {
		progStatus = metav1.ConditionFalse
		progReason = string(gatewayv1.GatewayReasonInvalid)
		progMsg = fmt.Sprintf("TLS certificate error: %v", certErr)
	}

	meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.GatewayConditionProgrammed),
		Status:             progStatus,
		ObservedGeneration: gw.Generation,
		Reason:             progReason,
		Message:            progMsg,
	})

	if len(addrs) > 0 {
		gw.Status.Addresses = addrs
	}

	listeners := make([]gatewayv1.ListenerStatus, 0, len(gw.Spec.Listeners))
	for _, l := range gw.Spec.Listeners {
		var attached int32
		var kind gatewayv1.Kind
		switch l.Protocol {
		case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
			attached = httpCount
			kind = "HTTPRoute"
		case gatewayv1.TLSProtocolType:
			attached = tlsCount
			kind = "TLSRoute"
		case gatewayv1.TCPProtocolType:
			attached = tcpCount
			kind = "TCPRoute"
		default:
			kind = "HTTPRoute"
		}

		listeners = append(listeners, gatewayv1.ListenerStatus{
			Name:           l.Name,
			AttachedRoutes: attached,
			SupportedKinds: []gatewayv1.RouteGroupKind{{Kind: kind}},
			Conditions: []metav1.Condition{
				{
					Type:               string(gatewayv1.ListenerConditionAccepted),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: gw.Generation,
					Reason:             string(gatewayv1.ListenerReasonAccepted),
					LastTransitionTime: metav1.Now(),
				},
				{
					Type:               string(gatewayv1.ListenerConditionProgrammed),
					Status:             progStatus,
					ObservedGeneration: gw.Generation,
					Reason:             progReason,
					LastTransitionTime: metav1.Now(),
				},
			},
		})
	}
	gw.Status.Listeners = listeners
}

func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mapParentRefs := func(refs []gatewayv1.ParentReference, routeNS string) []reconcile.Request {
		var reqs []reconcile.Request
		for _, ref := range refs {
			if ref.Kind != nil && *ref.Kind != "Gateway" {
				continue
			}
			ns := routeNS
			if ref.Namespace != nil && *ref.Namespace != "" {
				ns = string(*ref.Namespace)
			}
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: ns, Name: string(ref.Name)},
			})
		}
		return reqs
	}

	mapHTTPRoute := func(_ context.Context, obj client.Object) []reconcile.Request {
		route, ok := obj.(*gatewayv1.HTTPRoute)
		if !ok {
			return nil
		}
		return mapParentRefs(route.Spec.ParentRefs, route.Namespace)
	}

	mapTLSRoute := func(_ context.Context, obj client.Object) []reconcile.Request {
		route, ok := obj.(*gatewayv1alpha2.TLSRoute)
		if !ok {
			return nil
		}
		return mapParentRefs(route.Spec.ParentRefs, route.Namespace)
	}

	mapTCPRoute := func(_ context.Context, obj client.Object) []reconcile.Request {
		route, ok := obj.(*gatewayv1alpha2.TCPRoute)
		if !ok {
			return nil
		}
		return mapParentRefs(route.Spec.ParentRefs, route.Namespace)
	}

	mapSecret := func(ctx context.Context, obj client.Object) []reconcile.Request {
		var gwList gatewayv1.GatewayList
		if err := r.List(ctx, &gwList); err != nil {
			return nil
		}
		var reqs []reconcile.Request
		for i := range gwList.Items {
			gw := &gwList.Items[i]
			for _, l := range gw.Spec.Listeners {
				if l.TLS == nil {
					continue
				}
				for _, ref := range l.TLS.CertificateRefs {
					ns := gw.Namespace
					if ref.Namespace != nil && *ref.Namespace != "" {
						ns = string(*ref.Namespace)
					}
					if ns == obj.GetNamespace() && string(ref.Name) == obj.GetName() {
						reqs = append(reqs, reconcile.Request{
							NamespacedName: types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name},
						})
					}
				}
			}
		}
		return reqs
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}).
		Watches(&gatewayv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(mapHTTPRoute)).
		Watches(&gatewayv1alpha2.TLSRoute{}, handler.EnqueueRequestsFromMapFunc(mapTLSRoute)).
		Watches(&gatewayv1alpha2.TCPRoute{}, handler.EnqueueRequestsFromMapFunc(mapTCPRoute)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(mapSecret)).
		Complete(r)
}
