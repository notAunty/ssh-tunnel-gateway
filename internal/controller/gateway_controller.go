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

	"github.com/example/ssh-tunnel-gateway/internal/config"
	"github.com/example/ssh-tunnel-gateway/internal/proxy"
	"github.com/example/ssh-tunnel-gateway/internal/tunnel"
)

// GatewayReconciler watches Gateways, HTTPRoutes, and TLS Secrets, compiling
// them into hot-reloaded reverse proxy routes, internal TLS certificates, and
// resilient outbound SSH reverse tunnels (modeled on caddyserver/gateway).
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

	// Verify this Gateway belongs to our GatewayClass.
	var gc gatewayv1.GatewayClass
	if err := r.Get(ctx, types.NamespacedName{Name: string(gw.Spec.GatewayClassName)}, &gc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if string(gc.Spec.ControllerName) != r.Config.ControllerName {
		return ctrl.Result{}, nil
	}

	// 1. Resolve SSH tunnel parameters from global defaults + Gateway annotations.
	spec := r.buildTunnelSpec(&gw)

	// 2. Load TLS certificates from Gateway.spec.listeners[].tls.certificateRefs
	//    so TLS can be terminated internally when TLS tunneling mode is enabled.
	certs, certErr := r.loadGatewayCerts(ctx, &gw)
	if certErr != nil {
		logger.Error(certErr, "failed to load Gateway TLS certificates", "gateway", req.NamespacedName)
	}

	// 3. Collect all HTTPRoutes referencing this Gateway.
	routes, attachedCount, err := r.collectHTTPRoutes(ctx, &gw)
	if err != nil {
		return ctrl.Result{}, err
	}

	// 4. Reconcile the SSH reverse tunnel and hot-reload routes + TLS certs.
	assignedHost, connected, err := r.TunnelManager.ReconcileGateway(context.Background(), spec, routes, certs)
	if err != nil {
		return ctrl.Result{}, err
	}

	// 5. Update Gateway.status (Accepted, Programmed, Addresses, ListenerStatus).
	r.updateGatewayStatus(&gw, assignedHost, connected, attachedCount, certErr)
	if err := r.Status().Update(ctx, &gw); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *GatewayReconciler) buildTunnelSpec(gw *gatewayv1.Gateway) tunnel.TunnelSpec {
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

	// Enable TLS tunneling mode if annotated explicitly, or if any listener uses
	// HTTPS with tls.mode == Terminate (the default for HTTPS listeners).
	tlsTunnelMode := r.Config.TLSTunnelMode
	if v := strings.TrimSpace(ann[config.AnnotationTLSTunnelMode]); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			tlsTunnelMode = parsed
		}
	} else {
		for _, l := range gw.Spec.Listeners {
			if l.Protocol == gatewayv1.HTTPSProtocolType {
				if l.TLS == nil || l.TLS.Mode == nil || *l.TLS.Mode == gatewayv1.TLSModeTerminate {
					tlsTunnelMode = true
					break
				}
			}
		}
	}

	var hostname string
	for _, l := range gw.Spec.Listeners {
		if l.Hostname != nil && *l.Hostname != "" {
			hostname = string(*l.Hostname)
			break
		}
	}

	sessionCmd := r.Config.SessionCommand
	if v := strings.TrimSpace(ann[config.AnnotationSessionCommand]); v != "" {
		sessionCmd = v
	}

	return tunnel.TunnelSpec{
		GatewayKey:     types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}.String(),
		Provider:       provider,
		SSHServer:      server,
		SSHUsername:    username,
		Hostname:       hostname,
		TLSTunnelMode:  tlsTunnelMode,
		RemoteBindAddr: strings.TrimSpace(ann[config.AnnotationRemoteBindAddress]),
		SessionCommand: sessionCmd,
	}
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
		if !routeTargetsGateway(route, gw) {
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
			// Naive selection: pick the first Service backendRef.
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

		// Best-effort status update on the HTTPRoute.
		r.updateHTTPRouteStatus(ctx, route, gw)
	}

	return rules, attached, nil
}

func routeTargetsGateway(route *gatewayv1.HTTPRoute, gw *gatewayv1.Gateway) bool {
	for _, ref := range route.Spec.ParentRefs {
		if ref.Kind != nil && *ref.Kind != "Gateway" {
			continue
		}
		refNS := route.Namespace
		if ref.Namespace != nil && *ref.Namespace != "" {
			refNS = string(*ref.Namespace)
		}
		if refNS == gw.Namespace && string(ref.Name) == gw.Name {
			return true
		}
	}
	return false
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
	assignedHost string,
	connected bool,
	attachedRoutes int32,
	certErr error,
) {
	meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.GatewayConditionAccepted),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: gw.Generation,
		Reason:             string(gatewayv1.GatewayReasonAccepted),
		Message:            "Gateway accepted by ssh-tunnel-gateway",
	})

	progStatus := metav1.ConditionTrue
	progReason := string(gatewayv1.GatewayReasonProgrammed)
	progMsg := "SSH reverse tunnel active and serving traffic"
	if !connected {
		progStatus = metav1.ConditionFalse
		progReason = string(gatewayv1.GatewayReasonPending)
		progMsg = "Establishing SSH reverse tunnel"
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

	if assignedHost != "" {
		addrType := gatewayv1.HostnameAddressType
		gw.Status.Addresses = []gatewayv1.GatewayStatusAddress{
			{
				Type:  &addrType,
				Value: assignedHost,
			},
		}
	}

	listeners := make([]gatewayv1.ListenerStatus, 0, len(gw.Spec.Listeners))
	for _, l := range gw.Spec.Listeners {
		listeners = append(listeners, gatewayv1.ListenerStatus{
			Name:           l.Name,
			AttachedRoutes: attachedRoutes,
			SupportedKinds: []gatewayv1.RouteGroupKind{
				{Kind: "HTTPRoute"},
			},
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
	// Reconcile the referenced Gateway whenever an HTTPRoute changes.
	mapRouteToGateways := func(ctx context.Context, obj client.Object) []reconcile.Request {
		route, ok := obj.(*gatewayv1.HTTPRoute)
		if !ok {
			return nil
		}
		var reqs []reconcile.Request
		for _, ref := range route.Spec.ParentRefs {
			if ref.Kind != nil && *ref.Kind != "Gateway" {
				continue
			}
			ns := route.Namespace
			if ref.Namespace != nil && *ref.Namespace != "" {
				ns = string(*ref.Namespace)
			}
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: ns, Name: string(ref.Name)},
			})
		}
		return reqs
	}

	// Reconcile any Gateway that references a mutated TLS Secret.
	mapSecretToGateways := func(ctx context.Context, obj client.Object) []reconcile.Request {
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
		Watches(&gatewayv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(mapRouteToGateways)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(mapSecretToGateways)).
		Complete(r)
}
