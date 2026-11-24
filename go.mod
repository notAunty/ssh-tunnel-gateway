module github.com/example/ssh-tunnel-gateway

go 1.24.0

require (
	github.com/go-logr/logr v1.4.2
	golang.org/x/crypto v0.36.0
	k8s.io/api v0.32.3
	k8s.io/apimachinery v0.32.3
	k8s.io/client-go v0.32.3
	sigs.k8s.io/controller-runtime v0.20.4
	sigs.k8s.io/gateway-api v1.2.1
)
