# ssh-tunnel-gateway

A lightweight [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) implementation in Go that exposes Kubernetes `Service` workloads to the public internet over **outbound SSH reverse tunnels**, with first-class support for **TLS tunneling mode** (where the SaaS tunnel provider routes by SNI without decrypting traffic and TLS is terminated internally inside your cluster).

## Architecture (Inspired by `caddyserver/gateway`)

Modeled after [caddyserver/gateway](https://github.com/caddyserver/gateway)'s clean `controller-runtime` reconciliation loop and zero-downtime hot reload:

1. **Control Plane (`internal/controller/`)**: Watches standard Gateway API CRDs (`GatewayClass`, `Gateway`, `HTTPRoute`) and Kubernetes TLS `Secret`s (`kubernetes.io/tls`)—no custom CRDs required.
2. **SSH Reverse Tunnel Manager (`internal/tunnel/`)**: Opens resilient outbound SSH connections (`golang.org/x/crypto/ssh`) with keepalives and exponential backoff, requesting remote TCP forwarding (`ssh.Client.Listen`).
3. **Internal TLS Termination + Hot-Reload Router (`internal/proxy/`)**:
   - In **TLS Tunneling Mode** (`ssh-tunnel.io/tls-tunnel-mode: "true"` or an `HTTPS` listener with `tls.mode: Terminate`), the SSH provider forwards raw encrypted TLS bytes over the tunnel. The controller wraps the SSH-forwarded `net.Listener` directly with `tls.NewListener(remoteLn, tlsStore.TLSConfig())` so TLS terminates **inside your cluster** using certificates from `Gateway.spec.listeners[].tls.certificateRefs`.
   - Updating `HTTPRoute` rules or rotating a TLS `Secret` hot-reloads the in-memory router and SNI certificate map without tearing down active SSH tunnels.

## Supported SSH Tunnel Providers

| Provider | Default SSH Server | TLS Tunneling Mode Mechanism |
| :--- | :--- | :--- |
| **Pinggy** ([TLS Tunnels docs](https://pinggy.io/docs/tls_tunnels/)) | `free.pinggy.io:443` | Connects with `tls` or `<token>+tls` username and `-R 0:0`; Pinggy routes port 443 by SNI without decrypting. |
| **Pico.sh (`tuns.sh`)** ([tuns docs](https://pico.sh/tuns)) | `tuns.sh:22` | Requests remote bind `<hostname>:443` and executes `sni-proxy=true` on the SSH session; `tuns.sh` forwards raw TLS by SNI. |
| **localhost.run** | `localhost.run:22` | Requests remote bind `<hostname>:443` (custom domain TLS passthrough) or `0.0.0.0:80` for HTTP mode; override session flags via `ssh-tunnel.io/session-command`. |
| **Plain OpenSSH** | Custom `host:22` | Requests remote bind `0.0.0.0:443` (requires `AllowTcpForwarding yes` and `GatewayPorts yes` in `sshd_config`). |

## Related Projects

- **[dguerri/k8s-ssh-gateway-controller](https://github.com/dguerri/k8s-ssh-gateway-controller)**: Existing Go Gateway API controller for SSH tunnels (`tuns.sh`, Serveo, OpenSSH) supporting `TLSRoute` passthrough where backend pods terminate TLS.
- **[ngrok Kubernetes Operator](https://ngrok.com/docs/gateway/k8s/guides/using-gwapi)**: Official Gateway API operator for ngrok with [TLS routing / passthrough](https://ngrok.com/docs/gateway/k8s/guides/how-to/tls-routing) (uses ngrok's native agent protocol rather than raw SSH).

## Quickstart

```bash
# 1. Resolve go.sum and run unit tests
go mod tidy
go test -v -race ./...

# 2. Install standard Kubernetes Gateway API CRDs
make install-crds

# 3. Build image and deploy the controller
make docker-build IMAGE=your-registry/ssh-tunnel-gateway:latest
make deploy

# 4. Apply an example Gateway + HTTPRoute (Pinggy TLS tunneling mode)
kubectl create secret tls demo-tls-cert --cert=tls.crt --key=tls.key
kubectl apply -f example/pinggy-tls-tunnel.yaml

# 5. Inspect the discovered public tunnel address
kubectl get gateway pinggy-tls-gateway
```

## Configuration

Global defaults are configured via environment variables on the controller `Deployment` (`k8s/deployment.yaml`) and can be overridden per `Gateway` with annotations:

- `ssh-tunnel.io/provider`: `pinggy`, `pico`, `localhostrun`, or `openssh`
- `ssh-tunnel.io/ssh-server`: Remote `host:port` (e.g., `a.pinggy.io:443`, `tuns.sh:22`)
- `ssh-tunnel.io/ssh-username`: SSH username or Pinggy token (`<token>+tls`)
- `ssh-tunnel.io/tls-tunnel-mode`: `"true"` (internal TLS termination) or `"false"` (provider-terminated HTTP)
- `ssh-tunnel.io/remote-bind-address`: Explicit override for `ssh.Client.Listen("tcp", addr)`
- `ssh-tunnel.io/session-command`: Optional SSH session command (defaults to `sni-proxy=true` for `pico` in TLS mode)
