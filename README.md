# ssh-tunnel-gateway

A lightweight [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) implementation in Go that exposes Kubernetes `Service` workloads over **outbound SSH reverse tunnels**, supporting **HTTP, HTTPS (internal TLS termination), TLS (L4 SNI passthrough), and TCP** modes—including **wildcard subdomain tunnels** (`*.example.com`).

## Supported Protocol Modes

| Listener Protocol | Gateway API Route | Behavior |
| :--- | :--- | :--- |
| **`HTTP`** | `HTTPRoute` (`v1`) | Serves plaintext HTTP over the SSH tunnel (routed by exact or wildcard `Host` + `PathPrefix`/`Exact`). |
| **`HTTPS`** (`tls.mode: Terminate`) | `HTTPRoute` (`v1`) | **TLS Tunneling Mode**: SaaS SSH provider forwards raw encrypted TLS by SNI without decrypting; this controller terminates TLS internally using `Gateway` `Secret` certs (including wildcard `*.example.com` SANs) and routes HTTP to backend Services. |
| **`TLS`** (`tls.mode: Passthrough`) | `TLSRoute` (`v1alpha2`) | Peeks the TLS `ClientHello` SNI header non-destructively and splices raw encrypted TLS bytes straight to the backend pod (no backend certs held by the controller). Can **share port 443** with `HTTPS` on a single wildcard tunnel via the SNI demultiplexer (`internal/proxy/sni.go`). |
| **`TCP`** | `TCPRoute` (`v1alpha2`) | Forwards raw L4 TCP streams over the SSH tunnel (e.g., Postgres, Redis, SSH) to the target `Service:Port`. |

## Architecture (Inspired by `caddyserver/gateway`)

Modeled after [caddyserver/gateway](https://github.com/caddyserver/gateway)'s `controller-runtime` reconciliation loop and zero-downtime hot reload:

1. **Control Plane (`internal/controller/`)**: Watches standard Gateway API CRDs (`GatewayClass`, `Gateway`, `HTTPRoute`, `TLSRoute`, `TCPRoute`) and Kubernetes TLS `Secret`s (`kubernetes.io/tls`).
2. **Multi-Mode SSH Tunnel Manager (`internal/tunnel/`)**: Supervises resilient outbound `golang.org/x/crypto/ssh` tunnels per listener group with keepalives and exponential backoff. `HTTPS` and `TLS` listeners on the same port (e.g., wildcard `*.example.com:443`) share a single SNI-multiplexed SSH tunnel.
3. **SNI Demultiplexer + Internal TLS Terminator (`internal/proxy/`)**: Peeks `ClientHello` SNI on every incoming TLS connection—matching `TLSRoute` hostnames pass through untouched to backend pods, while all other traffic terminates TLS internally via `tls.Server` using hot-reloaded `Secret` certificates and routes through the L7 `HTTPRoute` proxy.

## Supported SSH Tunnel Providers

| Provider | HTTP Mode | HTTPS / TLS Tunneling Mode (Wildcard-ready) | TCP Mode |
| :--- | :--- | :--- | :--- |
| **Pinggy** ([TLS docs](https://pinggy.io/docs/tls_tunnels/)) | `<token>@a.pinggy.io:443` | `<token>+tls@a.pinggy.io:443` (or `tls@free.pinggy.io:443`) | `<token>+tcp@a.pinggy.io:443` |
| **Pico.sh `tuns.sh`** ([tuns docs](https://pico.sh/tuns)) | `-R *.example.com:80` | `-R *.example.com:443` + `sni-proxy=true` | `-R 0:0` (dynamic TCP port) |
| **localhost.run** | `-R 0.0.0.0:80` | `-R <hostname>:443` (custom domain) | `-R 0.0.0.0:<port>` |
| **Plain OpenSSH** | `-R 0.0.0.0:80` | `-R 0.0.0.0:443` (`GatewayPorts yes`) | `-R 0.0.0.0:<port>` |

## Related Projects

- **[dguerri/k8s-ssh-gateway-controller](https://github.com/dguerri/k8s-ssh-gateway-controller)**: Existing Go Gateway API controller for SSH tunnels (`tuns.sh`, Serveo, OpenSSH) supporting `HTTPRoute`, `TCPRoute`, and `TLSRoute` passthrough.
- **[ngrok Kubernetes Operator](https://ngrok.com/docs/gateway/k8s/guides/using-gwapi)**: Official Gateway API operator for ngrok with [TLS routing / passthrough](https://ngrok.com/docs/gateway/k8s/guides/how-to/tls-routing) over ngrok's native protocol.

## Quickstart

```bash
# 1. Resolve go.sum and run unit tests (includes SNI demux + wildcard TLS + TCP tests)
go mod tidy
go test -v -race ./...

# 2. Install Gateway API experimental CRDs (includes TCPRoute & TLSRoute)
make install-crds

# 3. Build image and deploy the controller
make docker-build IMAGE=your-registry/ssh-tunnel-gateway:latest
make deploy

# 4. Apply the all-modes wildcard example (HTTP + HTTPS + TLS passthrough + TCP)
kubectl create secret tls wildcard-example-tls --cert=tls.crt --key=tls.key
kubectl apply -f example/all-modes-wildcard.yaml
kubectl get gateway wildcard-multi-mode-gw
```
