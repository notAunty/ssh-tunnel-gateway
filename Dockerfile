# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder
WORKDIR /src

COPY go.mod ./
# Run `go mod tidy` locally first so go.sum is committed, or fetch on build.
COPY . .
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ssh-tunnel-gateway .

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /out/ssh-tunnel-gateway /ssh-tunnel-gateway
USER 65532:65532

ENTRYPOINT ["/ssh-tunnel-gateway"]
