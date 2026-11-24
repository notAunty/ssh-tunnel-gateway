BINARY_NAME := ssh-tunnel-gateway
IMAGE ?= ghcr.io/example/ssh-tunnel-gateway:latest

.PHONY: tidy build test vet fmt docker-build install-crds deploy clean

tidy:
	go mod tidy

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/$(BINARY_NAME) .

test:
	go test -v -race ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

docker-build:
	docker build -t $(IMAGE) .

# Experimental channel includes TCPRoute and TLSRoute CRDs in addition to GatewayClass, Gateway, and HTTPRoute.
install-crds:
	kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/experimental-install.yaml

deploy:
	kubectl apply -f k8s/rbac.yaml
	kubectl apply -f k8s/gatewayclass.yaml
	kubectl apply -f k8s/deployment.yaml

clean:
	rm -rf bin/
