REGISTRY      := your-registry
IMAGE_AGENT   := $(REGISTRY)/ai-traffic-interceptor
TAG           := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
ARCH          := $(shell go env GOARCH)

BIN_AGENT     := bin/ai-interceptor
GENERATED_DIR := internal/bpf/generated

.PHONY: all generate build docker-build docker-push deploy undeploy test lint clean

all: build

# Requires clang + llvm on a Linux host. Use docker-build from macOS.
generate:
	go generate ./internal/bpf/...

build: $(GENERATED_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) \
	  go build -ldflags="-s -w" -o $(BIN_AGENT) ./cmd/ai-interceptor/

$(GENERATED_DIR):
	@echo "ERROR: run 'make generate' first (needs clang on Linux, or use make docker-build)" && exit 1

docker-build:
	docker buildx build -f deploy/docker/Dockerfile \
	  --platform linux/amd64,linux/arm64 --push \
	  -t $(IMAGE_AGENT):$(TAG) -t $(IMAGE_AGENT):latest .

docker-push: docker-build

deploy:
	kubectl apply -f deploy/k8s/configmap.yaml
	kubectl apply -f deploy/k8s/clusterrole.yaml
	sed "s|IMAGE_TAG|$(IMAGE_AGENT):latest|g" deploy/k8s/daemonset.yaml | kubectl apply -f -

undeploy:
	kubectl delete -f deploy/k8s/ --ignore-not-found

clean:
	rm -rf bin/ internal/bpf/generated/
