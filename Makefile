REGISTRY      := your-registry
IMAGE_AGENT   := $(REGISTRY)/ai-traffic-interceptor
TAG           := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
ARCH          := $(shell go env GOARCH)

BIN_AGENT     := bin/ai-interceptor
GODIR         := src
GENERATED_DIR := $(GODIR)/internal/bpf/generated

.PHONY: all generate build docker-build docker-push deploy undeploy test lint clean

all: build

# Requires clang, llvm, libbpf-dev, and Go on a Linux host. Use docker-build from macOS.
generate:
	cd $(GODIR) && go generate ./internal/bpf/...

build: $(GENERATED_DIR)
	cd $(GODIR) && CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) \
	  go build -ldflags="-s -w" -o ../$(BIN_AGENT) ./cmd/ai-interceptor/

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
	rm -rf bin/ $(GENERATED_DIR)/
