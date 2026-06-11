# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.24-bookworm AS builder
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY src/go.mod src/go.sum src/
RUN cd src && go mod download

COPY . .

# Compile bpf/ai_interceptor.c → embedded Go bytecode files
RUN cd src && go generate ./internal/bpf/...

RUN cd src && CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/ai-interceptor ./cmd/ai-interceptor/

# ── Stage 2: agent image ──────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12

COPY --from=builder /out/ai-interceptor /ai-interceptor
ENTRYPOINT ["/ai-interceptor"]
