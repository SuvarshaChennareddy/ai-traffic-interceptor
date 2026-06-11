# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM golang:1.23-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compile bpf/ai_interceptor.c → embedded Go bytecode files
RUN go generate ./internal/bpf/...

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$(go env GOARCH) \
    go build -ldflags="-s -w" -o /out/ai-interceptor ./cmd/ai-interceptor/

# ── Stage 2: agent image ──────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12

COPY --from=builder /out/ai-interceptor /ai-interceptor
ENTRYPOINT ["/ai-interceptor"]
