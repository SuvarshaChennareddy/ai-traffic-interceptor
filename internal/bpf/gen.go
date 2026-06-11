package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -fno-stack-protector -I../../bpf/include" -output-dir ./generated -go-package generated -type redirect_event_t -target amd64,arm64 AIInterceptor ../../bpf/ai_interceptor.c
