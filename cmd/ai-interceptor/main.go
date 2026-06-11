//go:build linux

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/aurva-io/ai-traffic-interceptor/internal/ai"
	bpfpkg "github.com/aurva-io/ai-traffic-interceptor/internal/bpf"
	"github.com/aurva-io/ai-traffic-interceptor/internal/config"
	"github.com/aurva-io/ai-traffic-interceptor/internal/logger"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic("load config: " + err.Error())
	}

	log, err := logger.New(cfg.LogLevel)
	if err != nil {
		panic("init logger: " + err.Error())
	}
	defer log.Sync()

	if len(cfg.AIDomains) == 0 {
		cfg.AIDomains = ai.DefaultAIDomains
	}

	mgr, err := bpfpkg.NewManager(cfg, log)
	if err != nil {
		log.Fatal("init BPF manager", zap.Error(err))
	}
	defer mgr.Close()

	log.Info("ai-traffic-interceptor started",
		zap.String("interface", cfg.NetworkInterface),
		zap.String("proxy", cfg.ProxyIP),
		zap.Uint16("proxy_port", cfg.ProxyPort),
		zap.Int("ai_domains", len(cfg.AIDomains)),
	)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go mgr.ReadDNSEvents(ctx)
	go mgr.ReadRedirectEvents(ctx)

	<-ctx.Done()
	log.Info("shutting down")
}
