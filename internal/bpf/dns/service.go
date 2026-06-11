//go:build linux

package dns

import (
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/aurva-io/ai-traffic-interceptor/internal/bpf/generated"
)

type Service struct {
	AIDestMap *ebpf.Map
	AIDomains []string
	Log       *zap.Logger
}

func (svc *Service) ProcessDNSEvent(rawMsg []byte) error {
	msg := new(dns.Msg)
	if err := msg.Unpack(rawMsg); err != nil {
		return err
	}

	// Build a CNAME chain map: alias → canonical name.
	// e.g. api.openai.com → openai-api.cloudflare.net → 104.18.33.45
	// We need to know that any IP resolved via an AI domain CNAME is an AI IP.
	aiCNAMEs := make(map[string]string) // cname target → original ai hostname
	for _, rr := range msg.Answer {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}

		src := strings.TrimSuffix(cname.Hdr.Name, ".")
		tgt := strings.TrimSuffix(cname.Target, ".")
		if svc.isAIDomain(src) {
			aiCNAMEs[tgt] = src
			svc.Log.Debug("dns cname chain started",
				zap.String("ai_domain", src),
				zap.String("cname_target", tgt),
			)
		} else if origin, chained := aiCNAMEs[src]; chained {
			aiCNAMEs[tgt] = origin // propagate through multi-hop chains
			svc.Log.Debug("dns cname chain extended",
				zap.String("ai_domain", origin),
				zap.String("via", src),
				zap.String("cname_target", tgt),
			)
		}
	}

	for _, rr := range msg.Answer {
		rec, ok := rr.(*dns.A)
		if !ok {
			continue
		}

		ip4 := rec.A.To4()
		if ip4 == nil {
			continue
		}

		name := strings.TrimSuffix(rec.Hdr.Name, ".")

		var aiHostname string
		switch {
		case svc.isAIDomain(name):
			aiHostname = name
		case aiCNAMEs[name] != "":
			aiHostname = aiCNAMEs[name]
		default:
			continue
		}

		svc.Log.Debug("dns ai domain resolved",
			zap.String("hostname", aiHostname),
			zap.String("ip", net.IP(ip4).String()),
			zap.Uint32("ttl_s", rec.Hdr.Ttl),
		)
		svc.writeDestination(ip4, aiHostname, rec.Hdr.Ttl)
	}

	return nil
}

func (svc *Service) isAIDomain(hostname string) bool {
	for _, suffix := range svc.AIDomains {
		if hostname == suffix || strings.HasSuffix(hostname, "."+suffix) {
			return true
		}
	}

	return false
}

func (svc *Service) writeDestination(ip4 []byte, hostname string, ttl uint32) {
	// On little-endian hosts (amd64/arm64), reading network-order bytes as
	// LittleEndian produces a uint32 that cilium/ebpf re-encodes to the same
	// bytes, matching ctx->user_ip4 (network byte order) in the BPF program.
	key := binary.LittleEndian.Uint32(ip4)

	var info generated.AIInterceptorAiDestInfoT
	for i := 0; i < len(hostname) && i < len(info.Hostname); i++ {
		info.Hostname[i] = int8(hostname[i])
	}

	info.TimestampNs = uint64(time.Now().UnixNano())
	info.TtlS = ttl

	_ = svc.AIDestMap.Update(key, info, ebpf.UpdateAny)
}
