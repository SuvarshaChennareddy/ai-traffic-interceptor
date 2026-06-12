//go:build linux

package bpf

import (
	"context"
	"encoding/binary"
	"errors"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"

	"github.com/aurva-io/ai-traffic-interceptor/internal/bpf/generated"
)

// ReadDNSEvents reads from the dns_events ring buffer and feeds each message to m.dnsSvc.
// Blocks until ctx is cancelled or the ring buffer is closed.
func (m *Manager) ReadDNSEvents(ctx context.Context) {
	rd, err := ringbuf.NewReader(m.Objs.DnsEvents)
	if err != nil {
		m.log.Fatal("open dns_events ring buffer", zap.Error(err))
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}

			m.log.Debug("dns_events read error", zap.Error(err))

			continue
		}

		if len(rec.RawSample) <= dnsEventMsgOffset {
			continue
		}

		msgSize := binary.NativeEndian.Uint64(rec.RawSample[:dnsEventMsgOffset])
		end := dnsEventMsgOffset + int(msgSize)
		if msgSize == 0 || end > len(rec.RawSample) {
			continue
		}

		if err := m.dnsSvc.ProcessDNSEvent(rec.RawSample[dnsEventMsgOffset:end]); err != nil {
			m.log.Debug("dns parse error", zap.Error(err))
		}
	}
}

// ReadRedirectEvents reads from the redirect_events ring buffer and logs each event.
// Blocks until ctx is cancelled or the ring buffer is closed.
func (m *Manager) ReadRedirectEvents(ctx context.Context) {
	rd, err := ringbuf.NewReader(m.Objs.RedirectEvents)
	if err != nil {
		m.log.Fatal("open redirect_events ring buffer", zap.Error(err))
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}

			m.log.Debug("redirect_events read error", zap.Error(err))

			continue
		}

		ev, ok := ringbufCast[generated.AIInterceptorRedirectEventT](rec.RawSample)
		if !ok {
			m.log.Debug("redirect event too small", zap.Int("got", len(rec.RawSample)))
			continue
		}

		m.log.Info("ai_traffic_redirected",
			zap.Uint32("pid", ev.Pid),
			zap.String("process", int8SliceToString(ev.Command[:])),
			zap.String("original_host", int8SliceToString(ev.Hostname[:])),
			zap.String("original_ip", uint32ToIP(ev.OriginalIp)),
			zap.Uint16("original_port", ntohs(ev.OriginalPort)),
			zap.String("proxy_ip", uint32ToIP(ev.ProxyIp)),
			zap.Uint16("proxy_port", ntohs(ev.ProxyPort)),
		)
	}
}

// ringbufCast casts raw ring buffer bytes to T without copying.
// Returns (zero, false) if the slice is too small to hold T.
// T must embed structs.HostLayout so Go's field alignment matches the C struct.
func ringbufCast[T any](b []byte) (T, bool) {
	var zero T

	if uintptr(len(b)) < unsafe.Sizeof(zero) {
		return zero, false
	}

	return *(*T)(unsafe.Pointer(&b[0])), true
}
