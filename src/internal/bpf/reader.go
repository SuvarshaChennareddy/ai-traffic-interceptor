//go:build linux

package bpf

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
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

		msgSize := binary.LittleEndian.Uint64(rec.RawSample[:dnsEventMsgOffset])
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

func nullTermString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func int8SliceToString(s []int8) string {
	return nullTermString(unsafe.Slice((*byte)(unsafe.Pointer(&s[0])), len(s)))
}

// uint32ToIP recovers a dotted IP string from a uint32 read directly out of a
// BPF ring buffer sample. The kernel stores IPs in network byte order; after a
// native-endian memory cast the bytes are in host memory order, so we use
// NativeEndian to put them back.
func uint32ToIP(n uint32) string {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], n)
	return net.IP(b[:]).String()
}

// ntohs converts a uint16 from network byte order (big-endian) to host byte order.
// The generic swap (n>>8 | n<<8) only works on little-endian hosts; this is correct
// on any architecture.
func ntohs(n uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], n)
	return binary.BigEndian.Uint16(b[:])
}
