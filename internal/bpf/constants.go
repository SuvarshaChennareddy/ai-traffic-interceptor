//go:build linux

package bpf

const (
	// TC netlink attachment handles — must match kernel TC_H_* constants.
	tcClsactMajor    = 0xffff // TC_H_CLSACT major component
	tcIngressMinor   = 0xfff2 // TC_H_MIN_INGRESS minor component
	tcFilterHandle   = 1
	tcFilterPriority = 1

	// proxyConfigKey is the index into the single-element proxy_config BPF ARRAY map.
	proxyConfigKey uint32 = 0

	// dnsEventMsgOffset is the byte offset of the msg field within dns_event_t.
	// Matches sizeof(uint64_t msg_size) in bpf/defs.h.
	dnsEventMsgOffset = 8
)
