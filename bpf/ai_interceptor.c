#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "defs.h"
#include "maps.h"
#include "dns/helpers.h"

char LICENSE[] SEC("license") = "GPL";

// TC hook: copy DNS responses into the dns_events ring buffer

SEC("tc")
int tc_dns_observer(struct __sk_buff *skb)
{
	// Read IP version + IHL (first byte of IP header)
	__u8 ip_hdr_byte;
	if (bpf_skb_load_bytes(skb, ETH_HDR_LEN, &ip_hdr_byte, 1) < 0)
		return TC_ACT_OK;
	__u16 ip_hdr_len = (__u16)(ip_hdr_byte & 0x0f) * 4;
	if (ip_hdr_len < IP_HDR_MINLEN)
		return TC_ACT_OK;

	// Read IP protocol
	__u8 ip_proto;
	if (bpf_skb_load_bytes(skb, ETH_HDR_LEN + 9, &ip_proto, 1) < 0)
		return TC_ACT_OK;
	if (ip_proto != 17 && ip_proto != 6)  // UDP or TCP
		return TC_ACT_OK;

	__u16 transport_offset = ETH_HDR_LEN + ip_hdr_len;

	// Read source port (first 2 bytes of transport header)
	__u16 src_port;
	if (bpf_skb_load_bytes(skb, transport_offset, &src_port, 2) < 0)
		return TC_ACT_OK;
	if (bpf_ntohs(src_port) != 53)
		return TC_ACT_OK;

	// DNS payload starts after the transport header.
	// For DNS-over-TCP, skip the 2-byte message-length prefix before the DNS message.
	__u16 transport_hdr_len = (ip_proto == 17) ? UDP_HDR_LEN : TCP_HDR_MINLEN;
	__u16 dns_prefix        = (ip_proto == 6)  ? DNS_TCP_LEN_PREFIX : 0;
	__u16 payload_offset    = transport_offset + transport_hdr_len + dns_prefix;
	
	if (payload_offset >= skb->len)
		return TC_ACT_OK;

	__u32 payload_len = (skb->len - payload_offset);
	// The verifier can't prove payload_len is non-negative for the
	// bpf_skb_load_bytes call (R4 min value is negative). This mask
	// gives it a provable bound of [0, 1023]. We use 2*MAX_DNS_MSG_SIZE-1
	// instead of MAX_DNS_MSG_SIZE-1 so a 512-byte payload maps to 512, not 0.
	payload_len &= (2*MAX_DNS_MSG_SIZE - 1);

	if (payload_len < DNS_HDR_MIN_LEN || payload_len > MAX_DNS_MSG_SIZE)
		return TC_ACT_OK;

	struct dns_event_t *ev = bpf_ringbuf_reserve(&dns_events, sizeof(*ev), 0);
	if (!ev)
		return TC_ACT_OK;

	ev->msg_size = payload_len;

	if (bpf_skb_load_bytes(skb, payload_offset, ev->msg, payload_len) < 0) {
		bpf_ringbuf_discard(ev, 0);
		return TC_ACT_OK;
	}

	if (!is_valid_dns_response(ev->msg, payload_len)) {
		bpf_ringbuf_discard(ev, 0);
		return TC_ACT_OK;
	}

	bpf_ringbuf_submit(ev, 0);
	return TC_ACT_OK;
}

// cgroup/connect4: redirect AI destinations to proxy

SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx)
{
	__u32 dst_ip   = ctx->user_ip4;
	__u16 dst_port = ctx->user_port;

	struct ai_dest_info_t *info = bpf_map_lookup_elem(&ai_destinations, &dst_ip);
	if (!info)
		return 1;

	__u32 key = 0;
	struct proxy_config_t *proxy = bpf_map_lookup_elem(&proxy_config, &key);
	if (!proxy)
		return 1;  // fail open — allow unchanged

	struct redirect_event_t *ev = bpf_ringbuf_reserve(&redirect_events, sizeof(*ev), 0);
	if (ev) {
		__u64 pid_tgid  = bpf_get_current_pid_tgid();
		ev->pid          = (__u32)pid_tgid;
		ev->tgid         = (__u32)(pid_tgid >> 32);
		ev->original_ip  = dst_ip;
		ev->original_port = dst_port;
		ev->proxy_ip     = proxy->ip;
		ev->proxy_port   = proxy->port;
		ev->timestamp_ns = bpf_ktime_get_ns();

		bpf_probe_read_kernel(ev->hostname, MAX_HOSTNAME_LEN, info->hostname);
		bpf_get_current_comm(ev->command, sizeof(ev->command));

		bpf_ringbuf_submit(ev, 0);
	}

	ctx->user_ip4  = proxy->ip;
	ctx->user_port = proxy->port;

	return 1;
}
