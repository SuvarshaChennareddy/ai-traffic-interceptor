#pragma once

// ── TC return codes ─────────────────────────────────────────────────────────
#define TC_ACT_OK  0

// ── Network layer ────────────────────────────────────────────────────────────
#define ETH_HDR_LEN    14
#define IP_HDR_MINLEN  20

// ── Transport layer ──────────────────────────────────────────────────────────
#define UDP_HDR_LEN         8
#define TCP_HDR_MINLEN     20
#define DNS_TCP_LEN_PREFIX  2  // DNS-over-TCP 2-byte message-length prefix

// ── BPF struct limits ────────────────────────────────────────────────────────
#define MAX_HOSTNAME_LEN     64
#define MAX_COMMAND_SIZE     16
#define MAX_COMMANDLINE_SIZE 127
#define MAX_DNS_MSG_SIZE     512  // must be power of 2 for verifier masking

// ── Map sizing ───────────────────────────────────────────────────────────────
#define AI_DEST_MAP_MAX_ENTRIES    65536
#define DNS_EVENTS_RING_SIZE       (1 << 23)  // 8 MB
#define REDIRECT_EVENTS_RING_SIZE  (1 << 22)  // 4 MB

struct ai_dest_info_t {
	char     hostname[MAX_HOSTNAME_LEN];
	__u64    timestamp_ns;
	__u32    ttl_s;
	__u8     _pad[4];
};

struct proxy_config_t {
	__u32 ip;    // network byte order
	__u16 port;  // network byte order
	__u8  _pad[2];
};

struct redirect_event_t {
	__u32 pid;
	__u32 tgid;
	__u32 original_ip;    // network byte order
	__u16 original_port;  // network byte order
	__u32 proxy_ip;       // network byte order
	__u16 proxy_port;     // network byte order
	__u8  _pad[2];
	char  hostname[MAX_HOSTNAME_LEN];
	char  command[MAX_COMMAND_SIZE];
	__u32 commandline_len;
	char  commandline[MAX_COMMANDLINE_SIZE];
	__u64 timestamp_ns;
};

struct dns_event_t {
	__u64 msg_size;
	char  msg[MAX_DNS_MSG_SIZE];
};

// BTF hints: global unused pointer declarations force clang to include these
// struct types in BTF so that `bpf2go -type` can generate Go bindings for them.
// Ring buffer event types are not BPF map value types, so without this hint
// they do not appear in the compiled object's BTF section.
struct redirect_event_t *_redirect_event_unused __attribute__((unused));
struct dns_event_t      *_dns_event_unused      __attribute__((unused));
