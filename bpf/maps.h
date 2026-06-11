#pragma once

#include "defs.h"

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, AI_DEST_MAP_MAX_ENTRIES);
	__type(key,   __u32);
	__type(value, struct ai_dest_info_t);
} ai_destinations SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key,   __u32);
	__type(value, struct proxy_config_t);
} proxy_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, DNS_EVENTS_RING_SIZE);
} dns_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, REDIRECT_EVENTS_RING_SIZE);
} redirect_events SEC(".maps");
