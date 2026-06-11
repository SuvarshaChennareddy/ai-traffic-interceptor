#pragma once

#include "defs.h"

// Returns 1 if buf looks like a valid DNS response with at least one answer.
static __always_inline bool is_valid_dns_response(const char *buf, __u32 len)
{
	if (len < DNS_HDR_MIN_LEN)
		return false;

	// Byte 2: flags high byte; QR bit is bit 7 (0x80 = response)
	__u8 flags_hi = buf[2];
	if (!(flags_hi & 0x80))
		return false;

	// Bytes 6-7: ANCOUNT must be > 0
	__u8 ancount_hi = buf[6];
	__u8 ancount_lo = buf[7];
	if (((__u16)ancount_hi << 8 | ancount_lo) == 0)
		return false;

	return true;
}
