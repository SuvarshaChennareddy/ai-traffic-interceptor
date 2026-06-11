#pragma once

#define DNS_HDR_MIN_LEN  12  // minimum DNS wire-format header size

struct dns_header {
	__u16 id;
	__u16 flags;
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
};
