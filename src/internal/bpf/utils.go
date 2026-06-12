package bpf

import (
	"encoding/binary"
	"net"
	"unsafe"
)

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
func ntohs(n uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], n)
	return binary.BigEndian.Uint16(b[:])
}
