package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"time"
)

const (
	defaultListenAddr = ":8443"
	dialTimeout       = 15 * time.Second
	peekTimeout       = 10 * time.Second
)

func main() {
	addr := os.Getenv("PROXY_LISTEN_ADDR")
	if addr == "" {
		addr = defaultListenAddr
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	log.Printf("pass-through proxy listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(peekTimeout))

	first := make([]byte, 1)
	if _, err := io.ReadFull(conn, first); err != nil {
		return
	}

	var host, upstreamPort string
	var peeked []byte
	var err error

	if first[0] == tlsRecordHandshake {
		host, peeked, err = extractSNI(conn, first[0])
		upstreamPort = httpsPort
	} else {
		host, peeked, err = extractHTTPHost(conn, first[0])
		upstreamPort = httpPort
	}

	if err != nil || host == "" {
		log.Printf("[proxy] cannot determine target host from %s: %v", conn.RemoteAddr(), err)
		return
	}

	target := host
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		target = net.JoinHostPort(host, upstreamPort)
	}

	upstream, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("[proxy] dial %s: %v", target, err)
		return
	}
	defer upstream.Close()

	log.Printf("[proxy] %s → %s", conn.RemoteAddr(), target)

	if len(peeked) > 0 {
		if _, err := upstream.Write(peeked); err != nil {
			log.Printf("[proxy] forward peeked bytes to %s: %v", target, err)
			return
		}
	}

	conn.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})

	errc := make(chan error, 2)

	go func() { _, err := io.Copy(upstream, conn); errc <- err }()
	go func() { _, err := io.Copy(conn, upstream); errc <- err }()

	<-errc
}

func extractSNI(conn net.Conn, firstByte byte) (host string, peeked []byte, err error) {
	hdr := make([]byte, tlsRecordHdrTail)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return
	}

	recLen := int(binary.BigEndian.Uint16(hdr[tlsRecordLenOffset:tlsRecordHdrTail]))
	recData := make([]byte, recLen)

	if _, err = io.ReadFull(conn, recData); err != nil {
		return
	}

	peeked = append([]byte{firstByte}, hdr...)
	peeked = append(peeked, recData...)

	if len(recData) < tlsHandshakeHdrLen || recData[0] != tlsHandshakeClientHello {
		return
	}

	hsLen := int(recData[1])<<16 | int(recData[2])<<8 | int(recData[3])
	if len(recData) < tlsHandshakeHdrLen+hsLen {
		return
	}

	host = parseSNI(recData[tlsHandshakeHdrLen : tlsHandshakeHdrLen+hsLen])
	return
}

func parseSNI(hello []byte) string {
	if len(hello) < clientHelloMinLen {
		return ""
	}

	pos := clientHelloRandOffset

	if pos+1 > len(hello) {
		return ""
	}

	sessLen := int(hello[pos])
	pos += 1 + sessLen

	if pos+2 > len(hello) {
		return ""
	}

	cipherLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2 + cipherLen

	if pos+1 > len(hello) {
		return ""
	}

	compLen := int(hello[pos])
	pos += 1 + compLen

	if pos+2 > len(hello) {
		return ""
	}

	extTotal := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2

	end := pos + extTotal
	if end > len(hello) {
		end = len(hello)
	}

	for pos+tlsExtHdrLen <= end {
		extType := binary.BigEndian.Uint16(hello[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(hello[pos+2 : pos+tlsExtHdrLen]))
		pos += tlsExtHdrLen

		if pos+extLen > end {
			break
		}

		if extType == tlsExtSNI && extLen >= sniExtMinLen {
			ext := hello[pos : pos+extLen]
			nameLen := int(binary.BigEndian.Uint16(ext[sniNameLenOffset : sniNameLenOffset+2]))
			if sniNameOffset+nameLen <= len(ext) {
				return string(ext[sniNameOffset : sniNameOffset+nameLen])
			}
		}

		pos += extLen
	}

	return ""
}

func extractHTTPHost(conn net.Conn, firstByte byte) (host string, peeked []byte, err error) {
	var buf bytes.Buffer

	buf.WriteByte(firstByte)

	tmp := make([]byte, httpReadBufSize)
	for buf.Len() < httpMaxHeaderBuf {
		var n int
		n, err = conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
		if bytes.Contains(buf.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}

	peeked = buf.Bytes()
	host = parseHostHeader(peeked)
	if host != "" {
		err = nil
	}

	return
}

func parseHostHeader(data []byte) string {
	lower := bytes.ToLower(data)
	idx := bytes.Index(lower, []byte(needle))
	if idx == -1 {
		return ""
	}

	start := idx + len(needle)
	rest := data[start:]
	end := bytes.IndexByte(rest, '\r')
	if end == -1 {
		end = bytes.IndexByte(rest, '\n')
	}
	if end == -1 {
		return string(bytes.TrimSpace(rest))
	}

	return string(bytes.TrimSpace(rest[:end]))
}
