package main

const (
	// TLS record and handshake type identifiers.
	tlsRecordHandshake      byte   = 0x16   // TLS content type: handshake
	tlsHandshakeClientHello byte   = 0x01   // TLS handshake message type: ClientHello
	tlsExtSNI               uint16 = 0x0000 // TLS extension type: server_name

	// TLS record layout sizes/offsets (after the leading content-type byte).
	tlsRecordHdrTail   = 4 // remaining record header: version(2)+length(2)
	tlsRecordLenOffset = 2 // offset of length field within that tail
	tlsHandshakeHdrLen = 4 // handshake header: type(1)+length(3)
	tlsExtHdrLen       = 4 // extension header: type(2)+length(2)

	// ClientHello body layout.
	clientHelloMinLen     = 35 // minimum valid ClientHello body length
	clientHelloRandOffset = 34 // offset past client_version(2)+random(32)

	// SNI extension data layout (within the extension value bytes).
	sniExtMinLen     = 5 // minimum SNI extension data length
	sniNameLenOffset = 3 // offset of name_len field: list_len(2)+name_type(1)
	sniNameOffset    = 5 // offset of name bytes: list_len(2)+name_type(1)+name_len(2)

	// Upstream ports used when the host header / SNI carry no port.
	httpsPort = "443"
	httpPort  = "80"

	// I/O buffer sizes.
	httpReadBufSize  = 4096
	httpMaxHeaderBuf = 16384
)
