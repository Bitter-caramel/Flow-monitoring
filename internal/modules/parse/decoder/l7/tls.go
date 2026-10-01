package l7

import (
	"encoding/binary"
	"fmt"

	"flow-monitoring/internal/kernel/datamodel"
)

// TLS 记录/握手类型常量。
const (
	tlsHandshake       = 22
	tlsChangeCipher    = 20
	tlsAlert           = 21
	tlsApplicationData = 23
)

// isTLSRecord 检测是否为 TLS 记录（对应 PacketLens dispatch 4019-4020）。
func isTLSRecord(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	ct := b[0]
	if (ct == tlsHandshake || ct == tlsChangeCipher || ct == tlsAlert || ct == tlsApplicationData) &&
		b[1] == 0x03 {
		return true
	}
	return false
}

// tls 解析 TLS 记录（对应 PacketLens tls() index.html:3254 的 P0 子集）。
//
// 提取记录类型/版本，若为 Handshake 则识别握手类型并提取 ClientHello SNI。
func tls(p *datamodel.Packet, b []byte) {
	if len(b) < 5 {
		p.Proto = "TLS"
		return
	}

	t := &datamodel.TLS{
		RecordType:    b[0],
		RecordVersion: binary.BigEndian.Uint16(b[1:3]),
	}
	recordLen := int(binary.BigEndian.Uint16(b[3:5]))

	p.TLS = t

	// 记录层版本兜底协议名
	protoName := tlsVersionName(t.RecordVersion)

	if t.RecordType == tlsHandshake {
		t.HandshakeType = b[5] // 握手类型（在记录 body 的第一个字节）
		protoName = tlsVersionName(t.RecordVersion)

		if t.HandshakeType == 1 { // ClientHello
			parseClientHello(p, t, b[5:], recordLen)
		} else if t.HandshakeType == 2 { // ServerHello
			parseServerHello(p, t, b[5:])
		}
	}

	p.Proto = protoName
	if p.Info == "" {
		p.Info = tlsRecordName(t.RecordType)
	}
}

// parseClientHello 提取 ClientHello 的 SNI（对应 PacketLens parseClientHello）。
func parseClientHello(p *datamodel.Packet, t *datamodel.TLS, hb []byte, recordLen int) {
	if len(hb) < 4 {
		return
	}
	// handshake header: type(1) + length(3)
	hsLen := int(hb[1])<<16 | int(hb[2])<<8 | int(hb[3])
	body := hb[4:]
	if len(body) > hsLen {
		body = body[:hsLen]
	}
	// ClientHello body: legacy_version(2) + random(32) + session_id_len(1)
	if len(body) < 35 {
		return
	}
	t.Version = binary.BigEndian.Uint16(body[0:2])
	off := 2 + 32            // 跳过 version + random
	sidLen := int(body[off]) // session_id_len
	off += 1 + sidLen

	// cipher_suites_len(2)
	if off+2 > len(body) {
		return
	}
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2 + csLen

	// compression_methods_len(1)
	if off+1 > len(body) {
		return
	}
	compLen := int(body[off])
	off += 1 + compLen

	// extensions_len(2)
	if off+2 > len(body) {
		return
	}
	extLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	extEnd := off + extLen
	if extEnd > len(body) {
		extEnd = len(body)
	}

	// 遍历扩展
	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[off : off+2])
		el := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		if off+4+el > extEnd {
			break
		}
		if extType == 0 { // server_name (SNI)
			t.SNI = parseSNI(body[off+4 : off+4+el])
		}
		if extType == 16 { // ALPN
			t.ALPN = parseALPN(body[off+4 : off+4+el])
		}
		off += 4 + el
	}

	if t.SNI != "" {
		p.Info = fmt.Sprintf("Client Hello (SNI=%s)", t.SNI)
	} else {
		p.Info = "Client Hello"
	}
}

// parseSNI 解析 SNI 扩展（server_name_list）。
func parseSNI(ext []byte) string {
	if len(ext) < 3 {
		return ""
	}
	// ext = server_name_list_len(2) + server_name
	off := 2
	for off+3 <= len(ext) {
		nameType := ext[off]
		nameLen := int(binary.BigEndian.Uint16(ext[off+1 : off+3]))
		if off+3+nameLen > len(ext) {
			break
		}
		if nameType == 0 { // host_name
			return string(ext[off+3 : off+3+nameLen])
		}
		off += 3 + nameLen
	}
	return ""
}

// parseALPN 解析 ALPN 扩展（protocol_name_list）。
func parseALPN(ext []byte) string {
	if len(ext) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(ext[0:2]))
	body := ext[2:]
	if len(body) > listLen {
		body = body[:listLen]
	}
	off := 0
	var protos []string
	for off+1 <= len(body) {
		pl := int(body[off])
		off++
		if off+pl > len(body) {
			break
		}
		protos = append(protos, string(body[off:off+pl]))
		off += pl
	}
	if len(protos) > 0 {
		return protos[0]
	}
	return ""
}

// parseServerHello 提取 ServerHello 的协商版本与密码套件（P0 子集）。
func parseServerHello(p *datamodel.Packet, t *datamodel.TLS, hb []byte) {
	if len(hb) < 4 {
		return
	}
	hsLen := int(hb[1])<<16 | int(hb[2])<<8 | int(hb[3])
	body := hb[4:]
	if len(body) > hsLen {
		body = body[:hsLen]
	}
	if len(body) < 38 { // version(2) + random(32) + session_id_len(1) + cipher(2) + comp(1)
		return
	}
	t.Version = binary.BigEndian.Uint16(body[0:2])
	off := 2 + 32
	sidLen := int(body[off])
	off += 1 + sidLen
	t.CipherSuite = binary.BigEndian.Uint16(body[off : off+2])

	p.Info = fmt.Sprintf("Server Hello (%s, %s)",
		tlsVersionName(t.Version), cipherSuiteName(t.CipherSuite))
}

// tlsVersionName 返回 TLS 版本名。
func tlsVersionName(v uint16) string {
	switch v {
	case 0x0300:
		return "SSLv3"
	case 0x0301:
		return "TLSv1.0"
	case 0x0302:
		return "TLSv1.1"
	case 0x0303:
		return "TLSv1.2"
	case 0x0304:
		return "TLSv1.3"
	}
	return "TLS"
}

// tlsRecordName 返回记录类型名。
func tlsRecordName(ct uint8) string {
	switch ct {
	case tlsHandshake:
		return "Handshake"
	case tlsChangeCipher:
		return "Change Cipher Spec"
	case tlsAlert:
		return "Alert"
	case tlsApplicationData:
		return "Application Data"
	}
	return fmt.Sprintf("TLS record %d", ct)
}

// cipherSuiteName 返回密码套件名（常见子集）。
func cipherSuiteName(cs uint16) string {
	m := map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0xc02f: "TLS_ECDHE_RSA_AES_128_GCM_SHA256",
		0xc030: "TLS_ECDHE_RSA_AES_256_GCM_SHA384",
		0xcca8: "TLS_ECDHE_RSA_CHACHA20_POLY1305",
		0xc02b: "TLS_ECDHE_ECDSA_AES_128_GCM_SHA256",
		0x009c: "TLS_RSA_AES_128_GCM_SHA256",
	}
	if name, ok := m[cs]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", cs)
}
