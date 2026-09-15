package l7

import (
	"fmt"
	"net"
	"strings"

	"flow-monitoring/internal/kernel/datamodel"
)

// DNS RR 类型常量。
const (
	dnsTypeA     = 1
	dnsTypeNS    = 2
	dnsTypeCNAME = 5
	dnsTypeSOA   = 6
	dnsTypePTR   = 12
	dnsTypeMX    = 15
	dnsTypeTXT   = 16
	dnsTypeAAAA  = 28
	dnsTypeSRV   = 33
)

// dns 解析 DNS 报文（对应 PacketLens dns() index.html:2778）。
func dns(p *datamodel.Packet, msg []byte) {
	if len(msg) < 12 {
		p.Proto = "DNS"
		p.Info = "DNS 报文过短"
		return
	}

	id := u16be(msg, 0)
	flags := u16be(msg, 2)
	qr := flags>>15&1 == 1
	opcode := uint8(flags >> 11 & 0x0f)
	rcode := uint8(flags & 0x0f)
	qdcount := int(u16be(msg, 4))
	ancount := int(u16be(msg, 6))
	nscount := int(u16be(msg, 8))
	arcount := int(u16be(msg, 10))

	d := &datamodel.DNS{
		ID:     id,
		QR:     qr,
		OpCode: opcode,
		RCode:  rcode,
	}

	off := 12

	// Questions
	for i := 0; i < qdcount && off < len(msg); i++ {
		name, next, ok := dnsName(msg, off)
		if !ok || next+4 > len(msg) {
			break
		}
		qtype := u16be(msg, next)
		qclass := u16be(msg, next+2)
		d.Questions = append(d.Questions, datamodel.DNSQuestion{
			Name:  name,
			Type:  qtype,
			Class: qclass,
		})
		off = next + 4
	}

	// Answers / Authorities / Additionals
	d.Answers = dnsReadResources(msg, off, ancount, &off)
	d.Authorities = dnsReadResources(msg, off, nscount, &off)
	d.Additionals = dnsReadResources(msg, off, arcount, &off)

	p.DNS = d
	p.Proto = "DNS"

	// Info 摘要
	head := fmt.Sprintf("Standard query 0x%04x", id)
	if qr {
		head = fmt.Sprintf("Standard query response 0x%04x", id)
	}
	var body []string
	for _, q := range d.Questions {
		body = append(body, fmt.Sprintf("%s %s", dnsTypeName(q.Type), q.Name))
	}
	if qr {
		if rcode != 0 {
			body = append([]string{dnsRCodeName(rcode)}, body...)
		}
		var ans []string
		for i, a := range d.Answers {
			if i >= 6 {
				break
			}
			ans = append(ans, fmt.Sprintf("%s %s", dnsTypeName(a.Type), a.Data))
		}
		if len(ans) > 0 {
			body = append(body, strings.Join(ans, ", "))
		} else {
			body = append(body, "(无记录)")
		}
	}
	p.Info = head + " " + strings.Join(body, ", ")
}

// dnsReadResources 从 off 开始读 count 个资源记录，返回列表并更新 off。
func dnsReadResources(msg []byte, off, count int, next *int) []datamodel.DNSResource {
	var out []datamodel.DNSResource
	for i := 0; i < count && off < len(msg); i++ {
		name, no, ok := dnsName(msg, off)
		if !ok || no+10 > len(msg) {
			break
		}
		rtype := u16be(msg, no)
		rclass := u16be(msg, no+2)
		ttl := u32be(msg, no+4)
		rdlen := int(u16be(msg, no+8))
		if no+10+rdlen > len(msg) {
			break
		}
		rdata := msg[no+10 : no+10+rdlen]
		val := dnsRData(msg, rdata, rtype)

		out = append(out, datamodel.DNSResource{
			Name:  name,
			Type:  rtype,
			Class: rclass,
			TTL:   ttl,
			Data:  val,
		})
		off = no + 10 + rdlen
	}
	*next = off
	return out
}

// dnsName 解析 DNS 域名（支持指针压缩）。
//
// 返回域名、下一个未读偏移、是否成功。
// 对应 PacketLens dnsName()。
func dnsName(msg []byte, off int) (string, int, bool) {
	var labels []string
	pos := off
	next := -1
	jumped := false

	for {
		if pos >= len(msg) {
			return "", 0, false
		}
		ln := int(msg[pos])
		if ln == 0 {
			pos++
			if next < 0 {
				next = pos
			}
			break
		}
		if ln&0xc0 == 0xc0 {
			// 指针压缩：后 14 位为偏移
			if pos+1 >= len(msg) {
				return "", 0, false
			}
			ptr := int(ln&0x3f)<<8 | int(msg[pos+1])
			if next < 0 {
				next = pos + 2
			}
			pos = ptr
			jumped = true
			continue
		}
		if ln > 63 || pos+1+ln > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[pos+1:pos+1+ln]))
		pos += 1 + ln
		if jumped && next >= 0 {
			// 跳转后不再前进（指针已定位到新位置，但仍需继续读标签）
		}
	}

	if len(labels) == 0 {
		return "", 0, false
	}
	if next < 0 {
		next = pos
	}
	return strings.Join(labels, "."), next, true
}

// dnsRData 解析 RR 数据（对应 PacketLens rdata()）。
func dnsRData(msg, rdata []byte, rtype uint16) string {
	switch rtype {
	case dnsTypeA:
		if len(rdata) >= 4 {
			return net.IP(rdata[:4]).String()
		}
	case dnsTypeAAAA:
		if len(rdata) >= 16 {
			return net.IP(rdata[:16]).String()
		}
	case dnsTypeCNAME, dnsTypeNS, dnsTypePTR:
		if name, _, ok := dnsName(rdata, 0); ok {
			return name
		}
	case dnsTypeMX:
		if len(rdata) >= 3 {
			pref := u16be(rdata, 0)
			if name, _, ok := dnsName(rdata, 2); ok {
				return fmt.Sprintf("%d %s", pref, name)
			}
		}
	case dnsTypeTXT:
		// TXT: 多个 length-prefixed 字符串
		var parts []string
		pos := 0
		for pos < len(rdata) {
			ln := int(rdata[pos])
			pos++
			if pos+ln > len(rdata) {
				break
			}
			parts = append(parts, string(rdata[pos:pos+ln]))
			pos += ln
		}
		return strings.Join(parts, "")
	}
	return ""
}

// dnsTypeName 返回 RR 类型名。
func dnsTypeName(t uint16) string {
	switch t {
	case dnsTypeA:
		return "A"
	case dnsTypeNS:
		return "NS"
	case dnsTypeCNAME:
		return "CNAME"
	case dnsTypeSOA:
		return "SOA"
	case dnsTypePTR:
		return "PTR"
	case dnsTypeMX:
		return "MX"
	case dnsTypeTXT:
		return "TXT"
	case dnsTypeAAAA:
		return "AAAA"
	case dnsTypeSRV:
		return "SRV"
	}
	return fmt.Sprintf("TYPE%d", t)
}

// dnsRCodeName 返回 RCode 名。
func dnsRCodeName(rc uint8) string {
	m := map[uint8]string{
		0: "NoError", 1: "FormErr", 2: "ServFail", 3: "NXDOMAIN",
		4: "NotImp", 5: "Refused",
	}
	if name, ok := m[rc]; ok {
		return name
	}
	return fmt.Sprintf("rcode %d", rc)
}
