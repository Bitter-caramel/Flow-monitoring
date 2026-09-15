package l7

import (
	"fmt"
	"net"

	"flow-monitoring/internal/kernel/datamodel"
)

// DHCP 消息类型（option 53）。
var dhcpMsgTypes = map[uint8]string{
	1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
	5: "ACK", 6: "NAK", 7: "Release", 8: "Inform",
}

// dhcp 解析 DHCP 报文（对应 PacketLens dhcp() index.html:2875 的 P0 子集）。
func dhcp(p *datamodel.Packet, b []byte) {
	if len(b) < 240 {
		p.Proto = "DHCP"
		p.Info = "DHCP 报文过短"
		return
	}

	op := b[0]
	xid := u32be(b, 4)
	ciaddr := net.IP(b[12:16]).String()
	yiaddr := net.IP(b[16:20]).String()
	siaddr := net.IP(b[20:24]).String()

	d := &datamodel.DHCP{
		Op:     op,
		XID:    xid,
		CIADDR: ciaddr,
		YIADDR: yiaddr,
		SIADDR: siaddr,
	}

	// 选项区：magic cookie 后
	if u32be(b, 236) == 0x63825363 {
		o := 240
		for o+2 <= len(b) {
			opt := b[o]
			if opt == 255 { // End
				break
			}
			if opt == 0 { // Pad
				o++
				continue
			}
			ln := int(b[o+1])
			if o+2+ln > len(b) {
				break
			}
			val := b[o+2 : o+2+ln]
			switch opt {
			case 53: // Message Type
				if len(val) >= 1 {
					d.MsgType = dhcpMsgTypes[val[0]]
				}
			case 12: // Host Name
				d.HostName = string(val)
			case 51: // Lease Time
				if len(val) >= 4 {
					d.LeaseTime = u32be(val, 0)
				}
			}
			o += 2 + ln
		}
	}

	p.DHCP = d
	p.Proto = "DHCP"

	msgType := d.MsgType
	if msgType == "" {
		if op == 1 {
			msgType = "Request"
		} else {
			msgType = "Reply"
		}
	}
	p.Info = fmt.Sprintf("DHCP %s - Transaction ID 0x%08x", msgType, xid)
}
