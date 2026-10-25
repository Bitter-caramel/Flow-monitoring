package query

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/internal/modules/parse/decoder"
	"flow-monitoring/internal/modules/parse/pcapng"
)

const (
	// maxDetailFileSize 是包详情接口允许读取的单个抓包文件上限（64 MB）。
	// 超过直接 413，避免一个超大文件在单次请求里把内存打满。
	// ★ 仅在"无偏移索引、退回全量解析"时生效；有 offset 时只读一个包。
	maxDetailFileSize = 64 << 20
	// maxDetailPacketSize 是单包 CapLen 的防御上限（16 MB）。
	// 索引异常（截断/损坏）时避免把超大值带进 make([]byte, n)。
	maxDetailPacketSize = 16 << 20
	// maxPayloadText 是 payload_text 的上限（8 KB），超出部分截断并标记。
	maxPayloadText = 8 * 1024
	// detailTimeLayout 固定 6 位小数 + 时区，与前端契约示例一致。
	detailTimeLayout = "2006-01-02T15:04:05.000000Z07:00"
)

var (
	// ErrInvalidPacketNo 包序号非法（< 1）。
	ErrInvalidPacketNo = errors.New("包序号必须大于等于 1")

	// ErrPacketNotFound 包序号超出该抓包的实际包数（HTTP 404）。
	ErrPacketNotFound = errors.New("该包不存在")
	// ErrFileTooLarge 单次详情读取超过大小上限（整文件 64 MB / 单包 16 MB）。
	// 复用同一个 sentinel，让 handler 统一映射成 413。
	ErrFileTooLarge = errors.New("单次详情读取超过大小上限")
)

// LayerField 是协议树中的一个字段（键值对）。
//
// 对应前端契约 {"k": "...", "v": "..."}；不把字段做成 map，避免顺序丢失。
type LayerField struct {
	K string `json:"k"`
	V string `json:"v"`
}

// Layer 是协议树中的一层。
//
// Fields 必须是非 nil 数组（未知层也要给空数组），这样前端可以直接循环，
// 不会因为 JSON null 崩掉。
type Layer struct {
	Name   string       `json:"name"`
	Fields []LayerField `json:"fields"`
}

// PacketDetail 是单包详情响应。
//
// ★ 字段名是前后端契约，不要改。十六进制与协议分层都从原始抓包文件现解析，
// 不依赖 storage.PacketRecord（它只有元数据）。
type PacketDetail struct {
	No               int      `json:"no"`
	Time             string   `json:"time"`
	CapLen           int      `json:"cap_len"`
	OrigLen          int      `json:"orig_len"`
	LinkType         int      `json:"link_type"`
	Layers           []Layer  `json:"layers"`
	Hex              []string `json:"hex"`
	PayloadText      string   `json:"payload_text"`
	PayloadTruncated bool     `json:"payload_truncated"`
}

// PacketDetail 返回某 capture 第 no 个包（从 1 起）的协议分层、十六进制与载荷。
//
// 错误约定：
//   - no < 1                      → ErrInvalidPacketNo（HTTP 400）
//   - capture 不存在              → storage.ErrNotFound（HTTP 404）
//   - no 超过文件内包数           → storage.ErrNotFound（HTTP 404）
//   - 单包 CapLen 超过 16 MB      → ErrFileTooLarge（HTTP 413）
//   - 无偏移索引且文件超过 64 MB  → ErrFileTooLarge（HTTP 413）
//   - 读取/解析失败               → 携带原因的错误（HTTP 500）
//
// 性能（C2）：packets 表里有 Offset 时只 Seek 到该偏移读 CapLen 字节，
// 不再全量解析文件；旧数据（Offset=0）退回原有"全量解析"路径并保留 64 MB 上限。
func (s *Service) PacketDetail(ctx context.Context, captureID string, no int) (*PacketDetail, error) {
	if no < 1 {
		return nil, ErrInvalidPacketNo
	}

	rec, err := s.db.Captures().Get(ctx, captureID)
	if err != nil {
		return nil, err
	}

	// ★ 越界与"旧数据没有索引"是两回事：
	//   越界 ⇒ 这个包根本不存在 ⇒ 404；
	//   旧数据 ⇒ 包存在但 offset=0 ⇒ 退回全量解析。
	//   否则大文件越界会误报 413（fallback 的大小检查）。
	if rec.PacketCount > 0 && no > rec.PacketCount {
		return nil, ErrPacketNotFound
	}

	path := filepath.Join(s.getDataDir(), rec.FilePath)

	// ★ C2：优先走偏移索引，只读那一个包。旧数据 offset=0 ⇒ 退回全量解析。
	if pr := s.packetRecordAt(ctx, captureID, no); pr != nil && pr.Offset > 0 && pr.CapLen > 0 {
		return s.packetDetailByOffset(path, rec, pr, no)
	}
	return s.packetDetailByFullParse(path, no)
}

// packetRecordAt 按 capture_id + no 取单条 PacketRecord 索引；取不到返回 nil。
//
// 存储不可用/旧数据没有包索引时返回 nil，由调用方退回全量解析路径，
// 避免"原文件明明在，却因为索引缺失打不开"。
func (s *Service) packetRecordAt(ctx context.Context, captureID string, no int) *storage.PacketRecord {
	res, err := s.db.Packets().ListByCapture(ctx, captureID, storage.Page{Offset: no - 1, Limit: 1})
	if err != nil || res == nil || len(res.Items) != 1 {
		return nil
	}
	return &res.Items[0]
}

// packetDetailByOffset 用 packets.offset 定位并只读取一个包的数据。
func (s *Service) packetDetailByOffset(path string, rec *storage.CaptureRecord, pr *storage.PacketRecord, no int) (*PacketDetail, error) {
	// ★ 防异常 CapLen（截断/损坏的索引）把内存打满。
	if pr.CapLen > maxDetailPacketSize {
		return nil, fmt.Errorf("%w: 单包抓取长度 %d 字节超过 16 MB 上限", ErrFileTooLarge, pr.CapLen)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("读取抓包文件失败: %w", err)
	}
	defer f.Close()

	if _, err := f.Seek(int64(pr.Offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("定位包偏移失败（偏移索引可能失效，请重新导入该文件）: %w", err)
	}

	buf := make([]byte, pr.CapLen)
	if _, err := io.ReadFull(f, buf); err != nil {
		// 文件被截断 / offset 与 CapLen 不一致：给出明确原因，绝不 panic。
		return nil, fmt.Errorf("读取包数据失败（偏移索引可能失效，请重新导入该文件）: %w", err)
	}

	p := datamodel.NewPacket()
	p.No = no
	p.Time = pr.Time
	if !pr.Time.IsZero() {
		p.Sec = pr.Time.Unix()
		p.Usec = int64(pr.Time.Nanosecond() / 1000)
	}
	p.CapLen = pr.CapLen
	p.OrigLen = pr.OrigLen
	if p.OrigLen <= 0 {
		p.OrigLen = p.CapLen
	}
	p.Data = buf
	p.Offset = pr.Offset

	linkType := rec.LinkType
	decoder.Decode(p, linkType)
	if p.Malformed {
		// ★ E：偏移指向的字节解不出完整包 ⇒ 索引可能失效，要求重新导入。
		return nil, fmt.Errorf("偏移索引可能失效（偏移 %d 处的包解码失败），请重新导入该文件", pr.Offset)
	}

	return detailFromPacket(p, linkType), nil
}

// packetDetailByFullParse 是旧路径：读取并全量解析到第 no 个包。
//
// Offset=0 的旧数据仍走这里；64 MB 上限只在这条路上生效。
func (s *Service) packetDetailByFullParse(path string, no int) (*PacketDetail, error) {
	// ★ 先 Stat 再 ReadFile：大于上限时不把文件读进内存。
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("读取抓包文件失败: %w", err)
	}
	if fi.Size() > maxDetailFileSize {
		return nil, ErrFileTooLarge
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取抓包文件失败: %w", err)
	}

	// limit=no：只解析到需要的包，避免为取第 1 个包解析整个大文件。
	capture, err := pcapng.Parse(data, no)
	if err != nil {
		return nil, fmt.Errorf("解析抓包文件失败: %w", err)
	}
	if no > len(capture.Packets) {
		return nil, storage.ErrNotFound
	}

	p := capture.Packets[no-1]
	linkType := capture.LinkType
	if p.Iface >= 0 && p.Iface < len(capture.Ifaces) {
		linkType = capture.Ifaces[p.Iface].LinkType
	}

	// ★ 复用既有解码库：decoder 内部持有全套 gopacket 层对象，
	// 并把 L7 结果（HTTP/DNS/TLS）写进 datamodel.Packet。
	// 注意：decoder 的层对象是复用的，这里只在本函数内使用 p，不跨包持有引用。
	decoder.Decode(p, linkType)

	return detailFromPacket(p, linkType), nil
}

// detailFromPacket 把已解码的 datamodel.Packet 转成响应。
func detailFromPacket(p *datamodel.Packet, linkType int) *PacketDetail {
	payloadText, truncated := detailPayload(p)
	return &PacketDetail{
		No:               p.No,
		Time:             p.Time.Format(detailTimeLayout),
		CapLen:           p.CapLen,
		OrigLen:          p.OrigLen,
		LinkType:         linkType,
		Layers:           buildDetailLayers(p, linkType),
		Hex:              formatDetailHex(p.Data),
		PayloadText:      payloadText,
		PayloadTruncated: truncated,
	}
}

// detailPayload 返回 L7 可读载荷（最多 8 KB），并报告是否发生截断。
//
// 载荷边界来自 decoder：PayloadOff/PayloadLen 相对包字节。对二进制协议
// （如 TLS 密文）逐 rune 清洗，不可打印/非法 UTF-8 一律替换成 '.'。
func detailPayload(p *datamodel.Packet) (string, bool) {
	off, ln := p.PayloadOff, p.PayloadLen
	if off < 0 || ln <= 0 || off+ln > len(p.Data) {
		return "", false
	}
	b := p.Data[off : off+ln]
	truncated := false
	if len(b) > maxPayloadText {
		b = b[:maxPayloadText]
		truncated = true
	}
	return sanitizeDetailText(b), truncated
}

// sanitizeDetailText 把任意字节转成前端安全的可读文本。
//
// 保留 \r\n\t 与可打印字符（含合法的多字节 UTF-8），其余用 '.' 替代。
func sanitizeDetailText(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			sb.WriteByte('.')
			i++
			continue
		}
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			sb.WriteRune(r)
		case r >= 0x20 && r != 0x7f && unicode.IsPrint(r):
			sb.WriteRune(r)
		default:
			sb.WriteByte('.')
		}
		i += size
	}
	return sb.String()
}

// formatDetailHex 把原始字节格式化为 Wireshark 风格十六进制行：
//
//	偏移(4位hex) + 两个空格 + 16 字节 hex + 两个空格 + 可打印 ASCII（不可打印为 '.'）
//
// 偏移由 4 位小写十六进制输出；超过 0xffff 时自然扩展，不影响前端解析。
func formatDetailHex(data []byte) []string {
	if len(data) == 0 {
		return []string{}
	}
	lines := make([]string, 0, (len(data)+15)/16)
	for off := 0; off < len(data); off += 16 {
		var sb strings.Builder
		fmt.Fprintf(&sb, "%04x  ", off)
		for i := 0; i < 16; i++ {
			if off+i < len(data) {
				fmt.Fprintf(&sb, "%02x ", data[off+i])
			} else {
				sb.WriteString("   ")
			}
		}
		sb.WriteByte(' ')
		for i := 0; i < 16 && off+i < len(data); i++ {
			c := data[off+i]
			if c >= 0x20 && c <= 0x7e {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		lines = append(lines, sb.String())
	}
	return lines
}

// buildDetailLayers 构造协议分层树。
//
// ★ 先补 Frame 层；随后按链路类型选择起始层，用 gopacket 解出真实层顺序。
// ★ 未知层绝不静默跳过：用 {"name": "<LayerType>", "fields": []} 占位。
// ★ HTTP 不是 gopacket 层，由 decoder 的 L7 结果补在传输层之后。
func buildDetailLayers(p *datamodel.Packet, linkType int) []Layer {
	out := []Layer{{
		Name:   "Frame",
		Fields: []LayerField{{K: "frame.len", V: strconv.Itoa(p.OrigLen)}},
	}}

	first, data, ok := detailFirstLayer(p.Data, linkType)
	if !ok {
		// 不认识的链路类型：保留占位，便于前端/排障看到，而不是只给一个 Frame。
		out = append(out, Layer{Name: fmt.Sprintf("LinkType %d", linkType), Fields: []LayerField{}})
		return out
	}

	pkt := detailNewPacket(data, first)
	sawDNS, sawTLS := false, false
	if pkt != nil {
		for _, l := range pkt.Layers() {
			if l.LayerType() == gopacket.LayerTypePayload {
				continue // Payload 由 L7 层（HTTP/DNS/TLS/Data）表达
			}
			switch l.LayerType() {
			case layers.LayerTypeDNS:
				sawDNS = true
			case layers.LayerTypeTLS:
				sawTLS = true
			}

			layer, extracted := extractDetailLayer(l, p)
			if extracted {
				out = append(out, layer)
				continue
			}

			// 未知层占位。DecodeFailure 额外把原因写进 fields，避免"只失败不说原因"。
			name := l.LayerType().String()
			fields := []LayerField{}
			if df, bad := l.(*gopacket.DecodeFailure); bad {
				name = "Malformed"
				if msg := df.Error(); msg != nil {
					fields = append(fields, LayerField{K: "error", V: msg.Error()})
				}
			}
			out = append(out, Layer{Name: name, Fields: fields})
		}
	}

	switch {
	case p.HTTP != nil:
		out = append(out, httpDetailLayer(p.HTTP))
	case p.DNS != nil && !sawDNS:
		out = append(out, dnsDetailLayer(p.DNS))
	case p.TLS != nil && !sawTLS:
		out = append(out, tlsDetailLayer(p.TLS))
	case p.PayloadLen > 0:
		// 未识别出 L7 的载荷：至少给出 Data 层，不让字节凭空消失。
		out = append(out, Layer{Name: "Data", Fields: []LayerField{{K: "data.len", V: strconv.Itoa(p.PayloadLen)}}})
	}
	return out
}

// detailFirstLayer 按链路类型选择 gopacket 起始层，返回起始层类型和实际字节。
//
// 与 decoder 支持的链路类型保持一致：Ethernet(1/279)、NULL loopback(0)、
// 裸 IP(12/14/101/228/229)。
func detailFirstLayer(data []byte, linkType int) (gopacket.LayerType, []byte, bool) {
	if len(data) == 0 {
		return 0, nil, false
	}
	switch linkType {
	case 1, 279: // Ethernet II
		return layers.LayerTypeEthernet, data, true
	case 0: // BSD NULL loopback：4 字节地址族 + 内层 IP
		if len(data) < 4 {
			return 0, nil, false
		}
		fam := binary.BigEndian.Uint32(data[:4])
		data = data[4:]
		switch fam {
		case 2:
			return layers.LayerTypeIPv4, data, true
		case 24, 28, 30:
			return layers.LayerTypeIPv6, data, true
		default:
			return 0, nil, false
		}
	case 12, 14, 101, 228, 229: // 裸 IP
		switch data[0] >> 4 {
		case 4:
			return layers.LayerTypeIPv4, data, true
		case 6:
			return layers.LayerTypeIPv6, data, true
		default:
			return 0, nil, false
		}
	default:
		return 0, nil, false
	}
}

// detailNewPacket 安全地创建 gopacket.Packet：畸形包解码 panic 不应打垮接口。
func detailNewPacket(data []byte, first gopacket.LayerType) (pkt gopacket.Packet) {
	defer func() {
		if recover() != nil {
			pkt = nil
		}
	}()
	return gopacket.NewPacket(data, first, gopacket.Default)
}

// extractDetailLayer 把单个 gopacket 层映射成协议树的一层。
//
// 返回 false 表示未覆盖该层，由调用方按未知层占位。
func extractDetailLayer(l gopacket.Layer, p *datamodel.Packet) (Layer, bool) {
	switch v := l.(type) {
	case *layers.Ethernet:
		return Layer{Name: "Ethernet II", Fields: []LayerField{
			{K: "dst", V: v.DstMAC.String()},
			{K: "src", V: v.SrcMAC.String()},
			{K: "type", V: etherTypeLabel(v.EthernetType)},
		}}, true

	case *layers.Dot1Q:
		return Layer{Name: "802.1Q Virtual LAN", Fields: []LayerField{
			{K: "prio", V: strconv.Itoa(int(v.Priority))},
			{K: "dei", V: boolLabel(v.DropEligible)},
			{K: "vlan", V: strconv.Itoa(int(v.VLANIdentifier))},
			{K: "type", V: etherTypeLabel(v.Type)},
		}}, true

	case *layers.ARP:
		return Layer{Name: "Address Resolution Protocol", Fields: []LayerField{
			{K: "opcode", V: strconv.Itoa(int(v.Operation))},
			{K: "sender_ip", V: arpIP(v.SourceProtAddress)},
			{K: "sender_mac", V: arpMAC(v.SourceHwAddress)},
			{K: "target_ip", V: arpIP(v.DstProtAddress)},
			{K: "target_mac", V: arpMAC(v.DstHwAddress)},
		}}, true

	case *layers.IPv4:
		return Layer{Name: "Internet Protocol Version 4", Fields: []LayerField{
			{K: "version", V: strconv.Itoa(int(v.Version))},
			{K: "ihl", V: strconv.Itoa(int(v.IHL))},
			{K: "src", V: v.SrcIP.String()},
			{K: "dst", V: v.DstIP.String()},
			{K: "ttl", V: strconv.Itoa(int(v.TTL))},
			{K: "protocol", V: ipProtocolLabel(v.Protocol)},
			{K: "length", V: strconv.Itoa(int(v.Length))},
			{K: "id", V: fmt.Sprintf("0x%04x", v.Id)},
			{K: "flags", V: v.Flags.String()},
			{K: "frag_offset", V: strconv.Itoa(int(v.FragOffset))},
			{K: "checksum", V: fmt.Sprintf("0x%04x", v.Checksum)},
		}}, true

	case *layers.IPv6:
		return Layer{Name: "Internet Protocol Version 6", Fields: []LayerField{
			{K: "version", V: strconv.Itoa(int(v.Version))},
			{K: "traffic_class", V: fmt.Sprintf("0x%02x", v.TrafficClass)},
			{K: "flow_label", V: fmt.Sprintf("0x%05x", v.FlowLabel)},
			{K: "src", V: v.SrcIP.String()},
			{K: "dst", V: v.DstIP.String()},
			{K: "hop_limit", V: strconv.Itoa(int(v.HopLimit))},
			{K: "next_header", V: ipProtocolLabel(v.NextHeader)},
			{K: "length", V: strconv.Itoa(int(v.Length))},
		}}, true

	case *layers.TCP:
		fields := []LayerField{
			{K: "srcport", V: strconv.Itoa(int(v.SrcPort))},
			{K: "dstport", V: strconv.Itoa(int(v.DstPort))},
			{K: "seq", V: strconv.FormatUint(uint64(v.Seq), 10)},
			{K: "ack", V: strconv.FormatUint(uint64(v.Ack), 10)},
			{K: "flags", V: tcpFlagsLabel(v)},
			{K: "window", V: strconv.Itoa(int(v.Window))},
			{K: "checksum", V: fmt.Sprintf("0x%04x", v.Checksum)},
			{K: "urgptr", V: strconv.Itoa(int(v.Urgent))},
			{K: "data_offset", V: strconv.Itoa(int(v.DataOffset))},
		}
		if opts := tcpOptionsLabel(v.Options); opts != "" {
			fields = append(fields, LayerField{K: "options", V: opts})
		}
		return Layer{Name: "Transmission Control Protocol", Fields: fields}, true

	case *layers.UDP:
		return Layer{Name: "User Datagram Protocol", Fields: []LayerField{
			{K: "srcport", V: strconv.Itoa(int(v.SrcPort))},
			{K: "dstport", V: strconv.Itoa(int(v.DstPort))},
			{K: "length", V: strconv.Itoa(int(v.Length))},
			{K: "checksum", V: fmt.Sprintf("0x%04x", v.Checksum)},
		}}, true

	case *layers.ICMPv4:
		return Layer{Name: "Internet Control Message Protocol", Fields: []LayerField{
			{K: "type", V: strconv.Itoa(int(v.TypeCode.Type()))},
			{K: "code", V: strconv.Itoa(int(v.TypeCode.Code()))},
			{K: "summary", V: v.TypeCode.String()},
			{K: "checksum", V: fmt.Sprintf("0x%04x", v.Checksum)},
			{K: "id", V: strconv.Itoa(int(v.Id))},
			{K: "seq", V: strconv.Itoa(int(v.Seq))},
		}}, true

	case *layers.ICMPv6:
		return Layer{Name: "Internet Control Message Protocol v6", Fields: []LayerField{
			{K: "type", V: strconv.Itoa(int(v.TypeCode.Type()))},
			{K: "code", V: strconv.Itoa(int(v.TypeCode.Code()))},
			{K: "summary", V: v.TypeCode.String()},
			{K: "checksum", V: fmt.Sprintf("0x%04x", v.Checksum)},
		}}, true

	case *layers.DNS:
		if p != nil && p.DNS != nil {
			return dnsDetailLayer(p.DNS), true
		}
		return dnsGoDetailLayer(v), true

	case *layers.TLS:
		if p != nil && p.TLS != nil {
			return tlsDetailLayer(p.TLS), true
		}
		return tlsGoDetailLayer(v), true
	}
	return Layer{}, false
}

// httpDetailLayer 把 decoder 的 HTTP 结果映射成协议树层。
func httpDetailLayer(h *datamodel.HTTP) Layer {
	fields := make([]LayerField, 0, 8)
	add := func(k, v string) {
		if v != "" {
			fields = append(fields, LayerField{K: k, V: v})
		}
	}

	if h.IsRequest {
		add("request.method", h.Method)
		add("request.uri", h.URI)
	} else if h.StatusCode != 0 {
		add("response.code", strconv.Itoa(h.StatusCode))
		add("response.text", h.StatusText)
	}
	add("http.host", h.Host)
	add("http.user_agent", h.UserAgent)
	add("http.content_type", h.ContentType)
	if h.ContentLength != 0 {
		add("http.content_length", strconv.FormatInt(h.ContentLength, 10))
	}
	if h.HeaderLen > 0 {
		add("http.header_len", strconv.Itoa(h.HeaderLen))
	}
	return Layer{Name: "Hypertext Transfer Protocol", Fields: fields}
}

// dnsDetailLayer 把 decoder 的 DNS 结果映射成协议树层。
func dnsDetailLayer(d *datamodel.DNS) Layer {
	fields := []LayerField{
		{K: "dns.id", V: fmt.Sprintf("0x%04x", d.ID)},
		{K: "dns.flags.response", V: bool01(d.QR)},
		{K: "dns.flags.opcode", V: strconv.Itoa(int(d.OpCode))},
		{K: "dns.flags.rcode", V: strconv.Itoa(int(d.RCode))},
		{K: "dns.count.queries", V: strconv.Itoa(len(d.Questions))},
		{K: "dns.count.answers", V: strconv.Itoa(len(d.Answers))},
	}
	for _, q := range d.Questions {
		fields = append(fields,
			LayerField{K: "dns.qry.name", V: q.Name},
			LayerField{K: "dns.qry.type", V: dnsTypeLabel(q.Type)},
		)
	}
	for _, a := range d.Answers {
		fields = append(fields,
			LayerField{K: "dns.resp.name", V: a.Name},
			LayerField{K: "dns.resp.type", V: dnsTypeLabel(a.Type)},
			LayerField{K: "dns.resp.ttl", V: strconv.FormatUint(uint64(a.TTL), 10)},
			LayerField{K: "dns.resp.data", V: a.Data},
		)
	}
	return Layer{Name: "Domain Name System", Fields: fields}
}

// dnsGoDetailLayer 是 decoder 未产出 DNS 结构时的兜底（直接用 gopacket 层）。
func dnsGoDetailLayer(d *layers.DNS) Layer {
	fields := []LayerField{
		{K: "dns.id", V: fmt.Sprintf("0x%04x", d.ID)},
		{K: "dns.flags.response", V: bool01(d.QR)},
		{K: "dns.flags.opcode", V: strconv.Itoa(int(d.OpCode))},
		{K: "dns.flags.rcode", V: strconv.Itoa(int(d.ResponseCode))},
		{K: "dns.count.queries", V: strconv.Itoa(len(d.Questions))},
		{K: "dns.count.answers", V: strconv.Itoa(len(d.Answers))},
	}
	for _, q := range d.Questions {
		fields = append(fields,
			LayerField{K: "dns.qry.name", V: string(q.Name)},
			LayerField{K: "dns.qry.type", V: q.Type.String()},
		)
	}
	for _, a := range d.Answers {
		fields = append(fields,
			LayerField{K: "dns.resp.name", V: string(a.Name)},
			LayerField{K: "dns.resp.type", V: a.Type.String()},
			LayerField{K: "dns.resp.ttl", V: strconv.FormatUint(uint64(a.TTL), 10)},
		)
	}
	return Layer{Name: "Domain Name System", Fields: fields}
}

// tlsDetailLayer 把 decoder 的 TLS 结果映射成协议树层。
func tlsDetailLayer(t *datamodel.TLS) Layer {
	fields := []LayerField{
		{K: "tls.record.content_type", V: tlsRecordTypeLabel(t.RecordType)},
		{K: "tls.record.version", V: tlsVersionLabel(t.RecordVersion)},
	}
	if t.HandshakeType != 0 {
		fields = append(fields, LayerField{K: "tls.handshake.type", V: tlsHandshakeTypeLabel(t.HandshakeType)})
	}
	if t.SNI != "" {
		fields = append(fields, LayerField{K: "tls.handshake.extensions_server_name", V: t.SNI})
	}
	if t.Version != 0 {
		fields = append(fields, LayerField{K: "tls.handshake.version", V: tlsVersionLabel(t.Version)})
	}
	if t.CipherSuite != 0 {
		fields = append(fields, LayerField{K: "tls.handshake.ciphersuite", V: fmt.Sprintf("0x%04x", t.CipherSuite)})
	}
	if t.ALPN != "" {
		fields = append(fields, LayerField{K: "tls.alpn", V: t.ALPN})
	}
	if t.ServerName != "" {
		fields = append(fields, LayerField{K: "tls.server_name", V: t.ServerName})
	}
	return Layer{Name: "Transport Layer Security", Fields: fields}
}

// tlsGoDetailLayer 是 decoder 未产出 TLS 结构时的兜底（直接用 gopacket 层）。
func tlsGoDetailLayer(t *layers.TLS) Layer {
	fields := []LayerField{
		{K: "tls.record.handshake_count", V: strconv.Itoa(len(t.Handshake))},
		{K: "tls.record.change_cipher_spec_count", V: strconv.Itoa(len(t.ChangeCipherSpec))},
		{K: "tls.record.application_data_count", V: strconv.Itoa(len(t.AppData))},
		{K: "tls.record.alert_count", V: strconv.Itoa(len(t.Alert))},
	}
	if len(t.Handshake) > 0 {
		h := t.Handshake[0]
		fields = append(fields,
			LayerField{K: "tls.record.content_type", V: tlsRecordTypeLabel(uint8(h.ContentType))},
			LayerField{K: "tls.record.version", V: tlsVersionLabel(uint16(h.Version))},
			LayerField{K: "tls.handshake.type", V: tlsHandshakeTypeLabel(h.ClientHello.HandshakeType)},
		)
		if h.ClientHello.HandshakeType == layers.TLSHandshakeClientHello {
			fields = append(fields,
				LayerField{K: "tls.handshake.version", V: tlsVersionLabel(uint16(h.ClientHello.ProtocolVersion))},
			)
			if len(h.ClientHello.SNI) > 0 {
				fields = append(fields, LayerField{K: "tls.handshake.extensions_server_name", V: string(h.ClientHello.SNI)})
			}
		}
	}
	return Layer{Name: "Transport Layer Security", Fields: fields}
}

// etherTypeLabel 返回 "IPv4 (0x0800)" 形式的展示值。
func etherTypeLabel(t layers.EthernetType) string {
	return fmt.Sprintf("%s (0x%04x)", t.String(), uint16(t))
}

// ipProtocolLabel 返回 "TCP (6)" 形式的展示值。
func ipProtocolLabel(p layers.IPProtocol) string {
	return fmt.Sprintf("%s (%d)", p.String(), uint8(p))
}

// boolLabel / bool01 统一布尔展示：Wireshark 风格用 1/0。
func boolLabel(b bool) string { return bool01(b) }

func bool01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// tcpFlagsLabel 按 Wireshark 顺序拼接 TCP 标志。
func tcpFlagsLabel(t *layers.TCP) string {
	var flags []string
	if t.FIN {
		flags = append(flags, "FIN")
	}
	if t.SYN {
		flags = append(flags, "SYN")
	}
	if t.RST {
		flags = append(flags, "RST")
	}
	if t.PSH {
		flags = append(flags, "PSH")
	}
	if t.ACK {
		flags = append(flags, "ACK")
	}
	if t.URG {
		flags = append(flags, "URG")
	}
	if t.ECE {
		flags = append(flags, "ECE")
	}
	if t.CWR {
		flags = append(flags, "CWR")
	}
	if t.NS {
		flags = append(flags, "NS")
	}
	return strings.Join(flags, ", ")
}

// tcpOptionsLabel 渲染 TCP 选项；无选项返回空串。
func tcpOptionsLabel(opts []layers.TCPOption) string {
	if len(opts) == 0 {
		return ""
	}
	parts := make([]string, 0, len(opts))
	for _, o := range opts {
		s := o.OptionType.String()
		if len(o.OptionData) > 0 {
			s += fmt.Sprintf("=%x", o.OptionData)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// arpIP / arpMAC 容错格式化 ARP 地址（越界返回空串，不 panic）。
func arpIP(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func arpMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// dnsTypeLabel 把常见 DNS 类型映射成名称+类型号。
func dnsTypeLabel(t uint16) string {
	name := map[uint16]string{
		1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
		15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
	}[t]
	if name == "" {
		return strconv.Itoa(int(t))
	}
	return fmt.Sprintf("%s (%d)", name, t)
}

// tlsRecordTypeLabel 返回 TLS 记录类型名称。
func tlsRecordTypeLabel(t uint8) string {
	name := map[uint8]string{
		20: "Change Cipher Spec",
		21: "Alert",
		22: "Handshake",
		23: "Application Data",
	}[t]
	if name == "" {
		return strconv.Itoa(int(t))
	}
	return fmt.Sprintf("%s (%d)", name, t)
}

// tlsVersionLabel 返回 TLS/SSL 版本名称。
func tlsVersionLabel(v uint16) string {
	switch v {
	case 0x0300:
		return "SSL 3.0 (0x0300)"
	case 0x0301:
		return "TLS 1.0 (0x0301)"
	case 0x0302:
		return "TLS 1.1 (0x0302)"
	case 0x0303:
		return "TLS 1.2 (0x0303)"
	case 0x0304:
		return "TLS 1.3 (0x0304)"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// tlsHandshakeTypeLabel 返回 TLS 握手类型名称。
func tlsHandshakeTypeLabel(t uint8) string {
	name := map[uint8]string{
		0: "Hello Request", 1: "Client Hello", 2: "Server Hello",
		4: "New Session Ticket", 11: "Certificate", 12: "Server Key Exchange",
		13: "Certificate Request", 14: "Server Hello Done",
		15: "Certificate Verify", 16: "Client Key Exchange", 20: "Finished",
	}[t]
	if name == "" {
		return strconv.Itoa(int(t))
	}
	return fmt.Sprintf("%s (%d)", name, t)
}
