// Command mkpcap 是可复现的攻击/正常样本生成器。
//
// 产出 6 个场景（normal + 5 种攻击）的 pcapng 文件，作为检测规则验证的弹药基线。
// 所有场景只发单向数据包，不依赖 TCP 重组；地址、端口、时间戳全部固定，
// 保证同一 (scenario, seed) 的输出逐字节可复现。
//
// 用法：
//
//	mkpcap -scenario <name> -out <path> [-seed N]
//	mkpcap -scenario all  -out <dir>
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"flow-monitoring/internal/modules/parse/pcapng"
)

const (
	exitOK    = 0
	exitRun   = 1
	exitUsage = 2

	// linkTypeEthernet 是 pcapng LINKTYPE_ETHERNET。
	linkTypeEthernet = 1
)

const usageText = `mkpcap — 可复现的攻击/正常样本生成器

用法:
  mkpcap -scenario <name> -out <path> [-seed N]
  mkpcap -scenario all  -out <dir>

场景:
  normal     1 个 TCP HTTP GET（正常）+ 1 个 UDP DNS 查询
  sqli       1 个 TCP HTTP GET（URI 含 UNION SELECT）
  traversal  1 个 TCP HTTP GET（/../../etc/passwd）
  dotgit     1 个 TCP HTTP GET（/.git/config）
  c2ua       1 个 TCP HTTP GET（旧版 MSIE User-Agent）
  dnstunnel  1 个 UDP DNS 查询（首段 >= 40 个 a 的超长标签）
  all        生成以上全部场景，-out 视为输出目录

选项:
  -scenario string  场景名（见上）
  -out string       单场景：输出文件路径；all：输出目录
  -seed int         随机种子（默认 0，固定以保证可复现）
  -h, --help        显示本帮助

固定地址:
  TCP  10.0.0.1:40000 -> 10.0.0.2:80
  UDP  10.0.0.1:40001 -> 8.8.8.8:53

退出码: 0 成功 / 2 用法错误 / 1 运行错误
`

// baseTime 是所有样本的固定基准时间；每个包在其后 +1ms。
var baseTime = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// packetSpec 描述单个数据包：TCP 携带 HTTP 载荷，UDP 携带 DNS 查询名。
type packetSpec struct {
	proto   string // "tcp" | "udp"
	payload string // TCP: 完整 HTTP 报文（\r\n 换行）
	dnsName string // UDP: DNS 查询名
}

// scenarioOrder 是场景的稳定顺序（也用于 -scenario all 的文件生成顺序）。
var scenarioOrder = []string{"normal", "sqli", "traversal", "dotgit", "c2ua", "dnstunnel"}

// scenarios 返回全部场景定义，内容逐字对应任务 14-2a 的表格。
func scenarios() map[string][]packetSpec {
	return map[string][]packetSpec{
		"normal": {
			{proto: "tcp", payload: "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"},
			{proto: "udp", dnsName: "www.example.com"},
		},
		"sqli": {
			{proto: "tcp", payload: "GET /search?q=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1\r\nHost: www.example.com\r\n\r\n"},
		},
		"traversal": {
			{proto: "tcp", payload: "GET /../../etc/passwd HTTP/1.1\r\nHost: www.example.com\r\n\r\n"},
		},
		"dotgit": {
			{proto: "tcp", payload: "GET /.git/config HTTP/1.1\r\nHost: www.example.com\r\n\r\n"},
		},
		"c2ua": {
			{proto: "tcp", payload: "GET / HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)\r\n\r\n"},
		},
		"dnstunnel": {
			{proto: "udp", dnsName: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil-tunnel.example"},
		},
	}
}

// buildFrame 用 gopacket layers 构造一个以太网帧并序列化。
//
// seed 仅用于 DNS 事务 ID，保证同 seed 输出可复现（默认 0）。
func buildFrame(spec packetSpec, seed int64) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{10, 0, 0, 1},
	}

	switch spec.proto {
	case "tcp":
		ip.DstIP = net.IP{10, 0, 0, 2}
		ip.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{
			SrcPort: 40000,
			DstPort: 80,
			Seq:     1,
			Ack:     1,
			PSH:     true,
			ACK:     true,
			Window:  65535,
		}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			return nil, fmt.Errorf("tcp checksum: %w", err)
		}
		return serialize(eth, ip, tcp, gopacket.Payload([]byte(spec.payload)))
	case "udp":
		ip.DstIP = net.IP{8, 8, 8, 8}
		ip.Protocol = layers.IPProtocolUDP
		udp := &layers.UDP{SrcPort: 40001, DstPort: 53}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			return nil, fmt.Errorf("udp checksum: %w", err)
		}
		dns := &layers.DNS{
			ID:     uint16(0x1234) ^ uint16(seed),
			QR:     false,
			OpCode: layers.DNSOpCodeQuery,
			RD:     true,
			Questions: []layers.DNSQuestion{{
				Name:  []byte(spec.dnsName),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			}},
		}
		return serialize(eth, ip, udp, dns)
	default:
		return nil, fmt.Errorf("未知协议: %q", spec.proto)
	}
}

// serialize 用固定选项序列化各层，返回独立拷贝的字节切片。
func serialize(layersToWrite ...gopacket.SerializableLayer) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, layersToWrite...); err != nil {
		return nil, err
	}
	// buf 来自内部池，复制一份避免后续复用污染。
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out, nil
}

// generate 生成指定场景的完整 pcapng 字节流，返回字节与包数。
func generate(name string, seed int64) (data []byte, packets int, err error) {
	specs, ok := scenarios()[name]
	if !ok {
		return nil, 0, fmt.Errorf("未知 scenario: %q", name)
	}

	var buf bytes.Buffer
	w, err := pcapng.NewWriter(&buf, linkTypeEthernet, 0)
	if err != nil {
		return nil, 0, err
	}
	for i, spec := range specs {
		frame, err := buildFrame(spec, seed)
		if err != nil {
			return nil, 0, fmt.Errorf("场景 %s 第 %d 个包: %w", name, i, err)
		}
		// 从固定基准时间起每包 +1ms，保证时间戳可复现。
		ts := baseTime.Add(time.Duration(i) * time.Millisecond)
		if err := w.WritePacket(ts, frame); err != nil {
			return nil, 0, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), len(specs), nil
}

// run 是 CLI 的可测试入口：返回给 os.Exit 的退出码。
func run(args []string, stdout, stderr io.Writer) int {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "-help" || a == "help" {
			fmt.Fprint(stdout, usageText)
			return exitOK
		}
	}
	if len(args) == 0 {
		fmt.Fprint(stdout, usageText)
		return exitOK
	}

	fs := flag.NewFlagSet("mkpcap", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // 解析错误由 usageErr 统一输出
	var (
		scenarioName string
		out          string
		seed         int64
	)
	fs.StringVar(&scenarioName, "scenario", "", "场景名")
	fs.StringVar(&out, "out", "", "输出路径/目录")
	fs.Int64Var(&seed, "seed", 0, "随机种子")
	if err := fs.Parse(args); err != nil {
		return usageErr(stderr, err.Error())
	}
	if rest := fs.Args(); len(rest) > 0 {
		return usageErr(stderr, "未知参数: "+rest[0])
	}
	if scenarioName == "" {
		return usageErr(stderr, "缺少 -scenario")
	}
	if out == "" {
		return usageErr(stderr, "缺少 -out")
	}
	if scenarioName != "all" {
		if _, ok := scenarios()[scenarioName]; !ok {
			return usageErr(stderr, fmt.Sprintf("未知 scenario: %q", scenarioName))
		}
	}

	if scenarioName == "all" {
		if err := os.MkdirAll(out, 0o755); err != nil {
			return runErr(stderr, err)
		}
		for _, name := range scenarioOrder {
			data, packets, err := generate(name, seed)
			if err != nil {
				return runErr(stderr, err)
			}
			path := filepath.Join(out, name+".pcapng")
			if err := os.WriteFile(path, data, 0o644); err != nil {
				return runErr(stderr, err)
			}
			fmt.Fprintf(stdout, "[%s] 包数=%d 字节数=%d -> %s\n", name, packets, len(data), path)
		}
		return exitOK
	}

	// 单场景：-out 所在目录不存在时自动创建。
	if dir := filepath.Dir(out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return runErr(stderr, err)
		}
	}
	data, packets, err := generate(scenarioName, seed)
	if err != nil {
		return runErr(stderr, err)
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return runErr(stderr, err)
	}
	fmt.Fprintf(stdout, "[%s] 包数=%d 字节数=%d -> %s\n", scenarioName, packets, len(data), out)
	return exitOK
}

// usageErr 打印用法错误并返回退出码 2。
func usageErr(stderr io.Writer, msg string) int {
	fmt.Fprintln(stderr, "错误:", msg)
	fmt.Fprint(stderr, usageText)
	return exitUsage
}

// runErr 打印运行错误并返回退出码 1。
func runErr(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "错误:", err)
	return exitRun
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
