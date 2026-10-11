// Command parse-cli 是协议解析的命令行验证工具。
//
// 读取 pcap/pcapng 文件，解析并输出类似 Wireshark 的包列表，
// 用于验证 pcapng reader + decoder 的解析效果（不依赖后端/数据库）。
//
// 用法：
//
//	parse-cli <file.pcapng> [--limit N] [--analyze] [--top N] [--detect <规则文件>]
//
// 输出列：No / 时间 / 源 → 目的 / 协议 / 长度 / INFO
// 开启 --analyze 后不再逐包打印，改为输出流聚合/协议/端点/端口四段统计。
// 开启 --detect 后加载规则文件做检测，不逐包打印，仅打印命中行与告警汇总。
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/detect"
	"flow-monitoring/internal/modules/parse/analyzer"
	"flow-monitoring/internal/modules/parse/decoder"
	"flow-monitoring/internal/modules/parse/pcapng"
)

func main() {
	limit := flag.Int("limit", 0, "最大解析包数（0=不限制）")
	analyze := flag.Bool("analyze", false, "启用流聚合分析（不逐包打印）")
	top := flag.Int("top", 10, "排行榜显示条数")
	detectPath := flag.String("detect", "", "载入规则文件并做检测（如 --detect rules.rules）")
	flag.Parse()

	// Go 的 flag 包默认在首个位置参数（文件名）处停止解析，
	// 因此把文件名之后的剩余参数再解析一次，
	// 以兼容 `parse-cli <file> --analyze` 这种"文件在前"的用法。
	args := flag.Args()
	if len(args) > 1 {
		_ = flag.CommandLine.Parse(args[1:])
		args = args[:1]
	}

	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "用法: parse-cli <file.pcapng> [--limit N] [--analyze] [--top N] [--detect <规则文件>]")
		os.Exit(1)
	}
	path := args[0]

	// --detect：载入规则文件并构建检测引擎（检测也依赖流归属）。
	var eng *detect.Engine
	if *detectPath != "" {
		rs, err := detect.LoadFile(*detectPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "载入规则文件失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(rs.Report.String())
		fmt.Println()
		eng = rs.Engine()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取文件失败: %v\n", err)
		os.Exit(1)
	}

	cap, err := pcapng.Parse(data, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("格式: %s  字节序: %s  版本: %s\n", cap.Format, cap.Endian, cap.Version)
	fmt.Printf("链路类型: %d  接口数: %d  包数: %d\n", cap.LinkType, len(cap.Ifaces), len(cap.Packets))
	for i, ifc := range cap.Ifaces {
		fmt.Printf("  接口[%d]: linktype=%d snaplen=%d name=%q\n", i, ifc.LinkType, ifc.SnapLen, ifc.Name)
	}
	if len(cap.Warns) > 0 {
		fmt.Printf("警告 %d 条:\n", len(cap.Warns))
		for _, w := range cap.Warns {
			fmt.Printf("  - %s\n", w)
		}
	}
	fmt.Println()

	// 表头（仅在逐包模式下打印）。
	if !*analyze && eng == nil {
		fmt.Printf("%-6s %-18s %-21s %-21s %-9s %-6s %s\n",
			"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
		fmt.Println("----------------------------------------------------------------------------------------------")
	}

	// 检测/分析模式都需要流归属。
	var a *analyzer.Analyzer
	if *analyze || eng != nil {
		a = analyzer.New()
	}

	// 告警汇总累加器（仅检测模式使用）。
	alertTotal := 0
	hitsByRule := make(map[string]int)
	nameByRule := make(map[string]string)

	for _, p := range cap.Packets {
		linkType := cap.LinkType
		if p.Iface >= 0 && p.Iface < len(cap.Ifaces) {
			linkType = cap.Ifaces[p.Iface].LinkType
		}
		decoder.Decode(p, linkType)

		// 检测模式：归流并匹配规则（不逐包打印）。
		if eng != nil {
			var flow *datamodel.Flow
			if a != nil {
				flow = a.FeedFlow(p)
			}
			hits := eng.Match(&detect.Ctx{Pkt: p, Flow: flow})
			for _, h := range hits {
				alertTotal++
				hitsByRule[h.RuleID]++
				if _, ok := nameByRule[h.RuleID]; !ok {
					nameByRule[h.RuleID] = h.Name
				}
				fmt.Printf("[命中] No=%d 时间=%s %s:%d → %s:%d 规则=%s(%s) 缓冲=%s 偏移=%d 片段=%q\n",
					p.No, formatTime(p), p.Src, p.SrcPort, p.Dst, p.DstPort,
					h.RuleID, h.Name, h.Buffer, h.Offset, h.Snippet)
			}
			continue
		}

		// 纯 analyze 模式：只归流，不逐包打印（与改动前一致）。
		if a != nil {
			a.Feed(p)
			continue
		}

		src := formatEndpoint(p)
		dst := formatDstEndpoint(p)
		proto := p.Proto
		if proto == "" {
			proto = "?"
		}
		length := p.CapLen

		fmt.Printf("%-6d %-18s %-21s %-21s %-9s %-6d %s\n",
			p.No, formatTime(p), src, dst, proto, length, p.Info)
	}

	// 收尾 1：检测告警汇总（按规则分组，命中次数降序、同次数规则 ID 升序）。
	if eng != nil {
		type ruleGroup struct {
			ID    string
			Name  string
			Count int
		}
		groups := make([]ruleGroup, 0, len(hitsByRule))
		for id, cnt := range hitsByRule {
			groups = append(groups, ruleGroup{ID: id, Name: nameByRule[id], Count: cnt})
		}
		sort.Slice(groups, func(i, j int) bool {
			if groups[i].Count != groups[j].Count {
				return groups[i].Count > groups[j].Count
			}
			return groups[i].ID < groups[j].ID
		})
		fmt.Printf("=== 检测结果：命中 %d 次，涉及 %d 条规则 ===\n", alertTotal, len(groups))
		for _, g := range groups {
			fmt.Printf("规则 %s (%s) 命中 %d 次\n", g.ID, g.Name, g.Count)
		}
	}

	// 收尾 2：纯分析统计（保持原有顺序/格式）。
	if *analyze {
		printAnalysis(a, *top)
	}
}

// printAnalysis 打印聚合分析结果：流聚合/协议/端点/端口四段。
func printAnalysis(a *analyzer.Analyzer, top int) {
	if top < 0 {
		top = 0
	}

	// a) 流聚合：按字节数降序，最多显示 top 条。
	flows := a.Flows()
	sort.SliceStable(flows, func(i, j int) bool {
		if flows[i].ByteCnt != flows[j].ByteCnt {
			return flows[i].ByteCnt > flows[j].ByteCnt
		}
		return flows[i].ID < flows[j].ID
	})
	flowShow := len(flows)
	if flowShow > top {
		flowShow = top
	}
	fmt.Printf("=== 流聚合（共 %d 条，显示前 %d 条）：===\n", len(flows), flowShow)
	for i := 0; i < flowShow; i++ {
		f := flows[i]
		fmt.Printf("%d) %s:%d 到 %s:%d  Kind=%s  PacketCnt=%d  ByteCnt=%d  State=%s  Dirs[0](A→B) 包数=%d 字节数=%d  Dirs[1](B→A) 包数=%d 字节数=%d\n",
			i+1, ip4String(f.A), f.APort, ip4String(f.B), f.BPort,
			f.Kind, f.PacketCnt, f.ByteCnt, flowStateName(f.State),
			f.Dirs[0].Packets, f.Dirs[0].Bytes, f.Dirs[1].Packets, f.Dirs[1].Bytes)
	}
	fmt.Println()

	// b) 协议统计：按包数降序（全部）。
	stats := a.Stats()
	protoNames := make([]string, 0, len(stats.Protocols))
	for name := range stats.Protocols {
		protoNames = append(protoNames, name)
	}
	sort.Slice(protoNames, func(i, j int) bool {
		pi := stats.Protocols[protoNames[i]]
		pj := stats.Protocols[protoNames[j]]
		if pi.Packets != pj.Packets {
			return pi.Packets > pj.Packets
		}
		return protoNames[i] < protoNames[j]
	})
	fmt.Printf("=== 协议统计（共 %d 种，按包数降序）：===\n", len(protoNames))
	for _, name := range protoNames {
		st := stats.Protocols[name]
		label := name
		if label == "" {
			label = "?"
		}
		fmt.Printf("%s  包数=%d  字节数=%d\n", label, st.Packets, st.Bytes)
	}
	fmt.Println()

	// c) 端点 TOP N（按字节数）。
	endpoints := make([]analyzer.EndpointStat, 0, len(stats.Endpoints))
	for _, st := range stats.Endpoints {
		endpoints = append(endpoints, st)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Bytes != endpoints[j].Bytes {
			return endpoints[i].Bytes > endpoints[j].Bytes
		}
		if endpoints[i].A != endpoints[j].A {
			return endpoints[i].A < endpoints[j].A
		}
		return endpoints[i].B < endpoints[j].B
	})
	endpointShow := len(endpoints)
	if endpointShow > top {
		endpointShow = top
	}
	fmt.Printf("=== 端点 TOP %d（按字节数，共 %d 对）：===\n", endpointShow, len(endpoints))
	for i := 0; i < endpointShow; i++ {
		e := endpoints[i]
		fmt.Printf("%d) %s 到 %s  字节数=%d  包数=%d\n",
			i+1, ip4String(e.A), ip4String(e.B), e.Bytes, e.Packets)
	}
	fmt.Println()

	// d) 端口 TOP N（按包数）。
	type portEntry struct {
		Port    uint16
		Packets uint64
	}
	ports := make([]portEntry, 0, len(stats.Ports))
	for port, cnt := range stats.Ports {
		ports = append(ports, portEntry{Port: port, Packets: cnt})
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Packets != ports[j].Packets {
			return ports[i].Packets > ports[j].Packets
		}
		return ports[i].Port < ports[j].Port
	})
	portShow := len(ports)
	if portShow > top {
		portShow = top
	}
	fmt.Printf("=== 端口 TOP %d（按包数，共 %d 个）：===\n", portShow, len(ports))
	for i := 0; i < portShow; i++ {
		fmt.Printf("%d) 端口 %d  包数=%d\n", i+1, ports[i].Port, ports[i].Packets)
	}
	fmt.Println("=== 分析结束 ===")
}

// ip4String 把 IPv4 的 uint32 整数转换为点分十进制字符串。
func ip4String(v uint32) string {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
}

// flowStateName 把 FlowState 转成可读名字。
func flowStateName(s datamodel.FlowState) string {
	switch s {
	case datamodel.FlowEstablished:
		return "ESTABLISHED"
	case datamodel.FlowHalfClose:
		return "HALF_CLOSE"
	case datamodel.FlowClosed:
		return "CLOSED"
	case datamodel.FlowReset:
		return "RESET"
	default:
		return "UNKNOWN"
	}
}

// formatEndpoint 格式化源端点（IP:port 或 MAC）。
func formatEndpoint(p *datamodel.Packet) string {
	if p.SrcPort != 0 {
		return fmt.Sprintf("%s:%d", p.Src, p.SrcPort)
	}
	return p.Src
}

// formatDstEndpoint 格式化目的端点。
func formatDstEndpoint(p *datamodel.Packet) string {
	if p.DstPort != 0 {
		return fmt.Sprintf("%s:%d", p.Dst, p.DstPort)
	}
	return p.Dst
}

// formatTime 格式化时间（相对秒，若无则绝对）。
func formatTime(p *datamodel.Packet) string {
	if p.Time.IsZero() {
		return "-"
	}
	return p.Time.Format("15:04:05.000000")
}
