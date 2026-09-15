// Command parse-cli 是协议解析的命令行验证工具。
//
// 读取 pcap/pcapng 文件，解析并输出类似 Wireshark 的包列表，
// 用于验证 pcapng reader + decoder 的解析效果（不依赖后端/数据库）。
//
// 用法：
//
//	parse-cli <file.pcapng> [--limit N]
//
// 输出列：No / 时间 / 源 → 目的 / 协议 / 长度 / INFO
package main

import (
	"flag"
	"fmt"
	"os"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/parse/decoder"
	"flow-monitoring/internal/modules/parse/pcapng"
)

func main() {
	limit := flag.Int("limit", 0, "最大解析包数（0=不限制）")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "用法: parse-cli <file.pcapng> [--limit N]")
		os.Exit(1)
	}
	path := args[0]

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

	// 表头
	fmt.Printf("%-6s %-18s %-21s %-21s %-9s %-6s %s\n",
		"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
	fmt.Println("----------------------------------------------------------------------------------------------")

	for _, p := range cap.Packets {
		linkType := cap.LinkType
		if p.Iface >= 0 && p.Iface < len(cap.Ifaces) {
			linkType = cap.Ifaces[p.Iface].LinkType
		}
		decoder.Decode(p, linkType)

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
