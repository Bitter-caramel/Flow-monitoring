package datamodel

import "fmt"

// ConnKey 返回「双向连接键」：把两端归一化后拼成一个稳定字符串，
// 使同一条连接的两个方向得到**同一个键**。
//
// 用途：analyzer 目前只给 IPv4 包分配 StreamID（IPv6 恒为 -1），
// 证据导出/告警去重需要一个不依赖 StreamID 的连接标识。
//
// 归一化规则（必须**对称**：交换两端得到的键必须相同）：
//   - 每端拼成 "ip:port"（IPv6 原样，不加方括号）；
//   - 两端按**字符串字典序**排序后再拼接，形如 "a|b"；
//   - 用 '|' 作分隔符（IP 与端口里都不会出现它）。
//
// 为什么不用 StreamID：analyzer 只为 IPv4 分配 StreamID，IPv6 包恒为 -1，
// 直接用 StreamID 会让所有 IPv6 连接挤成同一个组；这里改成与 IP 版本无关的
// 端点字符串键，IPv4/IPv6 都能稳定区分与合并。
//
// 说明：这里**不做 IP 数值解析**，直接用 fmt.Sprintf 拼字符串，
// 因此 IPv4/IPv6、乃至非规范写法都能直接跑。
func ConnKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16) string {
	a := fmt.Sprintf("%s:%d", srcIP, srcPort)
	b := fmt.Sprintf("%s:%d", dstIP, dstPort)
	// 两端按字符串字典序排序，保证交换两端得到同一个键。
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

// ConnKeyOf 从包的两个端点取连接键（不含方向信息）。
//
// p 为 nil 时返回 ""（不 panic）；空串在 Ring 里不会建立连接索引，
// 避免把无端点信息的脏包都塞进同一个伪连接。
func ConnKeyOf(p *Packet) string {
	if p == nil {
		return ""
	}
	return ConnKey(p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
}
