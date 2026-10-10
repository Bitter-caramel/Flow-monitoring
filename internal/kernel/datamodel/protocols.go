package datamodel

// FillProtocols 把「该包所属的协议集合」以规范小写名写入调用方提供的数组 dst，
// 返回实际写入的个数（不追加、不建 map / 切片）。
//
// 三条必须知道的事：
//
//  1. 一个包可以同时属于多个协议。例如 HTTP 跑在 TCP 上时集合是 {"tcp","http"}，
//     所以规则里写 tcp 和写 http 都该能命中同一个包 —— 协议不是「单个值」而是「集合」。
//
//  2. 这里写出的名字与 rule.Protocol 的取值一一对应（见 rule/ir.go 里的
//     ProtoTCP / ProtoUDP / ProtoICMP / ProtoHTTP / ProtoDNS / ProtoTLS / ProtoSSH）。
//     改这里的词表必须同步改 rule 那边；detect 包有一条一致性测试会兜住这种漂移。
//
//  3. 采用「调用方提供数组」的形式是为了热路径零分配：本函数不 new、不 append、
//     不建 map / 切片，只按下标赋值。dst 太小时最多写满，绝不越界。
//
// 判定规则（同名只写一次，去重）：
//
//	IPProto == 6       -> "tcp"
//	IPProto == 17      -> "udp"
//	IPProto == 1 或 58 -> "icmp"
//	p.HTTP != nil      -> "http"
//	p.DNS  != nil      -> "dns"
//	p.TLS  != nil      -> "tls"
//	p.Proto == "SSH"   -> "ssh"（SSH 目前没有独立结构体，只能靠展示名判断）
func FillProtocols(p *Packet, dst []string) int {
	if p == nil || len(dst) == 0 {
		return 0
	}
	n := 0
	switch p.IPProto {
	case 6:
		n = fillAdd(dst, n, "tcp")
	case 17:
		n = fillAdd(dst, n, "udp")
	case 1, 58:
		n = fillAdd(dst, n, "icmp")
	}
	if p.HTTP != nil {
		n = fillAdd(dst, n, "http")
	}
	if p.DNS != nil {
		n = fillAdd(dst, n, "dns")
	}
	if p.TLS != nil {
		n = fillAdd(dst, n, "tls")
	}
	// SSH 没有独立解析结构体，只能用展示名判定。
	if p.Proto == "SSH" {
		n = fillAdd(dst, n, "ssh")
	}
	return n
}

// fillAdd 把 name 追加到 dst[0:n] 的尾部（去重 + 容量保护），返回新的长度。
//
// ★ 独立函数而非闭包，是为了让热路径彻底零分配：无闭包、无逃逸、无堆对象。
func fillAdd(dst []string, n int, name string) int {
	if n >= len(dst) {
		return n
	}
	for i := 0; i < n; i++ {
		if dst[i] == name {
			return n // 去重：同名只写一次，避免规则被重复求值、告警报两遍
		}
	}
	dst[n] = name
	return n + 1
}
