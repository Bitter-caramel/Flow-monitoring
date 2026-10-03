// TCP 状态机：依据 TCP 标志位推进 Flow 的握手/关闭状态。
//
// 位定义参考 decoder/l4.go 的 tcpFlagString：
//
//	0x02=SYN、0x10=ACK、0x04=RST、0x01=FIN
//
// 状态推进规则：
//   - SYN     ：记录首个 SYN 包号（Flow.SynNo），不置 Established；
//   - SYN+ACK ：记录 Flow.SynAckNo，置 FlowEstablished；
//   - RST     ：记录 Flow.RstNo，置 FlowReset（异常终止优先）；
//   - FIN     ：按方向置 Flow.FinDirs 位，单边 FIN 置 FlowHalfClose，
//     双边 FIN 置 FlowClosed。
//
// 仅处理 TCP；UDP 包不进入此状态机。
package analyzer

import "flow-monitoring/internal/kernel/datamodel"

// TCP 标志位掩码（与 decoder/l4.go 的 tcpFlagString 保持一致）。
const (
	tcpFlagFIN uint16 = 0x01
	tcpFlagSYN uint16 = 0x02
	tcpFlagRST uint16 = 0x04
	tcpFlagACK uint16 = 0x10
)

// advanceTCPState 是 TCP 流状态机的核心：根据当前包的标志位推进 f 的状态。
//
// dir 为该包在规范化五元组中的方向：0=A→B，1=B→A。
// 调用方需保证包为 TCP（IPProto==6）；f/p 为 nil 时直接返回。
func advanceTCPState(f *datamodel.Flow, p *datamodel.Packet, dir int) {
	if f == nil || p == nil {
		return
	}
	flags := p.TCPFlags

	switch {
	case flags&tcpFlagRST != 0:
		// RST：异常终止，优先级最高。
		f.RstNo = p.No
		f.State = datamodel.FlowReset
	case flags&tcpFlagSYN != 0 && flags&tcpFlagACK != 0:
		// SYN+ACK：完成握手。
		f.SynAckNo = p.No
		f.State = datamodel.FlowEstablished
	case flags&tcpFlagSYN != 0:
		// 纯 SYN：仅记录首个 SYN 包号，不置 Established。
		if f.SynNo == 0 {
			f.SynNo = p.No
		}
	case flags&tcpFlagFIN != 0:
		// FIN：按方向置位；双边 FIN 视为完全关闭。
		f.FinDirs |= uint8(1) << uint(dir&1)
		if f.FinDirs&0x03 == 0x03 {
			f.State = datamodel.FlowClosed
		} else {
			f.State = datamodel.FlowHalfClose
		}
	}
}
