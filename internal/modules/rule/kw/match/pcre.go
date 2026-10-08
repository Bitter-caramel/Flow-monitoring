package match

import (
	"flow-monitoring/internal/modules/rule"
	"flow-monitoring/internal/modules/rule/kw"
	"flow-monitoring/internal/modules/rule/suricata"
)

// pcreKW 实现 pcre 关键字。
type pcreKW struct{}

func (pcreKW) Name() string { return "pcre" }

// Handle 把 pcre 翻译为一个 CondPCRE 条件。
// 取反解析复用 content.go 里的同包私有函数 stripNegate；
// 与 content 一样，内容归属由 st.CurBuf（粘性缓冲）决定。
func (pcreKW) Handle(st *kw.State, opt suricata.Option) error {
	value, negate := stripNegate(opt.Value)
	var flags rule.CondFlags
	if negate {
		flags |= rule.FlagNegate
	}
	st.Rule.Match.Conditions = append(st.Rule.Match.Conditions, rule.Condition{
		Kind:   rule.CondPCRE,
		Buffer: st.CurBuf,
		Value:  value,
		Flags:  flags,
	})
	return nil
}

func init() {
	kw.Register(pcreKW{})
}
