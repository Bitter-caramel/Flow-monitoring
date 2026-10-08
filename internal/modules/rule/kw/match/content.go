package match

import (
	"flow-monitoring/internal/modules/rule"
	"flow-monitoring/internal/modules/rule/kw"
	"flow-monitoring/internal/modules/rule/suricata"
)

// stripNegate 解析关键字值开头的取反标记 '!'。
// 若 v 不以 '!' 开头，原样返回且 negate=false；
// 否则去掉开头那个 '!'，并且当剩余部分被一对双引号包裹时（长度>=2 且首尾都是 '"'），
// 再去掉这层引号，最后返回剩余部分与 negate=true。
// 该函数被 content 与 pcre 两个关键字共用，因此放在本文件里。
func stripNegate(v string) (value string, negate bool) {
	if len(v) == 0 || v[0] != '!' {
		return v, false
	}
	value = v[1:]
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	return value, true
}

// contentKW 实现 content 关键字。
type contentKW struct{}

func (contentKW) Name() string { return "content" }

// Handle 把 content 翻译为一个 CondContent 条件。
// 内容归属由 st.CurBuf（粘性缓冲）决定：CurBuf 记录当前所在的缓冲，
// content 会一直挂到该缓冲上，直到遇到切换缓冲的关键字为止。
func (contentKW) Handle(st *kw.State, opt suricata.Option) error {
	value, negate := stripNegate(opt.Value)
	var flags rule.CondFlags
	if negate {
		flags |= rule.FlagNegate
	}
	st.Rule.Match.Conditions = append(st.Rule.Match.Conditions, rule.Condition{
		Kind:   rule.CondContent,
		Buffer: st.CurBuf,
		Value:  value,
		Flags:  flags,
	})
	return nil
}

func init() {
	kw.Register(contentKW{})
}
