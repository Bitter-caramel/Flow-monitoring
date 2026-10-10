package detect

import (
	"errors"
	"fmt"
	"regexp"

	"flow-monitoring/internal/modules/rule"
)

// Cond 是编译后的单个判定条件：一条 matcher 的「可执行形态」。
type Cond struct {
	Kind    rule.ConditionKind
	Extract Extractor   // ★ 编译期固化：缓冲名已换成函数指针
	Buf     rule.Buffer // 仅用于告警里报「命中在哪个缓冲」
	Content []byte
	Lower   []byte // content + nocase 时预置的小写模式
	Regex   *regexp.Regexp
	Negate  bool
	Offset  int
	Depth   int
}

// Program 是编译后的规则：可直接送进匹配执行器。
type Program struct {
	ID          string
	Name        string
	Severity    string
	Action      rule.Action
	Proto       rule.Protocol
	AnyPort     bool
	Ports       []uint16
	Ranges      []rule.PortRange
	Flow        rule.FlowSpec
	Conds       []Cond
	Unsupported []string // 规则侧不支持项（供导入报告）
}

// ErrUnsupportedBuffer 表示规则引用了本引擎无法提取的缓冲区。
var ErrUnsupportedBuffer = errors.New("不支持的缓冲区")

// Compile 是「第二次编译」——把与数据源无关的 CompiledRule
// 绑定成可直接执行的 Program：把每个 matcher 的缓冲名换成对应的
// Extractor 函数指针，并复制规则头字段。
func Compile(cr *rule.CompiledRule) (*Program, error) {
	if cr == nil {
		return nil, errors.New("detect: nil compiled rule")
	}
	// 防御性：正常不会发生（规则侧有安全阀），但空 matchers 会让规则「匹配一切」。
	if len(cr.Matchers) == 0 {
		return nil, errors.New("detect: compiled rule has no matchers")
	}

	p := &Program{
		ID:          cr.ID,          // 嵌入的 Rule
		Name:        cr.Name,        // 嵌入的 Rule
		Severity:    cr.Severity,    // 嵌入的 Rule
		Action:      cr.Action,      // 嵌入的 Rule
		Proto:       cr.Match.Proto, // 嵌入的 Rule -> Match
		AnyPort:     cr.AnyPort,
		Ports:       cr.Ports,
		Ranges:      cr.PortRanges,
		Flow:        cr.Match.Flow, // 嵌入的 Rule -> Match
		Conds:       make([]Cond, 0, len(cr.Matchers)),
		Unsupported: append([]string(nil), cr.Unsupported...),
	}

	for _, m := range cr.Matchers {
		extract, ok := LookupBuffer(m.Buffer)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedBuffer, m.Buffer)
		}
		var lower []byte
		if m.Lower != "" {
			lower = []byte(m.Lower)
		}
		p.Conds = append(p.Conds, Cond{
			Kind:    m.Kind,
			Extract: extract,
			Buf:     m.Buffer,
			Content: []byte(m.Content),
			Lower:   lower,
			Regex:   m.Regex,
			Negate:  m.Negate,
			Offset:  m.Offset,
			Depth:   m.Depth,
		})
	}
	return p, nil
}
