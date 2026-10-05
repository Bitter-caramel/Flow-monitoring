// Package rule 提供规则编译能力：把 IR 层的 Rule 编译为可执行的匹配器集合。
//
// 本文件只依赖标准库，定义编译期产物（CompiledRule / Matcher）以及编译入口
// （Compile / CompileAll）。编译过程会做端口索引、条件转匹配器，并对无法
// 处理的条件进行记录，避免产生"匹配一切"的危险规则。
package rule

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// CompiledRule 表示一条 Rule 编译后的产物。
//
// 它嵌入了原始 IR，以便保留规则的元信息与 Action；同时把端口与条件
// 转换为更易于执行的形态。
type CompiledRule struct {
	Rule                    // 嵌入 IR（保留元信息与 Action）
	AnyPort     bool        // true = 不限端口（此时忽略 Ports/PortRanges）
	Ports       []uint16    // 单端口集合（SrcPort ∪ DstPort，去重、升序）
	PortRanges  []PortRange // 端口区间（SrcPort ∪ DstPort）
	Matchers    []Matcher   // 可执行匹配器，按 Match.Conditions 顺序
	Unsupported []string    // 编译期被丢弃的条件说明
}

// Matcher 表示单个可执行匹配器。
//
// CondContent 类型使用 Content / Lower；CondPCRE 类型使用 Regex。
type Matcher struct {
	Kind        ConditionKind
	Buffer      Buffer
	Content     string
	Lower       string // NoCase 时为 Content 的小写形式，否则空串
	NoCase      bool
	Negate      bool
	FastPattern bool
	Offset      int
	Depth       int
	Regex       *regexp.Regexp // 仅 CondPCRE：预编译正则
}

// Compile 把单条规则编译为 CompiledRule。
//
// r 为 nil 时返回 error；当规则带有条件但所有条件都被丢弃时会返回 error，
// 因为这种规则会退化为"匹配一切"，必须拒绝编译。
func Compile(r *Rule) (*CompiledRule, error) {
	if r == nil {
		return nil, fmt.Errorf("rule 为 nil，无法编译")
	}

	out := &CompiledRule{Rule: *r}

	// 端口索引。
	if r.Match.SrcPort.Any && r.Match.DstPort.Any {
		out.AnyPort = true
	} else {
		out.AnyPort = false
		out.Ports = mergePorts(r.Match.SrcPort.Ports, r.Match.DstPort.Ports)
		out.PortRanges = mergeRanges(r.Match.SrcPort.Ranges, r.Match.DstPort.Ranges)
	}

	// 条件转 Matcher，保持 Match.Conditions 的顺序。
	for _, cond := range r.Match.Conditions {
		switch cond.Kind {
		case CondContent:
			m := Matcher{
				Kind:        cond.Kind,
				Buffer:      cond.Buffer,
				Content:     cond.Value,
				NoCase:      cond.Flags&FlagNoCase != 0,
				Negate:      cond.Flags&FlagNegate != 0,
				FastPattern: cond.Flags&FlagFastPattern != 0,
				Offset:      cond.Offset,
				Depth:       cond.Depth,
			}
			if m.NoCase {
				m.Lower = strings.ToLower(m.Content)
			}
			out.Matchers = append(out.Matchers, m)
		case CondPCRE:
			pattern, flags, ok := parsePCRE(cond.Value)
			if !ok {
				out.Unsupported = append(out.Unsupported, "pcre 不支持: "+cond.Value)
				continue
			}
			if strings.ContainsRune(flags, 'i') {
				pattern = "(?i)" + pattern
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				out.Unsupported = append(out.Unsupported, "pcre 不支持: "+cond.Value)
				continue
			}
			out.Matchers = append(out.Matchers, Matcher{
				Kind:    CondPCRE,
				Buffer:  cond.Buffer,
				Content: cond.Value,
				Regex:   re,
				Negate:  cond.Flags&FlagNegate != 0,
			})
		default:
			out.Unsupported = append(out.Unsupported, "未知条件类型: "+string(cond.Kind))
		}
	}

	// 安全阀：有条件却没有任何可执行匹配器，会匹配一切，拒绝编译。
	if len(r.Match.Conditions) > 0 && len(out.Matchers) == 0 {
		return nil, fmt.Errorf("规则 %q 的所有条件均被丢弃，拒绝编译（会匹配一切）", r.ID)
	}

	return out, nil
}

// CompileAll 批量编译规则。
//
// 跳过 nil 项，并把对应 error 收集进第二个返回值；第一个返回值即使为空也保证非 nil。
func CompileAll(rules []*Rule) ([]*CompiledRule, []error) {
	out := make([]*CompiledRule, 0, len(rules))
	errs := make([]error, 0)
	for i, r := range rules {
		if r == nil {
			errs = append(errs, fmt.Errorf("第 %d 条规则为 nil，已跳过", i))
			continue
		}
		c, err := Compile(r)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, c)
	}
	return out, errs
}

// parsePCRE 解析 PCRE 字面量（形如 "/pattern/flags"）。
//
// 取第一个字符作为分隔符，用最后一个相同字符作为结束分隔符；
// 解析成功返回 pattern、flags 与 true，否则返回 false。
func parsePCRE(expr string) (pattern string, flags string, ok bool) {
	if len(expr) < 2 {
		return "", "", false
	}
	delim := expr[0]
	idx := strings.LastIndexByte(expr, delim)
	if idx <= 0 {
		return "", "", false
	}
	return expr[1:idx], expr[idx+1:], true
}

// mergePorts 合并两组端口，去重并升序排序。
func mergePorts(a, b []uint16) []uint16 {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	set := make(map[uint16]struct{}, len(a)+len(b))
	for _, p := range a {
		set[p] = struct{}{}
	}
	for _, p := range b {
		set[p] = struct{}{}
	}
	out := make([]uint16, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// mergeRanges 合并两组端口区间，按原顺序拼接。
func mergeRanges(a, b []PortRange) []PortRange {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := make([]PortRange, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}
