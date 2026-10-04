// Package suricata 提供 Suricata 规则的词法切分能力。
//
// 本包只做“切词”，不做语义校验：把一行 Suricata 规则切分为规则头
// （Header）与选项列表（Options），并在出现结构性错误时返回错误。
package suricata

import (
	"fmt"
	"strings"
)

// Header 表示 Suricata 规则头的七个字段。
type Header struct {
	Action    string // 动作，如 alert/drop/pass
	Proto     string // 协议，如 tcp/udp/ip/icmp
	SrcIP     string // 源地址，可为 $HOME_NET、地址列表或 any
	SrcPort   string // 源端口，可为 any、端口列表或具体端口
	Direction string // 方向符，只能是 -> 或 <>
	DstIP     string // 目的地址
	DstPort   string // 目的端口
}

// Option 表示选项块（外层括号内）的一个键值对。
//
// 没有冒号的选项（如 nocase）其 Value 为空字符串；有值的选项，
// Value 已经去掉外层成对双引号并处理过转义序列。
type Option struct {
	Key   string // 选项名，如 msg/content/sid
	Value string // 选项值
}

// RawRule 表示词法切分后的一行规则。
type RawRule struct {
	Header  Header   // 规则头
	Options []Option // 选项列表，按在文本中出现的顺序排列
	Line    int      // 该行在源文本中的行号，从 1 开始
	Text    string   // 该行的原始文本
}

// LexError 表示某一行规则在词法切分时出现的错误。
type LexError struct {
	Line int    // 出错行号，从 1 开始
	Text string // 出错行的原始文本
	Err  error  // 具体错误原因
}

// Error 实现 error 接口，返回带行号的错误描述。
func (e LexError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("suricata: 第 %d 行规则解析失败", e.Line)
	}
	return fmt.Sprintf("suricata: 第 %d 行规则解析失败: %v", e.Line, e.Err)
}

// Unwrap 返回被包装的底层错误。
func (e LexError) Unwrap() error { return e.Err }

// Lex 对一行 Suricata 规则做词法切分。
//
// line 为规则文本（不含换行符），lineNo 为该行行号（从 1 开始，仅用于报错）。
// 切分成功时返回的 RawRule.Text 等于 line；切分失败时返回 nil 与错误。
func Lex(line string, lineNo int) (*RawRule, error) {
	headerEnd := findHeaderEnd(line)

	var headerText, optionText string
	var hasOptions bool
	if headerEnd < 0 {
		// 没有选项块，整行都是规则头。
		headerText = line
	} else {
		optionEnd := findOptionEnd(line, headerEnd)
		if optionEnd < 0 {
			return nil, fmt.Errorf("选项块缺少与之配对的 )")
		}
		headerText = line[:headerEnd]
		optionText = line[headerEnd+1 : optionEnd]
		hasOptions = true
	}

	fields := splitHeader(headerText)
	if len(fields) != 7 {
		return nil, fmt.Errorf("规则头字段数应为 7，实际为 %d", len(fields))
	}
	if fields[4] != "->" && fields[4] != "<>" {
		return nil, fmt.Errorf("非法的方向符 %q，只能是 -> 或 <>", fields[4])
	}

	rule := &RawRule{
		Header: Header{
			Action:    fields[0],
			Proto:     fields[1],
			SrcIP:     fields[2],
			SrcPort:   fields[3],
			Direction: fields[4],
			DstIP:     fields[5],
			DstPort:   fields[6],
		},
		Options: []Option{},
		Line:    lineNo,
		Text:    line,
	}

	if hasOptions {
		for _, seg := range splitOptions(optionText) {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			rule.Options = append(rule.Options, parseOption(seg))
		}
	}

	return rule, nil
}

// findHeaderEnd 返回第一个处于双引号之外的 '(' 的下标，找不到时返回 -1。
func findHeaderEnd(s string) int {
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if c == '\\' && i+1 < len(s) {
				i++ // 跳过被转义的字符
				continue
			}
			if c == '"' {
				inQuote = false
			}
			continue
		}
		switch c {
		case '"':
			inQuote = true
		case '(':
			return i
		}
	}
	return -1
}

// findOptionEnd 从 start（'(' 所在下标）开始，返回与其配对且处于双引号之外的
// ')' 的下标；找不到时返回 -1。双引号内的括号、以及被 \" 转义的引号不计数。
func findOptionEnd(s string, start int) int {
	depth := 0
	inQuote := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if c == '\\' && i+1 < len(s) {
				i++ // 跳过被转义的字符
				continue
			}
			if c == '"' {
				inQuote = false
			}
			continue
		}
		switch c {
		case '"':
			inQuote = true
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitHeader 按空白切分规则头，但 [ ... ] 内部不切分（列表视为一个字段）。
func splitHeader(s string) []string {
	var fields []string
	var b strings.Builder
	depth := 0
	flush := func() {
		if b.Len() > 0 {
			fields = append(fields, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '[':
			depth++
			b.WriteByte(c)
		case c == ']':
			if depth > 0 {
				depth--
			}
			b.WriteByte(c)
		case depth == 0 && isSpace(c):
			flush()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return fields
}

// splitOptions 按双引号之外的 ';' 切分选项块，双引号内的 ';' 不切分。
func splitOptions(s string) []string {
	var segs []string
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++ // 跳过被转义的字符，原样保留两个字节
				b.WriteByte(s[i])
				continue
			}
			if c == '"' {
				inQuote = false
			}
			continue
		}
		switch c {
		case '"':
			inQuote = true
			b.WriteByte(c)
		case ';':
			segs = append(segs, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	segs = append(segs, b.String())
	return segs
}

// parseOption 把一个选项片段解析为 Option：按第一个 ':' 分成 Key / Value，
// 没有 ':' 时 Value 为空串。
func parseOption(seg string) Option {
	idx := strings.Index(seg, ":")
	if idx < 0 {
		return Option{Key: strings.TrimSpace(seg)}
	}
	return Option{
		Key:   strings.TrimSpace(seg[:idx]),
		Value: cleanValue(seg[idx+1:]),
	}
}

// cleanValue 处理选项值：去掉外层成对双引号，并还原转义序列
// （\" -> "，\\ -> \，\; -> ;，\: -> :）。其余内容原样保留。
func cleanValue(v string) string {
	v = strings.TrimSpace(v)
	if hasOuterQuotes(v) {
		v = v[1 : len(v)-1]
	}
	if !strings.Contains(v, "\\") {
		return v
	}
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\\' && i+1 < len(v) {
			switch v[i+1] {
			case '"', '\\', ';', ':':
				b.WriteByte(v[i+1])
				i++
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// hasOuterQuotes 判断 s 是否被一对未转义的成对双引号包裹。
func hasOuterQuotes(s string) bool {
	n := len(s)
	if n < 2 || s[0] != '"' || s[n-1] != '"' {
		return false
	}
	backslashes := 0
	for i := n - 2; i >= 0 && s[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 0
}

// isSpace 判断字节是否为 ASCII 空白字符。
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}

// LexAll 逐行切分整段文本。
//
// 空行与以 # 开头的注释行会被跳过；单行失败不影响其它行，失败的行会被
// 收集到 []LexError 中一并返回。行号从 1 开始。
func LexAll(text string) ([]*RawRule, []LexError) {
	rules := []*RawRule{}
	lexErrors := []LexError{}

	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		rule, err := Lex(line, i+1)
		if err != nil {
			lexErrors = append(lexErrors, LexError{Line: i + 1, Text: line, Err: err})
			continue
		}
		rules = append(rules, rule)
	}

	return rules, lexErrors
}
