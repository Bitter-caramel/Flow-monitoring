// Package suricata 提供 Suricata 规则的词法分析与语法解析能力。
package suricata

import (
	"fmt"
	"strconv"
	"strings"
)

// Content 表示一条 content 匹配条件及其修饰符。
type Content struct {
	Buffer      string // 目标字段：payload（默认）/ http_uri / http_header / http_method / http_client_body / dns_query / tls_sni
	Value       string // 内容文本
	NoCase      bool   // nocase
	Negate      bool   // 取反
	FastPattern bool   // fast_pattern
	Depth       int    // depth（0 = 未指定）
	Offset      int    // offset（0 = 未指定）
	Distance    int    // distance（0 = 未指定）
	Within      int    // within（0 = 未指定）
}

// PCRE 表示一条 pcre 正则匹配条件。
type PCRE struct {
	Buffer string // 目标字段，同 Content.Buffer
	Expr   string // 正则原文（保留 /.../ 与末尾修饰符）
	Negate bool   // 取反
}

// ParsedRule 表示一条解析完成的 Suricata 规则。
type ParsedRule struct {
	Raw         *RawRule
	Action      string
	Proto       string
	Direction   string
	SrcIP       string
	SrcPort     string
	DstIP       string
	DstPort     string
	Message     string
	SID         int
	Rev         int
	Priority    int
	Classtype   string
	References  []string
	Metadata    []string
	Flow        []string
	Contents    []Content
	PCRES       []PCRE
	Unsupported []string // 本层不认识的选项名（去重、保持首次出现顺序）
}

// bufferKeys 是全部可作为“缓冲设置项”的选项键名集合。
var bufferKeys = map[string]bool{
	"payload":          true,
	"http_uri":         true,
	"http_header":      true,
	"http_method":      true,
	"http_client_body": true,
	"dns_query":        true,
	"tls_sni":          true,
}

// stripNegate 处理 content / pcre 值的前导取反符号。
// 若值以 '!' 开头则返回 negate=true 并去掉该字符；
// 去掉 '!' 后若值仍被一对双引号包裹，则仅去掉这一层最外层双引号。
func stripNegate(v string) (value string, negate bool) {
	if !strings.HasPrefix(v, "!") {
		return v, false
	}
	v = v[1:]
	if len(v) >= 2 && strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"") {
		v = v[1 : len(v)-1]
	}
	return v, true
}

// Parse 将一条 RawRule 解析为 ParsedRule。
func Parse(raw *RawRule) (*ParsedRule, error) {
	if raw == nil {
		return nil, fmt.Errorf("suricata: nil raw rule")
	}

	pr := &ParsedRule{
		Raw:       raw,
		Action:    raw.Header.Action,
		Proto:     raw.Header.Proto,
		Direction: raw.Header.Direction,
		SrcIP:     raw.Header.SrcIP,
		SrcPort:   raw.Header.SrcPort,
		DstIP:     raw.Header.DstIP,
		DstPort:   raw.Header.DstPort,
	}

	curBuf := "payload"
	seenUnsupported := make(map[string]bool)
	addUnsupported := func(name string) {
		if seenUnsupported[name] {
			return
		}
		seenUnsupported[name] = true
		pr.Unsupported = append(pr.Unsupported, name)
	}

	for _, opt := range raw.Options {
		switch opt.Key {
		case "msg":
			pr.Message = opt.Value
		case "classtype":
			pr.Classtype = opt.Value
		case "sid", "rev", "priority":
			n, err := strconv.Atoi(opt.Value)
			if err != nil {
				return nil, fmt.Errorf("suricata: option %q: %w", opt.Key, err)
			}
			switch opt.Key {
			case "sid":
				pr.SID = n
			case "rev":
				pr.Rev = n
			case "priority":
				pr.Priority = n
			}
		case "reference":
			pr.References = append(pr.References, opt.Value)
		case "metadata":
			pr.Metadata = append(pr.Metadata, opt.Value)
		case "flow":
			for _, item := range strings.Split(opt.Value, ",") {
				item = strings.TrimSpace(item)
				if item == "" {
					continue
				}
				pr.Flow = append(pr.Flow, item)
			}
		case "content":
			value, negate := stripNegate(opt.Value)
			pr.Contents = append(pr.Contents, Content{
				Buffer: curBuf,
				Value:  value,
				Negate: negate,
			})
		case "pcre":
			value, negate := stripNegate(opt.Value)
			pr.PCRES = append(pr.PCRES, PCRE{
				Buffer: curBuf,
				Expr:   value,
				Negate: negate,
			})
		case "nocase", "fast_pattern":
			if len(pr.Contents) == 0 {
				addUnsupported(opt.Key)
				continue
			}
			last := &pr.Contents[len(pr.Contents)-1]
			if opt.Key == "nocase" {
				last.NoCase = true
			} else {
				last.FastPattern = true
			}
		case "depth", "offset", "distance", "within":
			if len(pr.Contents) == 0 {
				addUnsupported(opt.Key)
				continue
			}
			n, err := strconv.Atoi(opt.Value)
			if err != nil {
				return nil, fmt.Errorf("suricata: option %q: %w", opt.Key, err)
			}
			last := &pr.Contents[len(pr.Contents)-1]
			switch opt.Key {
			case "depth":
				last.Depth = n
			case "offset":
				last.Offset = n
			case "distance":
				last.Distance = n
			case "within":
				last.Within = n
			}
		default:
			if bufferKeys[opt.Key] {
				curBuf = opt.Key
				continue
			}
			addUnsupported(opt.Key)
		}
	}

	return pr, nil
}

// ParseAll 解析整段规则文本，返回成功解析的规则以及词法/语法错误。
func ParseAll(text string) ([]*ParsedRule, []LexError) {
	raws, errs := LexAll(text)
	rules := make([]*ParsedRule, 0, len(raws))
	parseErrs := make([]LexError, 0)

	for _, raw := range raws {
		pr, err := Parse(raw)
		if err != nil {
			line, txt := 0, ""
			if raw != nil {
				line, txt = raw.Line, raw.Text
			}
			parseErrs = append(parseErrs, LexError{Line: line, Text: txt, Err: err})
			continue
		}
		rules = append(rules, pr)
	}

	allErrs := make([]LexError, 0, len(errs)+len(parseErrs))
	allErrs = append(allErrs, errs...)
	allErrs = append(allErrs, parseErrs...)
	return rules, allErrs
}
