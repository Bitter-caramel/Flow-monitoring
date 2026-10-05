package rule

import "flow-monitoring/internal/modules/rule/suricata"

// TranslateResult 表示一次规则文本翻译（解析 + 归一化 + 编译）的汇总结果。
type TranslateResult struct {
	// Rules 是成功编译的规则。
	Rules []*CompiledRule
	// LexErrors 是词法 / 语法错误（含行号）。
	LexErrors []suricata.LexError
	// CompileErrs 是编译失败明细。
	CompileErrs []error
	// Total 是输入规则条数 = ParseAll 成功条数 + 词法失败条数。
	Total int
	// Compiled 是成功编译条数。
	Compiled int
	// Failed 是失败条数 = Total - Compiled。
	Failed int
	// Unsupported 是不支持项计数：键 = 说明文本，值 = 出现次数。
	Unsupported map[string]int
}

// Translate 将 Suricata 规则文本翻译为编译结果汇总。
// 它依次调用 suricata.ParseAll、NormalizeAll、CompileAll，统计不支持项、
// 成功与失败条数；对空字符串也不会 panic，且返回的切片与 map 均为非 nil。
func Translate(text string) *TranslateResult {
	parsed, lexErrs := suricata.ParseAll(text)
	rules := NormalizeAll(parsed)
	compiled, compileErrs := CompileAll(rules)

	res := &TranslateResult{
		Rules:       make([]*CompiledRule, 0, len(compiled)),
		LexErrors:   make([]suricata.LexError, 0, len(lexErrs)),
		CompileErrs: make([]error, 0, len(compileErrs)),
		Unsupported: make(map[string]int),
	}

	res.Rules = append(res.Rules, compiled...)
	res.LexErrors = append(res.LexErrors, lexErrs...)
	res.CompileErrs = append(res.CompileErrs, compileErrs...)

	res.Total = len(parsed) + len(lexErrs)
	res.Compiled = len(compiled)
	res.Failed = res.Total - res.Compiled

	for _, p := range parsed {
		if p == nil {
			continue
		}
		for _, u := range p.Unsupported {
			res.Unsupported[u]++
		}
	}
	for _, c := range compiled {
		if c == nil {
			continue
		}
		for _, u := range c.Unsupported {
			res.Unsupported[u]++
		}
	}

	return res
}
