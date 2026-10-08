package pipeline

import (
	"flow-monitoring/internal/modules/rule"
	"flow-monitoring/internal/modules/rule/kw"
	"flow-monitoring/internal/modules/rule/kw/meta"
	"flow-monitoring/internal/modules/rule/suricata"
)

// TranslateResult 是规则翻译器插件化后的对外结果。
type TranslateResult struct {
	Rules       []*rule.CompiledRule // 成功编译的规则
	LexErrors   []suricata.LexError  // 词法/语法错误（含行号）
	CompileErrs []error              // 编译失败明细
	Total       int                  // 词法成功条数 + 词法失败条数
	Compiled    int                  // 成功编译条数
	Failed      int                  // Total - Compiled
	Unsupported map[string]int       // 不支持项计数
}

// Translate 是规则翻译器插件化后的对外入口。
// 它先对整段文本做词法分析，再对每条规则依次执行关键字选项处理、
// 元信息收尾与编译，语义与 rule.Translate 保持一致。
func Translate(text string) *TranslateResult {
	raws, lexErrs := suricata.LexAll(text)

	res := &TranslateResult{
		Rules:       make([]*rule.CompiledRule, 0, len(raws)),
		LexErrors:   make([]suricata.LexError, 0, len(lexErrs)),
		CompileErrs: make([]error, 0),
		Unsupported: make(map[string]int),
	}
	res.LexErrors = append(res.LexErrors, lexErrs...)

	for _, raw := range raws {
		if raw == nil {
			continue
		}

		st := kw.NewState(raw)
		if err := kw.RunOptions(st); err != nil {
			res.LexErrors = append(res.LexErrors, suricata.LexError{Line: raw.Line, Text: raw.Text, Err: err})
			continue
		}
		meta.Finalize(st)

		c, cerr := rule.Compile(st.Rule)
		if cerr != nil {
			res.CompileErrs = append(res.CompileErrs, cerr)
		} else {
			res.Rules = append(res.Rules, c)
			// 编译期被丢弃的条件也计入"不支持项"（例如 RE2 不支持的正则）
			for _, name := range c.Unsupported {
				res.Unsupported[name]++
			}
		}

		for name, count := range st.Unsupported {
			res.Unsupported[name] += count
		}
	}

	res.Total = len(raws) + len(lexErrs)
	res.Compiled = len(res.Rules)
	res.Failed = res.Total - res.Compiled

	return res
}
