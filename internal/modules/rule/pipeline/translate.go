package pipeline

import (
	"fmt"

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

// Translate 是规则翻译器插件化后的对外入口（向后兼容）。
//
// 其语义等同于 TranslateSource(text, rule.SourceSuricata)：旧调用方无需改动，
// 导入的 Suricata 规则仍然按社区来源处理。
func Translate(text string) *TranslateResult {
	return TranslateSource(text, rule.SourceSuricata)
}

// TranslateSource 按指定来源翻译规则文本。
//
// 它先对整段文本做词法分析，再对每条规则依次执行关键字选项处理、
// 元信息收尾与编译。每条成功编译的规则都会把 Source 覆盖为 src，
// 因此 kw/frame.go 里写死的默认来源不会污染自写/发布规则。
//
// ★ ID 格式必须保持 "suricata-<sid>" 不变：告警、去重与 golden 快照都依赖它。
func TranslateSource(text string, src rule.Source) *TranslateResult {
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
			// 覆盖 kw/frame.go 里写死的 SourceSuricata，确保来源由调用方决定。
			c.Source = src
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

// init 把完整翻译器注入 rule 包，供 rule.LoadDir 使用。
//
// 为什么用注入而不是直接 import：pipeline 已经依赖 rule（以及依赖 rule 的 kw），
// 若 rule 再反向 import pipeline 就会形成导入环。注入点只在启动期写一次，
// 之后只读，因此无需加锁。
func init() {
	rule.SetTextTranslator(func(text string, src rule.Source) ([]*rule.CompiledRule, []string) {
		res := TranslateSource(text, src)
		issues := make([]string, 0, len(res.LexErrors)+len(res.CompileErrs))
		for _, le := range res.LexErrors {
			issues = append(issues, fmt.Sprintf("line %d: %s", le.Line, le.Err))
		}
		for _, ce := range res.CompileErrs {
			issues = append(issues, ce.Error())
		}
		return res.Rules, issues
	})
}
