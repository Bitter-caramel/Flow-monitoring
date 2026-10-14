package detect

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"flow-monitoring/internal/modules/rule"
	"flow-monitoring/internal/modules/rule/pipeline"
)

// ImportReport 是规则集加载/导入后的“人读友好”报告。
//
// 它的定位很朴素：导入报告是给人看的——运维和安全同学不需要翻日志、读源码，
// 只要看一眼这份报告，就能知道：
//   - 这次到底导进来多少条规则（Total）；
//   - 有多少条真正变成了可执行的 Program（Compiled）；
//   - 哪些规则没生效、为什么（词法错误 / 编译失败 / 不支持项 / 因缓冲区被剔除）。
//
// 因此报告里的所有切片都要求有序、可复现，绝不能让 map 的随机遍历顺序泄漏到输出中。
type ImportReport struct {
	Total        int                 // 文本里的总条数（词法成功 + 失败）
	Compiled     int                 // 最终成功编译成 Program 的条数
	Failed       int                 // Total - Compiled
	LexErrors    []string            // 每条渲染成 "line <行号>: <err.Error()>"，按行号升序
	CompileErrs  []string            // 规则侧编译失败明细
	Unsupported  []string            // 不支持项汇总（已排序），形如 "flowbits x1"
	DroppedRules []string            // 因引用引擎不支持的缓冲区而被剔除的规则，形如 "<规则ID>: <err>"
	Notes        map[string][]string // 每条规则的备注，key = 规则 ID
}

// String 把报告渲染成人类可读的分段文本。
// 约定：
//   - 用中文标题分段：总览 / 词法错误 / 编译失败 / 不支持项汇总 / 被剔除的规则 / 备注；
//   - 空段不打印；
//   - 输出稳定可复现：同一份报告连续调用两次，结果完全一致（备注的 key 会先排序）。
func (r *ImportReport) String() string {
	var b strings.Builder
	b.WriteString("========== 规则集导入报告 ==========\n")
	b.WriteString(fmt.Sprintf("总览：共 %d 条，成功编译 %d 条，失败 %d 条\n", r.Total, r.Compiled, r.Failed))

	if len(r.LexErrors) > 0 {
		b.WriteString("\n[词法错误]\n")
		for _, s := range r.LexErrors {
			b.WriteString("  " + s + "\n")
		}
	}
	if len(r.CompileErrs) > 0 {
		b.WriteString("\n[编译失败]\n")
		for _, s := range r.CompileErrs {
			b.WriteString("  " + s + "\n")
		}
	}
	if len(r.Unsupported) > 0 {
		b.WriteString("\n[不支持项汇总]\n")
		for _, s := range r.Unsupported {
			b.WriteString("  " + s + "\n")
		}
	}
	if len(r.DroppedRules) > 0 {
		b.WriteString("\n[被剔除的规则]\n")
		for _, s := range r.DroppedRules {
			b.WriteString("  " + s + "\n")
		}
	}
	if len(r.Notes) > 0 {
		// map 的遍历顺序是随机的，必须先取出 key 并排序，保证输出可复现。
		keys := make([]string, 0, len(r.Notes))
		for k := range r.Notes {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// 只有当至少有一条备注时，才打印“备注”这一段（空段不打印）。
		hasNote := false
		for _, k := range keys {
			if len(r.Notes[k]) > 0 {
				hasNote = true
				break
			}
		}
		if hasNote {
			b.WriteString("\n[备注]\n")
			for _, k := range keys {
				notes := r.Notes[k]
				if len(notes) == 0 {
					continue
				}
				b.WriteString("  " + k + ":\n")
				for _, n := range notes {
					b.WriteString("    - " + n + "\n")
				}
			}
		}
	}
	return b.String()
}

// RuleSet 是一次规则集导入的结果：可直接执行的程序 + 给人看的报告。
type RuleSet struct {
	Programs []*Program    // 成功编译、可直接交给 Engine 的规则程序
	Report   *ImportReport // 导入报告
}

// Engine 基于已成功编译的 Programs 构造一个引擎。
func (rs *RuleSet) Engine() *Engine {
	return NewEngine(rs.Programs)
}

// UsesBuffer 报告规则集里是否有任何条件引用了指定缓冲区。
// 用途：没有规则用 stream 时，上层可以完全跳过 TCP 重组（零开销）。
func (rs *RuleSet) UsesBuffer(b rule.Buffer) bool {
	if rs == nil {
		return false
	}
	for _, p := range rs.Programs {
		if p == nil {
			continue
		}
		for _, c := range p.Conds {
			if c.Buf == b {
				return true
			}
		}
	}
	return false
}

// LoadText 解析一段规则文本并生成导入报告。
//
// 处理流程与“为什么这么处理”：
//  1. 交给 pipeline.Translate 做词法/语法翻译；
//  2. 把词法错误按行号排序后渲染，方便人对照原文定位；
//  3. 逐条编译：成功的进入 Programs；只因为“引擎不支持某缓冲区”而失败的，
//     属于可预期的能力边界，单独丢进 DroppedRules（并说明原因），不当作编译错误；
//  4. 把不支持项汇总排序、把每条规则的备注整理好，最终产出稳定可复现的报告。
func LoadText(text string) *RuleSet {
	res := pipeline.Translate(text)

	// Notes 必须初始化成非 nil，避免调用方直接写入时 panic。
	report := &ImportReport{
		Total:        res.Total,
		Notes:        make(map[string][]string),
		LexErrors:    make([]string, 0, len(res.LexErrors)),
		CompileErrs:  make([]string, 0, len(res.CompileErrs)),
		Unsupported:  make([]string, 0, len(res.Unsupported)),
		DroppedRules: make([]string, 0),
	}

	// ---- 词法错误：按行号升序渲染 ----
	// 直接对 res.LexErrors 就地排序，省一次拷贝；res 是本次调用的私有产物。
	sort.Slice(res.LexErrors, func(i, j int) bool {
		return res.LexErrors[i].Line < res.LexErrors[j].Line
	})
	for _, le := range res.LexErrors {
		report.LexErrors = append(report.LexErrors, fmt.Sprintf("line %d: %s", le.Line, le.Err.Error()))
	}

	// ---- 规则侧编译失败：先收下 pipeline 已经报出来的 ----
	for _, e := range res.CompileErrs {
		report.CompileErrs = append(report.CompileErrs, e.Error())
	}

	// ---- 逐条编译 ----
	progs, dropped, compileErrs := compileRules(res.Rules)
	report.DroppedRules = append(report.DroppedRules, dropped...)
	report.CompileErrs = append(report.CompileErrs, compileErrs...)

	// ---- 不支持项汇总：先渲染成 "说明 xN"，再按“次数降序、说明字典序”排序 ----
	type unsupportedEntry struct {
		desc  string
		count int
	}
	entries := make([]unsupportedEntry, 0, len(res.Unsupported))
	for desc, n := range res.Unsupported {
		entries = append(entries, unsupportedEntry{desc: desc, count: n})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].desc < entries[j].desc
	})
	for _, e := range entries {
		report.Unsupported = append(report.Unsupported, fmt.Sprintf("%s x%d", e.desc, e.count))
	}

	// ---- 备注：把每条 Program 自带的 Unsupported 明细挂到对应规则 ID 下 ----
	// 这里的顺序保持 Program.Unsupported 的原顺序，不额外排序。
	for _, p := range progs {
		if len(p.Unsupported) == 0 {
			continue
		}
		report.Notes[p.ID] = append(report.Notes[p.ID], p.Unsupported...)
	}

	// ---- 汇总计数 ----
	report.Compiled = len(progs)
	report.Failed = report.Total - report.Compiled

	return &RuleSet{
		Programs: progs,
		Report:   report,
	}
}

// LoadFile 从磁盘读取规则文件并导入。
// 读文件失败时直接返回 error，交给调用方决定怎么处理。
func LoadFile(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadText(string(data)), nil
}

// compileRules 逐条编译规则。
// 返回：成功编译的程序、因引用引擎不支持的缓冲区而被剔除的明细、其它编译错误。
func compileRules(rules []*rule.CompiledRule) (progs []*Program, dropped []string, compileErrs []string) {
	progs = make([]*Program, 0, len(rules))
	for _, cr := range rules {
		p, err := Compile(cr)
		if err == nil {
			progs = append(progs, p)
			continue
		}
		if errors.Is(err, ErrUnsupportedBuffer) {
			// 引擎明确不支持该缓冲区：这条规则不会生效，剔除并记录原因。
			dropped = append(dropped, fmt.Sprintf("%s: %s", cr.ID, err))
			continue
		}
		// 其它错误才算真正的编译失败。
		compileErrs = append(compileErrs, err.Error())
	}
	return progs, dropped, compileErrs
}
