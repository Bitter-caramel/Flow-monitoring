package buildplan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"flow-monitoring/internal/kernel/registry"
)

// 架构守卫（12-5b）：宿主（cmd/server）的依赖闭包里只要出现"可选模块"的包，
// 那个模块就永远砍不掉，而且平时完全看不出来。本文件把这件事变成**构建时就会
// 失败**：GuardHostDeps 按清单精确映射模块包路径，检查是否有人直接 import 了它。
//
// ★ 为什么必须按清单精确映射：宿主闭包里本来就有
// flow-monitoring/internal/modules/store（进程内存储实现，没有对应清单）。
// 若用"包路径里含 internal/modules/"这种粗规则，会把它误判成违规。
//
// ★ 已知局限：这里只检测**直接** import。配合 go list -deps（已经把全部传递依赖
// 展开进闭包）实际上足够了——间接依赖模块包 M 时，M 自身也会以"被闭包内某个包
// 直接 import"的形式出现在边表里。go list 失败（无 go 工具链 / 编译不过）时
// LoadHostDeps 返回错误，绝不静默当成"没违规"。

const (
	// moduleIDPrefix 是清单 id 的模块前缀。
	moduleIDPrefix = "modules."
	// modulePkgPrefix 是模块包路径的公共前缀（go.mod 的 module path + internal/modules/）。
	modulePkgPrefix = "flow-monitoring/internal/modules/"
)

// HostDepIssue 一条违规/告警。
type HostDepIssue struct {
	Package    string   // 被耦合的模块包路径
	ModuleID   string   // 对应清单 id，如 modules.alert
	Core       bool     // 该模块是否 core
	ImportedBy []string // 直接 import 它的包路径（排序）
}

// HostGuardReport 一次守卫的结果。
type HostGuardReport struct {
	Checked  int            // 宿主闭包里的包总数
	Errors   []HostDepIssue // 可选（非 core）模块被耦合 ⇒ 必须让构建失败
	Warnings []HostDepIssue // core 模块被耦合 ⇒ 只告警（core 本来就不可裁剪，但值得知道）
}

// ModulePackage 返回清单 id 对应的包路径（id 前缀 modules. 去掉）。
// id 不以 modules. 开头时返回 error。
func ModulePackage(d registry.Descriptor) (string, error) {
	if !strings.HasPrefix(d.ID, moduleIDPrefix) {
		return "", fmt.Errorf("buildplan: 模块 id %q 不以 %q 开头，无法映射包路径", d.ID, moduleIDPrefix)
	}
	short := strings.TrimPrefix(d.ID, moduleIDPrefix)
	if short == "" {
		return "", fmt.Errorf("buildplan: 模块 id %q 去掉前缀 %q 后为空", d.ID, moduleIDPrefix)
	}
	return modulePkgPrefix + short, nil
}

// UnpackHostDeps 从 `go list -deps -json ./cmd/server` 的 JSON 流里解出
// 「包 → 它的直接 import」表。
//
// 用 json.Decoder 循环解码：go list -json 输出的是**多条** JSON 对象拼接的流，
// 一次性 Unmarshal 会直接失败。对象里其余字段忽略。
func UnpackHostDeps(r io.Reader) (map[string][]string, error) {
	dec := json.NewDecoder(r)
	edges := make(map[string][]string)
	for {
		var pkg struct {
			ImportPath string
			Imports    []string
		}
		if err := dec.Decode(&pkg); err != nil {
			if errors.Is(err, io.EOF) {
				return edges, nil
			}
			return nil, fmt.Errorf("buildplan: 解析 go list -deps -json 输出失败: %w", err)
		}
		if pkg.ImportPath == "" {
			continue
		}
		edges[pkg.ImportPath] = pkg.Imports
	}
}

// LoadHostDeps 在 repoRoot 下执行 `go list -deps -json ./cmd/server` 并调用
// UnpackHostDeps。
//
// ★ 直接用 os/exec 捕获 stdout：Config.Run 那种 func(dir, args...) error 的形状
// 拿不到输出，这里必须自己接管 stdout/stderr。stderr 由 commandOutput 截断到
// 500 字节拼进错误。go list 失败（无 go 工具链 / 编译不过）⇒ 返回 error，绝不
// 静默返回空表当成"没违规"。
func LoadHostDeps(repoRoot string) (map[string][]string, error) {
	out, err := commandOutput(repoRoot, "go", "list", "-deps", "-json", "./cmd/server")
	if err != nil {
		return nil, fmt.Errorf("buildplan: 求宿主依赖闭包失败: %w", err)
	}
	return UnpackHostDeps(strings.NewReader(out))
}

// GuardHostDeps 是纯函数：给出清单与边表，算出违规与告警。
//
// 规则：对每个清单模块求包路径 p；若 p 出现在边表的**任一包的 import 列表**里，
// 则该模块被耦合；core=false ⇒ Errors，core=true ⇒ Warnings。
// ★ 内嵌模块（InProcess=true）本就是给宿主用的库，不适用"可裁剪"概念，一律归入
// Warnings，不再判 Error。
// ImportedBy = 所有直接 import 了 p 的包路径（升序）；Errors/Warnings 都按 ModuleID 升序。
//
// ★ edges 为 nil/空 ⇒ 返回 Checked=0 且无违规（不是错误）。
// ★ 模块包路径本身不在边表里（宿主没引用它，且它也不是宿主的包）⇒ 与违规无关：
// 判断依据只能是"有人 import 了它"，而不是"它在闭包里"。
func GuardHostDeps(reg *registry.Registry, edges map[string][]string) HostGuardReport {
	report := HostGuardReport{Checked: len(edges)}
	if reg == nil {
		return report
	}

	// 反向索引：被 import 的包 → 直接 import 它的包。
	importers := make(map[string][]string)
	for pkg, imports := range edges {
		for _, imp := range imports {
			importers[imp] = append(importers[imp], pkg)
		}
	}

	for _, d := range reg.List() {
		p, err := ModulePackage(d)
		if err != nil {
			continue
		}
		by := importers[p]
		if len(by) == 0 {
			continue
		}
		by = append([]string(nil), by...)
		sort.Strings(by)
		issue := HostDepIssue{Package: p, ModuleID: d.ID, Core: d.Core, ImportedBy: by}
		if d.InProcess || d.Core {
			report.Warnings = append(report.Warnings, issue)
		} else {
			report.Errors = append(report.Errors, issue)
		}
	}

	sort.Slice(report.Errors, func(i, j int) bool { return report.Errors[i].ModuleID < report.Errors[j].ModuleID })
	sort.Slice(report.Warnings, func(i, j int) bool { return report.Warnings[i].ModuleID < report.Warnings[j].ModuleID })
	return report
}
