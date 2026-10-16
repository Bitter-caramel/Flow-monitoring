// Command fmbuild 是构建期裁剪的命令行薄壳（开发工具，不参与宿主装配）。
//
// ★ CLI 不自己实现任何业务逻辑：选择、依赖闭包、构建、构建清单全部由
// internal/buildplan 提供，本文件只负责参数解析、退出码、人类可读表格渲染。
// 与 cmd/fmctl/main.go 同构（run + main），便于测试。
//
// ★ 为什么脚本只做薄壳：bash / PowerShell 各写一份裁剪逻辑必然漂移，且
// PowerShell 5.1 读 UTF-8 必须显式 -Encoding UTF8，放在 Go 里一次实现最省心。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"flow-monitoring/internal/buildplan"
	"flow-monitoring/internal/kernel/registry"
)

const usageText = `fmbuild — 构建期裁剪 CLI（唯一行为实现：internal/buildplan）

用法:
  fmbuild [--all | --core-only | --modules=ID[,ID...]] [选项]

模式（互斥，缺省 --all）:
  --all                 构建全部清单模块（无源码的跳过并记录）
  --core-only           只构建 core 模块（无源码的跳过并记录）
  --modules=ID[,ID...]  只构建给定模块及其运行时依赖闭包（缺源码报错）
                        ID 接受 modules.query 或 query 两种写法

选项:
  --list                只打印这次会构建什么，不构建、不写任何文件
  --json                以 JSON 输出（配合 --list 输出 Plan）
  --out=DIR             产物目录（缺省 FLOW_PLUGIN_DIR，为空则 bin/plugins）
  --registry=DIR        清单目录（缺省 registry/backend-modules，相对 --repo）
  --repo=DIR            仓库根（缺省当前工作目录）

退出码: 0 成功 / 2 用法或选择错误 / 1 运行期失败（go build 失败、写文件失败）
`

// options 解析后的选项。
type options struct {
	mode       buildplan.Mode
	modeFlag   string
	ids        []string
	modulesSet bool
	list       bool
	jsonOut    bool
	out        string
	registry   string
	repo       string
	help       bool
}

// setMode 记录模式并做互斥校验。
func (o *options) setMode(flag string, m buildplan.Mode) error {
	if o.modeFlag != "" && o.modeFlag != flag {
		return fmt.Errorf("模式互斥：--%s 不能与 --%s 同时使用", flag, o.modeFlag)
	}
	o.modeFlag = flag
	o.mode = m
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// parseArgs 手工解析：风格对齐 cmd/fmctl/main.go。
func parseArgs(args []string) (options, error) {
	var o options
	for i := 0; i < len(args); i++ {
		a := args[i]
		var err error
		switch {
		case a == "--all":
			err = o.setMode("all", buildplan.ModeAll)
		case a == "--core-only":
			err = o.setMode("core-only", buildplan.ModeCoreOnly)
		case a == "--modules":
			if o.modulesSet {
				return o, errors.New("--modules 不能重复指定（后者覆盖前者会静默丢参数）")
			}
			i++
			if i >= len(args) {
				return o, errors.New("--modules 缺少参数")
			}
			o.ids, err = splitIDs(args[i])
			if err == nil {
				o.modulesSet = true
				err = o.setMode("modules", buildplan.ModeModules)
			}
		case strings.HasPrefix(a, "--modules="):
			if o.modulesSet {
				return o, errors.New("--modules 不能重复指定（后者覆盖前者会静默丢参数）")
			}
			o.ids, err = splitIDs(strings.TrimPrefix(a, "--modules="))
			if err == nil {
				o.modulesSet = true
				err = o.setMode("modules", buildplan.ModeModules)
			}
		case a == "--list":
			o.list = true
		case a == "--json":
			o.jsonOut = true
		case a == "--out":
			i++
			if i >= len(args) {
				return o, errors.New("--out 缺少参数")
			}
			o.out = args[i]
		case strings.HasPrefix(a, "--out="):
			o.out = strings.TrimPrefix(a, "--out=")
		case a == "--registry":
			i++
			if i >= len(args) {
				return o, errors.New("--registry 缺少参数")
			}
			o.registry = args[i]
		case strings.HasPrefix(a, "--registry="):
			o.registry = strings.TrimPrefix(a, "--registry=")
		case a == "--repo":
			i++
			if i >= len(args) {
				return o, errors.New("--repo 缺少参数")
			}
			o.repo = args[i]
		case strings.HasPrefix(a, "--repo="):
			o.repo = strings.TrimPrefix(a, "--repo=")
		case a == "-h" || a == "--help" || a == "help":
			o.help = true
		case strings.HasPrefix(a, "-") && a != "-":
			return o, fmt.Errorf("未知选项: %s", a)
		default:
			return o, fmt.Errorf("未知参数: %s", a)
		}
		if err != nil {
			return o, err
		}
	}
	return o, nil
}

// splitIDs 解析逗号分隔的模块 id 列表。
func splitIDs(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("--modules 需要至少一个模块 id")
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, errors.New("--modules 含空的模块 id")
		}
		out = append(out, p)
	}
	return out, nil
}

// run 是 CLI 的可测试入口：返回给 os.Exit 的退出码。
func run(args []string, stdout, stderr io.Writer) int {
	o, err := parseArgs(args)
	if err != nil {
		return usageErr(stderr, err.Error())
	}
	if o.help || len(args) == 0 {
		fmt.Fprint(stdout, usageText)
		return 0
	}
	if o.mode == "" {
		o.mode = buildplan.ModeAll
	}

	repo := o.repo
	if repo == "" {
		wd, wdErr := os.Getwd()
		if wdErr != nil {
			return fail(stderr, wdErr)
		}
		repo = wd
	}

	regDir := o.registry
	if regDir == "" {
		regDir = filepath.Join(repo, "registry", "backend-modules")
	} else if !filepath.IsAbs(regDir) {
		regDir = filepath.Join(repo, regDir)
	}

	outDir := o.out
	if outDir == "" {
		outDir = os.Getenv("FLOW_PLUGIN_DIR")
	}
	if outDir == "" {
		outDir = "bin/plugins"
	}

	reg, err := registry.Load(regDir)
	if err != nil {
		return fail(stderr, err)
	}

	hasSource := func(d registry.Descriptor) bool {
		_, statErr := os.Stat(filepath.Join(repo, "cmd", "plugins", d.Binary, "main.go"))
		return statErr == nil
	}

	plan, planErr := buildplan.Build(reg, o.mode, o.ids, hasSource)

	if o.list {
		if plan == nil {
			return selectionErr(stderr, planErr)
		}
		if o.jsonOut {
			return emitJSON(stdout, stderr, plan)
		}
		renderList(stdout, reg, plan)
		return 0
	}

	// 构建路径：选择错误（未知 id / --modules 缺源码）判为退出码 2。
	if planErr != nil {
		return selectionErr(stderr, planErr)
	}

	manifest, err := buildplan.Execute(buildplan.Config{
		RepoRoot:    repo,
		OutDir:      outDir,
		RegistryDir: regDir,
		Mode:        o.mode,
		IDs:         o.ids,
		HasSource:   hasSource,
	})
	if err != nil {
		return fail(stderr, err)
	}

	for _, m := range manifest.Modules {
		fmt.Fprintf(stdout, "built %s -> %s (%d bytes)\n", m.ID, m.File, m.Size)
	}
	if len(manifest.Skipped) > 0 {
		fmt.Fprintf(stdout, "skipped %d module(s) without source\n", len(manifest.Skipped))
	}
	fmt.Fprintf(stdout, "wrote %s\n", filepath.Join(manifest.OutDir, buildplan.ManifestName))
	return 0
}

// renderList 渲染 --list 表格：ID BINARY LAYER CORE ENABLED SOURCE ACTION。
func renderList(w io.Writer, reg *registry.Registry, plan *buildplan.Plan) {
	skipped := make(map[string]buildplan.Skipped, len(plan.Skipped))
	ids := make([]string, 0, len(plan.Selected)+len(plan.Skipped))
	desc := make(map[string]registry.Descriptor, len(plan.Selected)+len(plan.Skipped))
	for _, d := range plan.Selected {
		ids = append(ids, d.ID)
		desc[d.ID] = d
	}
	for _, s := range plan.Skipped {
		skipped[s.ID] = s
		ids = append(ids, s.ID)
		if d, ok := reg.Get(s.ID); ok {
			desc[s.ID] = d
		}
	}
	sort.Strings(ids)

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tBINARY\tLAYER\tCORE\tENABLED\tSOURCE\tACTION")
	for _, id := range ids {
		d := desc[id]
		if s, ok := skipped[id]; ok {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\tno\tskip:%s\n",
				d.ID, d.Binary, d.Layer, yesNo(d.Core), yesNo(d.IsEnabled()), s.Reason)
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\tyes\tbuild\n",
				d.ID, d.Binary, d.Layer, yesNo(d.Core), yesNo(d.IsEnabled()))
		}
	}
	_ = tw.Flush()
}

// emitJSON 以缩进 JSON 输出任意结构体。
func emitJSON(stdout, stderr io.Writer, v any) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "错误:", err)
		return 1
	}
	fmt.Fprintln(stdout, string(b))
	return 0
}

// fail 打印运行期错误，返回退出码 1。
func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "错误:", err)
	return 1
}

// selectionErr 打印用法/选择错误，返回退出码 2。
func selectionErr(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "错误:", err)
	return 2
}

// usageErr 打印用法错误与用法说明，返回退出码 2。
func usageErr(stderr io.Writer, msg string) int {
	fmt.Fprintln(stderr, "错误:", msg)
	fmt.Fprint(stderr, usageText)
	return 2
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
