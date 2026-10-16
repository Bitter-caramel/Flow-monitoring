// Command fmctl 是模块控制面的命令行薄壳（Unix 文件树语义）。
//
// ★ CLI 不自己实现任何业务逻辑：看模块、看依赖图、看影响面、启停模块
// 全部由服务层 internal/kernel/modulecontrol 提供，本文件只负责：
//   - 参数解析与退出码
//   - 表格 / 文件树 / 详情的人类可读渲染
//   - disable 的影响面确认
//
// ★ 本步不实现运行期启停：enable/disable 只把 enabled 写回清单，重启后生效。
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"flow-monitoring/internal/kernel/modulecontrol"
	"flow-monitoring/internal/kernel/registry"
)

const usageText = `fmctl — 模块控制面 CLI（唯一行为实现：internal/kernel/modulecontrol）

用法:
  fmctl [--manifest-dir DIR] [--json] <命令>

命令:
  modules               列出全部模块（ID/层/核心/启用/状态）
  show <id>             一个模块的详情（depends/provides/injects/http_base/binary）
  tree [layer]          依赖树（Unix 文件树风格；给了 layer 只看该层）
  impact <id>           停它的影响面（谁会连带被停、能不能停）
  selfcheck             自检结果（Errors/Warnings 全列，含 Code）
  enable <id>           启用（写回清单 → 提示重启后生效）
  disable <id> [--yes]  停用（先打印影响面并确认；--yes 跳过确认）

全局选项:
  --manifest-dir DIR    清单目录（默认 registry/backend-modules）
  --json                以 JSON 输出（直接复用服务层结构体）
  --yes                 跳过 disable 的确认

退出码: 0 成功 / 1 一般错误 / 2 被拒绝（core 或用户取消）
`

// cliOptions 解析后的选项与位置参数。
type cliOptions struct {
	manifestDir string
	jsonOut     bool
	yes         bool
	pos         []string
}

// parseArgs 手工解析：允许全局选项出现在命令前或后（如 `disable <id> --yes`）。
func parseArgs(args []string) (cliOptions, error) {
	var o cliOptions
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--manifest-dir":
			i++
			if i >= len(args) {
				return o, errors.New("--manifest-dir 缺少参数")
			}
			o.manifestDir = args[i]
		case strings.HasPrefix(a, "--manifest-dir="):
			o.manifestDir = strings.TrimPrefix(a, "--manifest-dir=")
		case a == "--json":
			o.jsonOut = true
		case a == "--yes" || a == "-y":
			o.yes = true
		case a == "-h" || a == "--help" || a == "help":
			o.pos = append(o.pos, "--help")
		case strings.HasPrefix(a, "-") && a != "-":
			return o, fmt.Errorf("未知选项: %s", a)
		default:
			o.pos = append(o.pos, a)
		}
	}
	return o, nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run 是 CLI 的可测试入口：返回给 os.Exit 的退出码。
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, err := parseArgs(args)
	if err != nil {
		return usageErr(stderr, err.Error())
	}
	if len(opts.pos) == 0 {
		fmt.Fprint(stderr, usageText)
		return 1
	}
	if opts.pos[0] == "--help" {
		fmt.Fprint(stdout, usageText)
		return 0
	}

	cmd := opts.pos[0]
	rest := opts.pos[1:]

	svc, err := modulecontrol.New(modulecontrol.Options{ManifestDir: opts.manifestDir})
	if err != nil {
		return fail(stderr, err)
	}

	switch cmd {
	case "modules":
		return cmdModules(svc, opts, stdout, stderr)
	case "show":
		if len(rest) < 1 {
			return usageErr(stderr, "show 需要 <id>")
		}
		return cmdShow(svc, opts, rest[0], stdout, stderr)
	case "tree":
		layer := ""
		if len(rest) >= 1 {
			layer = rest[0]
		}
		return cmdTree(svc, opts, layer, stdout, stderr)
	case "impact":
		if len(rest) < 1 {
			return usageErr(stderr, "impact 需要 <id>")
		}
		return cmdImpact(svc, opts, rest[0], stdout, stderr)
	case "selfcheck":
		return cmdSelfCheck(svc, opts, stdout, stderr)
	case "enable":
		if len(rest) < 1 {
			return usageErr(stderr, "enable 需要 <id>")
		}
		return cmdEnable(svc, opts, rest[0], stdout, stderr)
	case "disable":
		if len(rest) < 1 {
			return usageErr(stderr, "disable 需要 <id>")
		}
		return cmdDisable(svc, opts, rest[0], stdin, stdout, stderr)
	default:
		return usageErr(stderr, "未知命令: "+cmd)
	}
}

// ------------------------- 命令实现 -------------------------

func cmdModules(svc *modulecontrol.Service, o cliOptions, stdout, stderr io.Writer) int {
	mods, err := svc.List()
	if err != nil {
		return fail(stderr, err)
	}
	if o.jsonOut {
		return emitJSON(stdout, stderr, mods)
	}
	renderModules(stdout, mods)
	return 0
}

func cmdShow(svc *modulecontrol.Service, o cliOptions, id string, stdout, stderr io.Writer) int {
	mod, err := svc.Show(id)
	if err != nil {
		return moduleErr(stderr, id, err)
	}
	if o.jsonOut {
		return emitJSON(stdout, stderr, mod)
	}
	renderShow(stdout, mod)
	return 0
}

func cmdTree(svc *modulecontrol.Service, o cliOptions, layer string, stdout, stderr io.Writer) int {
	g, err := svc.Graph()
	if err != nil {
		return fail(stderr, err)
	}
	if o.jsonOut {
		return emitJSON(stdout, stderr, g)
	}
	renderTree(stdout, g, layer)
	return 0
}

func cmdImpact(svc *modulecontrol.Service, o cliOptions, id string, stdout, stderr io.Writer) int {
	imp, err := svc.Impact(id)
	if err != nil {
		return moduleErr(stderr, id, err)
	}
	if o.jsonOut {
		return emitJSON(stdout, stderr, imp)
	}
	renderImpact(stdout, imp)
	return 0
}

func cmdSelfCheck(svc *modulecontrol.Service, o cliOptions, stdout, stderr io.Writer) int {
	rep, err := svc.SelfCheck()
	if err != nil {
		return fail(stderr, err)
	}
	if o.jsonOut {
		return emitJSON(stdout, stderr, rep)
	}
	renderSelfCheck(stdout, rep)
	return 0
}

func cmdEnable(svc *modulecontrol.Service, o cliOptions, id string, stdout, stderr io.Writer) int {
	res, err := svc.SetEnabled(id, true)
	if err != nil {
		if errors.Is(err, modulecontrol.ErrCoreModule) {
			fmt.Fprintln(stderr, "拒绝:", err)
			return 2
		}
		return moduleErr(stderr, id, err)
	}
	return printChange(o, res, "启用", stdout, stderr)
}

// cmdDisable 实现"先打印影响面并要求确认"的停用流程。
//
//   - 影响面显示不可停（core 本体，或会连带停掉 core）⇒ 直接拒绝，退出码 2，不写文件
//   - 非 --yes 时读 stdin，用户拒绝 ⇒ 退出码 2，不写文件
//   - 通过后调用服务层 SetEnabled(id,false)
func cmdDisable(svc *modulecontrol.Service, o cliOptions, id string, stdin io.Reader, stdout, stderr io.Writer) int {
	imp, err := svc.Impact(id)
	if err != nil {
		return moduleErr(stderr, id, err)
	}
	if o.jsonOut {
		if rc := emitJSON(stdout, stderr, imp); rc != 0 {
			return rc
		}
	} else {
		renderImpact(stdout, imp)
	}

	if !imp.CanDisable {
		fmt.Fprintf(stderr, "拒绝停用 %s：%s\n", id, imp.BlockReason)
		return 2
	}

	if !o.yes {
		fmt.Fprintf(stderr, "确认停用 %s 吗？[y/N] ", id)
		if !confirm(stdin) {
			fmt.Fprintln(stderr, "已取消，未修改清单。")
			return 2
		}
	}

	res, err := svc.SetEnabled(id, false)
	if err != nil {
		if errors.Is(err, modulecontrol.ErrCoreModule) {
			fmt.Fprintln(stderr, "拒绝:", err)
			return 2
		}
		return moduleErr(stderr, id, err)
	}
	return printChange(o, res, "停用", stdout, stderr)
}

// confirm 读一行 stdin，只有 y/yes 才算确认。
func confirm(stdin io.Reader) bool {
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes"
}

// ------------------------- 渲染（独立、便于测试） -------------------------

// renderModules 用 tabwriter 渲染模块表格。
func renderModules(w io.Writer, mods []modulecontrol.ModuleView) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tLAYER\tCORE\tENABLED\tSTATE")
	for _, m := range mods {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", m.ID, m.Layer, yesNo(m.Core), yesNo(m.Enabled), m.State)
	}
	_ = tw.Flush()
}

// renderShow 渲染单模块详情。
func renderShow(w io.Writer, m modulecontrol.ModuleView) {
	fmt.Fprintf(w, "ID:        %s\n", m.ID)
	fmt.Fprintf(w, "Name:      %s\n", m.Name)
	fmt.Fprintf(w, "Version:   %s\n", m.Version)
	fmt.Fprintf(w, "Layer:     %s\n", m.Layer)
	fmt.Fprintf(w, "Core:      %s\n", yesNo(m.Core))
	fmt.Fprintf(w, "Enabled:   %s\n", yesNo(m.Enabled))
	fmt.Fprintf(w, "State:     %s\n", m.State)
	fmt.Fprintf(w, "Binary:    %s\n", orDash(m.Binary))
	fmt.Fprintf(w, "HTTPBase:  %s\n", orDash(m.HTTPBase))
	fmt.Fprintf(w, "Depends:   %s\n", joinOrDash(m.Depends))
	fmt.Fprintf(w, "Provides:  %s\n", joinOrDash(m.Provides))
	fmt.Fprintf(w, "Injects:   %s\n", joinOrDash(m.Injects))
}

// treeChild 是依赖树子节点。
type treeChild struct {
	id  string
	via string
}

// renderTree 用 Unix 文件树风格渲染依赖树：root 依赖其子节点（[via] 标依赖来源）。
// layer 非空时只看该层（两端都不在该层内的边忽略）。
func renderTree(w io.Writer, g modulecontrol.Graph, layer string) {
	nodes := g.Nodes
	if layer != "" {
		filtered := make([]modulecontrol.ModuleView, 0, len(nodes))
		for _, n := range nodes {
			if n.Layer == layer {
				filtered = append(filtered, n)
			}
		}
		nodes = filtered
	}
	if len(nodes) == 0 {
		if layer != "" {
			fmt.Fprintf(w, "（层 %s 无模块）\n", layer)
		} else {
			fmt.Fprintln(w, "（无模块）")
		}
		return
	}

	inSet := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		inSet[n.ID] = true
	}

	children := make(map[string][]treeChild)
	hasParent := make(map[string]bool)
	for _, e := range g.Edges {
		if !inSet[e.From] || !inSet[e.To] {
			continue
		}
		children[e.From] = append(children[e.From], treeChild{id: e.To, via: e.Via})
		hasParent[e.To] = true
	}
	for id := range children {
		sort.Slice(children[id], func(i, j int) bool { return children[id][i].id < children[id][j].id })
	}

	appeared := make(map[string]bool)
	var printChildren func(parent, prefix string, path map[string]bool)
	printChildren = func(parent, prefix string, path map[string]bool) {
		kids := children[parent]
		for i, c := range kids {
			connector, childPrefix := "├── ", prefix+"│   "
			if i == len(kids)-1 {
				connector, childPrefix = "└── ", prefix+"    "
			}
			if path[c.id] {
				fmt.Fprintf(w, "%s%s%s  [%s] (cycle)\n", prefix, connector, c.id, c.via)
				continue
			}
			fmt.Fprintf(w, "%s%s%s  [%s]\n", prefix, connector, c.id, c.via)
			appeared[c.id] = true
			next := make(map[string]bool, len(path)+1)
			for k := range path {
				next[k] = true
			}
			next[c.id] = true
			printChildren(c.id, childPrefix, next)
		}
	}

	fmt.Fprintln(w, "模块依赖树（root 依赖其子节点；[via] 为依赖来源）")
	// 根 = 本集合内没有父节点（无人依赖它）的模块；nodes 已按 ID 升序。
	for _, n := range nodes {
		if hasParent[n.ID] {
			continue
		}
		appeared[n.ID] = true
		fmt.Fprintln(w, n.ID)
		printChildren(n.ID, "", map[string]bool{n.ID: true})
	}
	// 兜底：成环导致没有根的节点，按 ID 升序补为根，保证全覆盖。
	for _, n := range nodes {
		if !appeared[n.ID] {
			appeared[n.ID] = true
			fmt.Fprintln(w, n.ID)
			printChildren(n.ID, "", map[string]bool{n.ID: true})
		}
	}
}

// renderImpact 渲染停用影响面。
func renderImpact(w io.Writer, imp modulecontrol.Impact) {
	fmt.Fprintf(w, "模块:      %s\n", imp.ID)
	fmt.Fprintf(w, "核心模块:  %s\n", yesNo(imp.Core))
	fmt.Fprintf(w, "可否停用:  %s\n", yesNo(imp.CanDisable))
	if !imp.CanDisable {
		fmt.Fprintf(w, "原因:      %s\n", imp.BlockReason)
	}
	if len(imp.Dependents) == 0 {
		fmt.Fprintln(w, "连带被停:  （无）")
		return
	}
	fmt.Fprintf(w, "连带被停（按关闭顺序，先关的在先）共 %d 个:\n", len(imp.Dependents))
	for i, d := range imp.Dependents {
		fmt.Fprintf(w, "  %d) %s\n", i+1, d)
	}
}

// renderSelfCheck 渲染自检报告（Errors/Warnings 全列，含 Code）。
func renderSelfCheck(w io.Writer, rep registry.SelfCheckReport) {
	if rep.OK {
		fmt.Fprintln(w, "自检结果: OK")
	} else {
		fmt.Fprintf(w, "自检结果: 不 OK（%d 个错误）\n", len(rep.Errors))
	}
	fmt.Fprintf(w, "Core:    %s\n", joinOrDash(rep.Core))
	fmt.Fprintf(w, "Enabled: %s\n", joinOrDash(rep.Enabled))
	fmt.Fprintf(w, "Errors (%d):\n", len(rep.Errors))
	for _, is := range rep.Errors {
		fmt.Fprintf(w, "  [%s] %s: %s\n", is.Code, orDash(is.ModuleID), is.Message)
	}
	fmt.Fprintf(w, "Warnings (%d):\n", len(rep.Warnings))
	for _, is := range rep.Warnings {
		fmt.Fprintf(w, "  [%s] %s: %s\n", is.Code, orDash(is.ModuleID), is.Message)
	}
}

// ------------------------- 输出辅助 -------------------------

// printChange 输出一次 enable/disable 的结果（JSON 或人类可读）。
func printChange(o cliOptions, res modulecontrol.ChangeResult, verb string, stdout, stderr io.Writer) int {
	if o.jsonOut {
		return emitJSON(stdout, stderr, res)
	}
	state := "已停用"
	if res.Enabled {
		state = "已启用"
	}
	fmt.Fprintf(stdout, "%s %s：%s\n", verb, res.ID, state)
	fmt.Fprintf(stdout, "提示：%s\n", res.RestartHint)
	return 0
}

// emitJSON 以缩进 JSON 输出服务层结构体。
func emitJSON(stdout, stderr io.Writer, v any) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "错误: 生成 JSON 失败:", err)
		return 1
	}
	fmt.Fprintln(stdout, string(b))
	return 0
}

// moduleErr 统一处理服务层错误：NotFound 友好提示，其余原样。
func moduleErr(stderr io.Writer, id string, err error) int {
	if errors.Is(err, modulecontrol.ErrNotFound) {
		fmt.Fprintf(stderr, "错误: 模块 %s 不存在\n", id)
		return 1
	}
	return fail(stderr, err)
}

// fail 打印一般错误，返回退出码 1。
func fail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "错误:", err)
	return 1
}

// usageErr 打印用法错误与用法说明，返回退出码 1。
func usageErr(stderr io.Writer, msg string) int {
	fmt.Fprintln(stderr, "错误:", msg)
	fmt.Fprint(stderr, usageText)
	return 1
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func joinOrDash(ss []string) string {
	if len(ss) == 0 {
		return "-"
	}
	return strings.Join(ss, ", ")
}
