// Package modulecontrol 是模块控制面的唯一行为实现：
// CLI（cmd/fmctl）与将来的 Web/HTTP 都调用本包，不允许任何入口自己再实现一套。
//
// 职责：
//   - 只读清单（registry/backend-modules/*.json）做展示：List/Show/Graph/SelfCheck
//   - 依赖影响面分析：Impact（停某模块会连带停掉谁、能不能停）
//   - 把 enabled 原子写回清单：SetEnabled
//
// ★ 本步（12-2）不实现运行期启停：所有模块的 State 恒为 StateUnknown；
//
//	enable/disable 只改清单文件，重启后生效（真实运行态热启停是 12-3）。
package modulecontrol

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"flow-monitoring/internal/kernel/logging"
	"flow-monitoring/internal/kernel/registry"
)

// DefaultManifestDir 是清单目录的默认位置（相对进程工作目录）。
const DefaultManifestDir = "registry/backend-modules"

// StateUnknown 是本步所有模块的运行态：12-3 才提供真实运行态，这里不假装能查到。
const StateUnknown = "unknown"

// RestartHint 是 enable/disable 写回清单后固定返回的提示：本步不做运行期热启停。
const RestartHint = "已写回清单，重启后生效（当前进程运行态不变；运行期热启停见 12-3）"

// 错误哨兵值（入口用 errors.Is 判定即可，不用匹配文本）。
var (
	// ErrNotFound 模块不存在。
	ErrNotFound = errors.New("modulecontrol: 模块不存在")
	// ErrCoreModule 核心模块不可禁用。
	ErrCoreModule = errors.New("modulecontrol: 核心模块不可禁用")
)

// Options 构造选项。
type Options struct {
	ManifestDir string          // 清单目录（空 = DefaultManifestDir）
	Logger      *logging.Logger // 可空
	Runtime     RuntimeBackend  // ★ 可选：nil = 只改清单（12-2 行为）
	StopTimeout time.Duration   // ★ 可选：单模块停止超时（默认 DefaultStopTimeout=10s）
	AuditSink   AuditSink       // ★ 可选：nil = 不写审计
	// BinaryChecker 判定"插件目录里是否存在该模块的可执行文件"。
	// binary 是清单里的 Binary（registry 已兜底为模块 ID），实现方负责按
	// pluginhost 的拼路径规则（PluginDir + binary + Windows 后缀）判存在性。
	// ★ nil = 不可判定：Impact.HasBinary 一律填 false（不 panic、不猜测）。
	BinaryChecker func(binary string) bool
}

// ModuleView 给入口展示的模块视图。
type ModuleView struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Layer    string   `json:"layer"`
	Core     bool     `json:"core"`
	Enabled  bool     `json:"enabled"`
	Depends  []string `json:"depends,omitempty"`
	Provides []string `json:"provides,omitempty"`
	Injects  []string `json:"injects,omitempty"`
	HTTPBase string   `json:"http_base,omitempty"`
	Binary   string   `json:"binary,omitempty"`
	State    string   `json:"state"` // ★ 本步恒为 StateUnknown（12-3 才接真实运行态）
}

// Edge 一条依赖边：From 依赖 To（⇒ To 必须先启、后停）。
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Via  string `json:"via"` // "depends" 或 "provides:<能力名>"
}

// Graph 模块依赖图（Nodes/Edges 都确定性排序）。
type Graph struct {
	Nodes []ModuleView `json:"nodes"`
	Edges []Edge       `json:"edges"`
}

// Impact 停某个模块的影响面。
type Impact struct {
	ID   string `json:"id"`
	Core bool   `json:"core"`
	// Dependents 是直接或间接依赖它的模块，按关闭顺序给出（最先被关的消费者在前，
	// target 本身不在列表里）。确定性排序。
	Dependents []string `json:"dependents"`
	// HasBinary 表示插件目录里存在该模块的可执行文件（与 pluginhost 启动时
	// 拼路径的规则一致）。false 只代表"没找到二进制"，不阻止写 enabled=true，
	// 但界面必须在启用前如实告知用户。
	HasBinary   bool   `json:"has_binary"`
	CanDisable  bool   `json:"can_disable"`
	BlockReason string `json:"block_reason,omitempty"` // CanDisable=false 时说明原因
}

// ChangeResult 一次 enable/disable 的结果。
type ChangeResult struct {
	ID          string `json:"id"`
	Enabled     bool   `json:"enabled"`
	RestartHint string `json:"restart_hint"`
}

// Service 模块控制面服务层（唯一行为实现）。
type Service struct {
	dir         string
	logger      *logging.Logger
	reg         *registry.Registry
	runtime     RuntimeBackend // ★ 可选：nil = 只改清单（12-2 行为）
	stopTimeout time.Duration  // ★ 单模块停止超时；New 时兜底为 DefaultStopTimeout
	audit       AuditSink      // ★ 可选：nil = 不写审计
	// binaryChecker 判定插件二进制是否存在；nil = 不可判定（Impact.HasBinary 恒 false）。
	binaryChecker func(binary string) bool
}

// New 构造服务：校验并加载清单目录。
//
// ★ registry.Load 对"目录不存在"是静默返回空注册表的（宿主可回退内置清单），
// 但控制面必须报错：这里先用 os.Stat 显式确认目录存在，错误信息带路径。
func New(opts Options) (*Service, error) {
	dir := opts.ManifestDir
	if dir == "" {
		dir = DefaultManifestDir
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("modulecontrol: 清单目录不可用 %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("modulecontrol: 清单目录不是目录 %s", dir)
	}
	reg, err := registry.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("modulecontrol: 加载清单目录 %s: %w", dir, err)
	}
	timeout := opts.StopTimeout
	if timeout <= 0 {
		timeout = DefaultStopTimeout
	}
	return &Service{
		dir:           dir,
		logger:        opts.Logger,
		reg:           reg,
		runtime:       opts.Runtime,
		stopTimeout:   timeout,
		audit:         opts.AuditSink,
		binaryChecker: opts.BinaryChecker,
	}, nil
}

// List 列出全部模块视图（按 ID 升序）。
//
// State：有后端就查后端（未出现的模块给 StateUnknown）；无后端仍恒为 StateUnknown。
func (s *Service) List() ([]ModuleView, error) {
	mods := s.reg.List() // 已按 ID 升序
	states := s.runtimeStates()
	out := make([]ModuleView, 0, len(mods))
	for _, d := range mods {
		v := toView(d)
		v.State = stateOf(states, d.ID)
		out = append(out, v)
	}
	return out, nil
}

// Show 返回单个模块视图；不存在 ⇒ ErrNotFound。
//
// State：同 List，有后端就查后端，未出现 ⇒ StateUnknown。
func (s *Service) Show(id string) (ModuleView, error) {
	d, ok := s.reg.Get(id)
	if !ok {
		return ModuleView{}, ErrNotFound
	}
	v := toView(d)
	v.State = stateOf(s.runtimeStates(), id)
	return v, nil
}

// Graph 返回依赖图。两种边来源都会出现：
//   - Depends          ⇒ Via "depends"
//   - Injects 的能力名 ⇒ 命中某模块 Provides ⇒ Via "provides:<能力名>"
//
// 自依赖（提供者 == 自己）跳过；To 不在清单里 ⇒ 跳过。
// Nodes 按 ID、Edges 按 (From,To,Via) 排序，保证确定性。
func (s *Service) Graph() (Graph, error) {
	mods := s.reg.List()
	nodes := make([]ModuleView, 0, len(mods))
	for _, d := range mods {
		nodes = append(nodes, toView(d))
	}
	edges := s.edges()
	if edges == nil {
		edges = []Edge{}
	}
	return Graph{Nodes: nodes, Edges: edges}, nil
}

// SelfCheck 透传 registry 的自检结果（只读）。
func (s *Service) SelfCheck() (registry.SelfCheckReport, error) {
	return s.reg.SelfCheck(), nil
}

// Impact 求停 id 的影响面。
//
// Dependents = 反向依赖闭包（谁直接或间接依赖 id），按关闭顺序（反向拓扑序）给出：
// 先关最末端消费者，最后才轮到 id（id 本身不在列表里）。
// 用分层/Kahn 算法在"闭包诱导子图"上求拓扑序再取反，★ 不依赖 layer 决定顺序。
func (s *Service) Impact(id string) (Impact, error) {
	d, ok := s.reg.Get(id)
	if !ok {
		return Impact{}, ErrNotFound
	}
	order := s.dependentsOrder(id)
	if order == nil {
		order = []string{}
	}
	hasBinary := false
	if s.binaryChecker != nil {
		hasBinary = s.binaryChecker(d.Binary)
	}
	imp := Impact{ID: id, Core: d.Core, Dependents: order, HasBinary: hasBinary}

	if d.Core {
		imp.CanDisable = false
		imp.BlockReason = "核心模块不可停用（core=true，构建与清单层面均不可裁剪）"
		return imp, nil
	}

	var coreDeps []string
	for _, dep := range order {
		if dd, ok := s.reg.Get(dep); ok && dd.Core {
			coreDeps = append(coreDeps, dep)
		}
	}
	if len(coreDeps) > 0 {
		imp.CanDisable = false
		imp.BlockReason = "停它会连带停掉核心模块 " + strings.Join(coreDeps, ", ")
	} else {
		imp.CanDisable = true
	}
	return imp, nil
}

// SetEnabled 把 enabled 写回清单。
//
//   - id 不存在 ⇒ ErrNotFound（写前先重新 Load 确认，反映磁盘最新状态）
//   - enabled=false 且模块是 core ⇒ ErrCoreModule，且不写文件
//   - 否则原子重写该模块对应的清单文件（临时文件 + os.Rename），末尾带换行
//
// ★ 只把 enabled 写回清单，不改变运行态：本步不实现运行期热启停（12-3）。
func (s *Service) SetEnabled(id string, enabled bool) (ChangeResult, error) {
	reg, err := registry.Load(s.dir)
	if err != nil {
		return ChangeResult{}, fmt.Errorf("modulecontrol: 重新加载清单目录 %s: %w", s.dir, err)
	}
	d, ok := reg.Get(id)
	if !ok {
		return ChangeResult{}, ErrNotFound
	}
	if !enabled && d.Core {
		return ChangeResult{}, ErrCoreModule
	}

	path, err := s.manifestFileForID(id)
	if err != nil {
		return ChangeResult{}, err
	}

	// ★ 就地改值：只替换 "enabled" 的 true/false token，其余字节**原样保留**。
	//
	// 为什么不做整体重写（踩坑 30）：真清单是 CRLF + 自定义字段顺序 + 内联数组（历史习惯），
	// 用 json.MarshalIndent 重写会把它们全部重排，并**丢掉 Descriptor 不认识的字段**；
	// 实测一次 enable 就让 rule.json 从 165 字节/9 个 CRLF 变成 163 字节/0 个 CRLF。
	old, err := os.ReadFile(path)
	if err != nil {
		return ChangeResult{}, fmt.Errorf("modulecontrol: 读取清单 %s: %w", path, err)
	}
	out, err := setEnabledInManifest(old, enabled)
	if err != nil {
		return ChangeResult{}, fmt.Errorf("modulecontrol: 改写清单 %s: %w", path, err)
	}

	if err := writeFileAtomic(path, out, 0o644); err != nil {
		s.logChange(id, enabled, err)
		return ChangeResult{}, err
	}
	// 刷新缓存，让后续 List/Graph/Impact 反映写回结果。
	if reg2, err := registry.Load(s.dir); err == nil {
		s.reg = reg2
	}
	s.logChange(id, enabled, nil)
	return ChangeResult{ID: id, Enabled: enabled, RestartHint: RestartHint}, nil
}

// edges 计算全部依赖边并确定性排序。
func (s *Service) edges() []Edge {
	mods := s.reg.List()

	// 能力名 → 提供者模块 id（重复提供者取 ID 最小者，与 registry.SelfCheck 同源）。
	provider := make(map[string]string)
	for _, d := range mods {
		for _, svc := range d.Provides {
			if _, dup := provider[svc]; !dup {
				provider[svc] = d.ID
			}
		}
	}

	var edges []Edge
	for _, d := range mods {
		for _, dep := range d.Depends {
			if dep == d.ID {
				continue // 自依赖跳过
			}
			if _, ok := s.reg.Get(dep); !ok {
				continue // 提供者不在清单里（交 SelfCheck 报 topology_error）
			}
			edges = append(edges, Edge{From: d.ID, To: dep, Via: "depends"})
		}
		for _, svc := range d.Injects {
			pid, ok := provider[svc]
			if !ok || pid == d.ID {
				continue // 缺提供者或自依赖，跳过
			}
			if _, ok := s.reg.Get(pid); !ok {
				continue
			}
			edges = append(edges, Edge{From: d.ID, To: pid, Via: "provides:" + svc})
		}
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].To != edges[j].To {
			return edges[i].To < edges[j].To
		}
		return edges[i].Via < edges[j].Via
	})
	return edges
}

// dependentsOrder 返回依赖 id 的模块（直接或间接），按关闭顺序（反向拓扑序）。
//
// 实现：先在依赖图上求"谁依赖 id"的闭包（沿 提供者→消费者 反向走），
// 再在闭包诱导子图上做 Kahn 拓扑排序（提供者在前），取反得到关闭顺序（消费者在前），
// 最后去掉 id 本身。
func (s *Service) dependentsOrder(id string) []string {
	edges := s.edges()

	// consumers[提供者] = 依赖它的消费者
	consumers := make(map[string][]string)
	for _, e := range edges {
		consumers[e.To] = append(consumers[e.To], e.From)
	}

	// 反向依赖闭包（BFS）。
	closure := make(map[string]bool)
	queue := []string{id}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range consumers[cur] {
			if !closure[c] {
				closure[c] = true
				queue = append(queue, c)
			}
		}
	}
	if len(closure) == 0 {
		return []string{}
	}

	inSet := func(x string) bool { return x == id || closure[x] }

	// 诱导子图上的 Kahn（拓扑序：依赖在前）。
	indeg := make(map[string]int, len(closure)+1)
	adj := make(map[string][]string, len(closure)+1)
	for n := range closure {
		indeg[n] = 0
	}
	indeg[id] = 0
	for _, e := range edges {
		if !inSet(e.From) || !inSet(e.To) {
			continue
		}
		adj[e.To] = append(adj[e.To], e.From) // 提供者 → 消费者
		indeg[e.From]++
	}

	var ready []string
	for n, dg := range indeg {
		if dg == 0 {
			ready = append(ready, n)
		}
	}
	sort.Strings(ready)

	var topo []string
	for len(ready) > 0 {
		cur := ready[0]
		ready = ready[1:]
		topo = append(topo, cur)
		children := append([]string(nil), adj[cur]...)
		sort.Strings(children)
		for _, c := range children {
			indeg[c]--
			if indeg[c] == 0 {
				ready = append(ready, c)
			}
		}
		sort.Strings(ready)
	}

	// 反向拓扑序 = 关闭顺序；去掉 id。
	out := make([]string, 0, len(topo))
	for i := len(topo) - 1; i >= 0; i-- {
		if topo[i] == id {
			continue
		}
		out = append(out, topo[i])
	}
	return out
}

// manifestFileForID 找到 id 对应的 *.json 文件路径（文件名不一定等于 id）。
func (s *Service) manifestFileForID(id string) (string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return "", fmt.Errorf("modulecontrol: 读取清单目录 %s: %w", s.dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		p := filepath.Join(s.dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("modulecontrol: 读取清单 %s: %w", p, err)
		}
		var d registry.Descriptor
		if err := json.Unmarshal(b, &d); err != nil {
			continue // 解析失败交给 Load 报错，这里跳过
		}
		if d.ID == id {
			return p, nil
		}
	}
	return "", ErrNotFound
}

// logChange 记一条 enable/disable 审计日志（Logger 为空时什么都不做）。
func (s *Service) logChange(id string, enabled bool, err error) {
	if s.logger == nil {
		return
	}
	if err != nil {
		s.logger.Error("modulecontrol: set enabled failed", "id", id, "enabled", enabled, "err", err)
		return
	}
	s.logger.Info("modulecontrol: set enabled", "id", id, "enabled", enabled, "result", "ok")
}

// writeFileAtomic 原子写文件：同目录临时文件 + os.Rename；失败清理临时文件。
// enabledValueRe 匹配清单里 "enabled": true/false 的**值 token**。
var enabledValueRe = regexp.MustCompile(`"enabled"\s*:\s*(true|false)`)

// layerLineRe 匹配一行 "layer": "Lx"（用于清单缺少 enabled 时插入新行）。
// 捕获组 1 = 该行缩进；捕获组 2 = 行尾逗号（可为空）。
var layerLineRe = regexp.MustCompile(`(?m)^([ \t]*)"layer"\s*:\s*"[^"]*"(,?)[ \t]*\r?$`)

// setEnabledInManifest 只改写清单里 enabled 的**值**，其余字节原样保留。
//
// ★ 为什么不做整体重写（踩坑 30）：真清单是 CRLF + 自定义字段顺序 + 内联数组（历史习惯），
// 用 json.MarshalIndent 重写会把它们全部重排、并丢掉 Descriptor 不认识的字段；
// 实测一次 enable 就让 rule.json 从 165 字节 / 9 个 CRLF 变成 163 字节 / 0 个 CRLF。
//
// 规则（不猜）：
//  1. 已有 "enabled": <bool> ⇒ 只替换那个 true/false token；
//  2. 没有 enabled 但有 "layer" ⇒ 在该行之后插入一行（沿用该行缩进与行尾风格；layer 无逗号时补一个）；
//  3. 两者都没有 ⇒ 明确报错，让操作者手工添加。
//
// ★ 写前自检：改完必须能被 json.Unmarshal 解析出**期望的 enabled 值**，否则返回错误
// （调用方就不会落盘）—— 文本编辑万一偏了也不会污染清单。
func setEnabledInManifest(src []byte, enabled bool) ([]byte, error) {
	want := "false"
	if enabled {
		want = "true"
	}

	var out []byte
	if loc := enabledValueRe.FindSubmatchIndex(src); loc != nil {
		// loc[2]:loc[3] 是捕获组 1（值 token）的区间；只替换这一段。
		out = make([]byte, 0, len(src))
		out = append(out, src[:loc[2]]...)
		out = append(out, want...)
		out = append(out, src[loc[3]:]...)
	} else {
		loc := layerLineRe.FindSubmatchIndex(src)
		if loc == nil {
			return nil, errors.New("清单里既没有 enabled 也没有 layer 字段，无法安全地就地写入（请手工添加 enabled）")
		}
		indent := src[loc[2]:loc[3]]
		hasComma := loc[4] != loc[5]
		lineEnd := loc[1]
		eol, contentEnd := "\n", lineEnd
		if contentEnd > 0 && src[contentEnd-1] == '\r' { // CRLF：\r 已被正则吃掉
			eol, contentEnd = "\r\n", contentEnd-1
		}
		out = make([]byte, 0, len(src)+len(indent)+24)
		out = append(out, src[:contentEnd]...)
		if !hasComma { // 原 layer 行变成非末行 ⇒ 补逗号
			out = append(out, ',')
		}
		out = append(out, eol...)
		out = append(out, indent...)
		out = append(out, `"enabled": `...)
		out = append(out, want...)
		if hasComma {
			out = append(out, ',')
		}
		out = append(out, src[lineEnd:]...)
	}

	var probe struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.Unmarshal(out, &probe); err != nil {
		return nil, fmt.Errorf("改值后 JSON 解析失败（已放弃写入）：%w", err)
	}
	if probe.Enabled == nil || *probe.Enabled != enabled {
		return nil, fmt.Errorf("改值后自检未通过：enabled 期望 %v，解析得到 %v（已放弃写入）", enabled, probe.Enabled)
	}
	return out, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".fmctl-*.tmp")
	if err != nil {
		return fmt.Errorf("modulecontrol: 创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("modulecontrol: 写临时文件 %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("modulecontrol: 同步临时文件 %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("modulecontrol: 关闭临时文件 %s: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("modulecontrol: 设置权限 %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("modulecontrol: 替换清单 %s: %w", path, err)
	}
	cleanup = false
	return nil
}

// toView 把 registry.Descriptor 转成对外的 ModuleView（State 恒为 unknown）。
func toView(d registry.Descriptor) ModuleView {
	return ModuleView{
		ID:       d.ID,
		Name:     d.Name,
		Version:  d.Version,
		Layer:    d.Layer,
		Core:     d.Core,
		Enabled:  d.IsEnabled(),
		Depends:  append([]string(nil), d.Depends...),
		Provides: append([]string(nil), d.Provides...),
		Injects:  append([]string(nil), d.Injects...),
		HTTPBase: d.HTTPBase,
		Binary:   d.Binary,
		State:    StateUnknown,
	}
}
