// Package kw 提供 flow-monitoring 规则翻译器的关键字插件化框架。
//
// 本包只有两个文件：
//   - registry.go：关键字注册表（关键字名 -> Handler），是插件化的中枢；
//   - frame.go：帧（State）及基于注册表执行词法选项的入口。
//
// 各关键字以独立插件的形式在各自的 init() 中把自己的 Handler 注册进来，
// 翻译器运行时只通过 Lookup 查询并调用，从而与具体关键字解耦。
package kw

import (
	"flow-monitoring/internal/modules/rule"
	"flow-monitoring/internal/modules/rule/suricata"
)

// State 表示单条规则翻译过程中的可变状态，即“帧”。
//
// 帧在同一个关键字 Handler 与后续 Handler 之间传递，承载词法结果、
// 正在被写出的 IR、当前生效的粘性缓冲以及不支持项统计等信息。
type State struct {
	// Raw 是词法阶段得到的原始规则，包含头字段与全部选项。
	Raw *suricata.RawRule
	// Rule 是正在被各个 Handler 逐步写出的 IR 规则。
	Rule *rule.Rule
	// CurBuf 是当前生效的粘性缓冲，供 payload/buffer 类关键字累积内容。
	CurBuf rule.Buffer
	// Unsupported 统计未被任何已注册关键字处理的不支持项及其出现次数。
	Unsupported map[string]int
}

// Handler 是单个 Suricata 关键字的处理插件。
type Handler interface {
	// Name 返回该 Handler 负责的关键字名称，全局必须唯一。
	Name() string
	// Handle 使用给定的帧状态处理一个词法选项。
	//
	// 返回非 nil error 表示该关键字本身不合法，Handler 借此拒绝这条规则，
	// 使整条规则解析失败，而不是降级为“不支持项”。
	Handle(st *State, opt suricata.Option) error
}

// registry 保存“关键字名称 -> Handler”的映射，是插件化框架的核心注册表。
//
// 注册表只在程序启动期被各关键字的 init() 写入，之后在整个运行期只读，
// 因此不需要加锁：启动完成后所有读取都是只读的，天然并发安全。
var registry = map[string]Handler{}

// Register 把 Handler h 注册进全局注册表。
//
// 若同名关键字已经注册过，则直接 panic("duplicate keyword: " + h.Name())，
// 以便在程序启动期尽早暴露关键字冲突。该函数只应在 init() 等启动期调用。
func Register(h Handler) {
	name := h.Name()
	if _, ok := registry[name]; ok {
		panic("duplicate keyword: " + name)
	}
	registry[name] = h
}

// Lookup 按关键字名称查询对应的 Handler。
//
// 第二个返回值表示是否命中；未命中时返回的 Handler 为 nil。
func Lookup(name string) (Handler, bool) {
	h, ok := registry[name]
	return h, ok
}
