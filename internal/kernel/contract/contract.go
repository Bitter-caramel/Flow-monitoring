package contract

import (
	"fmt"
	"sync"
)

// ContractID 契约的唯一标识。
//
// 命名约定："模块.契约名"，例如：
//   - "situation.api"   态势引擎契约
//   - "disposal.api"    处置引擎契约
//   - "parse.service"   解析服务契约
//   - "storage.core"    存储抽象契约
type ContractID string

// Version 语义化版本（SemVer 2.0.0 子集）。
//
// 兼容性约定（v0.3 第 7 章）：
//   - Major：破坏性变更（接口签名修改/语义变更），调用方必须更新
//   - Minor：新增能力（新方法/新 capability），旧调用方仍能跑
//   - Patch：修复与实现细节调整，调用方无感知
//   - PreRelease：预发布标记（如 "beta.1"），稳定版留空
type Version struct {
	Major      uint16
	Minor      uint16
	Patch      uint16
	PreRelease string // 留空 = 稳定版
}

// V 便捷构造器：稳定版本（无 PreRelease）。
//
// 用法：contract.V(1, 2, 3) 等价于 Version{Major:1, Minor:2, Patch:3}。
func V(major, minor, patch uint16) Version {
	return Version{Major: major, Minor: minor, Patch: patch}
}

// String 输出形如 "1.2.3" 或 "0.1.0-beta.1"。
func (v Version) String() string {
	if v.PreRelease != "" {
		return fmt.Sprintf("%d.%d.%d-%s", v.Major, v.Minor, v.Patch, v.PreRelease)
	}
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// IsCompatibleWith 调用方期望版本 vs 实现版本兼容性判定。
//
// 规则（SemVer）：
//   - 期望 Major 与实现 Major 必须相等
//   - 期望 Minor ≤ 实现 Minor（实现新增能力不破坏旧调用方）
//   - PreRelease 版本仅在完全相等时视为兼容（避免预发布版被生产代码依赖）
func (v Version) IsCompatibleWith(want Version) bool {
	if v.Major != want.Major {
		return false
	}
	if v.Minor < want.Minor {
		return false
	}
	if v.Minor == want.Minor && v.Patch < want.Patch {
		return false
	}
	if want.PreRelease != "" && v != want {
		return false
	}
	return true
}

// Contract 契约元数据。
//
// 字段 Impl 持有业务模块在 init() 阶段注册的实现实例（通常是一个 interface
// 类型的具体值）。调用方通过 Registry.Query 拿到 *Contract 后做类型断言
// 取出实际接口。
//
// Capabilities 是该契约声明支持的能力名列表（v0.3 第 7 章"能力探针优雅降级"）。
// 调用方先通过 HasCapability 探针确认支持，再调用对应方法；不支持的 capability
// 应让调用方走降级路径（而非硬失败）。
type Contract struct {
	ID           ContractID
	Version      Version
	Description  string
	Capabilities []string
	Impl         any // 业务模块注册的实现实例（具体接口类型由契约定义方约定）
}

// HasCapability 探针：契约是否声明了某 capability。
func (c *Contract) HasCapability(name string) bool {
	if c == nil {
		return false
	}
	for _, cap := range c.Capabilities {
		if cap == name {
			return true
		}
	}
	return false
}

// Registry 契约注册表。
//
// 双重使用方式：
//   - 包级单例 DefaultRegistry（init() 阶段注册）
//   - 依赖注入版 New()（便于测试隔离）
//
// 线程安全：所有方法内部加锁。bootstrap 在启动期注册所有契约，运行期只读。
type Registry struct {
	mu        sync.RWMutex
	contracts map[ContractID]*Contract
}

// Default 包级默认注册表，业务模块在 init() 中通过 Register 注册到此处。
var Default = NewRegistry()

// NewRegistry 创建独立注册表（用于测试隔离）。
func NewRegistry() *Registry {
	return &Registry{contracts: make(map[ContractID]*Contract)}
}

// Register 注册一个契约实现到注册表。
//
// 规则：
//   - 同一 ID 多次注册：返回 ErrConflict，防止两个模块争抢同一契约身份
//   - c 或 c.Impl 为 nil：返回 ErrInvalidContract
//   - 成功注册后调用方仍可通过 Replace 强制覆盖（仅用于热替换/测试）
func (r *Registry) Register(c *Contract) error {
	if c == nil || c.Impl == nil {
		return ErrInvalidContract
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.contracts[c.ID]; exists {
		return fmt.Errorf("%w: %s", ErrConflict, c.ID)
	}
	r.contracts[c.ID] = c
	return nil
}

// Replace 强制覆盖已注册的契约（仅用于热替换/测试场景）。
//
// 生产路径不应使用——契约应当 immutable；如确需升级，应通过版本号机制而非替换。
func (r *Registry) Replace(c *Contract) error {
	if c == nil || c.Impl == nil {
		return ErrInvalidContract
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.contracts[c.ID] = c
	return nil
}

// Query 查询契约。
func (r *Registry) Query(id ContractID) (*Contract, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.contracts[id]
	return c, ok
}

// MustQuery 查询契约；不存在时 panic（仅用于启动期"应有必有"的契约）。
//
// 适用场景：bootstrap 阶段确认核心契约已注册；运行时业务路径请用 Query + 降级。
func (r *Registry) MustQuery(id ContractID) *Contract {
	c, ok := r.Query(id)
	if !ok {
		panic(fmt.Errorf("contract %s not registered", id))
	}
	return c
}

// HasCapability 探针：某契约是否声明了某 capability。
//
// 不存在契约返回 false（v0.3 第 7 章"能力探针优雅降级"）。
func (r *Registry) HasCapability(id ContractID, capability string) bool {
	c, ok := r.Query(id)
	if !ok {
		return false
	}
	return c.HasCapability(capability)
}

// Versions 列出所有已注册契约的 ID + Version 摘要。
//
// 启动期日志输出、健康检查上报、前端模块清单 API 用。
func (r *Registry) Versions() []ContractSummary {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ContractSummary, 0, len(r.contracts))
	for _, c := range r.contracts {
		out = append(out, ContractSummary{
			ID:       string(c.ID),
			Version:  c.Version.String(),
			Caps:     len(c.Capabilities),
		})
	}
	return out
}

// ContractSummary 契约的轻量摘要（用于列表展示）。
type ContractSummary struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Caps    int    `json:"caps"`
}
