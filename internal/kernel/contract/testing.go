package contract

// TestMatrix 契约测试矩阵入口（骨架）。
//
// v0.3 架构第 7 章要求"契约测试矩阵"——每个契约都应有可执行的测试用例，
// 验证实现是否满足契约语义（输入→输出、并发安全、版本兼容等）。
//
// 当前为骨架版（v3 梯队 1.3 "先立框架不立具体接口"）：
//   - 提供注册入口 RegisterCase 与执行入口 Run
//   - 实际测试用例待首批业务契约（如 SituationAPI、ParseService）落地后补
//
// 用法（未来示例）：
//
//	contract.DefaultTests().RegisterCase("situation.api", "score below decay threshold → level downgrade",
//	    func(t *testing.T, reg *Registry) { ... })
//	contract.DefaultTests().Run(t)
type TestMatrix struct {
	cases []testCase
}

// testCase 单个测试用例。
type testCase struct {
	contractID ContractID
	name       string
	fn        func(reg *Registry) error // 返回 nil 视为通过
}

// DefaultTests 包级单例，业务模块在 init() 中向其注册测试用例。
var DefaultTests = &TestMatrix{}

// RegisterCase 注册一条测试用例。
//
// 参数：
//   - id: 被测契约 ID
//   - name: 用例描述（人类可读，用于报告）
//   - fn: 测试函数；返回 nil 视为通过，返回 error 视为失败
//
// 当前为骨架，不强制 fn 不为 nil（业务模块按需补完）。
func (m *TestMatrix) RegisterCase(id ContractID, name string, fn func(reg *Registry) error) {
	m.cases = append(m.cases, testCase{contractID: id, name: name, fn: fn})
}

// Run 执行所有已注册测试用例，返回失败列表。
//
// v0.3 要求契约测试由调用方在启动期或 CI 中触发；
// bootstrap 在 Debug 模式下会调用本方法做契约冒烟自检。
//
// 当前实现：仅遍历执行；具体测试断言逻辑由 fn 内部完成。
// TODO(v3 梯队 3+): 接入 testing.T 或独立 runner，按用例聚合输出。
func (m *TestMatrix) Run(reg *Registry) []TestFailure {
	var failures []TestFailure
	for _, c := range m.cases {
		// 契约未注册时跳过（避免阻塞未启用模块的测试）
		if _, ok := reg.Query(c.contractID); !ok {
			continue
		}
		if c.fn == nil {
			continue
		}
		if err := c.fn(reg); err != nil {
			failures = append(failures, TestFailure{
				ContractID: string(c.contractID),
				CaseName:   c.name,
				Error:      err.Error(),
			})
		}
	}
	return failures
}

// TestFailure 单个测试失败。
type TestFailure struct {
	ContractID string `json:"contract_id"`
	CaseName   string `json:"case_name"`
	Error      string `json:"error"`
}

// Count 已注册用例数（用于启动期日志输出"已注册 N 条契约测试"）。
func (m *TestMatrix) Count() int { return len(m.cases) }
