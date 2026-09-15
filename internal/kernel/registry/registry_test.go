package registry

import (
	"errors"
	"strings"
	"testing"
)

// TestRegisterAndGet 基本注册与查询。
func TestRegisterAndGet(t *testing.T) {
	reg := New()
	m := &ModuleInfo{ID: "kernel.transport", Name: "Transport", Layer: LayerKernel}
	if err := reg.Register(m); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, ok := reg.Get("kernel.transport")
	if !ok {
		t.Fatal("Get: not found")
	}
	if got.Name != "Transport" {
		t.Errorf("Name = %q, want Transport", got.Name)
	}
}

// TestRegister_DuplicateConflict 重复注册返回 ErrConflict。
func TestRegister_DuplicateConflict(t *testing.T) {
	reg := New()
	_ = reg.Register(&ModuleInfo{ID: "x", Name: "first"})
	err := reg.Register(&ModuleInfo{ID: "x", Name: "second"})
	if !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate Register: want ErrConflict, got %v", err)
	}
}

// TestRegister_NilRejected nil/空 ID 被拒绝。
func TestRegister_NilRejected(t *testing.T) {
	reg := New()
	if err := reg.Register(nil); !errors.Is(err, ErrInvalidModule) {
		t.Errorf("Register(nil) = %v, want ErrInvalidModule", err)
	}
	if err := reg.Register(&ModuleInfo{}); !errors.Is(err, ErrInvalidModule) {
		t.Errorf("Register(empty ID) = %v, want ErrInvalidModule", err)
	}
}

// TestTopologicalSort_NoDeps 无依赖模块直接返回。
func TestTopologicalSort_NoDeps(t *testing.T) {
	reg := New()
	_ = reg.Register(&ModuleInfo{ID: "a"})
	_ = reg.Register(&ModuleInfo{ID: "b"})
	_ = reg.Register(&ModuleInfo{ID: "c"})

	order, err := reg.TopologicalSort()
	if err != nil {
		t.Fatalf("TopologicalSort: %v", err)
	}
	if len(order) != 3 {
		t.Fatalf("len = %d, want 3", len(order))
	}
}

// TestTopologicalSort_LinearChain 线性依赖链：a→b→c，期望顺序 c,b,a。
func TestTopologicalSort_LinearChain(t *testing.T) {
	reg := New()
	_ = reg.Register(&ModuleInfo{ID: "a", Depends: []ModuleID{"b"}})
	_ = reg.Register(&ModuleInfo{ID: "b", Depends: []ModuleID{"c"}})
	_ = reg.Register(&ModuleInfo{ID: "c"})

	order, err := reg.TopologicalSort()
	if err != nil {
		t.Fatalf("TopologicalSort: %v", err)
	}
	want := "c,b,a"
	got := joinIDs(order)
	if got != want {
		t.Errorf("order = %s, want %s", got, want)
	}
}

// TestTopologicalSort_Diamond 菱形依赖：A→B,C→D。
//
//	A depends on B and C
//	B depends on D
//	C depends on D
//
// 期望 D 先出，B/C 中间（字典序），A 最后。
func TestTopologicalSort_Diamond(t *testing.T) {
	reg := New()
	_ = reg.Register(&ModuleInfo{ID: "a", Depends: []ModuleID{"b", "c"}})
	_ = reg.Register(&ModuleInfo{ID: "b", Depends: []ModuleID{"d"}})
	_ = reg.Register(&ModuleInfo{ID: "c", Depends: []ModuleID{"d"}})
	_ = reg.Register(&ModuleInfo{ID: "d"})

	order, err := reg.TopologicalSort()
	if err != nil {
		t.Fatalf("TopologicalSort: %v", err)
	}
	got := joinIDs(order)
	// d 必须 first，a 必须 last
	if !strings.HasPrefix(got, "d,") {
		t.Errorf("d should come first, got %s", got)
	}
	if !strings.HasSuffix(got, ",a") {
		t.Errorf("a should come last, got %s", got)
	}
}

// TestTopologicalSort_Cycle 检测循环依赖。
func TestTopologicalSort_Cycle(t *testing.T) {
	reg := New()
	_ = reg.Register(&ModuleInfo{ID: "a", Depends: []ModuleID{"b"}})
	_ = reg.Register(&ModuleInfo{ID: "b", Depends: []ModuleID{"c"}})
	_ = reg.Register(&ModuleInfo{ID: "c", Depends: []ModuleID{"a"}})

	_, err := reg.TopologicalSort()
	if !errors.Is(err, ErrCyclicDependency) {
		t.Errorf("want ErrCyclicDependency, got %v", err)
	}
}

// TestTopologicalSort_UnresolvedDep 依赖未注册返回 ErrUnresolvedDep。
func TestTopologicalSort_UnresolvedDep(t *testing.T) {
	reg := New()
	_ = reg.Register(&ModuleInfo{ID: "a", Depends: []ModuleID{"missing"}})
	_, err := reg.TopologicalSort()
	if !errors.Is(err, ErrUnresolvedDep) {
		t.Errorf("want ErrUnresolvedDep, got %v", err)
	}
}

// TestFindCycle 显式环查找。
func TestFindCycle(t *testing.T) {
	reg := New()
	_ = reg.Register(&ModuleInfo{ID: "a", Depends: []ModuleID{"b"}})
	_ = reg.Register(&ModuleInfo{ID: "b", Depends: []ModuleID{"c"}})
	_ = reg.Register(&ModuleInfo{ID: "c", Depends: []ModuleID{"a"}})

	cycle, has := reg.FindCycle()
	if !has {
		t.Fatal("FindCycle: should detect cycle")
	}
	if len(cycle) < 3 {
		t.Fatalf("cycle length too short: %v", cycle)
	}
	// 环首尾应相同（闭合）
	if cycle[0] != cycle[len(cycle)-1] {
		t.Errorf("cycle not closed: %v", cycle)
	}
}

// TestFindCycle_NoCycle 无环时返回 false。
func TestFindCycle_NoCycle(t *testing.T) {
	reg := New()
	_ = reg.Register(&ModuleInfo{ID: "a", Depends: []ModuleID{"b"}})
	_ = reg.Register(&ModuleInfo{ID: "b"})
	cycle, has := reg.FindCycle()
	if has {
		t.Errorf("FindCycle: should not detect, got %v", cycle)
	}
}

// TestLayer_String 层级名输出。
func TestLayer_String(t *testing.T) {
	cases := map[Layer]string{
		LayerKernel:     "L0",
		LayerFoundation: "L1",
		LayerFeature:    "L2",
		LayerExtension:  "L3",
	}
	for l, want := range cases {
		if got := l.String(); got != want {
			t.Errorf("Layer(%d).String() = %q, want %q", l, got, want)
		}
	}
}

// joinIDs 把 []ModuleID 用逗号拼接（测试用辅助）。
func joinIDs(ids []ModuleID) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = string(id)
	}
	return strings.Join(parts, ",")
}
