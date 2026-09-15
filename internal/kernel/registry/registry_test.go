package registry

import (
	"errors"
	"strings"
	"testing"

	"flow-monitoring/internal/kernel/plugin"
)

// testPlugin 测试用插件（嵌入 Base，覆盖 Manifest）。
type testPlugin struct {
	plugin.Base
	manifest plugin.Manifest
}

func (p *testPlugin) Manifest() plugin.Manifest { return p.manifest }

func newTestPlugin(id string, depends ...string) *testPlugin {
	return &testPlugin{manifest: plugin.Manifest{
		ID: id, Name: id, Version: "1.0.0", Layer: plugin.LayerKernel,
		Depends: depends,
	}}
}

// TestRegisterAndGet 基本注册与查询。
func TestRegisterAndGet(t *testing.T) {
	reg := New()
	p := newTestPlugin("kernel.transport")
	if err := reg.Register(p); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, ok := reg.Get("kernel.transport")
	if !ok {
		t.Fatal("Get: not found")
	}
	if got.Manifest().Name != "kernel.transport" {
		t.Errorf("Name = %q, want kernel.transport", got.Manifest().Name)
	}
}

// TestRegister_DuplicateConflict 重复注册返回 ErrConflict。
func TestRegister_DuplicateConflict(t *testing.T) {
	reg := New()
	_ = reg.Register(newTestPlugin("x"))
	err := reg.Register(newTestPlugin("x"))
	if !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate Register: want ErrConflict, got %v", err)
	}
}

// TestRegister_NilRejected nil/空 ID 被拒绝。
func TestRegister_NilRejected(t *testing.T) {
	reg := New()
	if err := reg.Register(nil); !errors.Is(err, ErrInvalidPlugin) {
		t.Errorf("Register(nil) = %v, want ErrInvalidPlugin", err)
	}
	if err := reg.Register(&testPlugin{manifest: plugin.Manifest{}}); !errors.Is(err, ErrInvalidPlugin) {
		t.Errorf("Register(empty ID) = %v, want ErrInvalidPlugin", err)
	}
}

// TestReplace 同名替换（可替换性）。
func TestReplace(t *testing.T) {
	reg := New()
	_ = reg.Register(newTestPlugin("x"))
	replacement := newTestPlugin("x")
	if err := reg.Replace(replacement); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	got, _ := reg.Get("x")
	if got != replacement {
		t.Error("Replace should replace the plugin")
	}
}

// TestTopologicalSort_NoDeps 无依赖直接返回。
func TestTopologicalSort_NoDeps(t *testing.T) {
	reg := New()
	_ = reg.Register(newTestPlugin("a"))
	_ = reg.Register(newTestPlugin("b"))
	_ = reg.Register(newTestPlugin("c"))

	order, err := reg.TopologicalSort()
	if err != nil {
		t.Fatalf("TopologicalSort: %v", err)
	}
	if len(order) != 3 {
		t.Fatalf("len = %d, want 3", len(order))
	}
}

// TestTopologicalSort_LinearChain 线性依赖：a→b→c，期望 c,b,a。
func TestTopologicalSort_LinearChain(t *testing.T) {
	reg := New()
	_ = reg.Register(newTestPlugin("a", "b"))
	_ = reg.Register(newTestPlugin("b", "c"))
	_ = reg.Register(newTestPlugin("c"))

	order, err := reg.TopologicalSort()
	if err != nil {
		t.Fatalf("TopologicalSort: %v", err)
	}
	got := strings.Join(order, ",")
	if got != "c,b,a" {
		t.Errorf("order = %s, want c,b,a", got)
	}
}

// TestTopologicalSort_Cycle 循环依赖检测。
func TestTopologicalSort_Cycle(t *testing.T) {
	reg := New()
	_ = reg.Register(newTestPlugin("a", "b"))
	_ = reg.Register(newTestPlugin("b", "c"))
	_ = reg.Register(newTestPlugin("c", "a"))

	_, err := reg.TopologicalSort()
	if !errors.Is(err, ErrCyclicDependency) {
		t.Errorf("want ErrCyclicDependency, got %v", err)
	}
}

// TestTopologicalSort_UnresolvedDep 依赖未注册。
func TestTopologicalSort_UnresolvedDep(t *testing.T) {
	reg := New()
	_ = reg.Register(newTestPlugin("a", "missing"))
	_, err := reg.TopologicalSort()
	if !errors.Is(err, ErrUnresolvedDep) {
		t.Errorf("want ErrUnresolvedDep, got %v", err)
	}
}

// TestFindCycle 显式环查找。
func TestFindCycle(t *testing.T) {
	reg := New()
	_ = reg.Register(newTestPlugin("a", "b"))
	_ = reg.Register(newTestPlugin("b", "c"))
	_ = reg.Register(newTestPlugin("c", "a"))

	cycle, has := reg.FindCycle()
	if !has {
		t.Fatal("FindCycle: should detect cycle")
	}
	if cycle[0] != cycle[len(cycle)-1] {
		t.Errorf("cycle not closed: %v", cycle)
	}
}

// TestLayer_String 层级名。
func TestLayer_String(t *testing.T) {
	cases := map[plugin.Layer]string{
		plugin.LayerKernel:     "L0",
		plugin.LayerFoundation: "L1",
		plugin.LayerFeature:    "L2",
		plugin.LayerExtension:  "L3",
	}
	for l, want := range cases {
		if got := l.String(); got != want {
			t.Errorf("Layer(%d).String() = %q, want %q", l, got, want)
		}
	}
}
