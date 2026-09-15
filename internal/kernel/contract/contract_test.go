package contract

import (
	"errors"
	"strings"
	"testing"
)

// 模拟业务契约类型（仅测试用）。
type fakeGreeter interface {
	Hello(name string) string
}

type fakeImpl struct{}

func (fakeImpl) Hello(name string) string { return "hi " + name }

// TestRegisterAndQuery 注册→查询→断言类型取回实现。
func TestRegisterAndQuery(t *testing.T) {
	reg := NewRegistry()
	c := &Contract{
		ID:           "test.greeter",
		Version:      Version{Major: 1, Minor: 0, Patch: 0},
		Description:  "fake greeter",
		Capabilities: []string{"en", "zh"},
		Impl:         fakeImpl{},
	}
	if err := reg.Register(c); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok := reg.Query("test.greeter")
	if !ok {
		t.Fatal("Query: not found")
	}
	g, ok := got.Impl.(fakeGreeter)
	if !ok {
		t.Fatal("type assertion failed")
	}
	if g.Hello("bob") != "hi bob" {
		t.Error("Hello returned unexpected value")
	}
}

// TestRegister_DuplicateConflict 重复注册同 ID 返回 ErrConflict。
func TestRegister_DuplicateConflict(t *testing.T) {
	reg := NewRegistry()
	c1 := &Contract{ID: "x.api", Version: Version{Major: 1}, Impl: fakeImpl{}}
	c2 := &Contract{ID: "x.api", Version: Version{Major: 2}, Impl: fakeImpl{}}
	if err := reg.Register(c1); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	err := reg.Register(c2)
	if !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate Register: want ErrConflict, got %v", err)
	}
}

// TestRegister_NilRejected nil 契约 / nil Impl 都被拒绝。
func TestRegister_NilRejected(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(nil); !errors.Is(err, ErrInvalidContract) {
		t.Errorf("Register(nil) = %v, want ErrInvalidContract", err)
	}
	if err := reg.Register(&Contract{ID: "x", Impl: nil}); !errors.Is(err, ErrInvalidContract) {
		t.Errorf("Register(Impl=nil) = %v, want ErrInvalidContract", err)
	}
}

// TestHasCapability 能力探针。
func TestHasCapability(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&Contract{
		ID:           "test.greeter",
		Version:      Version{Major: 1},
		Capabilities: []string{"en", "zh"},
		Impl:         fakeImpl{},
	})
	if !reg.HasCapability("test.greeter", "en") {
		t.Error("HasCapability(en) should be true")
	}
	if reg.HasCapability("test.greeter", "fr") {
		t.Error("HasCapability(fr) should be false")
	}
	// 未注册契约返回 false（不报错）
	if reg.HasCapability("not.registered", "en") {
		t.Error("unregistered contract should return false")
	}
}

// TestVersion_IsCompatibleWith SemVer 兼容规则。
func TestVersion_IsCompatibleWith(t *testing.T) {
	cases := []struct {
		name string
		impl Version
		want Version
		ok   bool
	}{
		{"same major, impl newer minor", V(1, 5, 0), V(1, 0, 0), true},
		{"same major, impl older minor", V(1, 0, 0), V(1, 5, 0), false},
		{"diff major", V(2, 0, 0), V(1, 0, 0), false},
		{"same major, impl newer patch", V(1, 0, 5), V(1, 0, 0), true},
		{"same major, impl older patch", V(1, 0, 0), V(1, 0, 5), false},
		{"impl prerelease, want stable", Version{Major: 1, PreRelease: "beta.1"}, V(1, 0, 0), true},
		{"want prerelease, impl stable", V(1, 0, 0), Version{Major: 1, PreRelease: "beta.1"}, false},
		{"want prerelease, impl exact match", Version{Major: 1, PreRelease: "beta.1"}, Version{Major: 1, PreRelease: "beta.1"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.impl.IsCompatibleWith(tc.want)
			if got != tc.ok {
				t.Errorf("IsCompatibleWith: impl=%s want=%s got=%v want=%v",
					tc.impl, tc.want, got, tc.ok)
			}
		})
	}
}

// TestVersions 启动期摘要正确。
func TestVersions(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&Contract{ID: "a", Version: V(1, 2, 3), Impl: fakeImpl{}, Capabilities: []string{"x"}})
	_ = reg.Register(&Contract{ID: "b", Version: V(0, 1, 0), Impl: fakeImpl{}})
	versions := reg.Versions()
	if len(versions) != 2 {
		t.Fatalf("Versions len = %d, want 2", len(versions))
	}
	// 应包含 "1.2.3" 与 "0.1.0"
	joined := strings.Join([]string{versions[0].Version, versions[1].Version}, ",")
	if !strings.Contains(joined, "1.2.3") {
		t.Errorf("missing 1.2.3 in %s", joined)
	}
	if !strings.Contains(joined, "0.1.0") {
		t.Errorf("missing 0.1.0 in %s", joined)
	}
}

// TestTestMatrix_Run 未注册契约的用例自动跳过。
func TestTestMatrix_Run(t *testing.T) {
	mtx := &TestMatrix{}
	called := false
	mtx.RegisterCase("unregistered.contract", "no-op test", func(reg *Registry) error {
		called = true
		return nil
	})
	failures := mtx.Run(NewRegistry())
	if len(failures) != 0 {
		t.Errorf("should have 0 failures for unregistered contract, got %d", len(failures))
	}
	if called {
		t.Error("fn should not be called when contract is not registered")
	}
}
