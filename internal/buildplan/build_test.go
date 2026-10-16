package buildplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/registry"
)

// writeModuleJSON 把模块声明写成 dir 下的 JSON 文件。
func writeModuleJSON(t *testing.T, dir string, m map[string]any) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal module %v: %v", m["id"], err)
	}
	id, _ := m["id"].(string)
	fn := strings.NewReplacer(".", "_", "/", "_").Replace(id) + ".json"
	if err := os.WriteFile(filepath.Join(dir, fn), b, 0o644); err != nil {
		t.Fatalf("write %s: %v", fn, err)
	}
}

// testExt 复刻 Execute 里按 GOOS 推导的二进制后缀。
func testExt() string {
	goos := os.Getenv("GOOS")
	if goos == "" {
		goos = runtime.GOOS
	}
	if goos == "windows" {
		return ".exe"
	}
	return ""
}

// 测试 7：注入假 Run，校验 go build 参数、清单 file/size/sha256 与写出的清单文件。
func TestExecute_FakeRun(t *testing.T) {
	repo := t.TempDir()
	regDir := t.TempDir()
	writeModuleJSON(t, regDir, map[string]any{
		"id": "modules.alpha", "binary": "alpha", "version": "1.0.0", "layer": "L1",
		"provides": []string{"alpha.svc"},
	})
	writeModuleJSON(t, regDir, map[string]any{
		"id": "modules.beta", "binary": "beta", "version": "2.0.0", "layer": "L2",
	})

	out := t.TempDir()
	type call struct {
		dir  string
		args []string
	}
	var calls []call
	content := []byte("fake-binary-contents")
	run := func(dir string, args ...string) error {
		calls = append(calls, call{dir: dir, args: append([]string(nil), args...)})
		if len(args) != 4 || args[0] != "build" || args[1] != "-o" {
			return fmt.Errorf("unexpected args: %v", args)
		}
		if err := os.MkdirAll(filepath.Dir(args[2]), 0o755); err != nil {
			return err
		}
		return os.WriteFile(args[2], content, 0o755)
	}
	hasSource := func(d registry.Descriptor) bool { return d.Binary == "alpha" }
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

	manifest, err := Execute(Config{
		RepoRoot:    repo,
		OutDir:      out,
		RegistryDir: regDir,
		Mode:        ModeAll,
		Now:         func() time.Time { return fixed },
		Run:         run,
		HasSource:   hasSource,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	ext := testExt()
	if len(calls) != 1 {
		t.Fatalf("run 调用次数 = %d, want 1: %+v", len(calls), calls)
	}
	if calls[0].dir != repo {
		t.Errorf("run dir = %q, want %q", calls[0].dir, repo)
	}
	wantArgs := []string{"build", "-o", filepath.Join(out, "alpha"+ext), "./cmd/plugins/alpha"}
	if !reflect.DeepEqual(calls[0].args, wantArgs) {
		t.Errorf("run args = %v, want %v", calls[0].args, wantArgs)
	}

	if len(manifest.Modules) != 1 {
		t.Fatalf("Modules = %+v, want 1", manifest.Modules)
	}
	m := manifest.Modules[0]
	if m.File != "alpha"+ext {
		t.Errorf("File = %q, want %q", m.File, "alpha"+ext)
	}
	if strings.ContainsAny(m.File, `/\`) {
		t.Errorf("File = %q, 含路径分隔符，want 纯文件名", m.File)
	}
	sum := sha256.Sum256(content)
	if m.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", m.Size, len(content))
	}
	if m.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("SHA256 = %q, want %q", m.SHA256, hex.EncodeToString(sum[:]))
	}
	if len(manifest.Skipped) != 1 || manifest.Skipped[0].ID != "modules.beta" ||
		manifest.Skipped[0].Reason != ReasonNoSource {
		t.Errorf("Skipped = %+v, want [{modules.beta beta %s}]", manifest.Skipped, ReasonNoSource)
	}

	raw, err := os.ReadFile(filepath.Join(out, ManifestName))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var got Manifest
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if got.Schema != ManifestSchema {
		t.Errorf("manifest Schema = %d, want %d", got.Schema, ManifestSchema)
	}
	if got.Mode != string(ModeAll) {
		t.Errorf("manifest Mode = %q, want %q", got.Mode, ModeAll)
	}
	if len(got.Skipped) != 1 || got.Skipped[0].Reason != ReasonNoSource {
		t.Errorf("manifest Skipped = %+v, want 1 条 %s", got.Skipped, ReasonNoSource)
	}
	if len(got.Modules) != 1 || got.Modules[0].File != "alpha"+ext {
		t.Errorf("manifest Modules = %+v, want alpha%s", got.Modules, ext)
	}
}

// 测试 8：第二个被选中模块构建失败 ⇒ 报错且不留下清单（避免旧清单配半成品）。
func TestExecute_FailureWritesNoManifest(t *testing.T) {
	repo := t.TempDir()
	regDir := t.TempDir()
	writeModuleJSON(t, regDir, map[string]any{"id": "modules.alpha", "binary": "alpha"})
	writeModuleJSON(t, regDir, map[string]any{"id": "modules.beta", "binary": "beta"})

	out := t.TempDir()
	n := 0
	run := func(dir string, args ...string) error {
		n++
		if n == 2 {
			return fmt.Errorf("boom")
		}
		return os.WriteFile(args[2], []byte("x"), 0o755)
	}

	_, err := Execute(Config{
		RepoRoot:    repo,
		OutDir:      out,
		RegistryDir: regDir,
		Mode:        ModeAll,
		Run:         run,
		HasSource:   allSource,
	})
	if err == nil {
		t.Fatal("Execute err = nil, want error")
	}
	if !strings.Contains(err.Error(), "请勿直接部署") {
		t.Errorf("err = %q, want 含 %q", err.Error(), "请勿直接部署")
	}
	if _, statErr := os.Stat(filepath.Join(out, ManifestName)); !os.IsNotExist(statErr) {
		t.Errorf("manifest 存在（stat err = %v），want 不存在", statErr)
	}
}

// 测试 9：真实构建 query（不写仓库 bin/plugins，只写 t.TempDir()）。
func TestExecute_RealQuery(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go not found in PATH: %v", err)
	}

	out := t.TempDir()
	manifest, err := Execute(Config{
		RepoRoot:    "../..",
		RegistryDir: "registry/backend-modules",
		OutDir:      out,
		Mode:        ModeModules,
		IDs:         []string{"query"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(manifest.Modules) != 1 {
		t.Fatalf("Modules = %+v, want 1", manifest.Modules)
	}
	m := manifest.Modules[0]
	if m.ID != "modules.query" {
		t.Errorf("ID = %q, want modules.query", m.ID)
	}
	ext := testExt()
	if m.File != "query"+ext {
		t.Errorf("File = %q, want %q", m.File, "query"+ext)
	}
	if m.SHA256 == "" {
		t.Error("SHA256 为空，want 非空")
	}

	artifact := filepath.Join(out, m.File)
	b, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatalf("产物不存在 %s: %v", artifact, err)
	}
	if want := fmt.Sprintf("%x", sha256.Sum256(b)); m.SHA256 != want {
		t.Errorf("SHA256 = %q, want %q", m.SHA256, want)
	}
	if m.Size != int64(len(b)) {
		t.Errorf("Size = %d, want %d", m.Size, len(b))
	}

	raw, err := os.ReadFile(filepath.Join(out, ManifestName))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var got Manifest
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if got.Schema != ManifestSchema {
		t.Errorf("manifest Schema = %d, want %d", got.Schema, ManifestSchema)
	}
	if got.Mode != string(ModeModules) {
		t.Errorf("manifest Mode = %q, want %q", got.Mode, ModeModules)
	}
}
