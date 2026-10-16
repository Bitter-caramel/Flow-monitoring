package buildplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"flow-monitoring/internal/kernel/registry"
)

// ManifestSchema 是 build-manifest.json 的当前 schema 版本。
const ManifestSchema = 1

// ManifestName 是构建清单文件名。
const ManifestName = "build-manifest.json"

// Module 是构建清单里的一个产物条目。
type Module struct {
	ID      string `json:"id"`
	Binary  string `json:"binary"`
	Version string `json:"version"`
	Layer   string `json:"layer"`
	Core    bool   `json:"core"`
	Package string `json:"package"`
	File    string `json:"file"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

// Manifest 是一次构建的产物清单（写入 <OutDir>/build-manifest.json）。
//
// 供运行期自检与前端展示"这份构建到底带了什么"。
type Manifest struct {
	Schema      int       `json:"schema"`
	GeneratedAt string    `json:"generated_at"`
	GitCommit   string    `json:"git_commit"`
	GoVersion   string    `json:"go_version"`
	GOOS        string    `json:"goos"`
	GOARCH      string    `json:"goarch"`
	Mode        string    `json:"mode"`
	OutDir      string    `json:"out_dir"`
	Requested   []string  `json:"requested,omitempty"`
	Modules     []Module  `json:"modules"`
	Skipped     []Skipped `json:"skipped"`
}

// Config 是 Execute 的入参。Now / Run / HasSource 为 nil 时用缺省实现。
type Config struct {
	RepoRoot    string
	OutDir      string
	RegistryDir string
	Mode        Mode
	IDs         []string
	Now         func() time.Time
	Run         func(dir string, args ...string) error
	HasSource   func(registry.Descriptor) bool
}

// Execute 加载清单 → 出计划 → 逐个构建 → 统计产物 → 写 build-manifest.json。
//
// 每个 Selected 模块执行：
//
//	Run(RepoRoot, "build", "-o", <OutDir>/<Binary><ext>, "./cmd/plugins/"+<Binary>)
//
// 缺省 Run 在 RepoRoot 下调用 go build；缺省 HasSource 检查
// <RepoRoot>/cmd/plugins/<Binary>/main.go 是否存在。
func Execute(cfg Config) (*Manifest, error) {
	repo := cfg.RepoRoot
	if repo == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("buildplan: resolve repo root: %w", err)
		}
		repo = wd
	}

	regDir := cfg.RegistryDir
	if regDir == "" {
		regDir = filepath.Join(repo, "registry", "backend-modules")
	} else if !filepath.IsAbs(regDir) {
		// 与 CLI 一致：相对 --registry 相对 RepoRoot，而不是进程 cwd。
		regDir = filepath.Join(repo, regDir)
	}

	reg, err := registry.Load(regDir)
	if err != nil {
		return nil, err
	}

	hasSource := cfg.HasSource
	if hasSource == nil {
		hasSource = func(d registry.Descriptor) bool {
			_, statErr := os.Stat(filepath.Join(repo, "cmd", "plugins", d.Binary, "main.go"))
			return statErr == nil
		}
	}

	plan, err := Build(reg, cfg.Mode, cfg.IDs, hasSource)
	if err != nil {
		return nil, err
	}

	// outDirRaw 保留用户传入的原值（相对就是相对），写进清单的 out_dir；
	// outDir 是解析后的绝对路径，只用于文件操作。
	outDirRaw := cfg.OutDir
	if outDirRaw == "" {
		outDirRaw = os.Getenv("FLOW_PLUGIN_DIR")
	}
	if outDirRaw == "" {
		outDirRaw = "bin/plugins"
	}
	outDir := outDirRaw
	if !filepath.IsAbs(outDir) {
		outDir = filepath.Join(repo, outDir)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("buildplan: create out dir %s: %w", outDir, err)
	}

	// 先删掉上一轮清单：本轮一旦中途失败，就不会留下"旧清单 + 新二进制"的自相矛盾目录。
	manifestPath := filepath.Join(outDir, ManifestName)
	if err := os.Remove(manifestPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("buildplan: remove stale manifest %s: %w", manifestPath, err)
	}

	run := cfg.Run
	if run == nil {
		run = func(dir string, args ...string) error {
			cmd := exec.Command("go", args...)
			cmd.Dir = dir
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		}
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	goos := envOr("GOOS", runtime.GOOS)
	goarch := envOr("GOARCH", runtime.GOARCH)
	ext := ""
	if goos == "windows" {
		ext = ".exe"
	}

	manifest := &Manifest{
		Schema:      ManifestSchema,
		GeneratedAt: now().UTC().Format(time.RFC3339),
		GitCommit:   gitCommit(repo),
		GoVersion:   goVersion(repo),
		GOOS:        goos,
		GOARCH:      goarch,
		Mode:        string(plan.Mode),
		OutDir:      outDirRaw,
		Requested:   plan.Requested,
		Modules:     []Module{},
		Skipped:     plan.Skipped,
	}

	for _, d := range plan.Selected {
		// file 是绝对路径（给 go build -o 用）；清单里只记纯文件名（相对 OutDir）。
		file := filepath.Join(outDir, d.Binary+ext)
		fileName := d.Binary + ext
		if err := run(repo, "build", "-o", file, "./cmd/plugins/"+d.Binary); err != nil {
			return nil, partialArtifactError(d.ID, outDir, err)
		}
		size, sum, err := fileDigest(file)
		if err != nil {
			return nil, partialArtifactError(d.ID, outDir, err)
		}
		manifest.Modules = append(manifest.Modules, Module{
			ID:      d.ID,
			Binary:  d.Binary,
			Version: d.Version,
			Layer:   d.Layer,
			Core:    d.Core,
			Package: "./cmd/plugins/" + d.Binary,
			File:    fileName,
			Size:    size,
			SHA256:  sum,
		})
	}

	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("buildplan: marshal manifest: %w", err)
	}
	b = append(b, '\n')
	if err := writeFileAtomic(manifestPath, b, 0o644); err != nil {
		return nil, fmt.Errorf("buildplan: write manifest %s: %w", manifestPath, err)
	}
	return manifest, nil
}

// partialArtifactError 构造"构建中途失败"的错误：必须含模块 id、原始错误，
// 以及一句提醒——产物目录里可能残留半成品二进制，不能直接部署。
func partialArtifactError(id, outDir string, err error) error {
	return fmt.Errorf("buildplan: 构建 %s 失败: %w；产物目录 %s 可能含部分已构建的二进制，请勿直接部署",
		id, err, outDir)
}

// writeFileAtomic 在同目录写临时文件再 os.Rename 原子替换，避免读到半截清单。
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".build-manifest-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // Rename 成功后是 no-op，失败时清理临时文件
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// fileDigest 返回文件大小与 SHA256（十六进制小写）。
func fileDigest(path string) (int64, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, "", err
	}
	sum := sha256.Sum256(b)
	return int64(len(b)), hex.EncodeToString(sum[:]), nil
}

// envOr 取环境变量，空则回退（★ 尊重 GOOS/GOARCH 以支持交叉编译）。
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// gitCommit 取短 commit；失败返回 "unknown"（不许因此报错）。
func gitCommit(dir string) string {
	out, err := commandOutput(dir, "git", "rev-parse", "--short", "HEAD")
	if err != nil {
		return "unknown"
	}
	s := strings.TrimSpace(out)
	if s == "" {
		return "unknown"
	}
	return s
}

// goVersion 取 Go 工具链版本；失败留空。
func goVersion(dir string) string {
	out, err := commandOutput(dir, "go", "env", "GOVERSION")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// commandOutput 在 dir 下执行命令并返回 stdout。
//
// 失败时把 stderr（截断到 500 字节以内）拼进错误信息——cmd.Output() 单独用会
// 把 stderr 丢掉，只留一句 "exit status 1" 根本无法排障。
// gitCommit / goVersion 仍按原样吞掉这个错误并优雅降级，不受影响。
func commandOutput(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return string(b), fmt.Errorf("%s %s: %w: %s",
				name, strings.Join(args, " "), err, truncateBytes(msg, 500))
		}
		return string(b), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return string(b), nil
}

// truncateBytes 把 s 截断到最多 n 字节（按字节切，末尾补省略号不超过 n）。
func truncateBytes(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	const ellipsis = "..."
	if n <= len(ellipsis) {
		return s[:n]
	}
	return s[:n-len(ellipsis)] + ellipsis
}
