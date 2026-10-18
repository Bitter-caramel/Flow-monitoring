package alerting

// 内核纯净性测试（任务 15-2b 的硬要求）：
// internal/kernel 下不允许任何 .go 文件 import 业务模块或 hotpath，
// 否则那个模块就永远砍不掉，而且平时完全看不出来。

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// storePkg 是唯一允许出现在内核里的 internal/modules 包：
// 它是进程内存储实现（db-adapter），没有对应清单、不是可选业务模块，
// hostguard 的 StoreIsNotAModule 已明确它不算模块。
const storePkg = "flow-monitoring/internal/modules/store"

func TestKernelImportsNoBusinessModules(t *testing.T) {
	root := repoRoot(t)
	kernelDir := filepath.Join(root, "internal", "kernel")

	var violations []string
	err := filepath.WalkDir(kernelDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// 扫描生产代码，跳过后端测试自身（测试里出现字符串不算 import）。
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		for _, imp := range f.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				return uerr
			}
			if p == "flow-monitoring/internal/hotpath" {
				violations = append(violations, filepath.ToSlash(path)+" imports "+p)
				continue
			}
			if strings.HasPrefix(p, "flow-monitoring/internal/modules/") && p != storePkg {
				violations = append(violations, filepath.ToSlash(path)+" imports "+p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("扫描 internal/kernel 失败: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("内核纯净性被破坏（含业务模块 / hotpath 的 import）：\n%s",
			strings.Join(violations, "\n"))
	}
}
