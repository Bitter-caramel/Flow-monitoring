package rule

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"flow-monitoring/internal/modules/rule/suricata"
)

// exportNow 取当前时间。做成包级变量，测试可覆盖以获得可复现输出。
var exportNow = time.Now

// ExportSource 把某来源目录下的全部 .rules 拼成一份文本（含元数据头），
// 供对外发布 / 备份。
//
// root 是规则根目录（其下有 builtin/local/et/public 子目录），src 决定读取
// 哪个来源目录。文件按相对路径升序拼接，保证输出可复现；元数据头包含来源、
// 规则条数与生成时间。
func ExportSource(root string, src Source) (string, error) {
	dirName, ok := sourceDirs[src]
	if !ok {
		return "", fmt.Errorf("rule: 未知规则来源 %q", string(src))
	}

	srcDir := filepath.Join(root, dirName)
	info, err := os.Stat(srcDir)
	if err != nil {
		return "", fmt.Errorf("rule: 规则来源 %q 的目录 %q 不可用: %w", string(src), srcDir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("rule: 规则来源 %q 的路径 %q 不是目录", string(src), srcDir)
	}

	files := make([]string, 0)
	err = filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".rules") {
			return nil
		}
		rel, relErr := filepath.Rel(srcDir, path)
		if relErr != nil {
			return relErr
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("rule: 遍历规则来源 %q 失败: %w", string(src), err)
	}

	// ★ 文件顺序必须确定：按相对路径升序，保证导出文本可复现。
	sort.Strings(files)

	var body strings.Builder
	for _, rel := range files {
		data, readErr := os.ReadFile(filepath.Join(srcDir, filepath.FromSlash(rel)))
		if readErr != nil {
			return "", fmt.Errorf("rule: 读取 %q 失败: %w", rel, readErr)
		}
		content := string(data)
		body.WriteString(content)
		// 防止上一个文件末尾缺换行导致与下一个文件黏连。
		if !strings.HasSuffix(content, "\n") {
			body.WriteString("\n")
		}
	}

	// 条数按“能识别的规则行”计，而不是文件数。
	raws, _ := suricata.LexAll(body.String())

	var b strings.Builder
	b.WriteString("# flow-monitoring rules export\n")
	b.WriteString("# source: " + string(src) + "\n")
	b.WriteString(fmt.Sprintf("# count: %d\n", len(raws)))
	b.WriteString("# generated: " + exportNow().Format(time.RFC3339) + "\n")
	b.WriteString("\n")
	b.WriteString(body.String())
	return b.String(), nil
}
