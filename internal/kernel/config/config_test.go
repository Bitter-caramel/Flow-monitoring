package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefault 保障默认值合理（PG DSN、HTTP 端口、日志路径等）。
func TestDefault(t *testing.T) {
	c := Default()
	if c.Server.HTTPAddr != ":18080" {
		t.Errorf("HTTPAddr default = %q, want :18080", c.Server.HTTPAddr)
	}
	// DSN 端口须与 scripts/docker-compose.yml 的宿主映射（5433）一致
	if !strings.Contains(c.Database.DSN, ":5433/") {
		t.Errorf("DSN default = %q, want host port 5433", c.Database.DSN)
	}
	if c.Database.Driver != "postgres" {
		t.Errorf("DB driver default = %q, want postgres", c.Database.Driver)
	}
	if c.Logging.Dir != "logs" || c.Logging.FileName != "program.log" {
		t.Errorf("log default = %s/%s, want logs/program.log", c.Logging.Dir, c.Logging.FileName)
	}
}

// TestLoad_MissingFileReturnsDefault 缺失文件返回 Default（开发期零配置可启动）。
func TestLoad_MissingFileReturnsDefault(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") err = %v", err)
	}
	if c.Server.HTTPAddr != ":18080" {
		t.Errorf("default HTTPAddr expected, got %q", c.Server.HTTPAddr)
	}
}

// TestLoad_ValidJSON 验证 JSON 文件覆盖默认值。
func TestLoad_ValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"server":{"http_addr":":9090","debug":false}}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.HTTPAddr != ":9090" {
		t.Errorf("HTTPAddr not overridden, got %q", c.Server.HTTPAddr)
	}
	if c.Server.Debug {
		t.Errorf("Debug should be false after override")
	}
	// 未在 JSON 中声明的 Database 字段应保留 Default
	if c.Database.Driver != "postgres" {
		t.Errorf("Database.Driver should keep default, got %q", c.Database.Driver)
	}
}

// TestLoad_EnvOverride 验证环境变量覆盖关键字段。
func TestLoad_EnvOverride(t *testing.T) {
	// 保存并恢复环境变量
	const keyDSN = "FLOW_DB_DSN"
	const keyHTTP = "FLOW_HTTP_ADDR"
	const keyLevel = "FLOW_LOG_LEVEL"
	defer func() {
		os.Unsetenv(keyDSN)
		os.Unsetenv(keyHTTP)
		os.Unsetenv(keyLevel)
	}()

	os.Setenv(keyDSN, "postgres://custom/custom")
	os.Setenv(keyHTTP, ":7777")
	os.Setenv(keyLevel, "DEBUG")

	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Database.DSN != "postgres://custom/custom" {
		t.Errorf("DSN env not applied, got %q", c.Database.DSN)
	}
	if c.Server.HTTPAddr != ":7777" {
		t.Errorf("HTTPAddr env not applied, got %q", c.Server.HTTPAddr)
	}
	if c.Logging.Level != "DEBUG" {
		t.Errorf("Level env not applied, got %q", c.Logging.Level)
	}
}
