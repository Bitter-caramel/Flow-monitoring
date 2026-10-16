// Package config 是平台读设置的工具底座。
//
// 设计依据 v3 流程梯队 1.2：「config + logging：工具底座，小而快」。
//
// 当前为最小可用版（P0 阶段）：
//   - 配置文件格式：JSON（用标准库 encoding/json，零第三方依赖）
//   - 环境变量覆盖关键项：FLOW_DB_DSN / FLOW_HTTP_ADDR / FLOW_LOG_LEVEL
//   - 缺失文件时返回 Default（开发期零配置即可启动）
//   - 数据库直接用 PostgreSQL（按 v0.3 第 6.2 节）
//
// 未来扩展点（v3 梯队 3+）：
//   - YAML/Hot-Reload/Vault Secret：留接口不实现
//   - 多实例部署的 NodeID/ZoneID
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config 平台主配置。
type Config struct {
	Server      ServerConfig   `json:"server"`
	Database    DBConfig       `json:"database"`
	Logging     LogConfig      `json:"logging"`
	DataDir     string         `json:"data_dir"`        // 原始抓包文件目录
	PluginDir   string         `json:"plugin_dir"`      // 模块进程二进制目录
	ManifestDir string         `json:"manifest_dir"`    // 用户扩展模块清单目录（L3）
	StaticDir   string         `json:"static_dir"`      // 前端构建产物目录（空=不托管）
	Extra       map[string]any `json:"extra,omitempty"` // 模块自定义配置
}

// ServerConfig HTTP/WebSocket 服务监听配置。
type ServerConfig struct {
	HTTPAddr string `json:"http_addr"` // 监听地址，如 ":18080"
	WSAddr   string `json:"ws_addr"`   // WebSocket 地址，默认与 HTTPAddr 复用
	Debug    bool   `json:"debug"`     // 调试模式（更详细日志 / 允许 CORS）
}

// DBConfig PostgreSQL 数据库连接配置。
type DBConfig struct {
	Driver   string `json:"driver"`    // 固定 "postgres"
	DSN      string `json:"dsn"`       // PostgreSQL 连接串
	MaxConns int    `json:"max_conns"` // 连接池上限
	MaxIdle  int    `json:"max_idle"`  // 空闲连接上限
}

// LogConfig 日志配置。
//
// 字段名与 logging 包的便利函数 NewFromConfigFile 入参一一对应；
// bootstrap 负责拆解后传给 logging。
type LogConfig struct {
	Level    string `json:"level"`     // DEBUG/INFO/WARN/ERROR
	Format   string `json:"format"`    // "json" 或 "text"
	Dir      string `json:"dir"`       // 日志目录
	FileName string `json:"file_name"` // 主日志文件名（program.log）
	MaxSize  int    `json:"max_size"`  // 单文件最大 MB（轮转阈值；当前仅做大小检查，未实现轮转）
	MaxFiles int    `json:"max_files"` // 保留旧文件数（当前未实现，预留字段）
}

// Default 返回开发期默认配置。
//
//   - HTTP 监听 :18080（与 frontend/vite.config.ts 的代理目标一致）
//   - PG DSN: postgres://flow:flow@127.0.0.1:5433/flow?sslmode=disable
//     （与 scripts/docker-compose.yml 的宿主端口映射一致；5432 常被 WSL 占用）
//   - 日志输出 JSON 格式到 ./logs/program.log，INFO 级别
//
// 模块启停不在这里控制：由 registry/backend-modules/*.json 的 enabled 字段决定，
// 保持"一个模块的声明与开关在同一处"。
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			HTTPAddr: ":18080",
			Debug:    true,
		},
		Database: DBConfig{
			Driver:   "postgres",
			DSN:      "postgres://flow:flow@127.0.0.1:5433/flow?sslmode=disable",
			MaxConns: 50,
			MaxIdle:  10,
		},
		Logging: LogConfig{
			Level:    "INFO",
			Format:   "json",
			Dir:      "logs",
			FileName: "program.log",
			MaxSize:  100,
			MaxFiles: 7,
		},
		DataDir:     "data",
		PluginDir:   "bin/plugins",
		ManifestDir: "registry/backend-modules",
		// ★ 前端构建产物目录（相对启动目录）：缺省托管 frontend/dist，
		//   目录不存在时 http.FileServer 自然返回 404，不影响任何后端接口；
		//   显式设为空字符串（FLOW_STATIC_DIR= ）= 纯 API 部署、不托管静态资源。
		StaticDir: "frontend/dist",
	}
}

// Load 从 path 读取 JSON 配置文件；缺失则返回 Default。
//
// 加载顺序：
//  1. 用 Default() 初始化 c（确保任何未在文件中声明的字段都有合理默认值）
//  2. json.Unmarshal 覆盖（用户配置覆盖默认）
//  3. 关键字段环境变量覆盖（部署期临时改 DSN/端口/日志级）
//
// Load 不验证 DSN 是否可连接、目录是否可写——这些由调用方在启动阶段验证。
func Load(path string) (*Config, error) {
	c := Default()
	if path == "" {
		return applyEnv(c), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return applyEnv(c), nil
}

// applyEnv 用环境变量覆盖关键字段。
//
// 覆盖项：
//   - FLOW_DB_DSN: 数据库连接串
//   - FLOW_HTTP_ADDR: HTTP 监听地址
//   - FLOW_LOG_LEVEL: 日志级别
//   - FLOW_DEBUG: "1"/"true" 开启 Debug
//   - FLOW_STATIC_DIR: 前端构建产物目录（★ 显式设为空串 = 不托管静态资源）
func applyEnv(c *Config) *Config {
	if v := os.Getenv("FLOW_DB_DSN"); v != "" {
		c.Database.DSN = v
	}
	if v := os.Getenv("FLOW_HTTP_ADDR"); v != "" {
		c.Server.HTTPAddr = v
	}
	if v := os.Getenv("FLOW_LOG_LEVEL"); v != "" {
		c.Logging.Level = v
	}
	// 用 LookupEnv：允许"显式设为空"来表达"不要托管前端"
	if v, ok := os.LookupEnv("FLOW_STATIC_DIR"); ok {
		c.StaticDir = v
	}
	switch os.Getenv("FLOW_DEBUG") {
	case "1", "true", "TRUE", "True":
		c.Server.Debug = true
	case "0", "false", "FALSE", "False":
		c.Server.Debug = false
	}
	return c
}
