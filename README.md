# 流量分析平台（Flow Monitoring）

一个前后端分离的流量分析平台。核心思想是 **「everything is a plugin」**：除了最底层的内核（索引、调度启动、事件总线、网关等）是写死的，其余能力全部以插件（模块）形式挂在内核上，按声明文件依次调度启动。

- **静态分析**：导入 pcapng 抓包文件 → 解析 → 落库 → 查询 → 前端展示，替代 Wireshark 的手工操作。
- **动态闭环（目标）**：检测 → 态势评估 → 分级处置，面向蓝队自动化，先模拟后真实。

---

## 一、架构概览

```
浏览器（React + Vite）
   │  REST / WebSocket
   ▼
宿主进程 server（Go，单一端口）
   ├─ L0 内核（写死，进程内）
   │   bootstrap · registry · pluginhost · transport(网关) ·
   │   eventbus · config · logging · health · storage · datamodel
   │
   └─ 模块进程（每个模块一个独立二进制，经 go-plugin/RPC 挂载）
       query · importer · detect · situation · disposal · alert · …
   └─ 网关按 http_base 前缀反代到各模块进程
```

关键约定：

- **内核最小化**：内核不 import 任何业务模块，只读注册表启动它们。
- **模块 = 独立进程**：一个模块崩溃不拖垮宿主。
- **声明式启停**：模块身份与开关都写在 `registry/backend-modules/*.json`（`enabled` 字段），加/删/换/停模块 = 改 json + 换二进制，内核零改动。未启用的模块不参与装配，只留在目录里可见可查。
- **模块间解耦**：靠事件总线（Publish/Poll）和服务注入（provides/injects）通信，不直连、不直连数据库。

## 二、目录结构

| 路径 | 作用 |
|---|---|
| `cmd/server` | 宿主进程入口（只启动内核，不写业务） |
| `cmd/plugins/<name>` | 每个模块的进程入口（约 5 行） |
| `internal/kernel` | L0 内核（地基，几乎不改） |
| `internal/modules/<name>` | 各模块业务代码（可替换） |
| `pkg/plugin` | 插件 SDK / 契约（宿主与模块共享） |
| `registry/backend-modules/*.json` | 模块身份证（声明式注册表） |
| `frontend` | React 前端（shell + panels） |
| `scripts` | 构建脚本 |
| `testdata` | 固定抓包样本 |
| `docs` | 项目说明文档 |

## 三、快速开始

```bash
# 构建全部模块进程到 bin/plugins/
bash scripts/build-plugins.sh

# 启动宿主（默认 :18080，读 registry/backend-modules/*.json）
go run ./cmd/server

# 离线解析一个抓包文件（与框架无关，纯解析验证）
go run ./cmd/parse-cli testdata/test.pcapng
```

环境变量覆盖：`FLOW_HTTP_ADDR`、`FLOW_DB_DSN`、`FLOW_LOG_LEVEL`、`FLOW_DEBUG`。
无数据库也能启动（存储降级、查询返回空），便于开发期验证框架。

## 四、当前进度

| 部分 | 状态 |
|---|---|
| L0 内核 | ✅ 完成（bootstrap / registry / pluginhost / transport / eventbus / storage / datamodel…） |
| 解析引擎 | ✅ 完成（pcapng reader + L2/L3/L4/L7 解码：DNS/DHCP/HTTP/TLS 等） |
| 存储 | ✅ 完成（PostgreSQL + 原始包文件仓库 packetstore） |
| 前端壳 | ✅ 完成（shell + 面板注册表 + 2 个面板） |
| 完整插件样板 | ✅ `query`、`importer`（module.go + main.go + json 三件套） |
| 其余 11 个模块 | ⬜ 已注册 json（`enabled: false`），业务代码待补：detect / situation / disposal / alert / attackchain / auth / capture / rule / ioc / case / export |

## 五、文档

| 文档 | 内容 |
|---|---|
| [`docs/架构.md`](docs/架构.md) | 总体架构、分层、数据流、态势闭环 |
| [`docs/插件与模块.md`](docs/插件与模块.md) | 插件契约、进程模型、服务装配、模块清单 |
| [`docs/解析器.md`](docs/解析器.md) | pcapng 区块格式、解码流程、解析要点 |
| [`docs/定制化与检测规划.md`](docs/定制化与检测规划.md) | 资产/规则数据模型、检测架构、事件线、部署形态、自研 vs 复用红线 |
| [`docs/规则翻译器.md`](docs/规则翻译器.md) | Suricata 规则导入的微型架构（三层 + IR） |
| [`docs/规则翻译器扩展指南.md`](docs/规则翻译器扩展指南.md) | 加关键字的改动地图 + 插件化搬家蓝图 |
| [`docs/检测引擎.md`](docs/检测引擎.md) | 检测引擎设计：`Ctx` / 缓冲区提取器 / 匹配语义 / 两次编译 / 性能红线 / P0 边界 |

---

## 六、开源协议

本项目采用 **MIT License**，详见 [`LICENSE`](LICENSE)。

第三方依赖（gopacket、pgx、gorilla/websocket、hashicorp/go-plugin 等）各自保留其原有协议
（均为 MIT / BSD / Apache-2.0 这类宽松协议，与 MIT 兼容）。
