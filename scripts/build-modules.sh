#!/usr/bin/env bash
# 构建期裁剪入口（Linux/macOS）。
#
# ★ 这里只是薄壳：真正的选择/依赖闭包/构建清单实现在
#   internal/buildplan + cmd/fmbuild（一份实现，两个平台行为一致）。
#   之所以不把逻辑写进 shell：清单里的 provides/injects 闭包需要解析 JSON
#   与图遍历，在 shell 里等于把同一套规则再写一遍（两份配置必然漂移）。
#
# 用法：
#   scripts/build-modules.sh --list                  # 只看会构建什么，不构建
#   scripts/build-modules.sh                         # 全部（--all，缺省）
#   scripts/build-modules.sh --core-only             # 只构建 core 模块
#   scripts/build-modules.sh --modules=alert         # alert + 它依赖的模块
#   scripts/build-modules.sh --out=dist/plugins      # 产物目录
#   FLOW_PLUGIN_DIR=dist/plugins scripts/build-modules.sh
#
# 退出码：0 成功；1 构建/写文件失败；2 用法或选择错误（未知模块、缺源码）。
set -euo pipefail
cd "$(dirname "$0")/.."

# ★ 先构建再 exec，不用 `go run`：`go run` 会把子进程退出码统一压成 1，
#   那样"2 = 用法/选择错误"这个契约在脚本层就失真了（退出码要能被 CI 与调用方区分）。
EXT=""
if [ "$(go env GOOS)" = "windows" ]; then EXT=".exe"; fi
mkdir -p bin/.tools
go build -o "bin/.tools/fmbuild$EXT" ./cmd/fmbuild
exec "bin/.tools/fmbuild$EXT" "$@"
