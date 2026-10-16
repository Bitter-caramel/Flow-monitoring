#!/usr/bin/env bash
# 兼容入口：等价于 scripts/build-modules.sh --all。
#
# 历史说明：本脚本原先直接扫描 cmd/plugins/*/ 目录构建，**不读模块清单**，
# 因此无法裁剪（不能只构建 core、也不能"某模块 + 它依赖的模块"），
# 也看不懂 provides/injects 依赖关系。裁剪能力现已收进
# internal/buildplan + cmd/fmbuild（唯一实现），本脚本保留仅为不破坏
# 既有引用（README、docs、cmd/plugins/*/main.go 注释）。
#
# 用法：
#   scripts/build-plugins.sh              # 构建全部（等于 scripts/build-modules.sh --all）
#   FLOW_PLUGIN_DIR=out/plugins scripts/build-plugins.sh
#
# 需要裁剪请直接用：scripts/build-modules.sh --core-only | --modules=<id> | --list
set -euo pipefail
cd "$(dirname "$0")/.."

# 无参数时补 --all（保持"裸跑=构建全部"的旧语义）；带参数则原样透传，
# 这样 `scripts/build-plugins.sh --core-only` 之类的用法不会被硬塞的 --all 撞成"模式互斥"。
if [ $# -eq 0 ]; then set -- --all; fi
exec "$(dirname "$0")/build-modules.sh" "$@"
