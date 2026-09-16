#!/usr/bin/env bash
# 一键构建全部「模块进程」二进制到 bin/plugins/。
#
# 模块二进制命名必须与 registry/backend-modules/*.json 里的 "binary" 字段一致
# （默认等于模块短名，如 query.json -> bin/plugins/query[.exe]）。
#
# 用法：
#   scripts/build-plugins.sh              # 构建全部
#   FLOW_PLUGIN_DIR=out/plugins scripts/build-plugins.sh
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${FLOW_PLUGIN_DIR:-bin/plugins}"
EXT=""
if [ "$(go env GOOS)" = "windows" ]; then EXT=".exe"; fi

mkdir -p "$OUT"

shopt -s nullglob
found=0
for src in cmd/plugins/*/; do
  name="$(basename "$src")"
  echo "building module process: $name -> $OUT/$name$EXT"
  go build -o "$OUT/$name$EXT" "./$src"
  found=$((found + 1))
done

if [ "$found" -eq 0 ]; then
  echo "no module process found under cmd/plugins/ (add cmd/plugins/<name>/main.go)" >&2
  exit 1
fi
echo "built $found module process(es) -> $OUT"
