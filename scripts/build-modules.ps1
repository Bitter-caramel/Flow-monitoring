# 构建期裁剪入口（Windows）。
#
# ★ 这里只是薄壳：真正的选择/依赖闭包/构建清单实现在
#   internal/buildplan + cmd/fmbuild（一份实现，两个平台行为一致）。
#   顺带绕开了 PowerShell 5.1 读 UTF-8 清单的编码陷阱
#   （5.1 的 Get-Content 不带 -Encoding UTF8 会把中文按 GBK 解码，
#    导致 ConvertFrom-Json 直接失败）——清单由 Go 读，不经过 PS。
#
# 用法：
#   scripts\build-modules.ps1 --list                 # 只看会构建什么，不构建
#   scripts\build-modules.ps1                        # 全部（--all，缺省）
#   scripts\build-modules.ps1 --core-only            # 只构建 core 模块
#   scripts\build-modules.ps1 --modules=alert        # alert + 它依赖的模块
#   scripts\build-modules.ps1 --out=dist\plugins     # 产物目录
#
# 退出码：0 成功；1 构建/写文件失败；2 用法或选择错误（未知模块、缺源码）。
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CliArgs
)

$ErrorActionPreference = 'Stop'

# 切到仓库根（本脚本位于 <root>\scripts\）
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $root
try {
    # ★ 先构建再执行，不用 `go run`：`go run` 会把子进程退出码统一压成 1，
    #   那样"2 = 用法/选择错误"这个契约在脚本层就失真了（退出码要能被 CI 与调用方区分）。
    $ext = ''
    if ((go env GOOS) -eq 'windows') { $ext = '.exe' }
    $tools = Join-Path $root 'bin\.tools'
    New-Item -ItemType Directory -Force -Path $tools | Out-Null
    $bin = Join-Path $tools "fmbuild$ext"
    & go build -o $bin ./cmd/fmbuild
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $bin @CliArgs
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
