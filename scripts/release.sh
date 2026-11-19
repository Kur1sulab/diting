#!/usr/bin/env bash
# scripts/release.sh —— diting 四平台打包 + GitHub Release 一键发布。
#
# 用法：
#   scripts/release.sh v3.1.2                    # 打包 + 打 tag + 推送 + 发 Release
#   scripts/release.sh v3.1.2 --dry-run          # 只打包 + 校验，不碰 git / GitHub
#   scripts/release.sh v3.1.2 --notes-file x.md  # 自定义 Release 正文
#
# 前置：
#   - 在仓库根目录能跑 `go`（Go 1.24+）
#   - `gh auth status` 已登录（发布用）
#   - 需要代理时先 export HTTPS_PROXY=/HTTP_PROXY
#
# 为什么有这个脚本：手工发版要重复 6 步（四平台编译 / 校验和 / tag / push / release / 复核资产），
# 漏一步就是「本地能跑、下载的人是坏的」。脚本把最后一步做成硬门禁：逐个资产回查 state=uploaded
# 并核对字节数，任一不符就非零退出。

set -euo pipefail

VERSION="${1:-}"
shift || true
DRY_RUN=0
NOTES_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --notes-file) NOTES_FILE="${2:-}"; shift 2 ;;
    *) echo "[!] 未知参数: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${VERSION}" ]]; then
  echo "用法: scripts/release.sh <vX.Y.Z> [--dry-run] [--notes-file <file>]" >&2
  exit 2
fi
if [[ ! "${VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "[!] 版本号必须形如 v3.1.2，收到: ${VERSION}" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
DIST="$REPO_ROOT/dist"
mkdir -p "${DIST}"

echo "==> 1/5 交叉编译四平台（${VERSION}）"
PLATFORMS=("darwin/arm64" "darwin/amd64" "linux/amd64" "linux/arm64")
for t in "${PLATFORMS[@]}"; do
  os="${t%/*}"; arch="${t#*/}"
  out="${DIST}/diting-$os-$arch"
  ( cd engine-go && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
      go build -trimpath -buildvcs=false -ldflags "-s -w -X github.com/Kur1sulab/diting/engine-go/cli.Version=${VERSION}" \
      -o "$out" ./cmd/diting )
  printf "    %-26s %s bytes\n" "diting-$os-$arch" "$(wc -c < "$out" | tr -d ' ')"
done

echo "==> 2/5 生成 SHA256SUMS.txt"
( cd "${DIST}" && shasum -a 256 diting-* > SHA256SUMS.txt || sha256sum diting-* > SHA256SUMS.txt )
cat "${DIST}/SHA256SUMS.txt"

echo "==> 3/5 二进制自检（本机可执行的架构直接跑 version）"
HOST_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
HOST_ARCH="$(uname -m)"
[[ "$HOST_ARCH" == "x86_64" ]] && HOST_ARCH="amd64"
[[ "$HOST_ARCH" == "aarch64" ]] && HOST_ARCH="arm64"
LOCAL_BIN="${DIST}/diting-$HOST_OS-$HOST_ARCH"
if [[ -x "$LOCAL_BIN" ]]; then
  GOT="$("$LOCAL_BIN" version)"
  echo "    $GOT"
  case "$GOT" in
    *"${VERSION}"*) ;;
    *) echo "[!] 版本注入失败：期望 ${VERSION}，实得 $GOT" >&2; exit 1 ;;
  esac
else
  echo "    （当前主机 $HOST_OS/$HOST_ARCH 不在四平台内，跳过自检）"
fi

if [[ "$DRY_RUN" == "1" ]]; then
  echo "==> dry-run 结束：产物在 ${DIST} （未打 tag、未推送、未发 Release）"
  exit 0
fi

echo "==> 4/5 打 tag 并推送"
if git rev-parse -q --verify "refs/tags/${VERSION}" >/dev/null; then
  echo "[!] tag ${VERSION} 已存在" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "[!] 工作区不干净，先提交或清理（发版必须对应一个确定的 commit）" >&2
  git status --short >&2
  exit 1
fi
git tag -a "${VERSION}" -m "diting ${VERSION}"
git push origin HEAD
git push origin "${VERSION}"

echo "==> 5/5 创建 GitHub Release 并上传资产"
TITLE="diting ${VERSION}"
if [[ -n "$NOTES_FILE" ]]; then
  gh release create "${VERSION}" --title "$TITLE" --notes-file "$NOTES_FILE" \
    "${DIST}"/diting-darwin-arm64 "${DIST}"/diting-darwin-amd64 \
    "${DIST}"/diting-linux-amd64 "${DIST}"/diting-linux-arm64 "${DIST}"/SHA256SUMS.txt
else
  gh release create "${VERSION}" --title "$TITLE" --generate-notes \
    "${DIST}"/diting-darwin-arm64 "${DIST}"/diting-darwin-amd64 \
    "${DIST}"/diting-linux-amd64 "${DIST}"/diting-linux-arm64 "${DIST}"/SHA256SUMS.txt
fi

echo "==> 复核：逐个资产确认 state=uploaded 且字节数符合"
EXPECT=$(cd "${DIST}" && ls diting-darwin-arm64 diting-darwin-amd64 diting-linux-amd64 diting-linux-arm64 SHA256SUMS.txt)
FAIL=0
# 复核这一步是脚本的全部意义（防止「本地能跑、下载的人是坏的」），但它自己也走网络：
# 实测在代理下偶发 `net/http: TLS handshake timeout` 直接非零退出，等于把已成功的发版
# 判成失败。只对网络类错误重试，真·资产缺失/字节不符立刻失败——别把重试做成掩盖。
gh_assets() {
  local i out
  for i in 1 2 3 4 5; do
    if out=$(gh release view "${VERSION}" --json assets \
               -q '.assets[] | "\(.name)\t\(.state) \(.size)"' 2>&1); then
      printf '%s\n' "$out"
      return 0
    fi
    case "$out" in
      *timeout*|*"connection reset"*|*"TLS handshake"*|*"i/o timeout"*|*"502"*|*"503"*)
        echo "    （复核请求第 $i 次失败：网络错误，重试）" >&2
        sleep 3 ;;
      *) printf '%s\n' "$out" >&2; return 1 ;;
    esac
  done
  return 1
}
ASSETS="$(gh_assets)" || { echo "[!] 无法读取 Release 资产列表——发版可能成功，请手工复核" >&2; exit 1; }
for name in $EXPECT; do
  want=$(wc -c < "${DIST}/$name" | tr -d ' ')
  got=$(printf '%s\n' "$ASSETS" | awk -F'\t' -v n="$name" '$1==n{print $2}')
  echo "    $name  want=$want  got=${got:-MISSING}"
  if [[ "$got" != "uploaded $want" ]]; then
    FAIL=1
  fi
done
if [[ "$FAIL" != "0" ]]; then
  echo "[!] 有资产未上传成功或字节数不符——不要对外宣传这次发版" >&2
  exit 1
fi
echo "[+] 发布完成：https://github.com/Kur1sulab/diting/releases/tag/${VERSION}"
