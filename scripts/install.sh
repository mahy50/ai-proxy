#!/usr/bin/env bash
set -euo pipefail

REPO="${AI_PROXY_REPO:-mahy50/ai-proxy}"
VERSION="latest"
PREFIX="/usr/local/bin"
PROXY_URL=""

usage() {
  cat <<'EOF'
用法: install.sh [选项]

选项:
  --version <vX.Y.Z|latest>  安装指定版本或最新版本（默认: latest）
  --prefix <dir>             安装目录（默认: /usr/local/bin）
  --repo <owner/repo>        GitHub 仓库（默认: mahy50/ai-proxy）
  --proxy <url>              手动指定下载代理（如 socks5h://127.0.0.1:7890）
  -h, --help                 显示此帮助信息
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || { echo "[错误] --version 缺少参数" >&2; exit 1; }
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#*=}"
      shift
      ;;
    --prefix)
      [[ $# -ge 2 ]] || { echo "[错误] --prefix 缺少参数" >&2; exit 1; }
      PREFIX="$2"
      shift 2
      ;;
    --prefix=*)
      PREFIX="${1#*=}"
      shift
      ;;
    --repo)
      [[ $# -ge 2 ]] || { echo "[错误] --repo 缺少参数" >&2; exit 1; }
      REPO="$2"
      shift 2
      ;;
    --repo=*)
      REPO="${1#*=}"
      shift
      ;;
    --proxy)
      [[ $# -ge 2 ]] || { echo "[错误] --proxy 缺少参数" >&2; exit 1; }
      PROXY_URL="$2"
      shift 2
      ;;
    --proxy=*)
      PROXY_URL="${1#*=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[错误] 未知参数: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "[错误] ai-proxy 仅支持 macOS (Darwin)，当前系统: $(uname -s)" >&2
  exit 1
fi

for cmd in curl python3 shasum; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[错误] 缺少必需系统工具: $cmd" >&2
    exit 1
  fi
done

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'; then
  echo "[错误] 需要 Python 3.9 及以上版本，当前: $(python3 --version 2>&1)" >&2
  exit 1
fi

fetch_url() {
  local url="$1"
  local dest="$2"

  rm -f "$dest"
  if [[ -n "$PROXY_URL" ]]; then
    curl -fsSL --max-time 60 -x "$PROXY_URL" -o "$dest" "$url"
    return 0
  fi

  if curl -fsSL --max-time 60 -o "$dest" "$url"; then
    return 0
  fi

  rm -f "$dest"
  if [[ -z "${HTTPS_PROXY:-}${https_proxy:-}${ALL_PROXY:-}${all_proxy:-}" ]]; then
    if python3 -c 'import socket; s=socket.create_connection(("127.0.0.1", 7890), timeout=0.6); s.close()' >/dev/null 2>&1; then
      echo "直连下载失败，检测到本地 127.0.0.1:7890，自动通过 FlClash 代理重试..." >&2
      if curl -fsSL --max-time 60 -x "socks5h://127.0.0.1:7890" -o "$dest" "$url"; then
        return 0
      fi
      rm -f "$dest"
    fi
  fi

  return 1
}

if [[ "$VERSION" == "latest" ]]; then
  BASE_URL="https://github.com/${REPO}/releases/latest/download"
  DISPLAY_VERSION="latest"
else
  TAG="${VERSION#v}"
  TAG="${TAG#V}"
  TAG="v${TAG}"
  BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
  DISPLAY_VERSION="$TAG"
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

TMP_BIN="$TMP_DIR/ai-proxy"
TMP_SUMS="$TMP_DIR/SHA256SUMS"

echo "正在从 GitHub (${REPO} @ ${DISPLAY_VERSION}) 下载 ai-proxy..."
fetch_url "${BASE_URL}/SHA256SUMS" "$TMP_SUMS" || {
  echo "[错误] 下载 SHA256SUMS 失败: ${BASE_URL}/SHA256SUMS" >&2
  exit 1
}
fetch_url "${BASE_URL}/ai-proxy" "$TMP_BIN" || {
  echo "[错误] 下载 ai-proxy 失败: ${BASE_URL}/ai-proxy" >&2
  exit 1
}

EXPECTED_SHA="$(awk '$2 == "ai-proxy" || $2 == "*ai-proxy" || $2 == "./ai-proxy" { gsub(/^\*/, "", $2); print tolower($1); exit }' "$TMP_SUMS")"
if [[ -z "$EXPECTED_SHA" ]]; then
  echo "[错误] SHA256SUMS 中未找到 ai-proxy 的校验值" >&2
  exit 1
fi

ACTUAL_SHA="$(shasum -a 256 "$TMP_BIN" | awk '{print tolower($1)}')"
if [[ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
  echo "[错误] SHA256 校验失败: 期望 $EXPECTED_SHA，实际 $ACTUAL_SHA" >&2
  exit 1
fi

chmod 755 "$TMP_BIN"
INSTALLED_VER="$("$TMP_BIN" --version 2>&1 || true)"
if [[ -z "$INSTALLED_VER" || "$INSTALLED_VER" != ai-proxy* ]]; then
  echo "[错误] 下载的二进制冒烟校验失败: $INSTALLED_VER" >&2
  exit 1
fi

PREFIX="${PREFIX%/}"
DEST="${PREFIX}/ai-proxy"

need_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    return 1
  fi
  if [[ -d "$PREFIX" ]]; then
    if [[ ! -w "$PREFIX" ]]; then
      return 0
    fi
    if [[ -e "$DEST" && ! -L "$DEST" && ! -w "$DEST" ]]; then
      return 0
    fi
    return 1
  fi
  local probe="$PREFIX"
  while [[ ! -e "$probe" && "$probe" != "/" ]]; do
    probe="$(dirname "$probe")"
  done
  [[ ! -w "$probe" ]]
}

SUDO=""
if need_sudo; then
  echo "目标目录 ${PREFIX} 需要管理员权限，正在请求 sudo 授权..."
  SUDO="sudo"
fi

if [[ ! -d "$PREFIX" ]]; then
  $SUDO mkdir -p "$PREFIX"
fi

STAGE_DEST="${PREFIX}/.ai-proxy.install.tmp.$$"
$SUDO install -m 755 "$TMP_BIN" "$STAGE_DEST"
if ! $SUDO mv -f "$STAGE_DEST" "$DEST"; then
  $SUDO rm -f "$STAGE_DEST" >/dev/null 2>&1 || true
  echo "[错误] 安装到 ${DEST} 失败" >&2
  exit 1
fi

echo ""
echo "[OK] 安装成功！"
echo "  - 安装路径: ${DEST}"
echo "  - 当前版本: ${INSTALLED_VER}"
echo "  - SHA256:   ${ACTUAL_SHA}"

case ":$PATH:" in
  *":${PREFIX}:"*)
    ;;
  *)
    echo ""
    echo "[提示] ${PREFIX} 当前不在 \$PATH 中，可将以下内容加入 ~/.zshrc："
    echo "  export PATH=\"${PREFIX}:\$PATH\""
    ;;
esac

echo ""
echo "常用命令:"
echo "  ai-proxy on           # 开启免 TUN 代理"
echo "  ai-proxy check        # 全面检测与连通性验证"
echo "  ai-proxy upgrade      # 检查并一键升级到最新版本"
