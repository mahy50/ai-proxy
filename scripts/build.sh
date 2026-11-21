#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="$ROOT_DIR/VERSION"
DIST_DIR="$ROOT_DIR/dist"

if [[ ! -f "$VERSION_FILE" ]]; then
  echo "Error: VERSION file not found at $VERSION_FILE" >&2
  exit 1
fi

VERSION="$(tr -d '[:space:]' < "$VERSION_FILE")"
if [[ -z "$VERSION" ]]; then
  echo "Error: VERSION file is empty" >&2
  exit 1
fi

PY_VERSION="$(PYTHONPATH="$ROOT_DIR/src" python3 -c "import ai_proxy; print(ai_proxy.__version__)")"
if [[ "$VERSION" != "$PY_VERSION" ]]; then
  echo "Error: VERSION ($VERSION) != ai_proxy.__version__ ($PY_VERSION)" >&2
  exit 1
fi

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

STAGE_ZIP="$WORK_DIR/zip_stage"
mkdir -p "$STAGE_ZIP"
cp -R "$ROOT_DIR/src/ai_proxy" "$STAGE_ZIP/ai_proxy"
find "$STAGE_ZIP" -name "__pycache__" -type d -exec rm -rf {} +
find "$STAGE_ZIP" -name "*.py[co]" -type f -delete

ZIPAPP_BIN="$DIST_DIR/ai-proxy"
python3 -m zipapp "$STAGE_ZIP" \
  -o "$ZIPAPP_BIN" \
  -p "/usr/bin/env python3" \
  -m "ai_proxy.cli:main" \
  -c
chmod 755 "$ZIPAPP_BIN"

STAGE_TAR="$WORK_DIR/tar_stage"
mkdir -p "$STAGE_TAR"
cp "$ZIPAPP_BIN" "$STAGE_TAR/ai-proxy"
cp "$ROOT_DIR/README.md" "$STAGE_TAR/README.md"
cp "$VERSION_FILE" "$STAGE_TAR/VERSION"
chmod 755 "$STAGE_TAR/ai-proxy"

TARBALL="$DIST_DIR/ai-proxy-v${VERSION}.tar.gz"
COPYFILE_DISABLE=1 tar -czf "$TARBALL" -C "$STAGE_TAR" ai-proxy README.md VERSION

(
  cd "$DIST_DIR"
  shasum -a 256 ai-proxy "ai-proxy-v${VERSION}.tar.gz" > SHA256SUMS
)

echo "Built ai-proxy v${VERSION} artifacts in $DIST_DIR:"
ls -lh "$DIST_DIR"
