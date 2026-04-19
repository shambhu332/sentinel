#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

echo "=== SENTINEL environment check ==="
check() {
  local name="$1"; local cmd="$2"
  if eval "$cmd" >/dev/null 2>&1; then
    echo "  [ok] $name"
  else
    echo "  [FAIL] $name"; exit 1
  fi
}
check "python 3.12"     "python --version | grep -qE '3\.12'"
check "poetry"          "poetry --version"
check "java 17+"        "java -version 2>&1 | grep -qE 'version \"(1[7-9]|2[0-9])'"
check "jadx"            "jadx --version"
check "apktool"         "apktool --version 2>&1 || java -jar \$HOME/tools/apktool.jar --version"
check "flowdroid jar"   "test -f \$HOME/tools/flowdroid.jar"
check "ollama service"  "systemctl is-active ollama"
check "ollama api"      "curl -sf http://localhost:11434/api/tags"
check "qwen2.5-coder"   "ollama list | grep -q qwen2.5-coder"
check "nomic-embed"     "ollama list | grep -q nomic-embed"
check ".env exists"     "test -f .env && grep -q CEREBRAS_API_KEY .env"
check "corpus has apk"  "ls corpus/*.apk >/dev/null 2>&1"
check "poetry env"      "poetry env info --path"
echo ""
echo "=== all checks passed ==="
