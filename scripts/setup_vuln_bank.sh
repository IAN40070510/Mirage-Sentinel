#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${1:-https://github.com/Commando-X/vuln-bank.git}"
TARGET_PATH="${2:-external/vuln-bank}"
BRANCH="${3:-main}"
INSTALL_DEPS="${INSTALL_DEPS:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FULL_TARGET="${REPO_ROOT}/${TARGET_PATH}"

echo "[setup-vuln-bank] repo root: ${REPO_ROOT}"
echo "[setup-vuln-bank] target path: ${FULL_TARGET}"

if ! command -v git >/dev/null 2>&1; then
  echo "git is required but not found in PATH" >&2
  exit 1
fi

if [ -d "${FULL_TARGET}/.git" ]; then
  echo "[setup-vuln-bank] existing clone found, pulling latest..."
  git -C "${FULL_TARGET}" fetch --all --prune
  git -C "${FULL_TARGET}" checkout "${BRANCH}"
  git -C "${FULL_TARGET}" pull --ff-only origin "${BRANCH}"
else
  mkdir -p "$(dirname "${FULL_TARGET}")"
  echo "[setup-vuln-bank] cloning..."
  git clone --depth 1 --branch "${BRANCH}" "${REPO_URL}" "${FULL_TARGET}"
fi

if [ "${INSTALL_DEPS}" = "1" ]; then
  if [ ! -f "${FULL_TARGET}/requirements.txt" ]; then
    echo "requirements.txt not found under ${FULL_TARGET}" >&2
    exit 1
  fi
  echo "[setup-vuln-bank] installing dependencies in current Python environment..."
  pip install -r "${FULL_TARGET}/requirements.txt"
fi

echo "[setup-vuln-bank] done."
echo "[next] start vuln-bank:"
echo "       cd ${FULL_TARGET}"
echo "       python app.py"
echo "[next] set Mirage env:"
echo "       VULN_BANK_BASE_URL=http://127.0.0.1:5000"
