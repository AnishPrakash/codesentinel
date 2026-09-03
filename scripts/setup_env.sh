#!/usr/bin/env bash
# Create the code_env conda environment, install CodeSentinel, and verify it.
#
# Usage:  ./scripts/setup_env.sh
#
# `conda activate` does not work in a non-interactive script until conda's shell
# hook is sourced, which is why the eval line below exists.
set -euo pipefail

ENV_NAME="${CS_ENV_NAME:-code_env}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v conda >/dev/null 2>&1; then
  echo "conda not found on PATH."
  echo "Install Miniconda, or use a plain venv instead:"
  echo "  python3.11 -m venv .venv && source .venv/bin/activate && pip install -e ."
  exit 1
fi

eval "$(conda shell.bash hook)"

if conda env list | awk '{print $1}' | grep -qx "$ENV_NAME"; then
  echo "==> environment '$ENV_NAME' already exists"
else
  echo "==> creating '$ENV_NAME' (python 3.11)"
  conda create -n "$ENV_NAME" python=3.11 -y
fi

conda activate "$ENV_NAME"

echo "==> installing dependencies"
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pip install -e .

echo "==> tests"
python -m pytest -q

echo "==> dogfood: scanning our own source"
python -m codesentinel scan codesentinel/ --fail-on critical --quiet

echo
echo "Done. Activate it with:  conda activate $ENV_NAME"
echo "Then:                    cs scan demo/invoices.py"
echo
echo "For the VS Code extension, set codesentinel.pythonPath to:"
python -c "import sys; print('  ' + sys.executable)"
