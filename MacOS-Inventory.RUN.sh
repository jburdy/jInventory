#!/bin/bash
# ============================================================
# macOS Inventory - Setup & Run
# Creates a Python venv, installs dependencies, runs inventory
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
PYTHON_SCRIPT="${SCRIPT_DIR}/MacOS-Inventory.py"
REQUIREMENTS="${SCRIPT_DIR}/requirements.txt"

echo "============================================================"
echo " macOS System Inventory"
echo "============================================================"
echo ""

# --- Check Python is available ---
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python 3 not found. Install via Xcode CLT or Homebrew."
    echo "        xcode-select --install"
    echo "        or: brew install python"
    exit 1
fi

PYVER=$(python3 --version 2>&1)
echo "[INFO] ${PYVER}"

# --- Create venv if not exists ---
if [[ ! -f "${VENV_DIR}/bin/python3" ]]; then
    echo "[INFO] Creating virtual environment in ${VENV_DIR}..."
    python3 -m venv "${VENV_DIR}"
    echo "[OK]   Virtual environment created"
else
    echo "[OK]   Virtual environment already exists"
fi

# --- Activate venv ---
source "${VENV_DIR}/bin/activate"

# --- Install / upgrade packages ---
echo "[INFO] Installing/upgrading dependencies..."
pip install --upgrade pip -q 2>/dev/null
pip install --upgrade psutil -q 2>/dev/null
echo "[OK]   Dependencies ready"

echo ""
echo "============================================================"
echo " Running inventory..."
echo "============================================================"
echo ""

# --- Run the inventory script ---
python3 "${PYTHON_SCRIPT}"

echo ""
echo "============================================================"
echo " Inventory complete!"
echo "============================================================"
