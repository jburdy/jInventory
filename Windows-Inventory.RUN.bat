@echo off
REM ============================================================
REM Windows Inventory - Setup & Run
REM Creates a Python venv, installs dependencies, runs inventory
REM ============================================================

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "VENV_DIR=%SCRIPT_DIR%.venv"
set "PYTHON_SCRIPT=%SCRIPT_DIR%Windows-Inventory.py"
set "REQUIREMENTS=%SCRIPT_DIR%requirements.txt"

echo ============================================================
echo  Windows System Inventory
echo ============================================================
echo.

REM --- Check Python is available ---
where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found in PATH. Install Python 3.14+
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set "PYVER=%%v"
echo [INFO] Python version: %PYVER%

REM --- Create venv if not exists ---
if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [INFO] Creating virtual environment in %VENV_DIR%...
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [ERROR] Failed to create venv
        pause
        exit /b 1
    )
    echo [OK]   Virtual environment created
) else (
    echo [OK]   Virtual environment already exists
)

REM --- Activate venv ---
call "%VENV_DIR%\Scripts\activate.bat"

REM --- Install / upgrade packages ---
echo [INFO] Installing/upgrading dependencies...
pip install --upgrade pip >nul 2>&1
pip install --upgrade psutil >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to install psutil
    pause
    exit /b 1
)
echo [OK]   Dependencies ready

echo.
echo ============================================================
echo  Running inventory...
echo ============================================================
echo.

REM --- Run the inventory script ---
python "%PYTHON_SCRIPT%"

echo.
echo ============================================================
echo  Inventory complete!
echo ============================================================
pause
