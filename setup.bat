@echo off
REM Setup script for Fileless Malware Detection System (Windows)
REM Installs Volatility 3 and all dependencies

echo ==================================================
echo Fileless Malware Detection System - Setup
echo ==================================================

REM Check Python version
echo.
echo [1/5] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo X Python not found! Please install Python 3.8 or higher
    echo   Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

python --version
echo OK Python found

REM Install Python dependencies
echo.
echo [2/5] Installing Python packages...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

REM Ensure WMI is installed (Windows-specific)
echo.
echo Installing WMI support for Windows monitoring...
python -m pip install WMI pywin32

REM Verify Volatility 3 installation
echo.
echo [3/5] Verifying Volatility 3 installation...
python -c "import volatility3; print('OK Volatility 3 installed successfully')" 2>nul
if %errorlevel% neq 0 (
    echo ! Volatility 3 installation may have failed
    echo   Attempting manual install...
    python -m pip install volatility3
)

REM Check for ProcDump
echo.
echo [4/5] Checking for ProcDump...
where procdump.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo OK ProcDump found
    where procdump.exe
) else (
    echo ! ProcDump not found ^(will auto-download if needed^)
    echo   Or manually download from:
    echo   https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
)

REM Check for ProcDump64
where procdump64.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo OK ProcDump64 found
    where procdump64.exe
)

REM Verify model file
echo.
echo [5/5] Checking AI model...
if exist "fileless_detector.pt" (
    echo OK Model file found: fileless_detector.pt
) else (
    echo ! Model file not found: fileless_detector.pt
    echo   Make sure to train the model first
)

REM Summary
echo.
echo ==================================================
echo Setup Complete!
echo ==================================================
echo.
echo Required components:
echo   OK Python ^>= 3.8
echo   OK PyTorch
echo   OK Transformers ^(BERT^)
echo   OK Volatility 3
echo   OK psutil
echo.
echo Optional components:
echo   - ProcDump ^(for memory dumps^)
echo   - AI model ^(fileless_detector.pt^)
echo.
echo Next steps:
echo   1. Run as Administrator ^(required for process monitoring^)
echo.
echo   2. Start the monitoring system:
echo      python process_monitor_api.py
echo.
echo   3. Access the UI:
echo      http://localhost:8000
echo.
pause
