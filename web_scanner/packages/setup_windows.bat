@echo off
echo ====================================================================
echo   ULTIMATE SECURITY TESTER - Windows Installation
echo ====================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed!
    echo Please install Python from: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo [+] Python found:
python --version
echo.

REM Check pip
echo [*] Checking pip...
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [!] pip not found, installing pip...
    python -m ensurepip --default-pip
)

echo [+] pip is installed
echo.

REM Upgrade pip
echo [*] Upgrading pip...
python -m pip install --upgrade pip

echo.
echo [*] Installing required packages...
echo.

REM Install packages
python -m pip install requests beautifulsoup4 lxml urllib3

echo.
echo ====================================================================
echo [+] Installation Complete!
echo ====================================================================
echo.
echo You can now run the scanner with:
echo   python ultimate_tester.py -u http://testphp.vulnweb.com
echo.
echo Or with OWASP 2025:
echo   python ultimate_tester.py -u http://testphp.vulnweb.com --owasp-2025
echo.
pause
