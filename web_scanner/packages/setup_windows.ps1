# Ultimate Security Tester - Windows PowerShell Setup
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  ULTIMATE SECURITY TESTER - Windows Installation" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
Write-Host "[*] Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[+] Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python is not installed!" -ForegroundColor Red
    Write-Host "Please install Python from: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "Make sure to check 'Add Python to PATH' during installation" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""

# Check pip
Write-Host "[*] Checking pip..." -ForegroundColor Yellow
try {
    $pipVersion = python -m pip --version 2>&1
    Write-Host "[+] pip is installed" -ForegroundColor Green
} catch {
    Write-Host "[!] pip not found, installing pip..." -ForegroundColor Yellow
    python -m ensurepip --default-pip
}

Write-Host ""

# Upgrade pip
Write-Host "[*] Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

Write-Host ""
Write-Host "[*] Installing required packages..." -ForegroundColor Yellow
Write-Host ""

# Install packages
$packages = @("requests", "beautifulsoup4", "lxml", "urllib3")
foreach ($package in $packages) {
    Write-Host "  Installing $package..." -ForegroundColor Cyan
    python -m pip install $package
}

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Green
Write-Host "[+] Installation Complete!" -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "You can now run the scanner with:" -ForegroundColor Yellow
Write-Host "  python ultimate_tester.py -u http://testphp.vulnweb.com" -ForegroundColor White
Write-Host ""
Write-Host "Or with OWASP 2025:" -ForegroundColor Yellow
Write-Host "  python ultimate_tester.py -u http://testphp.vulnweb.com --owasp-2025" -ForegroundColor White
Write-Host ""
Read-Host "Press Enter to exit"
