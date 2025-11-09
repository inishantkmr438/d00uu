#!/bin/bash

echo "======================================================================"
echo "  ULTIMATE SECURITY TESTER - Linux Installation"
echo "======================================================================"
echo ""

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "[!] Cannot detect OS"
    exit 1
fi

echo "[*] Detected: $PRETTY_NAME"
echo ""

# Install based on distribution
case $OS in
    ubuntu|debian|kali)
        echo "[*] Installing for Debian-based system..."
        sudo apt update
        sudo apt install python3 python3-pip -y
        ;;
    fedora|rhel|centos)
        echo "[*] Installing for Red Hat-based system..."
        sudo dnf install python3 python3-pip -y
        ;;
    arch|manjaro)
        echo "[*] Installing for Arch-based system..."
        sudo pacman -S python python-pip --noconfirm
        ;;
    *)
        echo "[!] Unsupported distribution: $OS"
        echo "[*] Trying generic installation..."
        ;;
esac

echo ""
echo "[*] Installing Python packages..."
pip3 install requests beautifulsoup4 lxml urllib3

echo ""
echo "======================================================================"
echo "[+] Installation Complete!"
echo "======================================================================"
echo ""
echo "You can now run the scanner with:"
echo "  python3 ultimate_tester.py -u http://testphp.vulnweb.com"
echo ""
echo "Or with OWASP 2025:"
echo "  python3 ultimate_tester.py -u http://testphp.vulnweb.com --owasp-2025"
echo ""
