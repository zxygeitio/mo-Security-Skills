#!/bin/bash
# Burp Suite 移动端抓包一键配置
set -e

echo "[1/5] 检查 ADB..."
which adb >/dev/null 2>&1 || apt-get install -y android-sdk-platform-tools

echo "[2/5] 获取 Kali IP..."
KALI_IP=$(ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+')
echo "  Kali IP: $KALI_IP"

echo "[3/5] 启动 socat 转发 ${KALI_IP}:8080 → 127.0.0.1:8080..."
pkill -f "socat.*8080" 2>/dev/null || true
socat TCP-LISTEN:8080,bind=$KALI_IP,fork,reuseaddr TCP:127.0.0.1:8080 &
SOCAT_PID=$!
echo "  socat PID: $SOCAT_PID"

echo "[4/5] 准备 Android 证书..."
CA_PEM=/usr/local/share/ca-certificates/burp_ca.crt
if [ ! -f "$CA_PEM" ]; then
    echo "  CA 证书不存在，请先运行 Burp 并安装 CA 证书到系统"
    exit 1
fi
HASH=$(openssl x509 -inform PEM -subject_hash_old -in $CA_PEM | head -1)
cp $CA_PEM /tmp/${HASH}.0
echo "  证书: /tmp/${HASH}.0"
echo "  Hash: $HASH"

echo ""
echo "========================================="
echo "  配置完成!"
echo "========================================="
echo ""
echo "  Kali 代理地址: ${KALI_IP}:8080"
echo ""
echo "  === 在 Android 设备上执行 ==="
echo ""
echo "  1. WiFi 代理设置:"
echo "     主机名: ${KALI_IP}"
echo "     端口: 8080"
echo ""
echo "  2. 推送系统证书 (Android ≥9):"
echo "     adb push /tmp/${HASH}.0 /data/local/tmp/"
echo "     adb shell"
echo "     su -c 'mount -o rw,remount /system'"
echo "     su -c 'cp /data/local/tmp/${HASH}.0 /system/etc/security/cacerts/'"
echo "     su -c 'chmod 644 /system/etc/security/cacerts/${HASH}.0'"
echo "     reboot"
echo ""
echo "  3. 打开目标 APP → Burp HTTP History"
echo "      (确保 Intercept 已关闭: Ctrl+Shift+P → Ctrl+T)"
