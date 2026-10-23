#!/usr/bin/env sh
# PHP2Shell Sentinel — Linux One-Line Installer
# Usage:
#   curl -fsSL https://suleman-elahi.github.io/php2shell-sentinel/install.sh | sudo sh
#   or with custom base URL:
#   curl -fsSL https://suleman-elahi.github.io/php2shell-sentinel/install.sh | sudo SENTINEL_BASE_URL="https://..." sh

set -eu

BASE_URL="${SENTINEL_BASE_URL:-https://suleman-elahi.github.io/php2shell-sentinel}"
INSTALL_BIN="/usr/local/bin/sentinel"
CONFIG_DIR="/etc/php2shell-sentinel"
CONFIG_FILE="${CONFIG_DIR}/sentinel.json"

echo "[*] Installing PHP2Shell Sentinel (CVE-2026-109618 / CVE-2026-109619 Defense Agent)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Please run this installer as root (e.g., curl -fsSL ... | sudo sh)" >&2
    exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        BIN_NAME="sentinel-linux-amd64"
        ;;
    *)
        echo "[!] Unsupported architecture: $ARCH (prebuilt binary is linux/amd64; build from source with 'go build ./cmd/sentinel')" >&2
        exit 1
        ;;
esac

mkdir -p "$CONFIG_DIR"

TMP_BIN="$(mktemp /tmp/sentinel.XXXXXX)"
trap 'rm -f "$TMP_BIN"' EXIT

echo "[*] Downloading ${BASE_URL}/downloads/${BIN_NAME} ..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${BASE_URL}/downloads/${BIN_NAME}" -o "$TMP_BIN"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_BIN" "${BASE_URL}/downloads/${BIN_NAME}"
else
    echo "[!] Neither curl nor wget found." >&2
    exit 1
fi

chmod 0755 "$TMP_BIN"
mv "$TMP_BIN" "$INSTALL_BIN"
echo "[+] Installed binary to ${INSTALL_BIN}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "[*] Creating default configuration at ${CONFIG_FILE} ..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${BASE_URL}/downloads/sentinel.example.json" -o "$CONFIG_FILE" || true
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$CONFIG_FILE" "${BASE_URL}/downloads/sentinel.example.json" || true
    fi
fi

echo "[*] Running initial PHP host audit..."
"$INSTALL_BIN" check || true

echo "[*] Registering and starting systemd service..."
if [ -f "$CONFIG_FILE" ]; then
    "$INSTALL_BIN" install -config "$CONFIG_FILE"
else
    "$INSTALL_BIN" install
fi
"$INSTALL_BIN" start

echo "[+] PHP2Shell Sentinel is installed and running!"
echo "    Mode:          out-of-band (proxy disabled by default; web ports unchanged)"
echo "    Check status:  sentinel status"
echo "    Service logs:  sudo journalctl -u php2shell-sentinel -f"
echo "    Harden php.ini: sudo sentinel harden"
echo ""
echo "[*] Optional in-line HTTP WAF:"
echo "    Set \"proxy_enabled\": true, \"listen_addr\": \"127.0.0.1:8080\", and a real"
echo "    \"backend_url\" (for example http://127.0.0.1:8081) in ${CONFIG_FILE},"
echo "    then run: sudo systemctl restart php2shell-sentinel"
echo "    Route public traffic to listen_addr; do not expose the PHP backend."
