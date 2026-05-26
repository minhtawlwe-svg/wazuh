#!/bin/bash

set -euo pipefail

clear

echo "=========================================="
echo "      DOCKER INSTALLER (PRODUCTION)"
echo "=========================================="
echo ""

# -----------------------------------
# Require root
# -----------------------------------
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run as root or sudo"
    exit 1
fi

# -----------------------------------
# Detect OS
# -----------------------------------
if [ ! -f /etc/os-release ]; then
    echo "[ERROR] Unsupported Linux distribution"
    exit 1
fi

source /etc/os-release

echo "[INFO] OS: $PRETTY_NAME"
echo ""

# -----------------------------------
# Remove old Docker packages
# -----------------------------------
echo "[+] Removing old Docker packages..."

for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
    apt-get remove -y "$pkg" >/dev/null 2>&1 || true
done

# -----------------------------------
# Install dependencies
# -----------------------------------
echo "[+] Installing dependencies..."

apt-get update -y

apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# -----------------------------------
# Setup Docker GPG
# -----------------------------------
echo "[+] Setting up Docker GPG key..."

install -m 0755 -d /etc/apt/keyrings

if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
else
    echo "[INFO] Docker GPG already exists, skipping..."
fi

chmod a+r /etc/apt/keyrings/docker.gpg

# -----------------------------------
# Add Docker repository
# -----------------------------------
echo "[+] Adding Docker repository..."

ARCH=$(dpkg --print-architecture)

echo \
"deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
> /etc/apt/sources.list.d/docker.list

# -----------------------------------
# Install Docker
# -----------------------------------
echo "[+] Installing Docker Engine..."

apt-get update -y

apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin
# -----------------------------------
# Add user to docker group
# -----------------------------------
echo ""
echo "[+] Configuring Docker permissions..."

REAL_USER="${SUDO_USER:-$USER}"

if id "$REAL_USER" &>/dev/null; then
    usermod -aG docker "$REAL_USER"

    echo "[SUCCESS] User added to docker group: $REAL_USER"
    echo ""
    echo "[IMPORTANT] Logout/login OR run:"
    echo "newgrp docker"
else
    echo "[WARNING] Could not determine real user"
fi
# -----------------------------------
# Enable/start service
# -----------------------------------
echo "[+] Starting Docker..."

systemctl daemon-reload
systemctl enable docker --now
systemctl restart docker

sleep 3

# -----------------------------------
# Verify service
# -----------------------------------
echo ""
echo "[+] Checking Docker service..."

if systemctl is-active --quiet docker; then
    echo "[SUCCESS] Docker service is running"
else
    echo "[ERROR] Docker service failed"
    exit 1
fi

# -----------------------------------
# Verify install
# -----------------------------------
echo ""
echo "[+] Checking Docker version..."

docker --version
docker compose version

echo ""
echo "[+] Running hello-world test..."

docker run --rm hello-world >/dev/null 2>&1 || true

# -----------------------------------
# Final output
# -----------------------------------
echo ""
echo "=========================================="
echo "[DONE] Docker installed successfully"
echo "=========================================="

echo "Docker Version:"
docker --version

echo ""
echo "Docker Compose:"
docker compose version

echo ""
echo "Useful commands:"
echo "  docker ps"
echo "  docker images"
echo "  docker compose up -d"
echo "=========================================="
