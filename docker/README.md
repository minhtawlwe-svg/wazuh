# 🐳 Docker Auto Installer (Production)

Production-ready Docker installer script for Ubuntu/Debian systems.

This script automatically installs:

- Docker Engine
- Docker CLI
- Docker Compose Plugin
- Docker Buildx
- Containerd

It also:

- Removes old Docker packages
- Configures official Docker repository
- Adds Docker GPG key securely
- Enables Docker service automatically
- Adds your user to the `docker` group
- Verifies installation
- Runs a Docker test

---

# ⚙️ Supported OS

Tested on:

- Ubuntu 22.04+
- Ubuntu 24.04
- Debian-based systems

---

# 🚀 One-Line Install (Recommended)

Run this command:

```bash
curl -fsSL https://raw.githubusercontent.com/yekyawhan/wazuh/7ec439638595a7d4f26ce232dd142c36c7239348/docker/install-docker.sh | sudo bash
```
```bash
wget https://raw.githubusercontent.com/yekyawhan/wazuh/7ec439638595a7d4f26ce232dd142c36c7239348/docker/install-docker.sh
chmod +x install-docker.sh
sudo ./install-docker.sh
```
