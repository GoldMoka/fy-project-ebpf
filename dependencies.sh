#!/bin/bash

set -e

echo "=============================================="
echo "  fy-project-ebpf Dependency Installation"
echo "=============================================="
echo

cd ~/fy-project-ebpf

echo "[1/4] Updating package lists..."
sudo apt update

echo
echo "[2/4] Installing project dependencies..."
sudo bash install_and_run.sh --install-only

echo
echo "[3/4] Installing benchmark dependencies..."
sudo apt install -y bc gcc arping hping3 tmux
sudo apt install -y linux-tools-$(uname -r)

echo
echo "[4/4] Verifying dependencies..."
echo

echo -n "bpftool: "
bpftool version
echo -n "hping3:  "
which hping3
echo -n "arping:  "
which arping
echo -n "tmux:    "
which tmux
echo -n "bc:      "
which bc

echo
echo "=============================================="
echo "  All dependencies are installed and ready."
echo "=============================================="