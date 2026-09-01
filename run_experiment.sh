#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# run_experiment.sh
#
# Usage:
#   sudo ./run_experiment.sh <topology> <defense>
#
# Example:
#   sudo ./run_experiment.sh mesh-6 xdp
# ============================================================

TOPOLOGY="${1:-}"
DEFENSE="${2:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VETH_SETUP="${SCRIPT_DIR}/veth_setup_r8.sh"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RESULT_DIR="${SCRIPT_DIR}/results/${TOPOLOGY}/${DEFENSE}/${TIMESTAMP}"

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

log() {
    echo
    echo "============================================================"
    echo "$1"
    echo "============================================================"
}

die() {
    echo "[ERROR] $1" >&2
    exit 1
}

# ------------------------------------------------------------
# Argument validation
# ------------------------------------------------------------

[[ $EUID -eq 0 ]] || die "Run with sudo."

[[ -n "$TOPOLOGY" ]] || die "Missing topology."
[[ -n "$DEFENSE" ]] || die "Missing defense."

case "$TOPOLOGY" in
    mesh-6)
        ;;
    *)
        die "Currently only mesh-6 is supported."
        ;;
esac

case "$DEFENSE" in
    xdp)
        ;;
    *)
        die "Currently only xdp is supported."
        ;;
esac

mkdir -p "$RESULT_DIR"

echo "Experiment:"
echo "  Topology : $TOPOLOGY"
echo "  Defense  : $DEFENSE"
echo "  Results  : $RESULT_DIR"

# ------------------------------------------------------------
# 1. Teardown previous topology
# ------------------------------------------------------------

log "[1/7] Tearing down previous ${TOPOLOGY}"

bash "$VETH_SETUP" teardown "$TOPOLOGY" || true

# ------------------------------------------------------------
# 2. Setup topology
# ------------------------------------------------------------

log "[2/7] Setting up ${TOPOLOGY}"

bash "$VETH_SETUP" setup "$TOPOLOGY"

# ------------------------------------------------------------
# 3. Configure defense
# ------------------------------------------------------------

log "[3/7] Configuring defense: ${DEFENSE}"

case "$DEFENSE" in
    xdp)
        echo "XDP configuration is performed by main.py."
        ;;
esac

# ------------------------------------------------------------
# 4. Start defense
# ------------------------------------------------------------

log "[4/7] Starting ${DEFENSE}"

bash "$VETH_SETUP" start "$TOPOLOGY" --non-interactive

# ------------------------------------------------------------
# 5. Verify firewall processes
# ------------------------------------------------------------

log "[5/7] Verifying firewall startup"

sleep 3

echo "Running main.py processes:"
pgrep -af "main.py.*fw-mesh" || {
    echo "[ERROR] No mesh-6 firewall processes found."
    bash "$VETH_SETUP" stop "$TOPOLOGY" || true
    bash "$VETH_SETUP" teardown "$TOPOLOGY" || true
    exit 1
}

# ------------------------------------------------------------
# 6. Run throughput measurement
# ------------------------------------------------------------

log "[6/7] Running throughput benchmark"

mkdir -p "$RESULT_DIR/throughput"

IFACE="fw-mesh-0"
TARGET="10.40.0.1"

KEY_FILE="${SCRIPT_DIR}/logs/mesh-6.key"

if [[ ! -f "$KEY_FILE" ]]; then
    die "HMAC key file not found: $KEY_FILE"
fi

KEY="$(cat "$KEY_FILE")"

echo "Interface : $IFACE"
echo "Target    : $TARGET"
echo "Runs      : 3"

sudo ip netns exec fw-mesh-0_ns bash "${SCRIPT_DIR}/benchmark.sh" \
    --iface "$IFACE" \
    --target "$TARGET" \
    --runs 3 \
    --veth \
    --hmac-key "$KEY" \
    --outdir "$RESULT_DIR/throughput"
# ------------------------------------------------------------
# 7. Save metadata and teardown
# ------------------------------------------------------------

log "[7/7] Saving experiment metadata"

cat > "$RESULT_DIR/metadata.txt" <<EOF
Experiment timestamp: $(date)
Topology: $TOPOLOGY
Defense: $DEFENSE
Host: $(hostname)
Kernel: $(uname -r)
EOF

echo "Results directory:"
echo "  $RESULT_DIR"

log "Experiment preparation complete"

echo
echo "Stopping firewall..."
bash "$VETH_SETUP" stop "$TOPOLOGY" || true

echo "Tearing down topology..."
bash "$VETH_SETUP" teardown "$TOPOLOGY" || true

echo
echo "[✓] Experiment completed."