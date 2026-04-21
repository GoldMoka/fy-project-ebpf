#!/usr/bin/env bash
# =============================================================================
#  XDP Adaptive Firewall — One-shot installer + launcher
#  Tested: Ubuntu 22.04 / 24.04, kernel 5.15+
#  Needs: sudo / root
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLU}[*]${NC} $*"; }
ok()   { echo -e "${GRN}[+]${NC} $*"; }
warn() { echo -e "${YLW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── 0. Root check ─────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0 [options]"

# ── 1. Argument parsing ───────────────────────────────────────────────────────
TOPOLOGY="star"
IFACE=""
PORT=5000
PEER_PORT=5001
INSTALL_ONLY=false
SKIP_INSTALL=false
UNINSTALL=false

usage() {
cat <<EOF
Usage: sudo bash install_and_run.sh [OPTIONS]

Options:
  --topology   <star|mesh|ring|hierarchical>  Gossip topology (default: star)
  --iface      <eth0|enp3s0|...>              NIC to attach XDP (auto-detect if omitted)
  --port       <N>                            Local gossip UDP port (default: 5000)
  --peer-port  <N>                            Peer gossip UDP port (default: 5001)
  --install-only                              Install deps, don't start firewall
  --skip-install                              Skip apt/pip, just run
  --uninstall                                 Remove XDP hook and clean up
  -h, --help                                  Show this help

Examples:
  sudo bash install_and_run.sh --topology mesh --iface eth0
  sudo bash install_and_run.sh --topology star --iface lo   # loopback test
  sudo bash install_and_run.sh --uninstall
EOF
exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --topology)     TOPOLOGY="$2"; shift 2 ;;
        --iface)        IFACE="$2";    shift 2 ;;
        --port)         PORT="$2";     shift 2 ;;
        --peer-port)    PEER_PORT="$2";shift 2 ;;
        --install-only) INSTALL_ONLY=true; shift ;;
        --skip-install) SKIP_INSTALL=true; shift ;;
        --uninstall)    UNINSTALL=true; shift ;;
        -h|--help)      usage ;;
        *) die "Unknown option: $1  (run with --help)" ;;
    esac
done

# ── 2. Uninstall mode ─────────────────────────────────────────────────────────
if $UNINSTALL; then
    log "Removing XDP hooks from all interfaces..."
    for iface in $(ip link show | awk -F': ' '/^[0-9]+:/{print $2}' | tr -d '@.*'); do
        ip link set "$iface" xdp off 2>/dev/null && ok "Removed XDP from $iface" || true
    done
    # New veth topology (fw0/fw1/fw2/coord0/coord1 + xdp_attacker netns)
    # Also handles old single-pair name for backwards compat
    for veth_iface in veth_fw fw0 fw1 fw2 coord0; do
        ip link del "$veth_iface" 2>/dev/null && ok "Removed veth containing $veth_iface" || true
    done
    for ns in attacker xdp_attacker; do
        ip netns del "$ns" 2>/dev/null && ok "Removed netns $ns" || true
    done
    ok "Uninstall complete."
    ok "For a full veth topology teardown also run: sudo bash veth_setup.sh teardown"
    exit 0
fi

# ── 3. Kernel version check ───────────────────────────────────────────────────
KVER=$(uname -r | cut -d. -f1-2 | tr -d '.')
if [[ $KVER -lt 415 ]]; then
    warn "Kernel $(uname -r) detected. XDP requires 4.15+. Native mode needs 5.x+."
    warn "Continuing with generic/SKB mode fallback."
fi

# ── 4. Auto-detect interface ──────────────────────────────────────────────────
#
# Real-world interface naming is messy. We handle all of:
#   Predictable names : eno1, eno2, enp3s0, enp0s31f6   (onboard / PCI ethernet)
#                       wlp1s0, wlp2s0                   (PCI wifi)
#   Legacy names      : eth0, eth1, wlan0, wlan1         (old kernels / VMs)
#   Virtual           : veth*, tun*, tap*, docker*, br-* (containers — skip these)
#
# Priority order:
#   1. Whatever interface carries the default route  (most reliable)
#   2. First UP wired ethernet that isn't a bridge/veth/container interface
#   3. First UP wifi interface
#   4. Loopback (last resort, useful for dev/testing)
#
detect_iface() {
    # 1. Interface with default route — works for both eth and wifi
    local via_route
    via_route=$(ip route show default 2>/dev/null | awk '/^default/{print $5}' | head -1)
    if [[ -n "$via_route" ]] && ip link show "$via_route" &>/dev/null; then
        echo "$via_route"; return
    fi

    # 2. Any UP non-loopback interface — parse 'ip link show' directly.
    #    We strip the altname lines (they start with spaces) and the @ifname
    #    suffix that appears on veth pairs (e.g. "veth0@if5").
    #    Then we filter OUT virtual/container prefixes: lo, veth, docker, br-,
    #    virbr, tun, tap, bond, dummy, sit, vlan, macvlan.
    local wired wifi
    while IFS= read -r line; do
        # Only process index lines (start with a digit)
        [[ "$line" =~ ^[0-9]+:\ ([^:@]+) ]] || continue
        local name="${BASH_REMATCH[1]}"
        # Skip loopback and known-virtual prefixes
        [[ "$name" =~ ^(lo|veth|docker|br-|virbr|tun|tap|bond|dummy|sit|vlan|macvlan) ]] && continue
        # Must be UP
        ip link show "$name" 2>/dev/null | grep -q "state UP" || continue
        # Categorise: wired ethernet (en*, eth*) vs wifi (wl*, wlan*)
        if [[ "$name" =~ ^(en|eth) ]]; then
            [[ -z "$wired" ]] && wired="$name"
        elif [[ "$name" =~ ^(wl|wlan) ]]; then
            [[ -z "$wifi" ]] && wifi="$name"
        fi
    done < <(ip link show 2>/dev/null)

    if [[ -n "$wired" ]]; then echo "$wired"; return; fi
    if [[ -n "$wifi"  ]]; then echo "$wifi";  return; fi

    # 3. Absolute fallback: any UP non-lo interface, even if we don't know its type
    local any
    any=$(ip link show 2>/dev/null \
          | awk -F': ' '/^[0-9]+:/{gsub(/@.*/,"",$2); print $2}' \
          | grep -v '^lo$' \
          | while read -r n; do
              ip link show "$n" 2>/dev/null | grep -q "state UP" && echo "$n" && break
            done)
    if [[ -n "$any" ]]; then echo "$any"; return; fi

    echo "lo"
}

if [[ -z "$IFACE" ]]; then
    IFACE=$(detect_iface)
    warn "No --iface given. Auto-detected: $IFACE"
    warn "Override with: sudo bash $0 --iface <name>"
    warn "Available interfaces:"
    ip link show | awk -F': ' '/^[0-9]+:/{gsub(/@.*/,"",$2); printf "    %s\n",$2}' >&2
fi

# Final validation — give a useful error showing what IS available
if ! ip link show "$IFACE" &>/dev/null; then
    die "Interface '$IFACE' not found.\n\nAvailable interfaces:\n$(ip link show | awk -F': ' '/^[0-9]+:/{gsub(/@.*/,"",$2); print "  "$2}')\n\nRe-run with: sudo bash $0 --iface <name>"
fi
ok "Interface: $IFACE"

# ── 5. Detect OS / package manager ───────────────────────────────────────────
if ! $SKIP_INSTALL; then
    log "Detecting OS..."
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VER="${VERSION_ID:-0}"
    else
        OS_ID="unknown"
    fi
    log "OS: $OS_ID $OS_VER"

    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop|raspbian|kali)
            log "Installing dependencies via apt (OS: $OS_ID $OS_VER)..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq

            # Kernel headers: running kernel first, then generic fallback
            KHEADER="linux-headers-$(uname -r)"
            if ! apt-get install -y --no-install-recommends "$KHEADER" 2>/dev/null; then
                warn "Headers for $(uname -r) not found, trying linux-headers-generic..."
                apt-get install -y --no-install-recommends linux-headers-generic 2>/dev/null || true
            fi

            # Core build tools — same across all versions
            apt-get install -y --no-install-recommends \
                python3 python3-pip iproute2 ethtool \
                gcc make clang llvm libelf-dev zlib1g-dev \
                2>/dev/null || true

            # BCC package name changed across Ubuntu versions:
            #   Ubuntu 18.04        : python-bpfcc  (Python 2 era, also has python3-bpfcc)
            #   Ubuntu 20.04        : python3-bpfcc
            #   Ubuntu 22.04/24.04  : python3-bpfcc  (same)
            #   Debian 10/11/12     : python3-bpfcc
            # We try in order: most-specific first, then fall back.
            BCC_INSTALLED=false
            for pkg in python3-bpfcc bpfcc-tools libbpfcc-dev; do
                if apt-get install -y --no-install-recommends "$pkg" 2>/dev/null; then
                    BCC_INSTALLED=true
                    ok "Installed BCC via: $pkg"
                    break
                fi
            done

            # On older Ubuntu (18.04 / 20.04), bpfcc-tools installs the Python bindings
            # under /usr/lib/python3/dist-packages — check that path exists
            if ! python3 -c "from bcc import BPF" 2>/dev/null; then
                # Try adding the dist-packages path explicitly
                for pypath in /usr/lib/python3/dist-packages /usr/lib/python3.6/dist-packages \
                              /usr/lib/python3.8/dist-packages /usr/lib/python3.10/dist-packages; do
                    if [[ -f "$pypath/bcc/__init__.py" ]]; then
                        export PYTHONPATH="$pypath:${PYTHONPATH:-}"
                        ok "Found BCC at $pypath — adding to PYTHONPATH"
                        break
                    fi
                done
            fi
            ;;
        fedora|rhel|centos|rocky|alma)
            log "Installing dependencies via dnf..."
            dnf install -y \
                kernel-devel-$(uname -r) \
                bcc bcc-tools python3-bcc \
                iproute ethtool \
                clang llvm elfutils-libelf-devel || true
            ;;
        arch|manjaro)
            log "Installing dependencies via pacman..."
            pacman -Sy --noconfirm bcc python-bcc iproute2 ethtool clang llvm || true
            ;;
        *)
            warn "Unknown distro '$OS_ID'. Attempting apt-get as fallback..."
            apt-get update -qq && apt-get install -y bpfcc-tools python3-bpfcc iproute2 ethtool clang llvm 2>/dev/null || true
            ;;
    esac

    # Python BCC — try system package first, pip as fallback
    if ! python3 -c "from bcc import BPF" 2>/dev/null; then
        log "python3-bpfcc not found via apt, trying pip..."
        # bcc doesn't publish to PyPI — try the git wheel
        pip3 install pyroute2 --break-system-packages 2>/dev/null || pip3 install pyroute2 || true
        # Last resort: the BCC Python bindings need the native lib
        if ! python3 -c "from bcc import BPF" 2>/dev/null; then
            warn "BCC Python bindings not found via pip either."
            warn "On Ubuntu 22.04+: sudo apt install python3-bpfcc"
            warn "On Ubuntu 20.04:  sudo apt install bpfcc-tools python3-bpfcc"
            die "Cannot import BCC. Install manually and re-run with --skip-install."
        fi
    fi
    ok "All dependencies installed."
fi

# ── 6. Verify BCC import ──────────────────────────────────────────────────────
python3 -c "from bcc import BPF; print('BCC OK')" 2>/dev/null || \
    die "BCC import failed. Check install. Try: python3 -c 'from bcc import BPF'"

# ── 7. Write peers.json based on topology ─────────────────────────────────────
PEERS_FILE="$SCRIPT_DIR/peers.json"

case "$TOPOLOGY" in
    star)
        warn "Star topology: this node acts as COORDINATOR by default."
        warn "Edit $PEERS_FILE to set role=leaf and coordinator=<IP> on non-coordinator nodes."
        cat > "$PEERS_FILE" <<EOF
{
  "topology": "star",
  "role": "coordinator",
  "peers": ["127.0.0.1"],
  "coordinator": "127.0.0.1"
}
EOF
        ;;
    mesh)
        warn "Mesh topology: edit $PEERS_FILE and add all peer IPs to 'peers' array."
        cat > "$PEERS_FILE" <<EOF
{
  "topology": "mesh",
  "role": "node",
  "peers": ["127.0.0.1"]
}
EOF
        ;;
    ring)
        warn "Ring topology: edit $PEERS_FILE and set 'next' to your successor node IP."
        cat > "$PEERS_FILE" <<EOF
{
  "topology": "ring",
  "role": "node",
  "next": "127.0.0.1",
  "ring_size": 4
}
EOF
        ;;
    hierarchical)
        warn "Hierarchical: edit $PEERS_FILE, set rack_coordinator and optionally global_root."
        cat > "$PEERS_FILE" <<EOF
{
  "topology": "hierarchical",
  "role": "leaf",
  "rack_coordinator": "127.0.0.1",
  "global_root": ""
}
EOF
        ;;
    *)
        die "Unknown topology '$TOPOLOGY'. Use: star | mesh | ring | hierarchical"
        ;;
esac
ok "Topology: $TOPOLOGY — peers config written to $PEERS_FILE"

$INSTALL_ONLY && { ok "Install-only mode complete. Run again without --install-only to start."; exit 0; }

# ── 8. NIC capability probe ───────────────────────────────────────────────────
log "Probing XDP mode support for $IFACE..."
DRIVER=$(ethtool -i "$IFACE" 2>/dev/null | awk '/^driver:/{print $2}')
log "Driver: ${DRIVER:-unknown}"

# Drivers with confirmed native XDP support.
# Note: e1000e (Intel onboard NICs — eno1 on most desktops/laptops) does NOT
# support native XDP; it needs generic/SKB mode. We default to generic and
# only upgrade to native for drivers that are explicitly known-good.
NATIVE_DRIVERS="i40e ice mlx4_en mlx5_core bnxt_en nfp virtio_net tun veth \
                dpaa2 thunderx2 netsec ixgbe igb"
XDP_FLAGS="generic"
for d in $NATIVE_DRIVERS; do
    [[ "$DRIVER" == "$d" ]] && XDP_FLAGS="native" && break
done

# Special case: loopback always needs generic
[[ "$IFACE" == "lo" ]] && XDP_FLAGS="generic"

ok "XDP mode: $XDP_FLAGS (driver: ${DRIVER:-unknown})"
[[ "$XDP_FLAGS" == "generic" ]] && \
    warn "Generic XDP mode: works on all NICs, slightly higher CPU overhead than native."

# ── 9. Launch firewall ────────────────────────────────────────────────────────
log "Launching XDP firewall..."
log "  Interface : $IFACE"
log "  Topology  : $TOPOLOGY"
log "  Gossip port (local): $PORT"
log "  Gossip port (peer) : $PEER_PORT"
log "  XDP mode  : $XDP_FLAGS"
echo ""

# Export PYTHONPATH so older Ubuntu distros (18.04/20.04) find BCC bindings
# that live in dist-packages rather than site-packages
export PYTHONPATH="${PYTHONPATH:-}"

exec python3 "$SCRIPT_DIR/main.py" \
    --iface      "$IFACE" \
    --port       "$PORT" \
    --peer-port  "$PEER_PORT" \
    --topology   "$TOPOLOGY" \
    --peers-file "$PEERS_FILE" \
    --xdp-mode   "$XDP_FLAGS"
