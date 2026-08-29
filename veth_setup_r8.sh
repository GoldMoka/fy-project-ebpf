#!/usr/bin/env bash
# =============================================================================
#  veth_setup.sh — XDP Adaptive Firewall — Multi-Topology Veth Grid
#
#  Creates isolated virtual network topologies for testing all gossip modes.
#  Every firewall interface (fw*) lives in its own firewall netns where
#  main.py and XDP run. Every attacker interface (atk*) lives in the shared
#  attacker_ns. Coordinator/ring backbone links are namespace-to-namespace.
#
#  Available topologies
#  ─────────────────────
#   simple        3 firewalls, 2 coordinators  (original quickstart)
#
#   star-large    1 central coordinator + 8 leaf firewalls (10.10.x.x)
#                 Tests coordinator fan-out at scale.
#
#   ring-8        8 firewall nodes in a ring: 0→1→2→…→7→0  (10.20.x.x)
#                 Tests ring gossip propagation latency across N hops.
#
#   hierarchical  3-tier: 1 global + 3 rack coords + 9 leaves = 13 nodes
#                 Mirrors real data-centre hierarchy.  (10.30.x.x)
#
#   mesh-6        6 nodes, every node peers with all others (10.40.x.x)
#                 Tests fan-out redundancy and de-dup under flood.
#
#   multi-ring    1 relay + two 4-node rings = 9 nodes  (10.50.x.x)
#                 Two network segments sharing a border firewall.
#
#   all           Create ALL topologies above simultaneously
#
#  Usage:
#    sudo bash veth_setup.sh setup   [topology]    # default: simple
#    sudo bash veth_setup.sh teardown [topology]   # default: all
#    sudo bash veth_setup.sh status                # show all interfaces
#    sudo bash veth_setup.sh launch   [topology]   # print start commands
#    sudo bash veth_setup.sh benchmark [topology]  # print benchmark commands
#
#  Examples:
#    sudo bash veth_setup.sh setup ring-8
#    sudo bash veth_setup.sh setup all
#    sudo bash veth_setup.sh launch hierarchical
#    sudo bash veth_setup.sh teardown all
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${BLU}[*]${NC} $*"; }
ok()   { echo -e "${GRN}[+]${NC} $*"; }
warn() { echo -e "${YLW}[!]${NC} $*"; }
hdr()  { echo -e "\n${CYN}━━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
die()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0 [setup|teardown|status|launch|benchmark] [topology]"

CMD="${1:-setup}"
TOPO="${2:-simple}"
# NETNS="xdp_attacker"
FIREWALL_NAMESPACES=(
    "fw0_ns"
    "fw1_ns"
    "fw2_ns"
)

ATTACKER_NAMESPACE="attacker_ns"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
#  Low-level helpers
# =============================================================================

ensure_namespace() {
    local ns="$1"
    if ! ip netns list | grep -q "^${ns}$"; then
        ip netns add "$ns"
        ip netns exec "$ns" ip link set lo up
        ok "Created namespace: $ns"
    else
        ip netns exec "$ns" ip link set lo up 2>/dev/null || true
    fi
}

ensure_namespaces() {
    for ns in "${FIREWALL_NAMESPACES[@]}"; do
        ensure_namespace "$ns"
    done
    ensure_namespace "$ATTACKER_NAMESPACE"
}


# make_veth <fw_ns> <fw_iface> <fw_cidr> <atk_iface> <atk_cidr>
# Firewall endpoint goes into fw_ns; attacker endpoint goes into attacker_ns.
make_veth() {
    # local fw="$1" fw_cidr="$2" atk="$3" atk_cidr="$4"
    local fw_ns="$1"
    local fw="$2"
    local fw_cidr="$3"
    local atk="$4"
    local atk_cidr="$5"
    if ip netns exec "$fw_ns" ip link show "$fw" &>/dev/null; then
        warn "  $fw@$fw_ns already exists — skipping"
        return
    fi
    ip link add "$fw" type veth peer name "$atk"
    ip link set "$fw" netns "$fw_ns"
    ip link set "$atk" netns "$ATTACKER_NAMESPACE"
    # ip addr add "$fw_cidr"  dev "$fw"
    # ip link set "$fw" up
    ip netns exec "$fw_ns" ip link set lo up
    ip netns exec "$fw_ns" ip addr add "$fw_cidr" dev "$fw"
    ip netns exec "$fw_ns" ip link set "$fw" up
    ip netns exec "$ATTACKER_NAMESPACE" ip addr add "$atk_cidr" dev "$atk"
    ip netns exec "$ATTACKER_NAMESPACE" ip link set "$atk" up
    local base
    base=$(python3 -c "import ipaddress; print(str(ipaddress.ip_network('$fw_cidr',strict=False)))" 2>/dev/null \
          || echo "${fw_cidr%.*}.0/24")
    ip netns exec "$ATTACKER_NAMESPACE" ip route add "$base" dev "$atk" 2>/dev/null || true
    # ethtool -K "$fw" rx-checksumming off tx-checksumming off gso off gro off 2>/dev/null || true
    ip netns exec "$fw_ns" \
    ethtool -K "$fw" \
    rx-checksumming off \
    tx-checksumming off \
    gso off \
    gro off \
    2>/dev/null || true
    # ok "  $fw ($fw_cidr) <--veth--> $atk@$ATTACKER_NAMESPACE ($atk_cidr)"
    ok "  $fw@$fw_ns ($fw_cidr) <--veth--> $atk@$ATTACKER_NAMESPACE ($atk_cidr)"
}

# make_backbone <iface_a> <cidr_a> <iface_b> <cidr_b>
# Both ends in root ns — for inter-node gossip backbone links
# make_backbone() {
#     local a="$1" a_cidr="$2" b="$3" b_cidr="$4"
#     if ip link show "$a" &>/dev/null; then
#         warn "  backbone $a already exists — skipping"; return
#     fi
#     ip link add "$a" type veth peer name "$b"
#     ip addr add "$a_cidr" dev "$a"
#     ip addr add "$b_cidr" dev "$b"
#     ip link set "$a" up
#     ip link set "$b" up
#     ethtool -K "$a" rx-checksumming off tx-checksumming off gso off gro off 2>/dev/null || true
#     ok "  backbone $a ($a_cidr) <---> $b ($b_cidr)"
# }

make_backbone() {
    local ns_a="$1"
    local a="$2"
    local a_cidr="$3"

    local ns_b="$4"
    local b="$5"
    local b_cidr="$6"

    # Check inside the source namespace, since the interface may
    # already have been moved out of the root namespace.
    if ip netns exec "$ns_a" ip link show "$a" &>/dev/null; then
        warn "  backbone $a@$ns_a already exists — skipping"
        return
    fi

    # Create the veth pair in the root namespace first.
    ip link add "$a" type veth peer name "$b"

    # Move each end into its respective namespace.
    ip link set "$a" netns "$ns_a"
    ip link set "$b" netns "$ns_b"

    # Configure addresses.
    ip netns exec "$ns_a" ip addr add "$a_cidr" dev "$a"
    ip netns exec "$ns_b" ip addr add "$b_cidr" dev "$b"

    # Bring interfaces up.
    ip netns exec "$ns_a" ip link set "$a" up
    ip netns exec "$ns_b" ip link set "$b" up

    # Disable offloading for predictable packet/XDP behaviour.
    ip netns exec "$ns_a" ethtool -K "$a" \
        rx-checksumming off \
        tx-checksumming off \
        gso off \
        gro off \
        2>/dev/null || true

    ip netns exec "$ns_b" ethtool -K "$b" \
        rx-checksumming off \
        tx-checksumming off \
        gso off \
        gro off \
        2>/dev/null || true

    ok "  backbone $a@$ns_a ($a_cidr) <---> $b@$ns_b ($b_cidr)"
}


del_if() { ip link del "$1" 2>/dev/null && ok "  Removed $1" || true; }

write_peers() {
    local path="$1" json="$2"
    echo "$json" > "$path"
    ok "  $(basename $path)"
}

sysctl_net() {
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
}

# =============================================================================
#  TOPOLOGY: simple
#  fw0 (coord) + fw1 (coord) + fw2 (leaf) + coord0/coord1 backbone
# =============================================================================
# =============================================================================
setup_simple() {
    hdr "simple — fw0+fw1 coordinators, fw2 leaf"
    ensure_namespaces

    # Firewall ↔ attacker links
    make_veth fw0_ns fw0 10.0.0.1/24 atk0 10.0.0.99/24
    make_veth fw1_ns fw1 10.0.1.1/24 atk1 10.0.1.99/24
    make_veth fw2_ns fw2 10.0.2.1/24 atk2 10.0.2.99/24

    # fw0 ↔ fw1 coordinator backbone
    make_backbone \
        fw0_ns coord0 10.99.0.1/30 \
        fw1_ns coord1 10.99.0.2/30

    # fw0 ↔ fw2 coordinator/leaf backbone
    make_backbone \
        fw0_ns coord2 10.99.1.1/30 \
        fw2_ns coord3 10.99.1.2/30

    # -------------------------------------------------------------------------
    # Routing between the two backbone networks
    #
    # fw1 reaches fw2 through fw0:
    #   fw1 (10.99.0.2)
    #       ↓
    #   fw0 (10.99.0.1)
    #       ↓
    #   fw2 (10.99.1.2)
    #
    # fw2 reaches fw1 through fw0:
    #   fw2 (10.99.1.2)
    #       ↓
    #   fw0 (10.99.1.1)
    #       ↓
    #   fw1 (10.99.0.2)
    # -------------------------------------------------------------------------

    ip netns exec fw1_ns ip route replace \
        10.99.1.0/30 via 10.99.0.1 dev coord1

    ip netns exec fw2_ns ip route replace \
        10.99.0.0/30 via 10.99.1.1 dev coord3

    sysctl_net

    # -------------------------------------------------------------------------
    # Gossip peer configuration
    #
    # Gossip uses the 10.99.x.x backbone addresses, not the 10.0.x.x
    # attacker/firewall addresses.
    # -------------------------------------------------------------------------

    write_peers "$SCRIPT_DIR/peers_coord0.json" \
        '{"role":"coordinator","coordinator_peers":["10.99.0.2"],"peers":["10.99.0.2","10.99.1.2"]}'

    write_peers "$SCRIPT_DIR/peers_coord1.json" \
        '{"role":"coordinator","coordinator_peers":["10.99.0.1"],"peers":["10.99.0.1","10.99.1.2"]}'

    write_peers "$SCRIPT_DIR/peers_fw2.json" \
        '{"role":"leaf","coordinators":["10.99.1.1"],"coordinator":"10.99.1.1"}'

    ok "simple ready — benchmark target: fw0 / 10.0.0.1"
}

teardown_simple() {
    # Remove veth interfaces
    for i in fw0 fw1 fw2 coord0 coord1 coord2 coord3; do
        del_if "$i"
    done

    # Delete network namespaces
    for ns in fw0_ns fw1_ns fw2_ns attacker_ns; do
        if ip netns list | grep -qw "$ns"; then
            # Kill any remaining processes in the namespace
            ip netns pids "$ns" | xargs -r kill -9

            # Delete the namespace
            ip netns del "$ns"
        fi
    done
}

# =============================================================================
#  TOPOLOGY: star-large
#  1 coordinator (fw-star-coord, dummy iface) + 8 leaf firewalls
#  Coordinator is a lightweight gossip relay — no XDP traffic on it.
#  Benchmark any leaf for XDP numbers.
#
#         fw-star-coord (10.10.0.1)
#        /  |  |  |  |  |  |  \
#  leaf0 leaf1 ... leaf6 leaf7
#  10.10.1.1 ... 10.10.8.1
# =============================================================================
setup_star_large() {
    hdr "star-large — 1 coordinator + 8 leaves"
    ensure_namespaces
    # Coordinator: dummy interface in root ns, no attacker side needed
    if ! ip link show fw-star-coord &>/dev/null; then
        ip link add fw-star-coord type dummy 2>/dev/null || true
        ip addr add 10.10.0.1/16 dev fw-star-coord 2>/dev/null || true
        ip link set fw-star-coord up 2>/dev/null || true
        ok "  fw-star-coord (10.10.0.1) coordinator"
    fi
    for i in $(seq 0 7); do
        local oct=$((i+1))
        make_veth "fw-star-${i}" "10.10.${oct}.1/24" "atk-star-${i}" "10.10.${oct}.99/24"
    done
    sysctl_net
    # coordinator: fans out to all 8 leaves
    local lplist; lplist=$(python3 -c "
import json; leaves=['10.10.%d.1'%(i+1) for i in range(8)]
print(json.dumps({'role':'coordinator','coordinator_peers':[],'peers':leaves}))")
    write_peers "$SCRIPT_DIR/peers_star_coord.json" "$lplist"
    for i in $(seq 0 7); do
        write_peers "$SCRIPT_DIR/peers_star_leaf${i}.json" \
            '{"role":"leaf","coordinators":["10.10.0.1"],"coordinator":"10.10.0.1"}'
    done
    ok "star-large ready — benchmark any leaf, e.g. fw-star-0 / 10.10.1.1"
}
teardown_star_large() {
    ip link del fw-star-coord 2>/dev/null || true
    for i in $(seq 0 7); do del_if "fw-star-${i}"; done
}

# =============================================================================
#  TOPOLOGY: ring-8
#  8 firewall nodes in a ring: fw-ring-0 → fw-ring-1 → … → fw-ring-7 → fw-ring-0
#  Each node knows only its successor (ring gossip mode).
#  A block on node-0 traverses all 8 hops before returning.
#
#  fw-ring-0 -> fw-ring-1 -> fw-ring-2 -> fw-ring-3
#       ^                                       |
#  fw-ring-7 <- fw-ring-6 <- fw-ring-5 <- fw-ring-4
# =============================================================================
setup_ring_8() {
    hdr "ring-8 — 8-node gossip ring"
    ensure_namespaces

    # Each firewall gets its own namespace, like the working simple topology.
    # The attacker-facing interface is also the XDP interface used by main.py.
    for i in $(seq 0 7); do
        ensure_namespace "fw-ring-${i}_ns"
        make_veth "fw-ring-${i}_ns" \
            "fw-ring-${i}" "10.20.${i}.1/24" \
            "atk-ring-${i}" "10.20.${i}.99/24"
    done

    # The old ring setup only created attacker-facing veths. There was no
    # network path between firewall namespaces. Create one /30 backbone
    # link from every node to its successor:
    #
    #   fw0 -> fw1 -> fw2 -> ... -> fw7 -> fw0
    #
    # Link i: node i = 10.29.i.1, successor = 10.29.i.2.
    local next_ips=()
    for i in $(seq 0 7); do
        local nxt=$(( (i+1) % 8 ))
        make_backbone \
            "fw-ring-${i}_ns" "ring${i}_out" "10.29.${i}.1/30" \
            "fw-ring-${nxt}_ns" "ring${nxt}_in" "10.29.${i}.2/30"
        next_ips+=("10.29.${i}.2")
    done

    sysctl_net

    # Each node knows only its successor, so gossip moves one hop at a time.
    for i in $(seq 0 7); do
        write_peers "$SCRIPT_DIR/peers_ring${i}.json" \
            "{\"role\":\"leaf\",\"topology_hint\":\"ring\",\"next\":\"${next_ips[$i]}\",\"ring_size\":8}"
    done

    ok "ring-8 ready — 8 firewall namespaces + 8 attacker links + 8 gossip backbone links"
}
teardown_ring_8() {
    # Interfaces live inside the firewall namespaces. Deleting the namespaces
    # removes the attacker and backbone interfaces automatically.
    for i in $(seq 0 7); do
        local ns="fw-ring-${i}_ns"
        if ip netns list | grep -q "^${ns}$"; then
            ip netns pids "$ns" | xargs -r kill -9 2>/dev/null || true
            ip netns del "$ns" 2>/dev/null || true
            ok "  Removed $ns"
        fi
    done
}

# =============================================================================
#  TOPOLOGY: hierarchical
#  3-tier data-centre hierarchy:
#    Tier-0 global coordinator: fw-h-global     10.30.0.1  (1 node)
#    Tier-1 rack coordinators:  fw-h-rack{0,1,2}  10.30.{1,2,3}.1  (3 nodes)
#    Tier-2 leaf firewalls:     fw-h-r{0,1,2}-l{0,1,2}  (9 nodes)
#                               rack0 leaves: 10.30.10.{1,2,3}
#                               rack1 leaves: 10.30.20.{1,2,3}
#                               rack2 leaves: 10.30.30.{1,2,3}
#
#  Block path: leaf → rack-coord → global → other racks → their leaves
#
#                fw-h-global (10.30.0.1)
#              /           |           \
#         rack0         rack1         rack2
#        10.30.1.1     10.30.2.1     10.30.3.1
#       / | \           / | \          / | \
#    l0 l1 l2        l0 l1 l2       l0 l1 l2
#  .10.1-.10.3      .20.1-.20.3   .30.1-.30.3
# =============================================================================
LEAF_BASES=(10 20 30)
setup_hierarchical() {
    hdr "hierarchical — global + 3 racks + 9 leaves = 13 nodes"
    ensure_namespaces
    # Tier-0: global coordinator (dummy iface — pure relay)
    if ! ip link show fw-h-global &>/dev/null; then
        ip link add fw-h-global type dummy 2>/dev/null || true
        ip addr add 10.30.0.1/16 dev fw-h-global 2>/dev/null || true
        ip link set fw-h-global up 2>/dev/null || true
        ok "  fw-h-global (10.30.0.1) global coordinator"
    fi
    # Tier-1: rack coordinators
    for r in 0 1 2; do
        make_veth "fw-h-rack${r}" "10.30.$((r+1)).1/24" "atk-h-rack${r}" "10.30.$((r+1)).99/24"
    done
    # Tier-2: leaves
    for r in 0 1 2; do
        local base="${LEAF_BASES[$r]}"
        for l in 0 1 2; do
            local h=$((l+1))
            make_veth "fw-h-r${r}-l${l}" "10.30.${base}.${h}/24" \
                      "atk-h-r${r}-l${l}" "10.30.${base}.$((h+10))/24"
        done
    done
    sysctl_net
    # peers files
    # Global coordinator: role=rack_coordinator but no upstream (it IS the top).
    # "rack_coordinator" key is intentionally absent — the banner detects this
    # and prints "(global coordinator — no upstream)" instead of "coordinators=['?']".
    write_peers "$SCRIPT_DIR/peers_h_global.json" \
        '{"role":"rack_coordinator","leaves":["10.30.1.1","10.30.2.1","10.30.3.1"]}' 
    for r in 0 1 2; do
        local base="${LEAF_BASES[$r]}"
        write_peers "$SCRIPT_DIR/peers_h_rack${r}.json" \
            "{\"role\":\"rack_coordinator\",\"rack_coordinator\":\"10.30.0.1\",
              \"leaves\":[\"10.30.${base}.1\",\"10.30.${base}.2\",\"10.30.${base}.3\"]}"
        for l in 0 1 2; do
            write_peers "$SCRIPT_DIR/peers_h_r${r}_l${l}.json" \
                "{\"role\":\"leaf\",\"rack_coordinator\":\"10.30.$((r+1)).1\"}"
        done
    done
    ok "hierarchical ready — global 10.30.0.1 | racks 10.30.{1,2,3}.1 | leaves 10.30.{10,20,30}.{1,2,3}"
}
teardown_hierarchical() {
    ip link del fw-h-global 2>/dev/null || true
    for r in 0 1 2; do
        del_if "fw-h-rack${r}"
        for l in 0 1 2; do del_if "fw-h-r${r}-l${l}"; done
    done
}

# =============================================================================
#  TOPOLOGY: mesh-6
#  6 nodes, full mesh: each node peers with all 5 others simultaneously.
#  Tests: redundant gossip fan-out, de-duplication, simultaneous flood.
#
#       fw-mesh-0 --- fw-mesh-1
#      /    \   X   /    \
#  fw-mesh-5  X X  fw-mesh-2
#      \    /   X   \    /
#       fw-mesh-4 --- fw-mesh-3
# =============================================================================
setup_mesh_6() {
    hdr "mesh-6 — 6-node full mesh"
    ensure_namespaces
    local ips=()
    for i in $(seq 0 5); do
        make_veth "fw-mesh-${i}" "10.40.${i}.1/24" "atk-mesh-${i}" "10.40.${i}.99/24"
        ips+=("10.40.${i}.1")
    done
    sysctl_net
    for i in $(seq 0 5); do
        local plist=""
        for j in $(seq 0 5); do
            [[ $i -eq $j ]] && continue
            plist="${plist:+$plist,}\"${ips[$j]}\""
        done
        write_peers "$SCRIPT_DIR/peers_mesh${i}.json" \
            "{\"role\":\"leaf\",\"topology_hint\":\"mesh\",\"peers\":[${plist}]}"
    done
    ok "mesh-6 ready — fw-mesh-{0..5} / 10.40.{0..5}.1"
}
teardown_mesh_6() {
    for i in $(seq 0 5); do del_if "fw-mesh-${i}"; done
}

# =============================================================================
#  TOPOLOGY: multi-ring
#  1 relay node bridging two independent 4-node rings (9 nodes total).
#  Models two network segments sharing a border firewall.
#  Block flow: Ring-A → relay → Ring-B (cross-segment propagation).
#
#  Ring-A: fw-mr-a0 → fw-mr-a1 → fw-mr-a2 → fw-mr-a3 --.
#               ^                                         |
#          fw-mr-relay (10.50.0.1)  <--------------------'
#               |
#  Ring-B: fw-mr-b0 → fw-mr-b1 → fw-mr-b2 → fw-mr-b3 --.
#               ^                                         |
#               '------(relay also inserts into B ring)---'
# =============================================================================
setup_multi_ring() {
    hdr "multi-ring — relay + ring-A(4) + ring-B(4) = 9 nodes"
    ensure_namespaces
    make_veth fw-mr-relay 10.50.0.1/24  atk-mr-relay 10.50.0.99/24
    local a_ips=() b_ips=()
    for i in 0 1 2 3; do
        local h=$((i+1))
        make_veth "fw-mr-a${i}" "10.50.1.${h}/24" "atk-mr-a${i}" "10.50.1.$((h+10))/24"
        make_veth "fw-mr-b${i}" "10.50.2.${h}/24" "atk-mr-b${i}" "10.50.2.$((h+10))/24"
        a_ips+=("10.50.1.${h}")
        b_ips+=("10.50.2.${h}")
    done
    sysctl_net
    # Relay: enters both rings
    write_peers "$SCRIPT_DIR/peers_mr_relay.json" \
        "{\"role\":\"leaf\",\"topology_hint\":\"ring\",\"next\":\"${a_ips[0]}\",\"ring_size\":9}"
    # Ring-A: a3 loops back to relay
    for i in 0 1 2 3; do
        local nxt
        if [[ $i -eq 3 ]]; then nxt="10.50.0.1"; else nxt="${a_ips[$((i+1))]}"; fi
        write_peers "$SCRIPT_DIR/peers_mr_a${i}.json" \
            "{\"role\":\"leaf\",\"topology_hint\":\"ring\",\"next\":\"${nxt}\",\"ring_size\":9}"
    done
    # Ring-B: b3 loops back to relay
    for i in 0 1 2 3; do
        local nxt
        if [[ $i -eq 3 ]]; then nxt="10.50.0.1"; else nxt="${b_ips[$((i+1))]}"; fi
        write_peers "$SCRIPT_DIR/peers_mr_b${i}.json" \
            "{\"role\":\"leaf\",\"topology_hint\":\"ring\",\"next\":\"${nxt}\",\"ring_size\":9}"
    done
    ok "multi-ring ready — relay 10.50.0.1 | A: 10.50.1.{1..4} | B: 10.50.2.{1..4}"
}
teardown_multi_ring() {
    del_if fw-mr-relay
    for i in 0 1 2 3; do del_if "fw-mr-a${i}"; del_if "fw-mr-b${i}"; done
}

# =============================================================================
#  Dispatchers
# =============================================================================
do_setup() {
    case "$1" in
        simple)        setup_simple ;;
        star-large)    setup_star_large ;;
        ring-8)        setup_ring_8 ;;
        hierarchical)  setup_hierarchical ;;
        mesh-6)        setup_mesh_6 ;;
        multi-ring)    setup_multi_ring ;;
        all)
            setup_simple; setup_star_large; setup_ring_8
            setup_hierarchical; setup_mesh_6; setup_multi_ring ;;
        *) die "Unknown topology '$1'. Choose: simple|star-large|ring-8|hierarchical|mesh-6|multi-ring|all" ;;
    esac
}

do_teardown() {
    log "Teardown: $1"
    for iface in $(ip link show 2>/dev/null | awk -F': ' '/^[0-9]+:/{print $2}' \
                   | grep -E '^(fw|coord)' || true); do
        ip link set "$iface" xdp off 2>/dev/null || true
    done
    case "$1" in
        simple)        teardown_simple ;;
        star-large)    teardown_star_large ;;
        ring-8)        teardown_ring_8 ;;
        hierarchical)  teardown_hierarchical ;;
        mesh-6)        teardown_mesh_6 ;;
        multi-ring)    teardown_multi_ring ;;
        all)
            teardown_simple; teardown_star_large; teardown_ring_8
            teardown_hierarchical; teardown_mesh_6; teardown_multi_ring
            # ip netns del "$NETNS" 2>/dev/null && ok "Removed netns $NETNS" || true ;;
            for ns in "${FIREWALL_NAMESPACES[@]}"; do
                ip netns del "$ns" 2>/dev/null || true
            done

            ip netns del "$ATTACKER_NAMESPACE" 2>/dev/null || true ;;
        *) die "Unknown topology: $1" ;;
    esac
    ok "Teardown complete."
}

do_status() {
    echo -e "${CYN}Interface        IPv4                  State    XDP${NC}"
    echo    "─────────────────────────────────────────────────────────"
    for iface in $(ip link show 2>/dev/null | awk -F': ' '/^[0-9]+:/ {sub(/@.*/, "", $2); print $2}' \
                   | grep -E '^(fw|coord)' | sort); do
        local st ip4 xdp
        st=$(ip link show "$iface" 2>/dev/null | awk '/state/{for(i=1;i<=NF;i++) if($i=="state") print $(i+1)}' | head -1)
        ip4=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}' | head -1)
        xdp=$(ip link show "$iface" 2>/dev/null | grep -o 'xdp[a-z_]*' | head -1 || true)
        printf "%-22s %-22s %-8s %s\n" "$iface" "${ip4:--}" "${st:--}" "${xdp:--}"
    done
    echo ""
    # echo -e "${CYN}Attacker netns (${NETNS}):${NC}"
    # if ip netns list | grep -q "^${NETNS}"; then
    #     ip netns exec "$NETNS" ip -4 addr show 2>/dev/null | awk '/inet /{print "  "$2}' | head -50
    # else echo "  (not running)"; fi
    echo -e "${CYN}Attacker netns (${ATTACKER_NAMESPACE}):${NC}"
    if ip netns list | grep -q "^${ATTACKER_NAMESPACE}$"; then
        ip netns exec "$ATTACKER_NAMESPACE" ip -4 addr show 2>/dev/null | \
            awk '/inet /{print "  "$2}' | head -50
    else
        echo "  (not running)"
    fi
    echo ""
    echo -e "${CYN}BPF map pins:${NC}"
    find /sys/fs/bpf/ -name "blacklist" -o -name "jac_map" 2>/dev/null | sed 's/^/  /' || echo "  (none)"
}

do_launch() {
    local t="$1"
    local KEY
    KEY=$(python3 -c "import secrets; print(secrets.token_hex(16))" 2>/dev/null || echo "REPLACE_WITH_HEX_KEY")
    echo -e "${GRN}=== Launch: $t  |  KEY=$KEY ===${NC}"
    echo "  (use the SAME KEY on every node)"
    echo ""
    case "$t" in
    simple)
        cat << EOF
  # T1 — fw0 (coordinator)
  sudo ip netns exec fw0_ns python3 main.py --iface fw0 --port 5000 --peer-port 5000 \\
       --topology star --peers-file peers_coord0.json --xdp-mode native --hmac-key \$KEY

  # T2 — fw1 (coordinator)
  sudo ip netns exec fw1_ns python3 main.py --iface fw1 --port 5000 --peer-port 5000 \\
       --topology star --peers-file peers_coord1.json --xdp-mode native --hmac-key \$KEY

  # T3 — fw2 (leaf)
  sudo ip netns exec fw2_ns python3 main.py --iface fw2 --port 5000 --peer-port 5000 \\
       --topology star --peers-file peers_fw2.json --xdp-mode native --hmac-key \$KEY

  # T4 — monitor
  sudo python3 monitor.py --interval 1.0

  # T5 — benchmark (after all nodes up)
  sudo bash benchmark.sh --iface fw0 --target 10.0.0.1 --runs 5 --veth \\
       --hmac-key \$KEY --outdir results/simple
EOF
        ;;
    star-large)
        echo "  # T1 — coordinator (gossip relay only, no XDP benchmarking)"
        echo "  sudo python3 main.py --iface fw-star-coord --port 6000 --peer-port 6001 \\"
        echo "       --topology star --peers-file peers_star_coord.json --xdp-mode generic --hmac-key \$KEY"
        echo ""
        for i in $(seq 0 7); do
            echo "  # T$((i+2)) — leaf $i"
            echo "  sudo python3 main.py --iface fw-star-${i} --port $((6001+i)) --peer-port 6000 \\"
            echo "       --topology star --peers-file peers_star_leaf${i}.json --xdp-mode native --hmac-key \$KEY"
        done
        echo ""
        echo "  # Benchmark (any leaf — stop all others first for accurate map pinning)"
        echo "  sudo bash benchmark.sh --iface fw-star-0 --target 10.10.1.1 --runs 5 --veth --hmac-key \$KEY"
        ;;
    ring-8)
        for i in $(seq 0 7); do
            echo "  # T$((i+1)) — ring node $i (namespace fw-ring-${i}_ns)"
            echo "  sudo ip netns exec fw-ring-${i}_ns python3 main.py --iface fw-ring-${i} --port $((7000+i)) --peer-port $((7000+((i+1)%8))) \\"
            echo "       --topology ring --peers-file peers_ring${i}.json --xdp-mode native --hmac-key \$KEY"
        done
        echo ""
        echo "  # Benchmark ring-0 from its firewall namespace"
        echo "  sudo ip netns exec fw-ring-0_ns bash benchmark.sh --iface fw-ring-0 --target 10.20.0.1 --runs 5 --veth --hmac-key \$KEY"
        ;;
    hierarchical)
        echo "  # T1 — global coordinator"
        echo "  sudo python3 main.py --iface fw-h-global --port 8000 --peer-port 8001 \\"
        echo "       --topology hierarchical --peers-file peers_h_global.json --xdp-mode generic --hmac-key \$KEY"
        echo ""
        for r in 0 1 2; do
            echo "  # T$((r+2)) — rack coordinator $r"
            echo "  sudo python3 main.py --iface fw-h-rack${r} --port $((8001+r)) --peer-port 8000 \\"
            echo "       --topology hierarchical --peers-file peers_h_rack${r}.json --xdp-mode native --hmac-key \$KEY"
        done
        echo ""
        local t=5
        for r in 0 1 2; do
            for l in 0 1 2; do
                echo "  # T${t} — r${r}-l${l}"
                echo "  sudo python3 main.py --iface fw-h-r${r}-l${l} --port $((8010+r*3+l)) --peer-port $((8001+r)) \\"
                echo "       --topology hierarchical --peers-file peers_h_r${r}_l${l}.json --xdp-mode native --hmac-key \$KEY"
                t=$((t+1))
            done
        done
        echo ""
        echo "  # Benchmark a leaf (block traverses: leaf->rack->global->other racks->leaves)"
        echo "  sudo bash benchmark.sh --iface fw-h-r0-l0 --target 10.30.10.1 --runs 5 --veth --hmac-key \$KEY"
        ;;
    mesh-6)
        for i in $(seq 0 5); do
            echo "  # T$((i+1)) — mesh node $i"
            echo "  sudo python3 main.py --iface fw-mesh-${i} --port $((9000+i)) --peer-port $((9000+i)) \\"
            echo "       --topology mesh --peers-file peers_mesh${i}.json --xdp-mode native --hmac-key \$KEY"
        done
        echo ""
        echo "  sudo bash benchmark.sh --iface fw-mesh-0 --target 10.40.0.1 --runs 5 --veth --hmac-key \$KEY"
        ;;
    multi-ring)
        echo "  # T1 — relay (bridges both rings)"
        echo "  sudo python3 main.py --iface fw-mr-relay --port 9100 --peer-port 9101 \\"
        echo "       --topology ring --peers-file peers_mr_relay.json --xdp-mode native --hmac-key \$KEY"
        echo ""
        for i in 0 1 2 3; do
            echo "  # T$((i+2)) — ring-A node $i"
            echo "  sudo python3 main.py --iface fw-mr-a${i} --port $((9101+i)) --peer-port 9100 \\"
            echo "       --topology ring --peers-file peers_mr_a${i}.json --xdp-mode native --hmac-key \$KEY"
        done
        echo ""
        for i in 0 1 2 3; do
            echo "  # T$((i+6)) — ring-B node $i"
            echo "  sudo python3 main.py --iface fw-mr-b${i} --port $((9110+i)) --peer-port 9100 \\"
            echo "       --topology ring --peers-file peers_mr_b${i}.json --xdp-mode native --hmac-key \$KEY"
        done
        echo ""
        echo "  # Benchmark relay — cross-ring propagation visible in B5"
        echo "  sudo bash benchmark.sh --iface fw-mr-relay --target 10.50.0.1 --runs 5 --veth --hmac-key \$KEY"
        ;;
    all)
        for top in simple ring-8 hierarchical mesh-6 multi-ring star-large; do
            echo "  sudo bash veth_setup.sh launch $top"
        done ;;
    esac
}

do_benchmark() {
    local t="$1"
    echo -e "${GRN}=== Benchmark commands: $t ===${NC}"
    echo "  # Run AFTER all main.py instances are up. Replace KEY= with your shared key."
    echo "  # IMPORTANT: stop fw1/fw2/other-nodes before benchmarking a single node"
    echo "  # to avoid the BCC map-identity bug (Bug 3 — multiple BPF instances)."
    echo ""
    case "$t" in
    simple)
        echo "  sudo bash benchmark.sh --iface fw0 --target 10.0.0.1 \\"
        echo "       --runs 5 --veth --hmac-key \$KEY --outdir results/simple" ;;
    star-large)
        for i in $(seq 0 7); do
            local oct=$((i+1))
            echo "  # leaf $i (stop all other main.py instances first)"
            echo "  sudo bash benchmark.sh --iface fw-star-${i} --target 10.10.${oct}.1 \\"
            echo "       --runs 3 --veth --hmac-key \$KEY --outdir results/star-leaf${i}"
        done ;;
    ring-8)
        echo "  # Benchmark each node from its firewall namespace"
        for i in $(seq 0 7); do
            echo "  sudo ip netns exec fw-ring-${i}_ns bash benchmark.sh --iface fw-ring-${i} --target 10.20.${i}.1 \\"
            echo "       --runs 3 --veth --hmac-key \$KEY --outdir results/ring${i}"
        done ;;
    hierarchical)
        echo "  # One leaf per rack — compare tier-propagation latency across racks"
        local bases=(10 20 30)
        for r in 0 1 2; do
            local base="${bases[$r]}"
            echo "  sudo bash benchmark.sh --iface fw-h-r${r}-l0 --target 10.30.${base}.1 \\"
            echo "       --runs 5 --veth --hmac-key \$KEY --outdir results/hier-r${r}-l0"
        done ;;
    mesh-6)
        echo "  # All 6 nodes — results should be symmetric"
        for i in $(seq 0 5); do
            echo "  sudo bash benchmark.sh --iface fw-mesh-${i} --target 10.40.${i}.1 \\"
            echo "       --runs 3 --veth --hmac-key \$KEY --outdir results/mesh${i}"
        done ;;
    multi-ring)
        echo "  sudo bash benchmark.sh --iface fw-mr-relay --target 10.50.0.1 \\"
        echo "       --runs 5 --veth --hmac-key \$KEY --outdir results/mr-relay"
        echo "  sudo bash benchmark.sh --iface fw-mr-a0 --target 10.50.1.1 \\"
        echo "       --runs 5 --veth --hmac-key \$KEY --outdir results/mr-a0"
        echo "  sudo bash benchmark.sh --iface fw-mr-b0 --target 10.50.2.1 \\"
        echo "       --runs 5 --veth --hmac-key \$KEY --outdir results/mr-b0" ;;
    all)
        for top in simple ring-8 hierarchical mesh-6 multi-ring star-large; do
            echo "  sudo bash veth_setup.sh benchmark $top"
        done ;;
    esac
}

# =============================================================================
#  do_start / do_stop — auto-launch / kill all firewall nodes for a topology
#
#  do_start asks for an HMAC key (one prompt), then:
#    1. If tmux is available: creates a new tmux session "xdp_<topology>" with
#       one window per node, sends the main.py command to each pane, and
#       attaches.  Each pane is labelled with the interface name.
#    2. If tmux is not available: launches each node with setsid in the
#       background, logging stdout/stderr to logs/<iface>.log.  A PID file
#       is written to logs/<iface>.pid for do_stop to use.
#
#  do_stop kills all main.py instances that were started for a topology.
#  It also XDP-detaches every fw* interface so the next run starts clean.
# =============================================================================

# _node_cmds <topology> <key>
# Prints one line per node: <iface> <main_py_cmd...>
# Used by both do_start (to launch) and do_launch (to print).
_node_cmds() {
    local t="$1" KEY="$2"
    local SCRIPT_DIR_local
    SCRIPT_DIR_local="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local PY="python3 ${SCRIPT_DIR_local}/main.py"

    case "$t" in
    simple)
        echo "fw0 ip netns exec fw0_ns ${PY} --iface fw0 --port 5000 --peer-port 5000 --topology star --peers-file ${SCRIPT_DIR_local}/peers_coord0.json --xdp-mode native --hmac-key ${KEY}"
        echo "fw1 ip netns exec fw1_ns ${PY} --iface fw1 --port 5000 --peer-port 5000 --topology star --peers-file ${SCRIPT_DIR_local}/peers_coord1.json --xdp-mode native --hmac-key ${KEY}"
        echo "fw2 ip netns exec fw2_ns ${PY} --iface fw2 --port 5000 --peer-port 5000 --topology star --peers-file ${SCRIPT_DIR_local}/peers_fw2.json --xdp-mode native --hmac-key ${KEY}"
    ;;
    star-large)
        echo "fw-star-coord ${PY} --iface fw-star-coord --port 6000 --peer-port 6001 --topology star --peers-file ${SCRIPT_DIR_local}/peers_star_coord.json --xdp-mode generic --hmac-key ${KEY}"
        for i in $(seq 0 7); do
            echo "fw-star-${i} ${PY} --iface fw-star-${i} --port $((6001+i)) --peer-port 6000 --topology star --peers-file ${SCRIPT_DIR_local}/peers_star_leaf${i}.json --xdp-mode native --hmac-key ${KEY}"
        done
        ;;
    ring-8)
        for i in $(seq 0 7); do
            echo "fw-ring-${i} ip netns exec fw-ring-${i}_ns ${PY} --iface fw-ring-${i} --port $((7000+i)) --peer-port $((7000+(i+1)%8)) --topology ring --peers-file ${SCRIPT_DIR_local}/peers_ring${i}.json --xdp-mode native --hmac-key ${KEY}"
        done
        ;;
    hierarchical)
        echo "fw-h-global ${PY} --iface fw-h-global --port 8000 --peer-port 8001 --topology hierarchical --peers-file ${SCRIPT_DIR_local}/peers_h_global.json --xdp-mode generic --hmac-key ${KEY}"
        for r in 0 1 2; do
            echo "fw-h-rack${r} ${PY} --iface fw-h-rack${r} --port $((8001+r)) --peer-port 8000 --topology hierarchical --peers-file ${SCRIPT_DIR_local}/peers_h_rack${r}.json --xdp-mode native --hmac-key ${KEY}"
        done
        local t_idx=0
        for r in 0 1 2; do
            for l in 0 1 2; do
                echo "fw-h-r${r}-l${l} ${PY} --iface fw-h-r${r}-l${l} --port $((8010+r*3+l)) --peer-port $((8001+r)) --topology hierarchical --peers-file ${SCRIPT_DIR_local}/peers_h_r${r}_l${l}.json --xdp-mode native --hmac-key ${KEY}"
                t_idx=$((t_idx+1))
            done
        done
        ;;
    mesh-6)
        for i in $(seq 0 5); do
            echo "fw-mesh-${i} ${PY} --iface fw-mesh-${i} --port $((9000+i)) --peer-port $((9000+i)) --topology mesh --peers-file ${SCRIPT_DIR_local}/peers_mesh${i}.json --xdp-mode native --hmac-key ${KEY}"
        done
        ;;
    multi-ring)
        echo "fw-mr-relay ${PY} --iface fw-mr-relay --port 9100 --peer-port 9101 --topology ring --peers-file ${SCRIPT_DIR_local}/peers_mr_relay.json --xdp-mode native --hmac-key ${KEY}"
        for i in 0 1 2 3; do
            echo "fw-mr-a${i} ${PY} --iface fw-mr-a${i} --port $((9101+i)) --peer-port 9100 --topology ring --peers-file ${SCRIPT_DIR_local}/peers_mr_a${i}.json --xdp-mode native --hmac-key ${KEY}"
        done
        for i in 0 1 2 3; do
            echo "fw-mr-b${i} ${PY} --iface fw-mr-b${i} --port $((9110+i)) --peer-port 9100 --topology ring --peers-file ${SCRIPT_DIR_local}/peers_mr_b${i}.json --xdp-mode native --hmac-key ${KEY}"
        done
        ;;
    esac
}

do_start() {
    local t="$1"
    [[ "$t" == "all" ]] && die "'start all' is not supported — pick one topology at a time."

    # ── Ask for HMAC key ──────────────────────────────────────────────────────
    local KEY=""
    if [[ -t 0 ]]; then
        echo -e "${CYN}Enter HMAC key (hex, leave empty to auto-generate):${NC}"
        read -r -p "  HMAC key > " KEY
    fi
    if [[ -z "$KEY" ]]; then
        KEY=$(python3 -c "import secrets; print(secrets.token_hex(16))" 2>/dev/null \
              || openssl rand -hex 16)
        ok "Auto-generated HMAC key: ${KEY}"
        echo "  (all nodes in this session will share this key)"
    fi

    # Validate: hex string, even length
    if ! [[ "$KEY" =~ ^[0-9a-fA-F]+$ ]] || (( ${#KEY} % 2 != 0 )); then
        die "HMAC key must be an even-length hex string (e.g. 32 hex chars = 16 bytes)"
    fi

    local LOG_DIR="${SCRIPT_DIR}/logs"
    mkdir -p "$LOG_DIR"

    # Write the key to a file so do_stop and benchmark can read it back
    echo "$KEY" > "${LOG_DIR}/${t}.key"
    ok "Key saved to ${LOG_DIR}/${t}.key"

    # Collect node commands
    local nodes=()
    while IFS= read -r line; do
        nodes+=("$line")
    done < <(_node_cmds "$t" "$KEY")

    if [[ ${#nodes[@]} -eq 0 ]]; then
        die "No nodes defined for topology '$t'"
    fi

    # Ask whether to use tmux (if available)
    local USE_TMUX=0
    if command -v tmux &>/dev/null; then
        echo ""
        read -r -p "Use tmux? [Y/n] " ans
        if [[ "${ans,,}" != "n" ]]; then
            USE_TMUX=1
        fi
    fi

    # ── tmux path ─────────────────────────────────────────────────────────────
    if [[ $USE_TMUX -eq 1 ]]; then
        local SESSION="xdp_${t}"
        # Kill any existing session with this name
        tmux kill-session -t "$SESSION" 2>/dev/null || true

        local first=1
        for entry in "${nodes[@]}"; do
            local iface cmd
            iface=$(echo "$entry" | awk '{print $1}')
            cmd=$(echo "$entry" | cut -d' ' -f2-)

            if [[ $first -eq 1 ]]; then
                tmux new-session -d -s "$SESSION" -n "$iface"
                first=0
            else
                tmux new-window -t "$SESSION" -n "$iface"
            fi
            # Each pane runs the command as root; we're already root so no sudo needed
            tmux send-keys -t "${SESSION}:${iface}" "echo '--- ${iface} ---' && ${cmd}" Enter
            ok "  [tmux] ${iface}"
        done

        echo ""
        ok "All ${#nodes[@]} nodes started in tmux session '${SESSION}'"
        echo -e "  ${CYN}Attach with: tmux attach -t ${SESSION}${NC}"
        echo -e "  ${CYN}Switch panes: Ctrl-b n (next)  Ctrl-b p (prev)  Ctrl-b w (list)${NC}"
        echo ""
        warn "Wait ~5s for all nodes to compile and attach XDP, then run benchmarks."
        echo -e "  ${GRN}Benchmark command:${NC}"
        do_benchmark "$t"
        echo ""
        echo -e "  ${GRN}Key for this session: ${KEY}${NC}"
        echo ""
        read -r -p "Attach to tmux session now? [Y/n] " _ans
        [[ "${_ans,,}" != "n" ]] && tmux attach -t "$SESSION"

    # ── background (no tmux) path ─────────────────────────────────────────────
    else
        warn "tmux not found — launching nodes in background (logs in ${LOG_DIR}/)"
        warn "Install tmux for a much better experience: sudo apt install tmux"
        echo ""

        for entry in "${nodes[@]}"; do
            local iface cmd
            iface=$(echo "$entry" | awk '{print $1}')
            cmd=$(echo "$entry" | cut -d' ' -f2-)
            local logfile="${LOG_DIR}/${iface}.log"
            local pidfile="${LOG_DIR}/${iface}.pid"

            # Kill any stale instance on this interface
            if [[ -f "$pidfile" ]]; then
                local old_pid
                old_pid=$(cat "$pidfile" 2>/dev/null)
                if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
                    kill "$old_pid" 2>/dev/null
                    sleep 0.5
                fi
            fi

            # Launch with setsid so it survives terminal close
            setsid bash -c "${cmd} > '${logfile}' 2>&1 & echo \$! > '${pidfile}'"
            ok "  ${iface}  →  log: ${logfile}  pid: $(cat ${pidfile} 2>/dev/null)"
        done

        echo ""
        ok "All ${#nodes[@]} nodes launched in background."
        echo -e "  ${CYN}Watch logs:   tail -f ${LOG_DIR}/*.log${NC}"
        echo -e "  ${CYN}Stop all:     sudo bash veth_setup.sh stop ${t}${NC}"
        echo ""
        warn "Wait ~5s for all nodes to compile and attach XDP, then run benchmarks."
        echo -e "  ${GRN}Key for this session: ${KEY}${NC}"
        do_benchmark "$t"
    fi
}

do_stop() {
    local t="$1"
    log "Stopping all firewall nodes for topology: $t"

    # Gracefully kill any main.py processes holding fw* interfaces for this topo
    # Strategy: SIGINT so main.py runs its shutdown() handler (XDP detach + unpin)
    local killed=0

    # Ring nodes live in separate namespaces, so their interfaces are not
    # visible to "ip link show" in the root namespace.
    if [[ "$t" == "ring-8" ]]; then
        for i in $(seq 0 7); do
            local iface="fw-ring-${i}"
            local pids
            pids=$(pgrep -f "main.py.*--iface[[:space:]]${iface}([[:space:]]|$)" 2>/dev/null || true)
            if [[ -n "$pids" ]]; then
                for p in $pids; do
                    kill -SIGINT "$p" 2>/dev/null && ok "  Sent SIGINT to ring node (PID=$p, iface=$iface)"
                done
                killed=$((killed+1))
            fi
            local pidfile="${SCRIPT_DIR}/logs/${iface}.pid"
            if [[ -f "$pidfile" ]]; then
                local fp
                fp=$(cat "$pidfile" 2>/dev/null)
                if [[ -n "$fp" ]] && kill -0 "$fp" 2>/dev/null; then
                    kill -SIGINT "$fp" 2>/dev/null && ok "  Sent SIGINT via pidfile (PID=$fp, iface=$iface)"
                    killed=$((killed+1))
                fi
                rm -f "$pidfile"
            fi
        done
    fi
    for iface in $(ip link show 2>/dev/null | awk -F': ' '/^[0-9]+:/{print $2}' \
                   | grep -E '^fw' | sort); do
        # Find a main.py holding this interface
        local pids
        pids=$(pgrep -f "main.py.*--iface[[:space:]]${iface}[[:space:]]" 2>/dev/null || true)
        if [[ -n "$pids" ]]; then
            for p in $pids; do
                kill -SIGINT "$p" 2>/dev/null && ok "  Sent SIGINT to main.py (PID=$p, iface=$iface)"
            done
            killed=$((killed+1))
        fi
        # Also check pid files from background launch
        local pidfile="${SCRIPT_DIR}/logs/${iface}.pid"
        if [[ -f "$pidfile" ]]; then
            local fp
            fp=$(cat "$pidfile" 2>/dev/null)
            if [[ -n "$fp" ]] && kill -0 "$fp" 2>/dev/null; then
                kill -SIGINT "$fp" 2>/dev/null && ok "  Sent SIGINT via pidfile (PID=$fp, iface=$iface)"
                killed=$((killed+1))
            fi
            rm -f "$pidfile"
        fi
    done

    sleep 1

    # Force-detach XDP from any fw* interface that still has it attached
    for iface in $(ip link show 2>/dev/null | awk -F': ' '/^[0-9]+:/{print $2}' \
                   | grep -E '^fw' | sort); do
        if ip link show "$iface" 2>/dev/null | grep -q 'xdp'; then
            ip link set "$iface" xdp off 2>/dev/null && ok "  XDP detached from $iface"
        fi
    done

    # Force-detach XDP from ring interfaces inside their namespaces.
    if [[ "$t" == "ring-8" ]]; then
        for i in $(seq 0 7); do
            ip netns exec "fw-ring-${i}_ns" ip link set "fw-ring-${i}" xdp off 2>/dev/null || true
        done
    fi

    # Kill any remaining main.py (SIGKILL after SIGINT timeout)
    sleep 0.5
    pkill -9 -f "main.py.*--iface fw" 2>/dev/null || true

    # Kill tmux session if it exists
    local SESSION="xdp_${t}"
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        tmux kill-session -t "$SESSION" && ok "  Killed tmux session $SESSION"
    fi

    if [[ $killed -eq 0 ]]; then
        warn "No running main.py instances found for fw* interfaces."
    else
        ok "Stopped $killed node(s)."
    fi
}

# =============================================================================
#  Main
# =============================================================================
case "$CMD" in
    setup)     do_setup     "$TOPO" ;;
    teardown)  do_teardown  "$TOPO" ;;
    status)    do_status ;;
    start)     do_start     "$TOPO" ;;
    stop)      do_stop      "$TOPO" ;;
    launch)    do_launch    "$TOPO" ;;
    benchmark) do_benchmark "$TOPO" ;;
    *)
        die "Unknown command: $CMD
Usage: sudo bash veth_setup.sh <cmd> [topology]
  cmd:      setup | teardown | status | start | stop | launch | benchmark
  topology: simple | star-large | ring-8 | hierarchical | mesh-6 | multi-ring | all

Quickstart (single machine, all veth):
  sudo bash veth_setup.sh setup simple
  sudo bash veth_setup.sh start simple       ← asks for HMAC key, launches all nodes
  sudo bash veth_setup.sh stop  simple       ← kills all nodes cleanly

Manual (original behaviour):
  sudo bash veth_setup.sh launch simple      ← prints copy-paste commands" ;;
esac
