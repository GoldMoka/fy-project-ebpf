#!/usr/bin/env bash
# =============================================================================
#  test_firewall.sh — XDP Adaptive Firewall test suite
#
#  Works across subnets (routed) and same-subnet (direct) automatically.
#
#  Usage:
#    sudo bash test_firewall.sh --iface eno1 --target <device1_IP>
#    sudo bash test_firewall.sh eno1 <device1_IP>          # positional ok too
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GRN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YLW}[WARN]${NC} $*"; }
log()  { echo -e "${BLU}[TEST]${NC} $*"; }
sep()  { echo -e "\n${YLW}──────────────────────────────────────────────────${NC}"; }

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IFACE=""; TARGET_IP=""; GOSSIP_PORT=5000

while [[ $# -gt 0 ]]; do
    case $1 in
        --iface)       IFACE="$2";      shift 2 ;;
        --target)      TARGET_IP="$2";  shift 2 ;;
        --gossip-port) GOSSIP_PORT="$2";shift 2 ;;
        *) [[ -z "$IFACE" ]] && IFACE="$1" || TARGET_IP="$1"; shift ;;
    esac
done

[[ -z "$IFACE" ]] && {
    IFACE=$(ip route show default 2>/dev/null | awk '/^default/{print $5}' | head -1)
    IFACE="${IFACE:-eno1}"
}
ip link show "$IFACE" &>/dev/null || { echo "Interface '$IFACE' not found"; exit 1; }
[[ -z "$TARGET_IP" ]] && { echo "Usage: sudo bash $0 --iface eno1 --target <IP>"; exit 1; }

OWN_IP=$(ip -4 addr show "$IFACE" 2>/dev/null \
         | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
[[ -z "$OWN_IP" ]] && { echo "No IPv4 address on $IFACE"; exit 1; }

# ── Resolve the correct next-hop MAC ─────────────────────────────────────────
#
# KEY INSIGHT: on a routed network (different subnets, TTL drops by 1),
# we cannot use ARP for the target IP — ARP is L2-only and stops at the
# first router. Instead we must:
#   1. Find the next-hop gateway for the target IP from the routing table
#   2. Resolve THAT gateway's MAC via ARP
#   3. Use the gateway MAC as dst_mac in our Ethernet frames
#
# The IP packets still carry the real target IP as dst IP — the router reads
# that, decrements TTL, and forwards to device 1. XDP on device 1 sees the
# packet arriving on eno1 with dst IP = device1's IP, exactly as expected.
#
sep
log "Resolving next-hop for $TARGET_IP..."

# Get the next-hop: either the target itself (same subnet) or a gateway
NEXTHOP=$(ip route get "$TARGET_IP" 2>/dev/null \
          | awk '/via/{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' \
          | head -1)

if [[ -z "$NEXTHOP" ]]; then
    # Same subnet — no 'via', next-hop IS the target
    NEXTHOP="$TARGET_IP"
    log "Same subnet — next-hop is target itself ($NEXTHOP)"
else
    log "Routed network — next-hop gateway: $NEXTHOP"
    warn "Devices are on different subnets. Frames will go via gateway $NEXTHOP."
    warn "XDP on device 1 will still see them arrive on eno1 with correct dst IP."
fi

# Force ARP resolution of the next-hop
ip neigh del "$NEXTHOP" dev "$IFACE" 2>/dev/null || true
ping -c 3 -W 1 -I "$IFACE" "$NEXTHOP" &>/dev/null || true
sleep 0.3

NEXTHOP_MAC=$(ip neigh show "$NEXTHOP" dev "$IFACE" 2>/dev/null \
              | awk '/lladdr/{print $3}' | head -1)

# arping fallback
if [[ -z "$NEXTHOP_MAC" ]] && command -v arping &>/dev/null; then
    NEXTHOP_MAC=$(arping -c 3 -I "$IFACE" "$NEXTHOP" 2>/dev/null \
                  | awk '/reply from/{gsub(/[\[\]]/,"",$5); print $5}' | head -1)
fi

if [[ -z "$NEXTHOP_MAC" ]]; then
    fail "Cannot resolve MAC for next-hop $NEXTHOP on $IFACE."
    echo ""
    echo "  Manual fix — run this on device 2, then re-run the test:"
    echo "    ping -c 3 -I $IFACE $NEXTHOP"
    echo "    ip neigh show $NEXTHOP"
    echo ""
    echo "  Or install arping: sudo apt install arping"
    exit 1
fi

ok "Next-hop MAC: $NEXTHOP_MAC  (for gateway $NEXTHOP)"

# Reachability check
if ping -c 1 -W 2 -I "$IFACE" "$TARGET_IP" &>/dev/null; then
    TTL=$(ping -c 1 -W 2 -I "$IFACE" "$TARGET_IP" 2>/dev/null \
          | awk '/ttl=/{match($0,/ttl=[0-9]+/); print substr($0,RSTART+4,RLENGTH-4)}')
    ok "Device 1 reachable — ping OK (ttl=$TTL)"
    [[ "${TTL:-64}" -lt 64 ]] && \
        warn "TTL<64 confirms routing (expected — frames go via $NEXTHOP)"
else
    warn "Ping to $TARGET_IP failed — device 1 may be blocking ICMP (ok if XDP is running)"
fi

sep
echo -e "${YLW}XDP Firewall Test Suite${NC}"
echo "  Sender    : $IFACE  ($OWN_IP)"
echo "  Target    : $TARGET_IP"
echo "  Next-hop  : $NEXTHOP  (MAC: $NEXTHOP_MAC)"
echo "  Gossip    : $TARGET_IP:$GOSSIP_PORT"

# ── Write injector with baked-in MAC ─────────────────────────────────────────
INJECTOR="$SCRIPT_DIR/_inject.py"
cat > "$INJECTOR" << PYEOF
#!/usr/bin/env python3
import sys, socket, struct, time, random

# Next-hop MAC resolved at test-start — baked in, no runtime ARP needed
NEXTHOP_MAC = bytes(int(x,16) for x in "$NEXTHOP_MAC".split(':'))

def cksum(data):
    if len(data) % 2: data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xffff)
    return (~(s + (s >> 16))) & 0xffff

def tcp_pkt(src_ip, dst_ip, sport, dport, flags):
    fb = (0x02 if 'S' in flags else 0) | (0x10 if 'A' in flags else 0) | (0x04 if 'R' in flags else 0)
    seq = random.randint(0, 0xffffffff)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, fb, 65535, 0, 0)
    si, di = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    csum = cksum(struct.pack('!4s4sBBH', si, di, 0, 6, len(tcp)) + tcp)
    tcp = tcp[:16] + struct.pack('!H', csum) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(tcp)+20,
                     random.randint(0,0xffff), 0, 64, 6, 0, si, di)
    csum = cksum(ip)
    return (ip[:10] + struct.pack('!H', csum) + ip[12:]) + tcp

def src_mac(iface):
    try:
        with open(f'/sys/class/net/{iface}/address') as f:
            return bytes(int(x,16) for x in f.read().strip().split(':'))
    except:
        return b'\x00'*6

def run(iface, src_ip, dst_ip, dport, count, mode):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.bind((iface, 0))
    eth = NEXTHOP_MAC + src_mac(iface) + b'\x08\x00'
    sent = 0

    print(f"[Inject] {mode}: {count} pkts → {dst_ip}:{dport} via {iface}")

    if mode == 'synflood':
        # Fixed source port so all SYNs accumulate on ONE jac_map entry (same saddr)
        # jac_map is keyed by saddr only, so random sport doesn't matter for scoring —
        # but using fixed sport makes the test cleaner and port 31337 is recognisable
        sp = 31337
        for _ in range(count):
            sock.send(eth + tcp_pkt(src_ip, dst_ip, sp, dport, 'S'))
            sent += 1
    elif mode == 'syn':
        for _ in range(count):
            sock.send(eth + tcp_pkt(src_ip, dst_ip, random.randint(1024,60000), dport, 'S'))
            time.sleep(0.01); sent += 1
    elif mode == 'ack':
        for _ in range(count):
            sock.send(eth + tcp_pkt(src_ip, dst_ip, random.randint(1024,60000), dport, 'A'))
            time.sleep(0.01); sent += 1
    elif mode == 'decay_test':
        sp = random.randint(1024, 60000)
        print("[Inject] Phase 1: 4 SYNs (score→40, stays below floor=50)...")
        for _ in range(4):
            sock.send(eth + tcp_pkt(src_ip, dst_ip, sp, dport, 'S'))
        print("[Inject] Phase 2: 3s silence (decay runs)...")
        time.sleep(3)
        print("[Inject] Phase 3: 20 ACKs (recovery)...")
        for _ in range(20):
            sock.send(eth + tcp_pkt(src_ip, dst_ip, sp, dport, 'A'))
            time.sleep(0.05)
        sent = 24

    print(f"[Inject] Done: {sent} packets sent")
    sock.close()

if __name__ == '__main__':
    run(sys.argv[1], sys.argv[2], sys.argv[3],
        int(sys.argv[4]), int(sys.argv[5]), sys.argv[6])
PYEOF

# ── Tests ─────────────────────────────────────────────────────────────────────
sep
log "Test 1: Normal mixed traffic — should NOT trigger alert"
log "25 SYNs + 25 ACKs (balanced — score rises slowly, stays below threshold)"
python3 "$INJECTOR" "$IFACE" "$OWN_IP" "$TARGET_IP" 8080 25 syn
sleep 0.3
python3 "$INJECTOR" "$IFACE" "$OWN_IP" "$TARGET_IP" 8080 25 ack
sleep 1
ok "Test 1 done — watch device 1 terminal: $OWN_IP should appear in top IPs, NO alert."

sep
log "Test 2: SYN flood — 200 rapid SYNs, no ACKs"
log "Expected: ALERT fires on device 1, $OWN_IP blocked"
python3 "$INJECTOR" "$IFACE" "$OWN_IP" "$TARGET_IP" 8080 200 synflood
sleep 2
ok "Test 2 done — device 1 terminal should show: ALERT + XDP_DROP for $OWN_IP"

sep
log "Test 3: Adaptive decay — burst, silence, recovery"
log "Phase 1: 4 SYNs (score=40, below floor=50) → Phase 2: 3s silence → Phase 3: 20 ACKs"
log "Expected: score rises then falls during silence (not permanently blocked)"
DECAY_SRC="10.255.255.1"
python3 "$INJECTOR" "$IFACE" "$DECAY_SRC" "$TARGET_IP" 8080 1 decay_test
sleep 1
ok "Test 3 done — device 1 [Stats] should show 10.255.255.1 score~40, then decaying to 0."

sep
log "Test 4: Gossip propagation (UDP direct to device 1 port $GOSSIP_PORT)"
python3 - << PYEOF
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'1.2.3.4', ('$TARGET_IP', $GOSSIP_PORT))
print("[Gossip] Sent: block 1.2.3.4")
msg = json.dumps({"ip": "5.6.7.8", "ttl": 3, "origin": "test_suite"}).encode()
s.sendto(msg, ('$TARGET_IP', $GOSSIP_PORT))
print("[Gossip] Sent: block 5.6.7.8")
PYEOF
sleep 1
ok "Gossip done — device 1 terminal should show 'Kernel block applied' for 1.2.3.4 and 5.6.7.8"

sep
echo -e "${GRN}All tests complete.${NC}"
echo ""
echo "  What to check in device 1's firewall terminal:"
echo "    Test 1: [Stats] shows $OWN_IP in top IPs with rising score"
echo "    Test 2: ALERT block for $OWN_IP"
echo "    Test 3: 10.255.255.1 in [Stats] with score~40 (no block), decays to 0 after silence"
echo "    Test 4: 'Kernel block applied: 1.2.3.4' and '5.6.7.8'"
echo ""
echo "  If device 1 still shows nothing after test 2, verify frames arrive:"
echo "    On device 1: sudo tcpdump -i eno1 -n 'tcp and src $OWN_IP' -c 5"
echo "    If tcpdump sees packets but XDP doesn't — check BPF compile log."
echo "    If tcpdump sees nothing — the router may be filtering raw frames."

rm -f "$INJECTOR"
