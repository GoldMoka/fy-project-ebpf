#!/usr/bin/env bash
# =============================================================================
#  veth_test.sh — Deterministic XDP firewall test suite over veth pairs
#
#  Prerequisites:
#    sudo bash veth_setup.sh setup      # create the veth topology
#    (then start main.py on fw0/fw1/fw2 in separate terminals)
#
#  This script runs from the attacker network namespace, injecting raw TCP
#  packets via atk0/atk1/atk2 directly into the fw* veth ends — zero
#  physical-layer variables (no cable, no switch, no ARP storm).
#
#  Tests:
#    1. Normal balanced traffic  → no block (baseline)
#    2. SYN flood on fw0         → ALERT + XDP_DROP
#    3. Adaptive decay           → score rises, decays, no permanent block
#    4. Multi-coordinator gossip → block detected on fw0 propagates to fw1/fw2
#    5. HMAC forge attempt       → gossip with wrong sig is rejected
#    6. Replay attack            → same nonce rejected second time
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GRN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YLW}[WARN]${NC} $*"; }
log()  { echo -e "${BLU}[TEST]${NC} $*"; }
sep()  { echo -e "\n${YLW}──────────────────────────────────────────────────${NC}"; }

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }

NETNS="xdp_attacker"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Verify veth topology exists
for iface in fw0 fw1 fw2; do
    ip link show "$iface" &>/dev/null || {
        echo "Interface $iface not found — run: sudo bash veth_setup.sh setup"
        exit 1
    }
done

ip netns list | grep -q "^${NETNS}" || {
    echo "Netns $NETNS not found — run: sudo bash veth_setup.sh setup"
    exit 1
}

# Firewall IPs (must match veth_setup.sh)
FW0_IP="10.0.0.1"
FW1_IP="10.0.1.1"
FW2_IP="10.0.2.1"
ATK0_IP="10.0.0.99"
ATK1_IP="10.0.1.99"
ATK2_IP="10.0.2.99"
GOSSIP_PORT=5000

# Optional HMAC key for gossip auth tests (pass as $1 if desired)
HMAC_KEY="${1:-}"

# ── Packet injector (runs inside attacker netns) ───────────────────────────────
INJECTOR="/tmp/xdp_veth_inject.py"
cat > "$INJECTOR" << 'PYEOF'
#!/usr/bin/env python3
"""
Raw TCP packet injector for veth test environment.
Runs inside the attacker netns — no ARP needed, direct veth injection.
"""
import sys, socket, struct, time, random

def cksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xffff)
    return (~(s + (s >> 16))) & 0xffff

def tcp_pkt(src_ip, dst_ip, sport, dport, flags):
    fb  = (0x02 if 'S' in flags else 0) | (0x10 if 'A' in flags else 0) | (0x04 if 'R' in flags else 0)
    seq = random.randint(0, 0xffffffff)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, fb, 65535, 0, 0)
    si, di = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    csum = cksum(struct.pack('!4s4sBBH', si, di, 0, 6, len(tcp)) + tcp)
    tcp  = tcp[:16] + struct.pack('!H', csum) + tcp[18:]
    ip   = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(tcp)+20,
                       random.randint(0, 0xffff), 0, 64, 6, 0, si, di)
    csum = cksum(ip)
    return (ip[:10] + struct.pack('!H', csum) + ip[12:]) + tcp

def src_mac(iface):
    try:
        with open(f'/sys/class/net/{iface}/address') as f:
            return bytes(int(x, 16) for x in f.read().strip().split(':'))
    except:
        return b'\x00' * 6

def dst_mac(iface):
    """Read the peer's MAC from the ARP table (pre-populated by veth setup)."""
    import subprocess
    try:
        out = subprocess.check_output(
            ['ip', 'neigh', 'show', 'dev', iface], text=True)
        for line in out.splitlines():
            if 'lladdr' in line:
                return bytes(int(x, 16) for x in line.split()[2].split(':'))
    except:
        pass
    # Veth peer MAC: read directly from sysfs path of peer
    # For veth, the MAC of the peer end is accessible via ethtool stats or
    # we can just ping once to populate the ARP table.
    return b'\xff\xff\xff\xff\xff\xff'   # broadcast fallback

def run(iface, src_ip, dst_ip, dport, count, mode):
    # Populate ARP table first (needed to get dst MAC on veth)
    import subprocess
    subprocess.run(['ping', '-c', '1', '-W', '1', '-I', iface, dst_ip],
                   capture_output=True)
    time.sleep(0.1)

    dmac = dst_mac(iface)
    smac = src_mac(iface)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.bind((iface, 0))
    eth = dmac + smac + b'\x08\x00'
    sent = 0

    print(f"[Inject] {mode}: {count} pkts  src={src_ip}  dst={dst_ip}:{dport}  iface={iface}")

    if mode == 'synflood':
        sp = 31337
        for _ in range(count):
            sock.send(eth + tcp_pkt(src_ip, dst_ip, sp, dport, 'S'))
            sent += 1

    elif mode == 'syn':
        for _ in range(count):
            sock.send(eth + tcp_pkt(src_ip, dst_ip, random.randint(1024, 60000), dport, 'S'))
            time.sleep(0.01)
            sent += 1

    elif mode == 'ack':
        for _ in range(count):
            sock.send(eth + tcp_pkt(src_ip, dst_ip, random.randint(1024, 60000), dport, 'A'))
            time.sleep(0.01)
            sent += 1

    elif mode == 'decay_test':
        sp = random.randint(1024, 60000)
        print("[Inject] Phase 1: 4 SYNs (score→40, below floor=50)")
        for _ in range(4):
            sock.send(eth + tcp_pkt(src_ip, dst_ip, sp, dport, 'S'))
        print("[Inject] Phase 2: 3s silence (kernel decay runs)")
        time.sleep(3)
        print("[Inject] Phase 3: 20 ACKs (score recovery)")
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

# ── Gossip forge test (plain Python, NOT in netns — testing auth from outside) ─
FORGE_TEST="/tmp/xdp_forge_test.py"
cat > "$FORGE_TEST" << PYEOF
#!/usr/bin/env python3
"""
Security test: attempt to forge a gossip block message.
Sends a message with a wrong HMAC signature and one with a replayed nonce.
The firewall should reject both silently (no block applied).
"""
import socket, json, time, hashlib, hmac, secrets

TARGET_IP   = "$FW0_IP"
GOSSIP_PORT = $GOSSIP_PORT
HMAC_KEY    = bytes.fromhex("$HMAC_KEY") if "$HMAC_KEY" else b""

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# ── Test A: forge with wrong key ─────────────────────────────────────────────
ip    = "9.9.9.9"
ts    = time.time()
nonce = secrets.token_hex(8)
body  = f"{ip}:{ts:.6f}:{nonce}"

# Sign with a deliberately wrong key
wrong_key = b"wrong_key_nobody_knows"
sig = hmac.new(wrong_key, body.encode(), hashlib.sha256).hexdigest()
msg = json.dumps({"ip": ip, "ts": ts, "nonce": nonce, "sig": sig})
sock.sendto(msg.encode(), (TARGET_IP, GOSSIP_PORT))
print(f"[ForgeTest-A] Sent forged message for {ip} with WRONG key — firewall should reject")

time.sleep(0.5)

# ── Test B: replay a valid nonce twice ──────────────────────────────────────
ip2   = "8.8.8.8"
ts2   = time.time()
nonce2 = secrets.token_hex(8)
body2  = f"{ip2}:{ts2:.6f}:{nonce2}"

if HMAC_KEY:
    sig2 = hmac.new(HMAC_KEY, body2.encode(), hashlib.sha256).hexdigest()
else:
    sig2 = ""

msg2 = json.dumps({"ip": ip2, "ts": ts2, "nonce": nonce2, "sig": sig2})

# Send valid message first
sock.sendto(msg2.encode(), (TARGET_IP, GOSSIP_PORT))
print(f"[ForgeTest-B] Sent valid message for {ip2} (first send — should be accepted)")
time.sleep(0.3)

# Replay exact same bytes
sock.sendto(msg2.encode(), (TARGET_IP, GOSSIP_PORT))
print(f"[ForgeTest-B] Replayed same nonce for {ip2} — firewall should reject replay")

sock.close()
PYEOF

# ── Helper: run injector inside attacker netns ─────────────────────────────────
inject() {
    local iface=$1 src_ip=$2 dst_ip=$3 dport=$4 count=$5 mode=$6
    ip netns exec "$NETNS" python3 "$INJECTOR" "$iface" "$src_ip" "$dst_ip" "$dport" "$count" "$mode"
}

# ─────────────────────────────────────────────────────────────────────────────
echo -e "${YLW}XDP Adaptive Firewall — veth Test Suite${NC}"
echo "  Network   : attacker netns → fw0/fw1/fw2 veth pairs"
echo "  No physical hardware, no ARP variables, fully deterministic"
echo ""

# ── Test 1: Balanced traffic on fw0 (no alert expected) ──────────────────────
sep
log "Test 1: Balanced traffic on fw0 — should NOT trigger alert"
log "25 SYNs + 25 ACKs (net score stays well below FLOOR_THRESHOLD=50)"
inject "atk0" "$ATK0_IP" "$FW0_IP" 8080 25 syn
sleep 0.3
inject "atk0" "$ATK0_IP" "$FW0_IP" 8080 25 ack
sleep 1
ok "Test 1 complete — check fw0 terminal: $ATK0_IP in top IPs, NO alert"

# ── Test 2: SYN flood on fw0 (alert + XDP_DROP expected) ─────────────────────
sep
log "Test 2: SYN flood on fw0 — 200 rapid SYNs, no ACKs"
log "Expected: ALERT + XDP_DROP + gossip propagated to fw1/fw2 via coordinator"
inject "atk0" "$ATK0_IP" "$FW0_IP" 8080 200 synflood
sleep 2
ok "Test 2 complete — check fw0 terminal: ALERT + block for $ATK0_IP"
warn "Also check fw1/fw2 terminals: they should receive gossip and apply the block"

# ── Test 3: Adaptive decay on fw1 ────────────────────────────────────────────
sep
log "Test 3: Adaptive decay on fw1"
log "Phase 1: 4 SYNs → score 40 (below floor=50)  Phase 2: 3s silence  Phase 3: ACKs"
log "Expected: score rises then decays to 0, NO permanent block"
inject "atk1" "10.111.111.1" "$FW1_IP" 8080 1 decay_test
sleep 1
ok "Test 3 complete — fw1 [Stats] should show 10.111.111.1 score~40, decaying to 0"

# ── Test 4: SYN flood on fw2 (leaf node, gossip to both coordinators) ─────────
sep
log "Test 4: SYN flood on fw2 leaf — block should propagate to both coordinators"
inject "atk2" "$ATK2_IP" "$FW2_IP" 8080 200 synflood
sleep 2
ok "Test 4 complete"
warn "Check fw0 AND fw1 (coordinators): both should show gossip block for $ATK2_IP"

# ── Test 5: Direct gossip injection (valid) ───────────────────────────────────
sep
log "Test 5: Direct gossip — send a block notification via UDP"
python3 - << PYEOF
import socket, json, time, hashlib, hmac, secrets

TARGET_IP   = "$FW0_IP"
GOSSIP_PORT = $GOSSIP_PORT
HMAC_KEY    = bytes.fromhex("$HMAC_KEY") if "$HMAC_KEY" else b""

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip    = "3.3.3.3"
ts    = time.time()
nonce = secrets.token_hex(8)

if HMAC_KEY:
    body = f"{ip}:{ts:.6f}:{nonce}"
    sig  = hmac.new(HMAC_KEY, body.encode(), hashlib.sha256).hexdigest()
else:
    sig  = ""

msg = json.dumps({"ip": ip, "ts": ts, "nonce": nonce, "sig": sig})
sock.sendto(msg.encode(), (TARGET_IP, GOSSIP_PORT))
print(f"[Gossip] Sent signed block for {ip} to {TARGET_IP}:{GOSSIP_PORT}")
sock.close()
PYEOF
sleep 1
ok "Test 5 complete — fw0 should show 'Kernel block applied: 3.3.3.3'"

# ── Test 6: Security — forge and replay ──────────────────────────────────────
sep
log "Test 6: Security tests — forge attempt + replay attack"
if [[ -n "$HMAC_KEY" ]]; then
    python3 "$FORGE_TEST"
    sleep 1
    ok "Test 6 complete — fw0 terminal should show REJECT messages for 9.9.9.9 (forge)"
    warn "9.9.9.9 should NOT appear in kernel blacklist (forge was rejected)"
    warn "8.8.8.8 should appear once (valid first send), second send rejected as replay"
else
    warn "Test 6 skipped — run with HMAC key: sudo bash $0 <hex_key>"
    warn "Example: sudo bash $0 $(python3 -c 'import secrets; print(secrets.token_hex(16))')"
fi

# ─────────────────────────────────────────────────────────────────────────────
sep
echo -e "${GRN}All veth tests complete.${NC}"
echo ""
echo "  What to verify in the firewall node terminals:"
echo "    Test 1 : fw0 shows $ATK0_IP in top IPs, score rising — NO alert"
echo "    Test 2 : fw0 ALERT + block for $ATK0_IP"
echo "           : fw1 and fw2 receive gossip, apply block (multi-coordinator)"
echo "    Test 3 : fw1 shows 10.111.111.1 score~40 decaying to 0 (no block)"
echo "    Test 4 : fw0 and fw1 both receive gossip for $ATK2_IP"
echo "    Test 5 : fw0 'Kernel block applied: 3.3.3.3'"
echo "    Test 6 : fw0 REJECT messages for 9.9.9.9 + 8.8.8.8 replay"
echo ""
echo "  Check kernel blacklist on any node:"
echo "    sudo bpftool map dump pinned /sys/fs/bpf/tc/globals/blacklist"
echo "  Or read it from Python:"
echo "    (run main.py in --dry-run mode and check the BPF map)"

rm -f "$INJECTOR" "$FORGE_TEST"
