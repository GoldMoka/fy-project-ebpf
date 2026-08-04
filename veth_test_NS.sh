#!/usr/bin/env bash
# =============================================================================
#  veth_test.sh — Deterministic XDP firewall test suite over veth pairs
#
#  Prerequisites:
#    sudo bash veth_setup.sh setup simple
#
#    Start firewalls:
#
#      sudo ip netns exec fw0_ns python3 main.py ...
#      sudo ip netns exec fw1_ns python3 main.py ...
#      sudo ip netns exec fw2_ns python3 main.py ...
#
#  Tests execute from attacker_ns using atk0/atk1/atk2.
# =============================================================================
echo "=== DEBUG ==="
ip netns list
echo "============="

set -euo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m'

ok()   { echo -e "${GRN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YLW}[WARN]${NC} $*"; }
log()  { echo -e "${BLU}[TEST]${NC} $*"; }
sep()  { echo -e "\n${YLW}──────────────────────────────────────────────────${NC}"; }

[[ $EUID -eq 0 ]] || {
    echo "Run as root: sudo bash $0"
    exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

###############################################################################
# Namespace configuration
###############################################################################

ATTACKER_NAMESPACE="attacker_ns"

FIREWALL_NAMESPACES=(
    "fw0_ns"
    "fw1_ns"
    "fw2_ns"
)

###############################################################################
# Verify topology
###############################################################################

for i in 0 1 2; do

    ns="fw${i}_ns"
    iface="fw${i}"

    # ip netns list | grep -q "^${ns}$" || {
    #     echo "Namespace ${ns} not found."
    #     echo "Run: sudo bash veth_setup.sh setup simple"
    #     exit 1
    # }

    ip netns list | awk '{print $1}' | grep -qx "$ns" || {
    echo "Namespace ${ns} not found."
    echo "Run: sudo bash veth_setup.sh setup simple"
    exit 1
}


    ip netns exec "$ns" ip link show "$iface" &>/dev/null || {
        echo "Interface ${iface} missing inside ${ns}"
        exit 1
    }

done

ip netns list | awk '{print $1}' | grep -qx "$ATTACKER_NAMESPACE" || {
    echo "Namespace ${ATTACKER_NAMESPACE} not found."
    echo "Run: sudo bash veth_setup.sh setup simple"
    exit 1
}

###############################################################################
# IP addresses
###############################################################################

FW0_IP="10.0.0.1"
FW1_IP="10.0.1.1"
FW2_IP="10.0.2.1"

ATK0_IP="10.0.0.99"
ATK1_IP="10.0.1.99"
ATK2_IP="10.0.2.99"

GOSSIP_PORT=5000

HMAC_KEY="${1:-}"

###############################################################################
# Packet injector
###############################################################################

INJECTOR="/tmp/xdp_veth_inject.py"

cat > "$INJECTOR" << 'PYEOF'
#!/usr/bin/env python3

import sys
import socket
import struct
import random
import subprocess
import time

def cksum(data):
    if len(data) % 2:
        data += b'\x00'

    s = sum((data[i] << 8) + data[i+1]
            for i in range(0, len(data), 2))

    s = (s >> 16) + (s & 0xffff)
    return (~(s + (s >> 16))) & 0xffff


def tcp_pkt(src_ip,dst_ip,sport,dport,flags):

    fb = 0
    if "S" in flags:
        fb |= 0x02
    if "A" in flags:
        fb |= 0x10
    if "R" in flags:
        fb |= 0x04

    seq=random.randint(0,0xffffffff)

    tcp=struct.pack(
        "!HHIIBBHHH",
        sport,dport,seq,0,
        0x50,
        fb,
        65535,
        0,
        0
    )

    si=socket.inet_aton(src_ip)
    di=socket.inet_aton(dst_ip)

    pseudo=struct.pack("!4s4sBBH",si,di,0,6,len(tcp))
    c=cksum(pseudo+tcp)

    tcp=tcp[:16]+struct.pack("!H",c)+tcp[18:]

    ip=struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        len(tcp)+20,
        random.randint(0,65535),
        0,
        64,
        6,
        0,
        si,
        di
    )

    ip=ip[:10]+struct.pack("!H",cksum(ip))+ip[12:]

    return ip+tcp


def src_mac(iface):
    with open(f"/sys/class/net/{iface}/address") as f:
        return bytes(int(x,16) for x in f.read().strip().split(":"))


def dst_mac(iface):

    subprocess.run(
        ["ping","-c","1","-W","1","-I",iface,sys.argv[3]],
        capture_output=True
    )

    time.sleep(0.1)

    try:
        out=subprocess.check_output(
            ["ip","neigh","show","dev",iface],
            text=True
        )

        for line in out.splitlines():
            if "lladdr" in line:
                return bytes(
                    int(x,16)
                    for x in line.split()[4].split(":")
                )

    except Exception:
        pass

    return b"\xff\xff\xff\xff\xff\xff"


def run(iface,src,dst,dport,count,mode):

    smac=src_mac(iface)
    dmac=dst_mac(iface)

    eth=dmac+smac+b"\x08\x00"

    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
    s.bind((iface,0))

    sent=0

    print(f"[Inject] {mode}: {count} packets via {iface}")

    if mode=="synflood":

        for _ in range(count):
            s.send(eth+tcp_pkt(src,dst,31337,dport,"S"))
            sent+=1

    elif mode=="syn":

        for _ in range(count):
            s.send(
                eth+tcp_pkt(
                    src,
                    dst,
                    random.randint(1024,60000),
                    dport,
                    "S"
                )
            )
            time.sleep(0.01)
            sent+=1

    elif mode=="ack":

        for _ in range(count):
            s.send(
                eth+tcp_pkt(
                    src,
                    dst,
                    random.randint(1024,60000),
                    dport,
                    "A"
                )
            )
            time.sleep(0.01)
            sent+=1

    elif mode=="decay_test":

        sport=random.randint(1024,60000)

        for _ in range(4):
            s.send(eth+tcp_pkt(src,dst,sport,dport,"S"))

        time.sleep(3)

        for _ in range(20):
            s.send(eth+tcp_pkt(src,dst,sport,dport,"A"))
            time.sleep(0.05)

        sent=24

    print(f"[Inject] Done ({sent} packets)")
    s.close()


if __name__=="__main__":
    run(
        sys.argv[1],
        sys.argv[2],
        sys.argv[3],
        int(sys.argv[4]),
        int(sys.argv[5]),
        sys.argv[6]
    )

PYEOF

chmod +x "$INJECTOR"

###############################################################################
# Injector helper
###############################################################################

inject() {

    local iface=$1
    local src=$2
    local dst=$3
    local port=$4
    local count=$5
    local mode=$6

    ip netns exec "$ATTACKER_NAMESPACE" \
        python3 "$INJECTOR" \
        "$iface" \
        "$src" \
        "$dst" \
        "$port" \
        "$count" \
        "$mode"
}

###############################################################################
# Banner
###############################################################################

echo -e "${YLW}=================================================${NC}"
echo -e "${YLW}      XDP Firewall veth Namespace Test Suite${NC}"
echo -e "${YLW}=================================================${NC}"
echo ""
echo "Topology:"
echo ""
echo "  attacker_ns"
echo "     ├── atk0 <------> fw0 (fw0_ns)"
echo "     ├── atk1 <------> fw1 (fw1_ns)"
echo "     └── atk2 <------> fw2 (fw2_ns)"
echo ""

###############################################################################
# Test 1
###############################################################################

sep
log "Test 1 : Balanced traffic"

inject atk0 "$ATK0_IP" "$FW0_IP" 8080 25 syn
sleep 1
inject atk0 "$ATK0_IP" "$FW0_IP" 8080 25 ack

ok "Completed Test 1"

###############################################################################
# Test 2
###############################################################################

sep
log "Test 2 : SYN Flood"

inject atk0 "$ATK0_IP" "$FW0_IP" 8080 200 synflood

ok "Completed Test 2"

###############################################################################
# Test 3
###############################################################################

sep
log "Test 3 : Adaptive decay"

inject atk1 "10.111.111.1" "$FW1_IP" 8080 1 decay_test

ok "Completed Test 3"

###############################################################################
# Test 4
###############################################################################

sep
log "Test 4 : Leaf gossip"

inject atk2 "$ATK2_IP" "$FW2_IP" 8080 200 synflood

ok "Completed Test 4"

###############################################################################
# Summary
###############################################################################

sep

echo -e "${GRN}Packet injection completed.${NC}"
echo ""
echo "Check these terminals:"
echo ""
echo "  fw0_ns:"
echo "      sudo ip netns exec fw0_ns python3 main.py ..."
echo ""
echo "  fw1_ns:"
echo "      sudo ip netns exec fw1_ns python3 main.py ..."
echo ""
echo "  fw2_ns:"
echo "      sudo ip netns exec fw2_ns python3 main.py ..."
echo ""
echo "NOTE:"
echo "At the moment main.py exits after attaching XDP because"
echo "bpffs (/sys/fs/bpf) is not visible inside ip netns exec."
echo "Therefore only namespace/veth connectivity can currently"
echo "be validated until the map pinning issue is resolved."

rm -f "$INJECTOR"