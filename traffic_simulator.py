#!/usr/bin/env python3

import argparse
import http.client
import socket
import sys
import time


def legitimate_traffic(args):
    latencies = []

    print(f"[LEGIT] Target   : {args.dst_ip}:{args.dst_port}")
    print(f"[LEGIT] Requests : {args.requests}")
    print(f"[LEGIT] Interval : {args.interval}s")
    print("[LEGIT] Connection: persistent HTTP connection")
    print()

    conn = None

    try:
        conn = http.client.HTTPConnection(
            args.dst_ip,
            args.dst_port,
            timeout=args.timeout
        )

        for i in range(1, args.requests + 1):
            start = time.perf_counter()

            try:
                conn.request(
                    "GET",
                    "/",
                    headers={"Connection": "keep-alive"}
                )

                response = conn.getresponse()
                response.read()

                elapsed_ms = (time.perf_counter() - start) * 1000.0
                latencies.append(elapsed_ms)

                print(
                    f"[LEGIT] request={i} "
                    f"status={response.status} "
                    f"latency_ms={elapsed_ms:.3f}"
                )

            except Exception as e:
                elapsed_ms = (time.perf_counter() - start) * 1000.0

                print(
                    f"[LEGIT] request={i} "
                    f"FAILED "
                    f"elapsed_ms={elapsed_ms:.3f} "
                    f"error={e}"
                )

                # If the persistent connection was closed/broken,
                # establish a new one for the next request.
                try:
                    conn.close()
                except Exception:
                    pass

                conn = http.client.HTTPConnection(
                    args.dst_ip,
                    args.dst_port,
                    timeout=args.timeout
                )

            if i < args.requests:
                time.sleep(args.interval)

    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    if latencies:
        avg = sum(latencies) / len(latencies)
        minimum = min(latencies)
        maximum = max(latencies)

        print()
        print("========== LEGITIMATE TRAFFIC SUMMARY ==========")
        print(f"successful_requests : {len(latencies)}")
        print(f"average_latency_ms  : {avg:.3f}")
        print(f"min_latency_ms      : {minimum:.3f}")
        print(f"max_latency_ms      : {maximum:.3f}")
        print("=================================================")
    else:
        print()
        print("[LEGIT] No successful requests.")

        
def check_server(args):
    """
    Simple TCP connectivity check.
    """

    print(f"[CHECK] Connecting to {args.dst_ip}:{args.dst_port}")

    try:
        start = time.perf_counter()

        sock = socket.create_connection(
            (args.dst_ip, args.dst_port),
            timeout=args.timeout
        )

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        sock.close()

        print(f"[CHECK] TCP connection successful")
        print(f"[CHECK] connect_latency_ms={elapsed_ms:.3f}")

    except Exception as e:
        print(f"[CHECK] FAILED: {e}")
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Traffic simulator for firewall evaluation"
    )

    parser.add_argument(
        "--mode",
        required=True,
        choices=["legitimate", "check"],
        help="Traffic mode"
    )

    parser.add_argument(
        "--dst-ip",
        required=True,
        help="Destination IPv4 address"
    )

    parser.add_argument(
        "--dst-port",
        type=int,
        default=8080,
        help="Destination TCP port (default: 8080)"
    )

    parser.add_argument(
        "--requests",
        type=int,
        default=100,
        help="Number of legitimate requests (default: 100)"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=0.1,
        help="Delay between requests in seconds (default: 0.1)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="TCP/HTTP timeout in seconds (default: 2)"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if args.mode == "legitimate":
        legitimate_traffic(args)

    elif args.mode == "check":
        check_server(args)


if __name__ == "__main__":
    main()
