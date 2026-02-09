#!/usr/bin/env python3
"""Port knocking client (UDP knocks + optional protected-port check)."""

import argparse
import socket
import time

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_DELAY = 0.3


def send_knock_udp(target: str, port: int, delay: float) -> None:
    """Send a single UDP knock to the target port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"knock", (target, port))
    except OSError:
        pass
    time.sleep(delay)


def perform_knock_sequence(target: str, sequence: list[int], delay: float) -> None:
    """Send the full knock sequence."""
    for port in sequence:
        send_knock_udp(target, port, delay)


def check_protected_port(target: str, protected_port: int) -> None:
    """Try connecting to the protected port after knocking."""
    try:
        with socket.create_connection((target, protected_port), timeout=2.0):
            print(f"[+] Connected to protected port {protected_port}")
    except OSError:
        print(f"[-] Could not connect to protected port {protected_port}")


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking client")
    parser.add_argument("--target", required=True, help="Target host or IP")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports (UDP knocks)",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port (TCP)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Delay between knocks in seconds",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Attempt TCP connection to protected port after knocking",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    perform_knock_sequence(args.target, sequence, args.delay)

    if args.check:
        check_protected_port(args.target, args.protected_port)


if __name__ == "__main__":
    main()
