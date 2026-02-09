#!/usr/bin/env python3
"""Port knocking server: UDP knock detection + iptables-based protected port opening."""

import argparse
import logging
import select
import socket
import subprocess
import threading
import time
from typing import Dict, Tuple

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0
DEFAULT_OPEN_SECONDS = 30.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def _run_iptables(args: list[str]) -> Tuple[int, str, str]:
    """Run iptables safely and return (rc, stdout, stderr)."""
    p = subprocess.run(
        ["iptables"] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def _ensure_rule(args: list[str], insert: bool = False, insert_index: int = 1) -> None:
    """
    Ensure an iptables rule exists:
      - check with iptables -C
      - if missing, add with -A or -I
    """
    rc, _, _ = _run_iptables(["-C"] + args)
    if rc == 0:
        return

    if insert:
        _run_iptables(["-I", "INPUT", str(insert_index)] + args[len(["INPUT"]):] if args[:1] == ["INPUT"] else ["-I"] + args)
    else:
        _run_iptables(["-A"] + args)


def _delete_rule_if_exists(args: list[str]) -> None:
    """Delete an iptables rule if it exists (best-effort)."""
    rc, _, _ = _run_iptables(["-C"] + args)
    if rc != 0:
        return
    _run_iptables(["-D"] + args)


def _delete_all_matching_allow_rules(protected_port: int, src_ip: str) -> None:
    """Delete all matching ACCEPT rules for src_ip -> protected_port with our comment. We loop because duplicates can exist during dev/testing."""
    while True:
        rc, _, _ = _run_iptables(
            [
                "-C",
                "INPUT",
                "-p",
                "tcp",
                "-s",
                src_ip,
                "--dport",
                str(protected_port),
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                "knock_allow",
            ]
        )
        if rc != 0:
            break
        _run_iptables(
            [
                "-D",
                "INPUT",
                "-p",
                "tcp",
                "-s",
                src_ip,
                "--dport",
                str(protected_port),
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                "knock_allow",
            ]
        )


def firewall_init(protected_port: int) -> None:
    """
    Initialize firewall behavior:
      - allow loopback
      - allow established/related
      - default DROP for protected_port
    """
    #Allow loopback (usually already fine, but safe)
    _ensure_rule(["INPUT", "-i", "lo", "-j", "ACCEPT"])

    #Allow established connections
    _ensure_rule(
        ["INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        insert=True,
        insert_index=1,
    )

    #Default drop for protected port (TCP)
    _ensure_rule(["INPUT", "-p", "tcp", "--dport", str(protected_port), "-j", "DROP"])


def open_protected_port_for_ip(protected_port: int, src_ip: str) -> None:
    """Insert an ACCEPT rule for src_ip -> protected_port above the DROP rule."""
    #Ensure the DROP rule exists (just in case)
    _ensure_rule(["INPUT", "-p", "tcp", "--dport", str(protected_port), "-j", "DROP"])

    #Insert allow near the top
    rc, _, _ = _run_iptables(
        [
            "-C",
            "INPUT",
            "-p",
            "tcp",
            "-s",
            src_ip,
            "--dport",
            str(protected_port),
            "-j",
            "ACCEPT",
            "-m",
            "comment",
            "--comment",
            "knock_allow",
        ]
    )
    if rc == 0:
        return

    _run_iptables(
        [
            "-I",
            "INPUT",
            "2",
            "-p",
            "tcp",
            "-s",
            src_ip,
            "--dport",
            str(protected_port),
            "-j",
            "ACCEPT",
            "-m",
            "comment",
            "--comment",
            "knock_allow",
        ]
    )


def close_protected_port_for_ip(protected_port: int, src_ip: str) -> None:
    """Remove the ACCEPT rule for src_ip -> protected_port."""
    _delete_all_matching_allow_rules(protected_port, src_ip)


def start_demo_protected_service(protected_port: int) -> None:
    """Tiny TCP service so your demo works:
      - When firewall opens, `nc -z -v <ip> 2222` will succeed. """
    logger = logging.getLogger("ProtectedService")

    def _srv():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", protected_port))
            s.listen(50)
            logger.info("Demo protected service listening on TCP %s", protected_port)
            while True:
                try:
                    conn, addr = s.accept()
                    with conn:
                        #Send a tiny banner then close; nc -z just needs a successful handshake
                        conn.sendall(b"Protected service: access granted.\n")
                except Exception:
                    #keep service alive
                    time.sleep(0.05)

    t = threading.Thread(target=_srv, daemon=True)
    t.start()


def listen_for_knocks(sequence, window_seconds, protected_port, open_seconds):
    """Listen for UDP knocks on each port in 'sequence'. Maintain per-source IP progress. On success: open firewall for that IP to protected_port for open_seconds."""
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for UDP knocks: %s", sequence)
    logger.info("Protected TCP port: %s", protected_port)
    logger.info("Sequence window: %.1fs | Open duration: %.1fs", window_seconds, open_seconds)

    #Bind UDP sockets for each knock port
    sockets_by_port: Dict[int, socket.socket] = {}
    for p in sequence:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", p))
        s.setblocking(False)
        sockets_by_port[p] = s

    #State per IP: (next_index, start_time)
    state: Dict[str, Tuple[int, float]] = {}

    def reset_ip(ip: str):
        state.pop(ip, None)

    def success(ip: str):
        logger.info("Valid knock sequence from %s -> opening port %s for %.1fs", ip, protected_port, open_seconds)
        open_protected_port_for_ip(protected_port, ip)

        #Auto-close after open_seconds
        def _close():
            logger.info("Closing port %s for %s", protected_port, ip)
            close_protected_port_for_ip(protected_port, ip)

        threading.Timer(open_seconds, _close).start()
        reset_ip(ip)

    #Main loop
    sock_list = list(sockets_by_port.values())
    port_by_sock = {s: p for p, s in sockets_by_port.items()}

    while True:
        #Expire old in-progress sequences
        now = time.time()
        for ip, (idx, start_t) in list(state.items()):
            if now - start_t > window_seconds:
                reset_ip(ip)

        r, _, _ = select.select(sock_list, [], [], 0.5)
        for s in r:
            try:
                data, (src_ip, _src_port) = s.recvfrom(4096)
            except OSError:
                continue

            knocked_port = port_by_sock[s]
            expected_next = 0
            start_time = now

            if src_ip in state:
                expected_next, start_time = state[src_ip]

            #If window exceeded, restart
            if now - start_time > window_seconds:
                expected_next = 0
                start_time = now

            expected_port = sequence[expected_next]

            if knocked_port == expected_port:
                next_idx = expected_next + 1
                state[src_ip] = (next_idx, start_time)

                logger.info("Knock %d/%d from %s on UDP %d",
                            next_idx, len(sequence), src_ip, knocked_port)

                if next_idx == len(sequence):
                    success(src_ip)
            else:
                #Reset on incorrect sequence; allow "restart" if they hit first port
                if knocked_port == sequence[0]:
                    state[src_ip] = (1, now)
                    logger.info("Incorrect step but restart from first knock: %s on UDP %d", src_ip, knocked_port)
                else:
                    reset_ip(src_ip)
                    logger.info("Incorrect knock from %s on UDP %d (expected UDP %d) -> reset",
                                src_ip, knocked_port, expected_port)


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server (UDP + iptables)")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports (UDP)",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port (TCP)",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    parser.add_argument(
        "--open-seconds",
        type=float,
        default=DEFAULT_OPEN_SECONDS,
        help="How long to allow the IP after a correct knock",
    )
    parser.add_argument(
        "--no-demo-service",
        action="store_true",
        help="Disable the built-in demo protected TCP service",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()
    logger = logging.getLogger("Main")

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    #Initialize firewall: default DROP protected port
    logger.info("Initializing firewall rules for protected port %s", args.protected_port)
    firewall_init(args.protected_port)

    #Start demo protected service (so nc/ssh-like demo works)
    if not args.no_demo_service:
        start_demo_protected_service(args.protected_port)

    listen_for_knocks(sequence, args.window, args.protected_port, args.open_seconds)


if __name__ == "__main__":
    main()
