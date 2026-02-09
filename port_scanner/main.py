#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional, Tuple, Union



@dataclass
class PortResult:
    host: str
    port: int
    state: str                  
    rtt_ms: float               
    service: str = ""           
    banner: str = ""            
    error: str = ""             


def parse_ports(spec: str) -> List[int]:
    """Parse ports like '1-1024' or '22,80,443' into a unique sorted list."""
    ports = set()
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    for part in parts:
        if "-" in part:
            a, b = part.split("-", 1)
            start = int(a.strip())
            end = int(b.strip())
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            for p in range(start, end + 1):
                ports.add(p)
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def expand_targets(target: str) -> List[str]:
    """Expand CIDR into host IPs; otherwise return the input as a single target."""
    target = target.strip()
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses == 1:
            return [str(net.network_address)]
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [target]



COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5672: "amqp",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}


def sanitize_banner(b: bytes, max_len: int = 160) -> str:
    """Keep banner printable + short."""
    text = b[:max_len].decode(errors="replace")
    #Collapse whitespace
    text = " ".join(text.split())
    return text


def try_grab_banner(sock: socket.socket, host: str, port: int, read_timeout: float) -> Tuple[str, str]:
    sock.settimeout(read_timeout)
    """Best-effort banner grab; sends HTTP HEAD on common HTTP ports."""
    #If it looks HTTP-ish, try an HTTP HEAD to coax a response
    httpish = port in (80, 443, 8080, 8000, 8008, 8888, 5000, 5001, 3000, 8081, 8443)
    if httpish:
        try:
            req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: port_scanner\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode())
        except OSError:
            pass

    #For many services (SSH/FTP/SMTP/etc.), they talk first.
    try:
        data = sock.recv(512)
    except socket.timeout:
        data = b""
    except OSError:
        data = b""

    banner = sanitize_banner(data) if data else ""
    service = guess_service(port, banner)
    return service, banner


def guess_service(port: int, banner: str) -> str:
    """Lightweight service guess: banner keywords first, then port map."""
    b = banner.lower()
    if "ssh" in b:
        return "ssh"
    if "smtp" in b:
        return "smtp"
    if "ftp" in b:
        return "ftp"
    if "http/" in b or "server:" in b or "<html" in b:
        return "http"
    if "mysql" in b:
        return "mysql"
    if "redis" in b:
        return "redis"

    #Fallback to port map
    return COMMON_SERVICES.get(port, "")



def scan_one(host: str, port: int, timeout: float, grab_banner: bool, read_timeout: float) -> PortResult:
"""Scan a single (host, port) using TCP connect_ex."""
    start = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        # connect_ex returns 0 on success, or errno-style int on failure
        code = s.connect_ex((host, port))
        rtt_ms = (time.perf_counter() - start) * 1000.0

        if code == 0:
            service = ""
            banner = ""
            if grab_banner:
                service, banner = try_grab_banner(s, host, port, read_timeout)
            return PortResult(host=host, port=port, state="open", rtt_ms=round(rtt_ms, 2), service=service, banner=banner)
        else:
            # Common "closed" causes: refused, unreachable, etc.
            err = ""
            try:
                err = f"connect_ex={code}"
            except Exception:
                err = "connect_failed"
            return PortResult(host=host, port=port, state="closed", rtt_ms=round(rtt_ms, 2), error=err)

    except socket.timeout:
        rtt_ms = (time.perf_counter() - start) * 1000.0
        return PortResult(host=host, port=port, state="closed", rtt_ms=round(rtt_ms, 2), error="timeout")
    except OSError as e:
        rtt_ms = (time.perf_counter() - start) * 1000.0
        return PortResult(host=host, port=port, state="closed", rtt_ms=round(rtt_ms, 2), error=f"oserror:{e}")
    finally:
        try:
            s.close()
        except Exception:
            pass


def scan(hosts: List[str], ports: List[int], threads: int, timeout: float, grab_banner: bool, read_timeout: float) -> List[PortResult]:
"""Run threaded scans across all hosts/ports."""
    results: List[PortResult] = []
    tasks = []

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for h in hosts:
            for p in ports:
                tasks.append(ex.submit(scan_one, h, p, timeout, grab_banner, read_timeout))

        for fut in as_completed(tasks):
            try:
                results.append(fut.result())
            except Exception as e:
                #Should be rare because scan_one is defensive, but keep it robust
                results.append(PortResult(host="?", port=-1, state="closed", rtt_ms=0.0, error=f"exception:{e}"))

    #Sort: host, open first, then port
    results.sort(key=lambda r: (r.host, 0 if r.state == "open" else 1, r.port))
    return results


def print_table(results: List[PortResult], show_closed: bool) -> None:
    """Pretty text table output."""
    headers = ["HOST", "PORT", "STATE", "RTT(ms)", "SERVICE", "BANNER/ERROR"]
    rows = []
    for r in results:
        if (not show_closed) and r.state != "open":
            continue
        extra = r.banner if r.state == "open" else r.error
        rows.append([r.host, str(r.port), r.state, f"{r.rtt_ms:.2f}", r.service, extra])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    def fmt_row(row: List[str]) -> str:
        return "  ".join(cell.ljust(col_widths[i]) for i, cell in enumerate(row))

    print(fmt_row(headers))
    print("  ".join("-" * w for w in col_widths))
    for row in rows:
        print(fmt_row(row))


def write_json(results: List[PortResult], path: str) -> None:
"""Write JSON output file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2)


def write_csv(results: List[PortResult], path: str) -> None:
    """Write CSV output file."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["host", "port", "state", "rtt_ms", "service", "banner", "error"])
        w.writeheader()
        for r in results:
            w.writerow(asdict(r))



TIMING_PRESETS = {
    "polite":   {"timeout": 1.5, "read_timeout": 1.0, "threads": 50},
    "normal":   {"timeout": 0.8, "read_timeout": 0.6, "threads": 150},
    "aggressive": {"timeout": 0.4, "read_timeout": 0.3, "threads": 300},
}


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="port_scanner", description="TCP connect port scanner (authorized lab use).")
    p.add_argument("--target", required=True, help="Target host/IP or CIDR (e.g., 172.20.0.0/24)")
    p.add_argument("--ports", required=True, help='Port spec like "1-1024" or "22,80,443"')
    p.add_argument("--threads", type=int, default=None, help="Worker threads (default from timing preset)")
    p.add_argument("--timeout", type=float, default=None, help="Connect timeout seconds (default from timing preset)")
    p.add_argument("--read-timeout", type=float, default=None, help="Banner read timeout seconds")
    p.add_argument("--timing", choices=TIMING_PRESETS.keys(), default="normal", help="Convenience preset")
    p.add_argument("--no-banner", action="store_true", help="Disable banner grabbing")
    p.add_argument("--show-closed", action="store_true", help="Include closed ports in output table")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text", help="Output format")
    p.add_argument("--out", default="", help="Output file path for json/csv (required for those formats)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    preset = TIMING_PRESETS[args.timing]
    threads = args.threads if args.threads is not None else preset["threads"]
    timeout = args.timeout if args.timeout is not None else preset["timeout"]
    read_timeout = args.read_timeout if args.read_timeout is not None else preset["read_timeout"]
    grab_banner = not args.no_banner

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] Port parse error: {e}", file=sys.stderr)
        return 2

    hosts = expand_targets(args.target)
    if not hosts:
        print("[!] No targets resolved.", file=sys.stderr)
        return 2

    print(f"[*] Targets: {len(hosts)} host(s)")
    print(f"[*] Ports: {len(ports)} port(s)")
    print(f"[*] Threads={threads} timeout={timeout}s read_timeout={read_timeout}s banner={grab_banner} timing={args.timing}")

    t0 = time.perf_counter()
    results = scan(hosts, ports, threads=threads, timeout=timeout, grab_banner=grab_banner, read_timeout=read_timeout)
    elapsed = time.perf_counter() - t0

    open_count = sum(1 for r in results if r.state == "open")
    print(f"\n[+] Scan complete in {elapsed:.2f}s. Open ports: {open_count}")

    if args.format == "text":
        print()
        print_table(results, show_closed=args.show_closed)
    elif args.format in ("json", "csv"):
        if not args.out:
            print("[!] --out is required for json/csv output.", file=sys.stderr)
            return 2
        if args.format == "json":
            write_json(results, args.out)
        else:
            write_csv(results, args.out)
        print(f"[+] Wrote {args.format.upper()} to {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
