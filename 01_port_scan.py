"""
01_port_scan.py — Port Scan Attack Simulation
==============================================
Simulates TCP connect scan and UDP scan across a target's port range.
Designed to trigger port sweep / horizontal scan alerts in Vyuh.

Usage:
    python 01_port_scan.py
    python 01_port_scan.py --target 192.168.1.50 --ports 1-65535
"""

import socket
import argparse
import logging
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
import config

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(config.LOG_FILE, mode="a"),
    ]
)
log = logging.getLogger("port_scan")

# ── Globals ───────────────────────────────────────────────────────────────────
open_ports   = []
closed_ports = []
lock         = threading.Lock()

BANNER = """
╔══════════════════════════════════════════════════╗
║       Vyuh Attack Sim — 01 PORT SCANNER          ║
╚══════════════════════════════════════════════════╝
"""

# ── TCP Connect Scan ──────────────────────────────────────────────────────────
def tcp_connect_scan(target: str, port: int, timeout: float) -> bool:
    """Attempt a TCP connection to determine if port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            return result == 0
    except (socket.error, OSError):
        return False


# ── UDP Scan ──────────────────────────────────────────────────────────────────
def udp_scan(target: str, port: int, timeout: float) -> str:
    """
    Send a UDP packet and infer state from response (or lack thereof).
    Returns: 'open|filtered', 'closed', or 'filtered'
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00" * 16, (target, port))
            try:
                s.recvfrom(1024)
                return "open"
            except socket.timeout:
                return "open|filtered"
    except (socket.error, OSError):
        return "closed"


# ── Worker ────────────────────────────────────────────────────────────────────
def scan_port(target: str, port: int, timeout: float, mode: str):
    """Scan a single port and record result."""
    if mode == "tcp":
        is_open = tcp_connect_scan(target, port, timeout)
        state   = "OPEN" if is_open else "closed"
    else:
        state   = udp_scan(target, port, timeout)
        is_open = state in ("open", "open|filtered")

    with lock:
        if is_open:
            open_ports.append((port, mode.upper(), state))
            log.info(f"  [+] {target}:{port}/{mode.upper()} — {state}")
        else:
            closed_ports.append(port)

    return port, state


# ── Common ports quick scan ───────────────────────────────────────────────────
def quick_scan(target: str, timeout: float):
    """Scan only the most common ports (fast, highly detectable)."""
    log.info(f"[*] Quick scan of {len(config.COMMON_PORTS)} common ports on {target}")
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(scan_port, target, p, timeout, "tcp"): p
                   for p in config.COMMON_PORTS}
        for f in as_completed(futures):
            pass  # results collected via lock


# ── Full range scan ───────────────────────────────────────────────────────────
def full_scan(target: str, start: int, end: int, timeout: float,
              mode: str = "tcp", max_workers: int = 100):
    """Scan all ports in [start, end] range."""
    total = end - start + 1
    log.info(f"[*] Full {mode.upper()} scan of ports {start}–{end} ({total} ports) on {target}")
    log.info(f"[*] Threads: {max_workers} | Timeout: {timeout}s")

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_port, target, p, timeout, mode): p
                   for p in range(start, end + 1)}
        done = 0
        for f in as_completed(futures):
            done += 1
            if done % 100 == 0:
                pct = (done / total) * 100
                print(f"\r  Progress: {done}/{total} ports ({pct:.1f}%)", end="", flush=True)
    print()


# ── Banner grab ───────────────────────────────────────────────────────────────
def grab_banner(target: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="replace").strip()
            return banner[:120]
    except Exception:
        return ""


# ── Report ────────────────────────────────────────────────────────────────────
def print_report(target: str, start_time: datetime):
    elapsed = (datetime.now() - start_time).total_seconds()
    print("\n" + "═" * 52)
    print(f"  SCAN REPORT — {target}")
    print("═" * 52)
    print(f"  Scan completed in {elapsed:.2f}s")
    print(f"  Open ports found: {len(open_ports)}")
    print(f"  Closed/filtered:  {len(closed_ports)}")
    print()
    if open_ports:
        print(f"  {'PORT':<8} {'PROTO':<6} {'STATE'}")
        print(f"  {'-'*8} {'-'*6} {'-'*12}")
        for port, proto, state in sorted(open_ports, key=lambda x: x[0]):
            banner = grab_banner(target, port) if proto == "TCP" else ""
            banner_str = f"  [{banner[:60]}]" if banner else ""
            print(f"  {port:<8} {proto:<6} {state}{banner_str}")
    else:
        print("  No open ports found.")
    print("═" * 52)
    log.info(f"Scan report: {len(open_ports)} open ports on {target} in {elapsed:.2f}s")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="Port Scanner — Vyuh Attack Simulation")
    parser.add_argument("--target",  default=config.TARGET_IP,          help="Target IP address")
    parser.add_argument("--start",   default=config.PORT_SCAN_RANGE_START, type=int, help="Start port")
    parser.add_argument("--end",     default=config.PORT_SCAN_RANGE_END,   type=int, help="End port")
    parser.add_argument("--timeout", default=config.PORT_SCAN_TIMEOUT,     type=float, help="Timeout per port (s)")
    parser.add_argument("--mode",    default="tcp", choices=["tcp", "udp", "both"], help="Scan mode")
    parser.add_argument("--quick",   action="store_true", help="Scan common ports only")
    parser.add_argument("--workers", default=100, type=int, help="Max parallel threads")
    args = parser.parse_args()

    log.info(f"=== Port Scan started on target: {args.target} ===")
    start_time = datetime.now()

    if args.quick:
        quick_scan(args.target, args.timeout)
    else:
        if args.mode in ("tcp", "both"):
            full_scan(args.target, args.start, args.end,
                      args.timeout, "tcp", args.workers)
        if args.mode in ("udp", "both"):
            full_scan(args.target, args.start, min(args.end, 1024),
                      args.timeout * 2, "udp", args.workers // 2)

    print_report(args.target, start_time)


if __name__ == "__main__":
    main()
