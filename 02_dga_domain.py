"""
02_dga_domain.py — DGA (Domain Generation Algorithm) Simulation
================================================================
Simulates malware-style DGA: generates pseudo-random domain names
using a seed (date-based or custom) and attempts DNS resolution.

This mimics how botnets find their C2 servers via algorithmically
generated domains that rotate daily — a key indicator for Vyuh to detect.

Usage:
    python 02_dga_domain.py
    python 02_dga_domain.py --seed myseed --count 50 --tld .com
"""

import hashlib
import socket
import string
import argparse
import logging
import time
import random
import math
from datetime import datetime, date
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
log = logging.getLogger("dga_domain")

BANNER = """
╔══════════════════════════════════════════════════╗
║    Vyuh Attack Sim — 02 DGA DOMAIN GENERATION    ║
╚══════════════════════════════════════════════════╝
"""

CHARSET = string.ascii_lowercase + string.digits


# ── DGA Algorithms ────────────────────────────────────────────────────────────

def dga_md5(seed: str, index: int, length: int = 12) -> str:
    """
    MD5-based DGA — widely used in real malware families.
    Uses MD5 hash of (seed + index) truncated to domain-like length.
    """
    raw = hashlib.md5(f"{seed}{index}".encode()).hexdigest()
    # Map hex chars to a-z range for more realistic domain look
    domain = ""
    for ch in raw[:length]:
        if ch.isdigit():
            domain += CHARSET[int(ch) % 26]  # map digit to letter
        else:
            domain += ch
    return domain


def dga_sha256(seed: str, index: int, length: int = 10) -> str:
    """SHA-256 based DGA — higher entropy, harder to sinkhole."""
    raw = hashlib.sha256(f"{seed}{index}".encode()).hexdigest()
    domain = "".join(
        ch if ch.isalpha() else CHARSET[int(ch) % 26]
        for ch in raw[:length]
    )
    return domain


def dga_arithmetic(seed_date: date, index: int) -> str:
    """
    Arithmetic DGA — uses date arithmetic (common in Conficker-like malware).
    Generates domain based on year/month/day math.
    """
    year  = seed_date.year
    month = seed_date.month
    day   = seed_date.day

    domain = ""
    val = (year * 100 + month) * 100 + day + index * 31337
    while len(domain) < 12:
        domain += CHARSET[val % len(CHARSET)]
        val = val // len(CHARSET) + index
    return domain


def dga_wordlist(seed: str, index: int) -> str:
    """
    Wordlist-based DGA — concatenates pseudo-random word fragments.
    Produces more 'pronounceable' looking domains.
    """
    prefixes = ["sys", "net", "win", "host", "proc", "srv", "api",
                 "cdn", "img", "auth", "web", "app", "log", "data"]
    suffixes = ["update", "sync", "check", "ping", "info", "core",
                 "link", "stats", "cfg", "mgmt", "ctrl", "rpc"]

    random.seed(f"{seed}{index}")
    pre = random.choice(prefixes)
    suf = random.choice(suffixes)
    num = random.randint(10, 9999)
    return f"{pre}{suf}{num}"


# ── Shannon Entropy ───────────────────────────────────────────────────────────
def shannon_entropy(domain: str) -> float:
    """Calculate Shannon entropy of domain string (higher = more DGA-like)."""
    freq = {}
    for ch in domain:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(domain)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


# ── DNS Resolution ────────────────────────────────────────────────────────────
def resolve_domain(fqdn: str, timeout: float = 2.0) -> tuple[bool, str]:
    """
    Attempt to resolve a domain. Returns (resolved, ip_or_error).
    Real malware would then connect to the resolved IP as its C2.
    """
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        ip = socket.gethostbyname(fqdn)
        return True, ip
    except socket.gaierror as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)
    finally:
        socket.setdefaulttimeout(old_timeout)


# ── Generate domains ──────────────────────────────────────────────────────────
def generate_domains(seed: str, count: int, tld: str,
                     algorithm: str = "md5") -> list[dict]:
    """Generate `count` DGA domains using the specified algorithm."""
    domains = []
    seed_date = config.DGA_SEED_DATE or date.today()

    algo_map = {
        "md5":        lambda i: dga_md5(seed, i),
        "sha256":     lambda i: dga_sha256(seed, i),
        "arithmetic": lambda i: dga_arithmetic(seed_date, i),
        "wordlist":   lambda i: dga_wordlist(seed, i),
    }
    gen = algo_map.get(algorithm, algo_map["md5"])

    for i in range(count):
        name   = gen(i)
        fqdn   = f"{name}{tld}"
        entropy = shannon_entropy(name)
        domains.append({
            "index":   i,
            "name":    name,
            "fqdn":    fqdn,
            "entropy": round(entropy, 3),
        })
    return domains


# ── Simulate malware behavior ─────────────────────────────────────────────────
def simulate_malware_lookup(domains: list[dict], resolve: bool,
                             delay: float = 0.3):
    """
    Simulate a bot iterating through DGA domains looking for an active C2.
    Generates high-entropy DNS queries — exactly what Vyuh should catch.
    """
    log.info(f"[*] Starting DGA lookup simulation — {len(domains)} domains")
    resolved_count = 0
    nxdomain_count = 0

    print(f"\n  {'#':<4} {'FQDN':<35} {'ENTROPY':<8} {'RESULT'}")
    print(f"  {'-'*4} {'-'*35} {'-'*8} {'-'*20}")

    for d in domains:
        result_str = "—"
        if resolve:
            ok, result = resolve_domain(d["fqdn"])
            if ok:
                result_str = f"✅ {result}"
                resolved_count += 1
                log.info(f"DGA domain RESOLVED: {d['fqdn']} -> {result}")
                # In real malware, execution would stop here and connect to C2
                break
            else:
                result_str = "NXDOMAIN"
                nxdomain_count += 1
                log.debug(f"DGA domain NXDOMAIN: {d['fqdn']}")
        else:
            result_str = "(resolution disabled)"

        print(f"  {d['index']:<4} {d['fqdn']:<35} {d['entropy']:<8} {result_str}")
        time.sleep(delay)  # Jitter between lookups — mimics real malware

    return resolved_count, nxdomain_count


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="DGA Domain Simulation — Vyuh")
    parser.add_argument("--seed",      default=str(date.today()),    help="DGA seed string")
    parser.add_argument("--count",     default=config.DGA_DOMAIN_COUNT, type=int, help="Domains to generate")
    parser.add_argument("--tld",       default=".com",               help="TLD to append")
    parser.add_argument("--algo",      default="md5",
                        choices=["md5", "sha256", "arithmetic", "wordlist"],
                        help="DGA algorithm")
    parser.add_argument("--resolve",   action="store_true",          help="Attempt DNS resolution")
    parser.add_argument("--no-resolve",action="store_true",          help="Skip DNS resolution")
    parser.add_argument("--delay",     default=0.3, type=float,      help="Delay between lookups (s)")
    args = parser.parse_args()

    do_resolve = config.DGA_RESOLVE if not args.no_resolve else False
    if args.resolve:
        do_resolve = True

    log.info(f"=== DGA Simulation started | algo={args.algo} seed={args.seed} count={args.count} ===")
    print(f"  Algorithm : {args.algo.upper()}")
    print(f"  Seed      : {args.seed}")
    print(f"  Count     : {args.count}")
    print(f"  TLD       : {args.tld}")
    print(f"  Resolve   : {'Yes' if do_resolve else 'No (generation only)'}")

    # Generate
    domains = generate_domains(args.seed, args.count, args.tld, args.algo)

    # Run lookup simulation
    resolved, nxdomain = simulate_malware_lookup(domains, do_resolve, args.delay)

    # Summary
    print("\n" + "═" * 52)
    print("  DGA SIMULATION SUMMARY")
    print("═" * 52)
    print(f"  Domains generated : {len(domains)}")
    if do_resolve:
        print(f"  Resolved (active) : {resolved}")
        print(f"  NXDOMAIN          : {nxdomain}")

    avg_entropy = sum(d["entropy"] for d in domains) / len(domains)
    print(f"  Avg. entropy      : {avg_entropy:.3f} bits")
    print(f"  (Human domains avg ~2.5-3.5, DGA typically >3.8)")
    print("═" * 52)
    log.info(f"DGA simulation complete: {len(domains)} domains, avg entropy={avg_entropy:.3f}")

    # Also show all 4 algorithms for comparison
    print("\n  [INFO] Domains across all 4 algorithms (first 3 each):")
    for algo in ["md5", "sha256", "arithmetic", "wordlist"]:
        samples = generate_domains(args.seed, 3, args.tld, algo)
        names = [d["fqdn"] for d in samples]
        print(f"  {algo.upper():<12}: {' | '.join(names)}")


if __name__ == "__main__":
    main()
