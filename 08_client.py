"""
08_client.py -- File Requester Client (Laptop 3)
=================================================
Runs on Laptop 3 (the user/client machine).
Requests files from the attack server on Laptop 1.
All traffic passes THROUGH Vyuh on Laptop 2.

3-Laptop flow:
    Laptop 3 (this script)
        |  HTTP request
        v
    Laptop 2 (Vyuh proxy at LAPTOP2_IP:VYUH_PROXY_PORT)
        |  Vyuh inspects ALL packets here, generates alerts
        |  then forwards the request to server
        v
    Laptop 1 (07_attack_server.py at LAPTOP1_IP:ATTACK_SERVER_PORT)
        |  Serves file + embeds all 6 attacks in HTTP response
        v
    Laptop 2 (Vyuh)
        |  Vyuh inspects the RESPONSE too -- catches:
        |    [1] C2 Beacon headers in the HTTP response
        |    [2] High-entropy data appended to file body
        |    [3] DGA DNS queries fired from server
        |    [4] DNS tunnel queries from server
        |    [5] Exfil POST from server to itself
        |    [6] Port scan from server toward client IP
        v
    Laptop 3 (this script receives the file with attacks embedded)

Usage (on Laptop 3):
    # Request all files once:
    python 08_client.py

    # Request repeatedly to simulate real user activity:
    python 08_client.py --loop --interval 10

    # Override IPs from command line:
    python 08_client.py --server 192.168.1.10 --proxy 192.168.1.20:8080

    # Direct mode (no Vyuh proxy -- for comparison):
    python 08_client.py --no-proxy
"""

import urllib.request
import urllib.error
import argparse
import time
import sys
import os
import json
import base64
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
import config

# ---- Files to request from the server ----------------------------------------
FILES_TO_REQUEST = [
    "financial_report.txt",
    "customers.csv",
    "dashboard.html",
    "credentials.txt",
    "logo.png",
]

BANNER = """
+--------------------------------------------------------------+
|    Vyuh Attack Sim -- 08 CLIENT (Laptop 3)                   |
|    Requests files through Vyuh detection layer               |
+--------------------------------------------------------------+
"""

# ---- Attack header keys Vyuh should detect -----------------------------------
ATTACK_HEADERS = [
    "X-Beacon-Id",
    "X-Session-Token",
    "X-C2-Server",
    "X-C2-Interval",
    "X-Beacon-Proto",
    "X-Exfil-Mark",
    "X-DGA-Domain",
    "X-Implant-Ver",
    "X-Attack-Embed",
]


def make_request(url: str, proxy_url: str = None) -> dict:
    """
    Perform HTTP GET request, optionally through Vyuh proxy.
    Returns a dict with response details including detected attack headers.
    """
    result = {
        "url":            url,
        "proxy":          proxy_url,
        "status":         None,
        "size":           0,
        "attack_headers": {},
        "error":          None,
        "ts":             datetime.now().strftime("%H:%M:%S"),
    }

    try:
        # Configure proxy if given
        if proxy_url:
            proxy_handler = urllib.request.ProxyHandler({
                "http": proxy_url,
            })
            opener = urllib.request.build_opener(proxy_handler)
        else:
            opener = urllib.request.build_opener()

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Client Laptop)"},
        )

        with opener.open(req, timeout=10) as resp:
            result["status"] = resp.status
            body = resp.read()
            result["size"]   = len(body)

            # Extract attack-related headers from the response
            for h in ATTACK_HEADERS:
                val = resp.headers.get(h)
                if val:
                    result["attack_headers"][h] = val

    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["error"]  = str(e)
    except urllib.error.URLError as e:
        result["error"] = str(e.reason)
    except Exception as e:
        result["error"] = str(e)

    return result


def print_result(result: dict, file_num: int, total: int):
    """Pretty-print a request result, highlighting detected attack headers."""
    ts     = result["ts"]
    url    = result["url"].split("/")[-1]
    status = result["status"] or "ERR"
    size   = result["size"]
    err    = result["error"]

    ok_sym = "OK " if result["status"] == 200 else "ERR"
    print(f"\n  [{ok_sym}] [{ts}] ({file_num}/{total}) {url}")

    if err:
        print(f"        Error : {err}")
        return

    print(f"        Status : {status}   Size: {size:,} bytes")

    routed = "via Vyuh proxy" if result["proxy"] else "DIRECT (no proxy)"
    print(f"        Route  : {routed}")

    if result["attack_headers"]:
        print(f"        Attack headers detected by Vyuh:")
        for h, v in result["attack_headers"].items():
            # Truncate long values
            display = v if len(v) <= 60 else v[:57] + "..."
            print(f"          [{h}] = {display}")
    else:
        print(f"        No attack headers in response (check Vyuh dashboard)")


def run_requests(server_url: str, proxy_url: str, loop: bool, interval: float):
    """Main request loop."""
    round_num = 0

    while True:
        round_num += 1
        if loop:
            print(f"\n  {'='*60}")
            print(f"  REQUEST ROUND #{round_num}  [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]")
            print(f"  {'='*60}")

        results = []
        for i, filename in enumerate(FILES_TO_REQUEST, 1):
            url    = f"{server_url}/files/{filename}"
            result = make_request(url, proxy_url)
            results.append(result)
            print_result(result, i, len(FILES_TO_REQUEST))
            time.sleep(0.5)  # Small gap between requests

        # Summary for this round
        ok_count  = sum(1 for r in results if r["status"] == 200)
        total_kb  = sum(r["size"] for r in results) / 1024
        hdrs_seen = sum(len(r["attack_headers"]) for r in results)

        print(f"\n  Round #{round_num} Summary:")
        print(f"    Files received       : {ok_count}/{len(FILES_TO_REQUEST)}")
        print(f"    Total data received  : {total_kb:.1f} KB")
        print(f"    Attack headers found : {hdrs_seen} across all responses")
        print(f"    (Vyuh should have flagged these in its dashboard)")

        if not loop:
            break

        print(f"\n  Next round in {interval:.0f}s... (Ctrl+C to stop)")
        time.sleep(interval)


def main():
    print(BANNER)

    # Build defaults from config
    server_default = f"http://{config.LAPTOP1_IP}:{config.ATTACK_SERVER_PORT}"
    proxy_default  = f"http://{config.LAPTOP2_IP}:{config.VYUH_PROXY_PORT}"

    parser = argparse.ArgumentParser(
        description="File Client (Laptop 3) -- Vyuh Attack Simulation"
    )
    parser.add_argument(
        "--server", default=server_default,
        help=f"Attack server URL (default: {server_default})"
    )
    parser.add_argument(
        "--proxy", default=proxy_default,
        help=f"Vyuh proxy URL (default: {proxy_default})"
    )
    parser.add_argument(
        "--no-proxy", action="store_true",
        help="Connect directly to server, bypassing Vyuh (comparison mode)"
    )
    parser.add_argument(
        "--loop", action="store_true",
        help="Keep requesting files repeatedly to simulate ongoing user activity"
    )
    parser.add_argument(
        "--interval", default=15.0, type=float,
        help="Seconds between request rounds when --loop is set (default: 15)"
    )
    args = parser.parse_args()

    proxy_url = None if args.no_proxy else args.proxy

    # Print setup
    print(f"  This script runs on : Laptop 3 (Client)")
    print(f"  Requesting from     : {args.server}  (Laptop 1 - Server)")
    if proxy_url:
        print(f"  Routed through      : {proxy_url}  (Laptop 2 - Vyuh)")
        print(f"  Vyuh will inspect   : every request AND response packet")
    else:
        print(f"  Route               : DIRECT -- Vyuh NOT in the path")
        print(f"  (Run without --no-proxy to route through Vyuh)")

    print(f"\n  Files to request:")
    for f in FILES_TO_REQUEST:
        print(f"    {args.server}/files/{f}")

    print(f"\n  What Vyuh (Laptop 2) will detect in the traffic:")
    print(f"    [1] C2 Beacon headers  -- in every HTTP response")
    print(f"    [2] Embedded C2 block  -- high-entropy data in file body")
    print(f"    [3] DGA DNS queries    -- from Laptop 1 after each request")
    print(f"    [4] DNS tunnel queries -- encoded file bytes as DNS subdomains")
    print(f"    [5] Exfil POST traffic -- Laptop 1 re-POSTing files to itself")
    print(f"    [6] Port scan traffic  -- Laptop 1 scanning Laptop 3's ports")

    print("\n  " + "-"*62)

    run_requests(
        server_url = args.server,
        proxy_url  = proxy_url,
        loop       = args.loop,
        interval   = args.interval,
    )

    print(f"\n  Done. Check Vyuh dashboard on Laptop 2 for alerts.")


if __name__ == "__main__":
    main()
