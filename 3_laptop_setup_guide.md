# 3-Laptop Lab Setup Guide
## Vyuh Attack Simulation — Complete Step-by-Step

---

## What Each Laptop Does

```
LAPTOP 1                    LAPTOP 2                    LAPTOP 3
(Server / Attacker)         (Vyuh / Detector)           (Client / User)
─────────────────           ─────────────────           ─────────────────
Runs the file server.       Vyuh sits here.             Requests files.
Serves real files           Sees ALL traffic            Gets files back
(images, docs, CSV)         between L1 and L3.          with attacks
PLUS embeds all 6           Detects attacks,            embedded inside.
attacks into every          generates alerts.
HTTP response.              Does NOT block —
                            only detects & reports.
```

---

## STEP 0 — Physical Network Setup

Connect all 3 laptops to the **same WiFi router or network switch**.

```
        [WiFi Router / Network Switch]
               |          |          |
          Laptop 1    Laptop 2    Laptop 3
```

> [!IMPORTANT]
> All 3 laptops must be able to ping each other.
> Test: open CMD on Laptop 3, run `ping 192.168.13.7` (Laptop 1's IP).

---

## STEP 1 — Find the IP address of each laptop

Run this command on **each laptop** to find its IP:

```cmd
ipconfig
```

Look for `IPv4 Address` under your WiFi or Ethernet adapter.
Write them down:

| Laptop | Role | IP |
|--------|------|----|
| Laptop 1 | Server | `192.168.13.7` |
| Laptop 2 | Vyuh | `10.82.166.1` |
| Laptop 3 | Client | `10.124.150.101` |

---

## STEP 2 — Copy the project to all 3 laptops

Copy the entire `attacks for vyuh/` folder to all 3 laptops.
All 3 laptops need the same files.

> [!TIP]
> Use a USB drive, shared folder, or `git clone` if it's in a repo.

---

## STEP 3 — Edit config.py on ALL 3 laptops

Open `config.py` and set the 3 real IPs you found in Step 1:

```python
LAPTOP1_IP = "192.168.13.7"     # Laptop 1 — Server
LAPTOP2_IP = "10.82.166.1"     # Laptop 2 — Vyuh (detector)
LAPTOP3_IP = "10.124.150.101"  # Laptop 3 — Client
```

Save the file. Do this on all 3 laptops.

---

## STEP 4 — Install Python and requirements on all 3 laptops

```cmd
pip install -r requirements.txt
```

---

## STEP 5 — How Vyuh sits in the middle (2 options)

### Option A — Vyuh as HTTP Proxy (EASIEST for lab)

```
Laptop 3  ──HTTP request──▶  Laptop 2 (Vyuh proxy:8080)  ──▶  Laptop 1 (server:8888)
                                        │
                              Vyuh inspects here
                              Sees: C2 headers, DGA,
                              DNS tunnel, exfil, port scan
                                        │
Laptop 3  ◀─ file + attacks ──────────◀┘
```

**Configure Vyuh on Laptop 2 to listen on port 8080 as HTTP proxy.**
Laptop 3 will send all requests to Laptop 2:8080.
Vyuh forwards to Laptop 1:8888, inspects both request and response.

### Option B — Network Bridge / TAP (Vyuh sees raw packets)

```
Laptop 3  ──▶  [Managed Switch with port mirroring]  ──▶  Laptop 1
                           │
                    Vyuh gets a copy
                    of ALL packets
                    (passive tap)
```

If Vyuh is a passive packet sniffer (listens on network interface),
use Option B. No proxy config needed — Vyuh just watches.

> [!NOTE]
> Ask your Vyuh documentation which mode it uses.
> Most detection tools support proxy mode. Use Option A if unsure.

---

## STEP 6 — Start everything (in this order)

### On Laptop 2 (Vyuh) — START FIRST
Start Vyuh and configure it to:
- Listen as proxy on port `8080`  
- Forward requests to `192.168.13.7:8888` (Laptop 1)
- Monitor and alert on: C2 headers, DGA DNS, DNS tunneling, data exfil, port scan

*(Refer to your Vyuh documentation for exact startup steps)*

---

### On Laptop 1 (Server) — START SECOND

```cmd
cd "attacks for vyuh"
python 07_attack_server.py
```

You will see:
```
[1] Creating sample assets...
    financial_report.txt  (348 bytes)
    customers.csv         (1,888 bytes)
    dashboard.html        (319 bytes)
    credentials.txt       (173 bytes)
    logo.png              (76 bytes)

Running at http://0.0.0.0:8888 -- Ctrl+C to stop
```

The server is now ready and waiting for requests.

---

### On Laptop 3 (Client) — START LAST

**Through Vyuh proxy (recommended — Vyuh will see everything):**
```cmd
cd "attacks for vyuh"
python 08_client.py --proxy http://10.82.166.1:8080
```

**Direct to server (for comparison — Vyuh won't see HTTP layer):**
```cmd
python 08_client.py --no-proxy
```

**Continuous mode (keeps requesting every 15 seconds):**
```cmd
python 08_client.py --proxy http://10.82.166.1:8080 --loop --interval 15
```

---

## STEP 7 — What happens on each file request

```
Laptop 3 requests: /files/financial_report.txt

    │
    ▼ HTTP GET → Laptop 2 (Vyuh)
    │            Vyuh logs request, forwards to Laptop 1
    │
    ▼ Laptop 1 receives request
    │
    │  [1] Reads real financial_report.txt
    │  [2] ADDS 9 attack headers to HTTP response:
    │        X-Beacon-Id: 1
    │        X-Session-Token: eyJpZCI6IDEs...  (base64 implant data)
    │        X-C2-Server: 192.168.13.7:8888
    │        X-C2-Interval: 30
    │        X-Beacon-Proto: dns
    │        X-Exfil-Mark: RVhGSUx8aG9z...
    │        X-DGA-Domain: bbfddcfajcga.com
    │        X-Implant-Ver: 4.2.1
    │        X-Attack-Embed: TEXT+C2_BLOCK
    │
    │  [3] APPENDS C2 command block to file body:
    │        <!-- [SYS:eyJjbWQiOiAiZXhlY...] -->
    │        <!-- X-DGA:bbfddcfajcga.com -->
    │
    │  [4] Fires background threads:
    │        [DGA]    Resolves 5 high-entropy domains via DNS
    │        [TUNNEL] Encodes file bytes into DNS subdomain queries
    │        [EXFIL]  POSTs the file to 192.168.13.7 (itself)
    │        [SCAN]   Scans ports 21,22,23,80,443... on 10.124.150.101
    │
    ▼ HTTP Response goes back through Laptop 2 (Vyuh)
    │  Vyuh inspects the RESPONSE and sees:
    │    → C2 Beacon headers (beaconing pattern)
    │    → High-entropy body (embedded C2 block)
    │    → DGA DNS queries in DNS traffic
    │    → DNS tunnel queries in DNS traffic
    │    → Exfil POST traffic from Laptop 1
    │    → Port scan traffic from Laptop 1 → Laptop 3
    │
    ▼ Laptop 3 receives file
      File arrives but contains embedded attack data
```

---

## STEP 8 — What Vyuh Should Alert On

| # | Alert Type | What Vyuh sees |
|---|-----------|---------------|
| 1 | **C2 Beaconing** | `X-Beacon-Id` incrementing, `X-C2-Server` pointing to a host, periodic pattern |
| 2 | **Body Embedding** | High-entropy base64 block appended after legitimate file content |
| 3 | **DGA Detection** | Burst of DNS queries for `bbfddcfajcga.com`, `fbdjjgjefffi.com` — high Shannon entropy |
| 4 | **DNS Tunneling** | DNS TXT queries with base32 subdomains like `0001.jbswy3dpehpk3pxp.lab.local` |
| 5 | **Data Exfiltration** | Large HTTP POST from Laptop 1 to itself — same file going to 2 destinations |
| 6 | **Port Scan** | TCP connection attempts from Laptop 1 → Laptop 3 on ports 21,22,23,80,443… |

---

## STEP 9 — Verify it's working

### Check Laptop 1 server log:
```
attack_log.txt
```
You should see lines like:
```
[INFO] [HTTP] 10.124.150.101 -- "GET /files/customers.csv HTTP/1.1" 200
[INFO] [DGA] NXDOMAIN: fbdjjgjefffi.com (entropy=3.81)
[INFO] [DNS-TUNNEL] Tunneling 200B in 11 DNS queries
[INFO] [EXFIL] 'customers.csv' (1888B) -> 192.168.13.7
[INFO] [PORT-SCAN] 10.124.150.101:135 -- OPEN
```

### Check Laptop 3 client output:
You should see attack headers printed for every file:
```
[OK] financial_report.txt
     [X-Beacon-Id]     = 1
     [X-C2-Server]     = 192.168.13.7:8888
     [X-DGA-Domain]    = bbfddcfajcga.com
     ...
Attack headers found: 45 across all responses
```

### Check Vyuh dashboard on Laptop 2:
Should show alerts for all 6 attack types.

---

## Quick Reference — Commands Summary

| Laptop | Command |
|--------|---------|
| **1 (Server)** | `python 07_attack_server.py` |
| **2 (Vyuh)** | Start Vyuh, configure proxy on port 8080 |
| **3 (Client)** | `python 08_client.py --proxy http://10.82.166.1:8080` |
| **3 (loop)** | `python 08_client.py --proxy http://10.82.166.1:8080 --loop` |
| **3 (no proxy)** | `python 08_client.py --no-proxy` *(for comparison)* |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Client can't reach server | Check firewall on Laptop 1: allow port 8888 |
| Vyuh doesn't see traffic | Make sure client uses `--proxy http://LAPTOP2_IP:8080` |
| DNS attacks not showing | Vyuh must sniff UDP port 53 on the LAN interface |
| Port scan not showing | Vyuh must see TCP traffic between Laptop 1 and Laptop 3 |
| `No attack headers found` | Server not running or wrong `--server` IP |

**Allow server port through Windows Firewall on Laptop 1:**
```cmd
netsh advfirewall firewall add rule name="VyuhAttackServer" dir=in action=allow protocol=TCP localport=8888
```
