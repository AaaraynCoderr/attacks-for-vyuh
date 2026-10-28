# ============================================================
#  config.py -- Shared configuration for all attack scripts
#  Edit these values to match your lab environment
# ============================================================

# ============================================================
#  3-LAPTOP LAB SETUP
#  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
#  │  LAPTOP 1    │────▶│  LAPTOP 2    │────▶│  LAPTOP 3    │
#  │  Server      │     │  Vyuh        │     │  Client      │
#  │  (attacker)  │     │  (detector)  │     │  (user)      │
#  │  08:attack   │     │  monitors &  │     │  08:client   │
#  │  server runs │     │  reports     │     │  requests    │
#  │  here        │     │  all attacks │     │  files       │
#  └──────────────┘     └──────────────┘     └──────────────┘
#
#  SET THESE 3 IPs to match your actual laptops:
# ============================================================
LAPTOP1_IP = "10.82.166.229"    # Laptop 1: runs 07_attack_server.py  (SERVER)
LAPTOP2_IP = "10.82.166.1"     # Laptop 2: runs Vyuh detection tool  (VYUH)
LAPTOP3_IP = "10.82.166.101"    # Laptop 3: runs 08_client.py         (CLIENT)

# How traffic flows through Vyuh (choose one):
#   "proxy"       -- Client sends requests to Vyuh proxy, Vyuh forwards to server
#   "transparent" -- Vyuh bridges the network (switch port mirroring / inline)
VYUH_MODE = "proxy"

# Vyuh proxy port (only used when VYUH_MODE = "proxy")
VYUH_PROXY_PORT = 8080

# Attack server port (on Laptop 1)
ATTACK_SERVER_PORT = 8888

# ---- Target Settings ----------------------------------------
TARGET_IP       = LAPTOP1_IP            # Primary target = the server laptop
TARGET_IPS      = [LAPTOP1_IP, LAPTOP3_IP]  # Both ends for DDoS tests

# ---- Port Settings ------------------------------------------
PORT_SCAN_RANGE_START = 1
PORT_SCAN_RANGE_END   = 1024
PORT_SCAN_TIMEOUT     = 0.5            # seconds per port
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                443, 445, 3306, 3389, 5432, 5900, 8080, 8443]

# ---- DNS Settings -------------------------------------------
DNS_SERVER      = LAPTOP2_IP           # Use Vyuh laptop as DNS (it can sniff queries)
DNS_PORT        = 53
DNS_DOMAIN      = "lab.local"          # Base domain for DNS tests

# ---- C2 Beaconing Settings ----------------------------------
C2_SERVER          = LAPTOP1_IP        # C2 = server laptop (for simulation)
C2_PORT            = 4444
C2_HTTP_PORT       = ATTACK_SERVER_PORT
C2_BEACON_INTERVAL = 30                # seconds between beacons
C2_JITTER          = 5                 # +/- seconds random jitter
C2_BEACON_COUNT    = 10                # how many beacons to send

# ---- Data Exfiltration Settings -----------------------------
EXFIL_SERVER    = LAPTOP1_IP           # Exfil back to server laptop
EXFIL_PORT      = 9999
EXFIL_HTTP_PORT = ATTACK_SERVER_PORT
EXFIL_FILE_SIZE = 1024 * 50            # 50 KB of simulated sensitive data

# ---- DDoS / DoS Settings ------------------------------------
DDOS_TARGET_IP   = LAPTOP3_IP         # DDoS target = client laptop
DDOS_TARGET_PORT = 80
DDOS_DURATION    = 30                  # seconds to flood
DDOS_THREADS     = 10                  # concurrent flood threads
DDOS_PACKET_SIZE = 1024                # bytes per UDP packet

# ---- DGA Settings -------------------------------------------
DGA_SEED_DATE    = None                # None = use today's date
DGA_TLD_LIST     = [".com", ".net", ".org", ".info", ".biz"]
DGA_DOMAIN_COUNT = 20                  # domains to generate per run
DGA_RESOLVE      = True                # attempt to resolve generated domains

# ---- Logging ------------------------------------------------
LOG_LEVEL = "INFO"                     # DEBUG / INFO / WARNING
LOG_FILE  = "attack_log.txt"
