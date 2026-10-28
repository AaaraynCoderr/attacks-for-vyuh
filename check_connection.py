"""
check_connection.py -- Run this on Laptop 3 to test connectivity
"""

import subprocess
import socket

LAPTOP1_IP = "192.168.137.1"    # Server (hotspot)
LAPTOP2_IP = "192.168.137.151"  # Vyuh

def ping(ip):
    result = subprocess.run(
        ["ping", "-n", "2", "-w", "1000", ip],
        capture_output=True, text=True
    )
    return "Reply from" in result.stdout

def check_port(ip, port):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        s.close()
        return True
    except:
        return False

print("=" * 50)
print("  Vyuh Lab -- Connection Checker (Laptop 3)")
print("=" * 50)

# --- Ping tests ---
print("\n[PING TESTS]")
r = ping(LAPTOP1_IP)
print(f"  Ping Laptop 1 ({LAPTOP1_IP}) : {'OK' if r else 'FAILED'}")

r = ping(LAPTOP2_IP)
print(f"  Ping Laptop 2 ({LAPTOP2_IP})  : {'OK' if r else 'FAILED'}")

# --- Port tests ---
print("\n[PORT TESTS]")
r = check_port(LAPTOP1_IP, 8888)
print(f"  Laptop 1 port 8888 (server) : {'OPEN' if r else 'CLOSED / server not running'}")

r = check_port(LAPTOP2_IP, 8080)
print(f"  Laptop 2 port 8080 (Vyuh)   : {'OPEN' if r else 'CLOSED / Vyuh not running'}")

print("\n" + "=" * 50)
print("  If all show OK/OPEN -> run the client:")
print("  python 08_client.py --proxy http://10.82.166.1:8080")
print("=" * 50)
