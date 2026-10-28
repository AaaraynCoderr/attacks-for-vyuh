# 🛡️ Vyuh Security Platform — Attack Simulation Suite

A collection of **Python-based network attack simulation scripts** designed to test and validate detection capabilities of the **Vyuh** security platform on a controlled local LAN environment.

> ⚠️ **DISCLAIMER**: These scripts are strictly for authorized security testing in controlled lab environments. Only use against systems you own or have explicit permission to test. Never run against production or unauthorized networks.

---

## 📁 Project Structure

```
attacks for vyuh/
├── README.md
├── requirements.txt
├── config.py                    # Shared configuration (targets, ports, etc.)
├── 01_port_scan.py              # TCP/UDP Port Scanner
├── 02_dga_domain.py             # DGA Domain Generation Algorithm simulation
├── 03_dns_tunneling.py          # DNS Tunneling simulation
├── 04_c2_beaconing.py           # C2 Command & Control Beaconing simulation
├── 05_data_exfiltration.py      # Data Exfiltration simulation
└── 06_ddos_dos.py               # DDoS/DoS flood simulation
```

---

## 🔧 Setup

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

Edit `config.py` before running any script:

```python
TARGET_IP   = "192.168.1.100"   # Your lab target IP
DNS_SERVER  = "192.168.1.1"     # Your lab DNS server
C2_SERVER   = "192.168.1.200"   # Simulated C2 listener IP
```

---

## 🚀 Attack Simulations

| # | Script | Attack Type | Description |
|---|--------|-------------|-------------|
| 1 | `01_port_scan.py` | Port Scan | TCP SYN / connect scan across port ranges |
| 2 | `02_dga_domain.py` | DGA Domain | Algorithmically generates and resolves malware-like domains |
| 3 | `03_dns_tunneling.py` | DNS Tunneling | Encodes data into DNS queries to simulate covert channel |
| 4 | `04_c2_beaconing.py` | C2 Beaconing | Periodic HTTP/HTTPS check-ins simulating malware C2 |
| 5 | `05_data_exfiltration.py` | Data Exfiltration | Simulates sensitive data leaving the network |
| 6 | `06_ddos_dos.py` | DDoS/DoS | SYN flood, UDP flood, HTTP flood simulation |

---

## 🧪 Running Scripts

Each script can be run independently:

```bash
python 01_port_scan.py
python 02_dga_domain.py
python 03_dns_tunneling.py
python 04_c2_beaconing.py
python 05_data_exfiltration.py
python 06_ddos_dos.py
```

---

## 📡 What Vyuh Should Detect

| Attack | Expected Alert |
|--------|---------------|
| Port Scan | Port sweep / horizontal scan alert |
| DGA Domain | High-entropy domain / DGA lookup alert |
| DNS Tunneling | Anomalous DNS query length / frequency alert |
| C2 Beaconing | Periodic outbound connection / beaconing alert |
| Data Exfiltration | Large outbound data transfer alert |
| DDoS/DoS | Traffic flood / rate anomaly alert |
