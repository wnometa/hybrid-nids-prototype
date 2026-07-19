"""
traffic_generator.py

Generates a synthetic stream of network flow records standing in for
packets captured off a mirrored switch port in the simulated remote
fintech network (the VMware/GNS3 environment described in the project
proposal). Each record carries a ground-truth label (normal or a
specific attack type) so the detection engine's output can be scored
afterward -- something that is not possible with a real, unlabelled
packet capture, which is exactly why a labelled synthetic dataset is
used for controlled testing here.

Traffic modelled:
  - normal:      ordinary HTTPS API calls, DB queries, and a handful
                  of legitimate SSH logins from the internal admin host
  - port_scan:   a single external host probing many destination ports
                  on the target server in a short window (Nmap-style)
  - brute_force: repeated failed SSH login attempts from one source
  - sql_injection: HTTP requests carrying SQLi payloads in the request body
  - ddos:        a volumetric burst of connections to a single service
"""

import random
import uuid
from datetime import datetime, timedelta

random.seed(42)  # reproducible test runs

TARGET_SERVER = "10.20.0.10"       # the simulated fintech application server
INTERNAL_ADMIN = "10.20.0.5"       # legitimate internal admin workstation
NORMAL_CLIENT_POOL = [f"41.203.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(25)]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users;--",
    "1 UNION SELECT username, password FROM accounts",
    "' OR 1=1 --",
    "admin'--",
]

def _ts(base, offset_seconds):
    return (base + timedelta(seconds=offset_seconds)).isoformat()


def _flow(ts, src, dst, sport, dport, proto, bytes_, flags, payload, label, attack_type=None):
    return {
        "id": str(uuid.uuid4())[:8],
        "timestamp": ts,
        "src_ip": src, "dst_ip": dst,
        "src_port": sport, "dst_port": dport,
        "protocol": proto, "bytes": bytes_, "flags": flags,
        "payload": payload,
        "label": label,                 # ground truth: "normal" or "attack"
        "attack_type": attack_type,     # None, or the specific attack category
    }


def generate_normal_traffic(base_time, n=400):
    flows = []
    for i in range(n):
        client = random.choice(NORMAL_CLIENT_POOL)
        dport = random.choice([443, 443, 443, 5432])
        flows.append(_flow(
            _ts(base_time, random.uniform(0, 900)),
            client, TARGET_SERVER, random.randint(1024, 65000), dport,
            "TCP", random.randint(200, 4000), "SYN,ACK,FIN",
            "GET /api/v1/transactions HTTP/1.1" if dport == 443 else "SELECT * FROM ledger WHERE id=?",
            "normal",
        ))
    # a few legitimate admin SSH logins
    for i in range(6):
        flows.append(_flow(
            _ts(base_time, random.uniform(0, 900)),
            INTERNAL_ADMIN, TARGET_SERVER, random.randint(1024, 65000), 22,
            "TCP", random.randint(500, 1500), "SYN,ACK,FIN",
            "SSH-2.0-OpenSSH_login_success",
            "normal",
        ))
    return flows


def generate_port_scan(base_time, start_offset=100):
    attacker = "185.220.101.7"  # simulated external scanning host
    ports = random.sample(range(1, 10000), 40)
    flows = []
    for i, port in enumerate(ports):
        flows.append(_flow(
            _ts(base_time, start_offset + i * 0.15),  # rapid-fire, sub-second between probes
            attacker, TARGET_SERVER, random.randint(1024, 65000), port,
            "TCP", random.randint(40, 60), "SYN",
            "", "attack", "port_scan",
        ))
    return flows


def generate_brute_force(base_time, start_offset=300):
    attacker = "193.106.191.44"
    flows = []
    for i in range(15):
        flows.append(_flow(
            _ts(base_time, start_offset + i * 1.2),
            attacker, TARGET_SERVER, random.randint(1024, 65000), 22,
            "TCP", random.randint(300, 500), "SYN,ACK",
            "SSH-2.0-OpenSSH_auth_failed",
            "attack", "brute_force",
        ))
    return flows


def generate_sql_injection(base_time, start_offset=500):
    attacker = "41.190.3.201"
    flows = []
    for i in range(5):
        flows.append(_flow(
            _ts(base_time, start_offset + i * 4),
            attacker, TARGET_SERVER, random.randint(1024, 65000), 443,
            "TCP", random.randint(300, 900), "SYN,ACK,FIN",
            f"POST /api/v1/login HTTP/1.1 body=username={random.choice(SQLI_PAYLOADS)}",
            "attack", "sql_injection",
        ))
    return flows


def generate_ddos(base_time, start_offset=650, n=60):
    flows = []
    for i in range(n):
        src = f"91.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        flows.append(_flow(
            _ts(base_time, start_offset + i * 0.05),  # very high rate, many sources
            src, TARGET_SERVER, random.randint(1024, 65000), 443,
            "TCP", random.randint(40, 80), "SYN",
            "", "attack", "ddos",
        ))
    return flows


def generate_full_dataset():
    base_time = datetime(2026, 3, 2, 9, 0, 0)
    flows = []
    flows += generate_normal_traffic(base_time, n=400)
    flows += generate_port_scan(base_time)
    flows += generate_brute_force(base_time)
    flows += generate_sql_injection(base_time)
    flows += generate_ddos(base_time)
    flows.sort(key=lambda f: f["timestamp"])
    return flows
