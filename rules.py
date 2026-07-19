"""
rules.py

Two families of detection rule, mirroring the two approaches discussed
directly in the project's literature review:

  1. Signature-based rules, in the style of a real Snort rule: a fixed
     pattern is matched against a flow's payload. These are fast and
     precise, but by definition can only catch attacks whose payload
     matches something already known and written down -- they cannot
     catch a pattern nobody has written a rule for yet.

  2. Anomaly-based rules, which look at *behaviour* over a sliding
     time window rather than the content of any single packet (e.g.
     "too many distinct destination ports from one source in a short
     window" for a port scan). This is the detection style Disha &
     Waheed (2022) and Garcia-Teodoro et al. (2009) describe as being
     able to catch activity that has no known signature.

The engine in nids_engine.py can be run with signature rules only, or
with both rule families together (the "hybrid" mode), which is what
lets the experiment in run_experiment.py directly measure the
difference the anomaly layer makes.
"""

SQLI_PATTERNS = [
    "' OR '1'='1",
    "DROP TABLE",
    "UNION SELECT",
    "OR 1=1",
    "admin'--",
]


def signature_match(flow: dict) -> dict or None:
    """
    A Snort-style content match: if the payload contains a known
    malicious pattern, raise an alert immediately, independent of any
    other flow. Equivalent in spirit to a rule such as:
        alert tcp any any -> $TARGET 443 (content:"UNION SELECT"; ...)
    """
    payload = flow.get("payload", "") or ""
    for pattern in SQLI_PATTERNS:
        if pattern.lower() in payload.lower():
            return {
                "rule": "SIGNATURE-SQLI-001",
                "category": "sql_injection",
                "severity": "high",
                "detail": f"payload matched known SQLi pattern: '{pattern}'",
            }
    return None


class AnomalyState:
    """
    Holds the sliding-window counters the anomaly rules need. A fresh
    instance is created per test run so results never leak between
    trials.
    """

    def __init__(self, port_scan_threshold=15, port_scan_window=5.0,
                 bruteforce_threshold=8, bruteforce_window=20.0,
                 ddos_threshold=30, ddos_window=5.0):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.bruteforce_threshold = bruteforce_threshold
        self.bruteforce_window = bruteforce_window
        self.ddos_threshold = ddos_threshold
        self.ddos_window = ddos_window

        # src_ip -> list of (timestamp, dst_port)
        self._port_history = {}
        # (src_ip, dst_port) -> list of timestamps, only for dst_port 22
        self._auth_history = {}
        # dst_ip -> list of timestamps
        self._conn_history = {}

    @staticmethod
    def _prune(history, now, window):
        return [t for t in history if (now - t).total_seconds() <= window]

    def check_port_scan(self, flow, now):
        src = flow["src_ip"]
        hist = self._port_history.setdefault(src, [])
        hist.append((now, flow["dst_port"]))
        hist[:] = [(t, p) for (t, p) in hist if (now - t).total_seconds() <= self.port_scan_window]
        distinct_ports = {p for (_, p) in hist}
        if len(distinct_ports) >= self.port_scan_threshold:
            return {
                "rule": "ANOMALY-PORTSCAN-001",
                "category": "port_scan",
                "severity": "medium",
                "detail": f"{len(distinct_ports)} distinct ports from {src} "
                          f"within {self.port_scan_window}s window",
            }
        return None

    def check_bruteforce(self, flow, now):
        if flow["dst_port"] != 22:
            return None
        key = flow["src_ip"]
        hist = self._auth_history.setdefault(key, [])
        hist.append(now)
        hist[:] = self._prune(hist, now, self.bruteforce_window)
        if len(hist) >= self.bruteforce_threshold:
            return {
                "rule": "ANOMALY-BRUTEFORCE-001",
                "category": "brute_force",
                "severity": "high",
                "detail": f"{len(hist)} SSH connection attempts from {flow['src_ip']} "
                          f"within {self.bruteforce_window}s window",
            }
        return None

    def check_ddos(self, flow, now):
        dst = flow["dst_ip"]
        hist = self._conn_history.setdefault(dst, [])
        hist.append(now)
        hist[:] = self._prune(hist, now, self.ddos_window)
        if len(hist) >= self.ddos_threshold:
            return {
                "rule": "ANOMALY-DDOS-001",
                "category": "ddos",
                "severity": "critical",
                "detail": f"{len(hist)} connections to {dst} within {self.ddos_window}s window",
            }
        return None
