"""
nids_engine.py

The detection engine itself: takes the ordered stream of flow records
produced by traffic_generator.py and evaluates each one against the
active rule set, producing an alert log. This is the simulated
stand-in for Snort running on the Ubuntu Server host described in the
proposal, listening on a mirrored switch port.

Two modes are supported, selected by the `mode` argument, so the
experiment can measure the difference directly:

  "signature_only" - only rules.signature_match() runs (closer to a
                      default, out-of-the-box Snort ruleset relying on
                      known content patterns).
  "hybrid"          - signature_match() AND the three anomaly rules in
                      AnomalyState all run together.
"""

import time
from datetime import datetime

import rules


def _parse_ts(ts_str):
    return datetime.fromisoformat(ts_str)


def run_engine(flows, mode="hybrid"):
    """
    Processes `flows` in order and returns:
      alerts   - list of alert dicts, one per flow that triggered a rule
      timings  - list of per-flow processing latencies (seconds), used
                 to characterise engine performance/throughput
    """
    assert mode in ("signature_only", "hybrid")

    anomaly_state = rules.AnomalyState()
    alerts = []
    timings = []

    for flow in flows:
        t0 = time.perf_counter()
        now = _parse_ts(flow["timestamp"])

        triggered = []

        sig_hit = rules.signature_match(flow)
        if sig_hit:
            triggered.append(sig_hit)

        if mode == "hybrid":
            for check in (anomaly_state.check_port_scan,
                          anomaly_state.check_bruteforce,
                          anomaly_state.check_ddos):
                hit = check(flow, now)
                if hit:
                    triggered.append(hit)

        t1 = time.perf_counter()
        timings.append(t1 - t0)

        for hit in triggered:
            alerts.append({
                "flow_id": flow["id"],
                "timestamp": flow["timestamp"],
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "dst_port": flow["dst_port"],
                "rule": hit["rule"],
                "category": hit["category"],
                "severity": hit["severity"],
                "detail": hit["detail"],
                "ground_truth_label": flow["label"],
                "ground_truth_attack_type": flow["attack_type"],
            })

    return alerts, timings
