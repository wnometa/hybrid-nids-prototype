"""
run_experiment.py

Runs the NIDS prototype against the labelled synthetic traffic dataset
in both signature-only and hybrid (signature + anomaly) modes, scores
the results against ground truth, and writes out the metrics, raw
logs, and charts used in the final report's data-analysis section.
"""

import csv
import json
import os
import statistics as stats

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from traffic_generator import generate_full_dataset
from nids_engine import run_engine

OUT_DIR = "results"
os.makedirs(OUT_DIR, exist_ok=True)


def score(flows, alerts):
    """
    Builds a per-flow verdict (was this specific flow detected by at
    least one alert?) and from that, a confusion matrix against the
    ground-truth label attached at generation time.
    """
    detected_flow_ids = {a["flow_id"] for a in alerts}

    tp = fp = fn = tn = 0
    per_type = {}  # attack_type -> {"total": n, "detected": n}

    for f in flows:
        was_detected = f["id"] in detected_flow_ids
        if f["label"] == "attack":
            entry = per_type.setdefault(f["attack_type"], {"total": 0, "detected": 0})
            entry["total"] += 1
            if was_detected:
                entry["detected"] += 1
                tp += 1
            else:
                fn += 1
        else:
            if was_detected:
                fp += 1
            else:
                tn += 1

    return {
        "confusion_matrix": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
        "detection_rate_percent": round(100 * tp / (tp + fn), 2) if (tp + fn) else 0,
        "false_positive_rate_percent": round(100 * fp / (fp + tn), 2) if (fp + tn) else 0,
        "precision_percent": round(100 * tp / (tp + fp), 2) if (tp + fp) else 0,
        "per_attack_type": {
            k: {
                "total": v["total"],
                "detected": v["detected"],
                "detection_rate_percent": round(100 * v["detected"] / v["total"], 2) if v["total"] else 0,
            }
            for k, v in per_type.items()
        },
    }


def write_csv(rows, filename):
    if not rows:
        with open(os.path.join(OUT_DIR, filename), "w") as f:
            f.write("")
        return
    keys = sorted({k for row in rows for k in row.keys()})
    with open(os.path.join(OUT_DIR, filename), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def timing_summary(timings, label):
    return {
        "mode": label,
        "flows_processed": len(timings),
        "mean_latency_ms": round(1000 * stats.mean(timings), 4),
        "median_latency_ms": round(1000 * stats.median(timings), 4),
        "p95_latency_ms": round(1000 * sorted(timings)[int(0.95 * len(timings)) - 1], 4),
        "throughput_flows_per_sec": round(len(timings) / sum(timings), 1) if sum(timings) > 0 else None,
    }


def chart_detection_comparison(sig_scores, hybrid_scores):
    types = sorted(set(list(sig_scores["per_attack_type"].keys()) + list(hybrid_scores["per_attack_type"].keys())))
    sig_rates = [sig_scores["per_attack_type"].get(t, {}).get("detection_rate_percent", 0) for t in types]
    hyb_rates = [hybrid_scores["per_attack_type"].get(t, {}).get("detection_rate_percent", 0) for t in types]

    x = range(len(types))
    width = 0.35
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar([i - width/2 for i in x], sig_rates, width, label="Signature-only", color="#a0aec0")
    ax.bar([i + width/2 for i in x], hyb_rates, width, label="Hybrid (signature + anomaly)", color="#2b6cb0")
    ax.set_xticks(list(x))
    ax.set_xticklabels([t.replace("_", " ").title() for t in types], rotation=15)
    ax.set_ylabel("Detection rate (%)")
    ax.set_ylim(0, 110)
    ax.set_title("Detection Rate by Attack Type: Signature-only vs. Hybrid NIDS")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "detection_by_attack_type.png"), dpi=150)
    plt.close(fig)


def chart_confusion(sig_scores, hybrid_scores):
    fig, axes = plt.subplots(1, 2, figsize=(9, 4))
    for ax, sc, title in zip(axes, [sig_scores, hybrid_scores], ["Signature-only", "Hybrid"]):
        cm = sc["confusion_matrix"]
        labels = ["TP", "FN", "FP", "TN"]
        vals = [cm["TP"], cm["FN"], cm["FP"], cm["TN"]]
        colors = ["#2f855a", "#c53030", "#dd6b20", "#4a5568"]
        ax.bar(labels, vals, color=colors)
        ax.set_title(f"{title}\nDetection rate {sc['detection_rate_percent']}% | "
                     f"FP rate {sc['false_positive_rate_percent']}%")
        ax.set_ylabel("Count")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "confusion_matrices.png"), dpi=150)
    plt.close(fig)


def chart_throughput(sig_timing, hyb_timing):
    labels = [sig_timing["mode"], hyb_timing["mode"]]
    vals = [sig_timing["throughput_flows_per_sec"], hyb_timing["throughput_flows_per_sec"]]
    fig, ax = plt.subplots(figsize=(5.5, 4))
    bars = ax.bar(labels, vals, color=["#a0aec0", "#2b6cb0"])
    ax.set_ylabel("Flows processed per second")
    ax.set_title("Engine Throughput: Signature-only vs. Hybrid")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width()/2, v, f"{v:,.0f}", ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "throughput_comparison.png"), dpi=150)
    plt.close(fig)


def main():
    flows = generate_full_dataset()
    write_csv(flows, "synthetic_traffic_dataset.csv")

    print(f"Generated {len(flows)} synthetic flow records "
          f"({sum(1 for f in flows if f['label']=='attack')} labelled attack flows).")

    sig_alerts, sig_timings = run_engine(flows, mode="signature_only")
    hyb_alerts, hyb_timings = run_engine(flows, mode="hybrid")

    write_csv(sig_alerts, "alerts_signature_only.csv")
    write_csv(hyb_alerts, "alerts_hybrid.csv")

    sig_scores = score(flows, sig_alerts)
    hyb_scores = score(flows, hyb_alerts)

    sig_timing_summary = timing_summary(sig_timings, "Signature-only")
    hyb_timing_summary = timing_summary(hyb_timings, "Hybrid")

    chart_detection_comparison(sig_scores, hyb_scores)
    chart_confusion(sig_scores, hyb_scores)
    chart_throughput(sig_timing_summary, hyb_timing_summary)

    summary = {
        "dataset": {
            "total_flows": len(flows),
            "normal_flows": sum(1 for f in flows if f["label"] == "normal"),
            "attack_flows": sum(1 for f in flows if f["label"] == "attack"),
            "attack_breakdown": {
                t: sum(1 for f in flows if f["attack_type"] == t)
                for t in sorted(set(f["attack_type"] for f in flows if f["attack_type"]))
            },
        },
        "signature_only": {**sig_scores, "timing": sig_timing_summary},
        "hybrid": {**hyb_scores, "timing": hyb_timing_summary},
    }

    with open(os.path.join(OUT_DIR, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print(json.dumps(summary, indent=2))
    print(f"\nAll results, charts, and CSVs written to ./{OUT_DIR}/")


if __name__ == "__main__":
    main()
