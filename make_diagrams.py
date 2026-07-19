import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

# ---------- Figure 1: simulated network architecture ----------
fig, ax = plt.subplots(figsize=(10, 5.6))
ax.set_xlim(0, 10)
ax.set_ylim(0, 6)
ax.axis("off")

def box(x, y, w, h, title, subtitle, color):
    b = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08",
                        linewidth=1.5, edgecolor="#2d3748", facecolor=color)
    ax.add_patch(b)
    ax.text(x + w/2, y + h*0.62, title, ha="center", va="center", fontsize=10, fontweight="bold")
    ax.text(x + w/2, y + h*0.26, subtitle, ha="center", va="center", fontsize=7.6)

box(0.3, 3.9, 2.4, 1.4, "Attacker Host", "Kali Linux\nNmap / brute-force / SQLi scripts", "#fed7d7")
box(3.9, 3.9, 2.4, 1.4, "Mirrored Switch Port", "Duplicates all traffic\nto/from the target server", "#feebc8")
box(7.4, 3.9, 2.3, 1.4, "Target Server", "Simulated fintech app\n+ SSH + DB service", "#bee3f8")

box(3.9, 1.6, 2.4, 1.4, "NIDS Engine", "Signature rules + anomaly\nrules (this prototype)", "#c6f6d5")
box(7.4, 1.6, 2.3, 1.4, "Alert Log", "Timestamped alerts\nwith rule + severity", "#e9d8fd")

for (x1,y1,x2,y2) in [(2.7,4.6,3.9,4.6), (6.3,4.6,7.4,4.6)]:
    ax.add_patch(FancyArrowPatch((x1,y1),(x2,y2), arrowstyle="->", mutation_scale=15, color="#2d3748"))
ax.add_patch(FancyArrowPatch((5.1,3.9),(5.1,3.0), arrowstyle="->", mutation_scale=15, color="#2d3748"))
ax.add_patch(FancyArrowPatch((6.3,2.3),(7.4,2.3), arrowstyle="->", mutation_scale=15, color="#2d3748"))

ax.set_title("Figure 1: Simulated Remote Fintech Network and NIDS Placement", fontsize=12, fontweight="bold", pad=12)
fig.tight_layout()
fig.savefig("results/architecture_diagram.png", dpi=170)
plt.close(fig)

# ---------- Figure 2: per-flow detection sequence ----------
fig, ax = plt.subplots(figsize=(9, 6.2))
ax.set_xlim(0, 9); ax.set_ylim(0, 8.6); ax.axis("off")

steps = [
    ("1. A flow record arrives at the engine\n(src/dst IP, ports, protocol, payload,\ntimestamp)", "#bee3f8"),
    ("2. Signature check: does the payload\nmatch a known malicious pattern\n(e.g. a SQL injection string)?", "#c6f6d5"),
    ("3. Anomaly checks (hybrid mode only):\nport-scan, brute-force, and volumetric\n(DDoS) counters updated for this flow", "#feebc8"),
    ("4. If any check fires, an alert is logged\nwith its rule ID, category, severity,\nand a plain-language reason", "#fed7d7"),
    ("5. Flow is scored later against its\nground-truth label to build the\nconfusion matrix", "#e9d8fd"),
]
y = 8.0
h = 1.35
for i, (text, color) in enumerate(steps):
    b = FancyBboxPatch((1.0, y - h), 7.0, h, boxstyle="round,pad=0.06", linewidth=1.3,
                        edgecolor="#2d3748", facecolor=color)
    ax.add_patch(b)
    ax.text(4.5, y - h/2, text, ha="center", va="center", fontsize=9)
    if i < len(steps) - 1:
        ax.add_patch(FancyArrowPatch((4.5, y-h), (4.5, y-h-0.2), arrowstyle="-|>", mutation_scale=14, color="#2d3748"))
    y -= (h + 0.2)

ax.set_title("Figure 2: Per-Flow Detection Sequence", fontsize=12, fontweight="bold", pad=10)
fig.tight_layout()
fig.savefig("results/flow_diagram.png", dpi=170)
plt.close(fig)
print("saved")
