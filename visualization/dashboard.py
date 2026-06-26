# visualization/dashboard.py
"""
NetSentinel Dashboard (2 pages, dark theme)
Works with either:
  - artifacts/lm_scored.csv  (rich: lm_score, fanout, correlated, etc.)
  - visualization/alert_data.csv (basic: timestamp, severity, src/dest_ip)
Exports PNG + PDF to artifacts/, and opens two windows unless --save-only.
"""

from pathlib import Path
from textwrap import fill
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

# ---------- Theme ----------
BG = "#0b0b0b"
PANEL = "#141414"
ACCENT = "#ff6b6b"
GRID = "#3a3a3a"
TEXT = "#f2f2f2"
SUB = "#c8c8c8"

plt.rcParams.update({
    "figure.facecolor": BG,
    "axes.facecolor": BG,
    "savefig.facecolor": BG,
    "axes.edgecolor": SUB,
    "axes.labelcolor": TEXT,
    "xtick.color": SUB,
    "ytick.color": SUB,
    "grid.color": GRID,
    "text.color": TEXT,
    "font.size": 12,
})

# ---------- Safe converters ----------
def _to_series_numeric(df, key, default=0, dtype=float):
    if key in df.columns and isinstance(df[key], pd.Series):
        s = pd.to_numeric(df[key], errors="coerce").fillna(default)
    else:
        s = pd.Series([default] * len(df), index=df.index)
    return s.astype(dtype)

def _to_series_bool(df, key, default=False):
    if key in df.columns and isinstance(df[key], pd.Series):
        raw = df[key]
        if raw.dtype == bool:
            s = raw.fillna(default)
        else:
            s = raw.map(lambda v: str(v).strip().lower() in ("1","true","t","yes","y")).fillna(default)
    else:
        s = pd.Series([default] * len(df), index=df.index)
    return s.astype(bool)

# ---------- Data ----------
def load_data():
    rich_path = Path("artifacts/lm_scored.csv")
    basic_path = Path("visualization/alert_data.csv")
    enriched = rich_path.exists()

    df = pd.read_csv(rich_path if enriched else basic_path)

    # normalize
    df["timestamp"] = pd.to_datetime(df.get("timestamp"), errors="coerce", utc=True)
    df["severity"]   = _to_series_numeric(df, "severity", 0, int)
    df["lm_score"]   = _to_series_numeric(df, "lm_score", 0.0, float)
    df["fanout"]     = _to_series_numeric(df, "fanout", np.nan, float)
    df["correlated"] = _to_series_bool(df, "correlated", False)

    # derive fanout if missing
    if df["fanout"].isna().all():
        if "src_ip" in df.columns and "dest_ip" in df.columns:
            nu = df.groupby("src_ip")["dest_ip"].nunique()
            df["fanout"] = df["src_ip"].map(nu).astype(float)
        else:
            df["fanout"] = 1.0

    uniq_src  = int(df["src_ip"].nunique())  if "src_ip"  in df.columns else 0
    uniq_dest = int(df["dest_ip"].nunique()) if "dest_ip" in df.columns else 0
    max_fan   = int(float(np.nanmax(df["fanout"]))) if len(df) else 0

    meta = {"enriched": enriched, "uniq_src": uniq_src, "uniq_dest": uniq_dest, "max_fan": max_fan}
    return df, meta

# ---------- Small widgets ----------
def kpi_card(ax, title, value):
    ax.set_axis_off()
    pad = 0.02
    ax.add_patch(FancyBboxPatch(
        (pad, pad), 1-2*pad, 1-2*pad,
        boxstyle="round,pad=0.02,rounding_size=8",
        linewidth=1.2, edgecolor=SUB, facecolor=PANEL, alpha=0.95,
    ))
    ax.text(0.06, 0.70, fill(str(title), width=16), ha="left", va="top", fontsize=12, color=SUB)
    ax.text(0.06, 0.35, f"{value}", ha="left", va="top", fontsize=28, color=TEXT, weight="bold")

def note_box(fig, y_norm, lines):
    txt = "\n".join("• " + l for l in lines)
    fig.text(0.06, y_norm, txt, ha="left", va="top", fontsize=12,
             bbox=dict(boxstyle="round,pad=0.5", fc=PANEL, ec=SUB, alpha=0.95))

def _safe_line(ax, x, y, title, ylabel):
    if len(x) and len(y):
        ax.plot(x, y, color=ACCENT, lw=2, marker="o", ms=4)
    else:
        ax.text(0.5, 0.5, "No data", ha="center", va="center", fontsize=12, color=SUB, transform=ax.transAxes)
    ax.set_title(title, pad=8, fontsize=16, weight="bold")
    ax.set_ylabel(ylabel)
    ax.grid(True, linestyle="--", alpha=0.35)

# ---------- Page 1 ----------
def page1(fig, df, meta):
    fig.suptitle("NetSentinel — Basic Alert Overview", x=0.5, y=0.965, fontsize=20, weight="bold")

    gs = fig.add_gridspec(
        nrows=4, ncols=12,
        height_ratios=[1.1, 3.2, 3.2, 1.0],
        left=0.06, right=0.94, top=0.92, bottom=0.08, wspace=0.8, hspace=0.8
    )

    # KPI row
    cards = [
        ("Total alerts", len(df)),
        ("Correlated\n(Suri+Zeek)", int(df["correlated"].sum())),
        ("High risk\n(LM≥60)", int((df["lm_score"] >= 60).sum())),
        ("Unique src hosts", meta["uniq_src"]),
        ("Unique dest hosts", meta["uniq_dest"]),
        ("Max fan-out\n(src→dests)", meta["max_fan"]),
    ]
    for i, (title, val) in enumerate(cards):
        ax = fig.add_subplot(gs[0, 2*i:2*i+2])
        kpi_card(ax, title, val)

    # Severity distribution
    ax_sev = fig.add_subplot(gs[1:3, 0:7])
    counts = df["severity"].value_counts().sort_index()
    bars = ax_sev.bar(counts.index.astype(str), counts.values, color=ACCENT, edgecolor="white", linewidth=1.0)
    ax_sev.set_title("Alert Severity Distribution", pad=10, fontsize=18, weight="bold")
    ax_sev.set_xlabel("Severity")
    ax_sev.set_ylabel("Count")
    ax_sev.grid(True, axis="y", linestyle="--", alpha=0.4)
    for b in bars:
        h = b.get_height()
        ax_sev.text(b.get_x()+b.get_width()/2, h+0.4, f"{int(h)}", ha="center", va="bottom", fontsize=11, color=TEXT)

    # Correlation
    ax_corr = fig.add_subplot(gs[1:3, 7:12])
    n_corr = int(df["correlated"].sum())
    n_not  = int(len(df) - n_corr)
    ax_corr.barh(["Correlated", "Not correlated"], [n_corr, n_not],
                 color=ACCENT, edgecolor="white", linewidth=1.0)
    ax_corr.set_title("Suri↔Zeek Correlation", pad=10, fontsize=18, weight="bold")
    ax_corr.set_xlabel("Count")
    ax_corr.grid(True, axis="x", linestyle="--", alpha=0.4)

    # Help box
    span = "unknown"
    if df["timestamp"].notna().any():
        tmin, tmax = df["timestamp"].min(), df["timestamp"].max()
        if pd.notna(tmin) and pd.notna(tmax):
            span = f"{tmin} → {tmax}"
    note_box(fig, 0.16, [
        "Purpose: fuse Suricata alerts with Zeek flows to surface early indicators of lateral movement.",
        "“Correlated” = a Zeek flow confirms context for a Suricata alert (same 5-tuple within 60 seconds).",
        "LM score combines severity, correlation, fan-out, and risky ports (e.g., 445/3389).",
        f"Dataset span (UTC): {span}",
    ])

# ---------- Page 2 ----------
def page2(fig, df, meta):
    
    gs = fig.add_gridspec(
        nrows=3, ncols=12,
        height_ratios=[3.0, 3.0, 1.2],
        left=0.06, right=0.975, top=0.92, bottom=0.08,
        wspace=0.6, hspace=0.65
    )

    # (1) Alert rate (top-left)
    ax_rate = fig.add_subplot(gs[0, 0:6])
    if df["timestamp"].notna().any():
        tmp = df.dropna(subset=["timestamp"]).copy()
        per_min = tmp["timestamp"].dt.floor("1min").value_counts().sort_index()
        _safe_line(ax_rate, per_min.index, per_min.values, "Alert rate over time (1-min buckets)", "Alerts/min")
        fig.autofmt_xdate(rotation=25)
    else:
        _safe_line(ax_rate, [], [], "Alert rate over time (1-min buckets)", "Alerts/min")

    # (2) Top sources by fan-out (top-right)
    ax_top = fig.add_subplot(gs[0, 6:12])
    if {"src_ip","dest_ip"}.issubset(df.columns):
        fan = df.groupby("src_ip")["dest_ip"].nunique().sort_values(ascending=False).head(6)
        ax_top.barh(fan.index.astype(str), fan.values, color=ACCENT, edgecolor="white", linewidth=1.0)
        ax_top.invert_yaxis()
        ax_top.set_title("Top sources by fan-out", pad=8, fontsize=16, weight="bold")
        ax_top.set_xlabel("Distinct destinations")
        ax_top.grid(True, axis="x", linestyle="--", alpha=0.35)
    else:
        ax_top.set_title("Top sources by fan-out", pad=8, fontsize=18, weight="bold")
        ax_top.text(0.5, 0.5, "Fan-out not available in basic CSV",
                    ha="center", va="center", fontsize=12, color=SUB, transform=ax_top.transAxes)

    # (3) LM score over time (bottom-left)
    ax_lm = fig.add_subplot(gs[1, 0:6])
    if meta["enriched"] and df["timestamp"].notna().any():
        lm = df.dropna(subset=["timestamp"]).sort_values("timestamp")
        _safe_line(ax_lm, lm["timestamp"], lm["lm_score"], "Lateral-Movement score over time", "LM score")
        fig.autofmt_xdate(rotation=25)
    else:
        ax_lm.set_title("Lateral-Movement score over time", pad=8, fontsize=18, weight="bold")
        ax_lm.set_ylabel("LM score")
        ax_lm.grid(True, linestyle="--", alpha=0.35)
        ax_lm.text(0.5, 0.5, "LM features not available (use artifacts/lm_scored.csv)",
                   ha="center", va="center", fontsize=12, color=SUB, transform=ax_lm.transAxes)

    # (4) High-risk table (bottom-right) — its own axes; no overlap
    ax_tbl = fig.add_subplot(gs[1, 6:12])
    ax_tbl.set_axis_off()
    header = "Top high-risk events (max 8):\n"
    cols = [c for c in ["timestamp","src_ip","dest_ip","dest_port","severity","lm_score"] if c in df.columns]
    if cols:
        top = df.sort_values("lm_score", ascending=False).head(8)[cols].copy()
        lines = []
        for _, r in top.iterrows():
            ts  = (str(r.get("timestamp",""))[:19]).ljust(19)
            sip = str(r.get("src_ip","")).ljust(11)
            dip = str(r.get("dest_ip","")).ljust(11)
            dpt = "-" if pd.isna(r.get("dest_port")) else str(int(r.get("dest_port")))
            sev = "-" if pd.isna(r.get("severity"))  else str(int(r.get("severity")))
            lm  = f"{float(r.get('lm_score',0)):.1f}"
            lines.append(f"{ts} | {sip} → {dip}:{dpt:<5} | sev={sev:<2} | lm={lm}")
        txt = header + "\n".join(lines) if lines else header + "(no rows)"
    else:
        txt = header + "(columns not available)"

    ax_tbl.text(0.04, 0.98, txt, ha="left", va="top", family="monospace", fontsize=9,
                bbox=dict(boxstyle="round,pad=0.5", fc=PANEL, ec=SUB, alpha=0.95),
                linespacing=1.25, transform=ax_tbl.transAxes)

    # Bottom guidance (full width)
    note_box(fig, 0.16, [
        "Investigate sources with unusually high fan-out (many distinct internal destinations).",
        "Prioritize correlated alerts (Suri+Zeek) — they carry stronger confidence.",
        "Watch for rising LM-score clusters in short windows (possible lateral burst).",
        "Exports: artifacts/dashboard_page1.png/.pdf and artifacts/dashboard_page2.png/.pdf",
    ])

# ---------- Build / Main ----------
def build(df, meta, save_only=False):
    Path("artifacts").mkdir(exist_ok=True)

    # Page 1 (16×9)
    fig1 = plt.figure(figsize=(16, 9))
    page1(fig1, df, meta)
    fig1.savefig("artifacts/dashboard_page1.png", dpi=160)
    fig1.savefig("artifacts/dashboard_page1.pdf")

    # Page 2 (16×9)
    fig2 = plt.figure(figsize=(16, 9))
    page2(fig2, df, meta)
    fig2.savefig("artifacts/dashboard_page2.png", dpi=160)
    fig2.savefig("artifacts/dashboard_page2.pdf")

    if save_only:
        plt.close(fig1); plt.close(fig2)
    else:
        plt.show()  # keep both windows open

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--save-only", action="store_true", help="Export PNG/PDF without opening windows")
    args = ap.parse_args()
    df, meta = load_data()
    build(df, meta, save_only=args.save_only)

if __name__ == "__main__":
    main()
