#!/usr/bin/env python3
"""Parameter sweep: compare fidelity, utility, and privacy across k, ε, and n_samples.

Runs the full SPIDEr pipeline for every (k, ε, n_samples) combination and
measures all three evaluation dimensions in one automated report.

Output
------
  output/comparison_results.csv    — raw numbers for every combination
  output/comparison_report.pdf     — summary table + heatmaps + line charts

Usage
-----
  python3 compare_params.py                              # default grid
  python3 compare_params.py --k 5 25 50 --epsilon 0.5 1.0 5.0
  python3 compare_params.py --n-train 5000              # faster, smaller training set
  python3 compare_params.py --n-synth 2000 8000         # vary synthetic size too
  python3 compare_params.py --n-sweep                   # extra n_samples sweep page
"""
from __future__ import annotations

import argparse
import itertools
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from evaluate_synthetic import (
    CATEGORICAL_QIS,
    NUMERICAL_QIS,
    QI_META,
    SENSITIVE_COL,
    compute_dcr,
    compute_fidelity_stats,
    encode_features,
    load_adult,
    run_propensity_test,
    train_and_eval,
)
from pipeline.spider import spider_pipeline

sns.set_theme(style="whitegrid", font_scale=1.0)

# ─── metric registry ──────────────────────────────────────────────────────────
# (display_label, direction, seaborn_cmap)
# direction "lower_better": green=low, red=high
# direction "higher_better": green=high, red=low

METRICS: dict[str, tuple[str, str, str]] = {
    "avg_js":         ("Avg JS Divergence",      "lower_better",  "RdYlGn_r"),
    "avg_ks_num":     ("Avg KS (numerical)",      "lower_better",  "RdYlGn_r"),
    "avg_tvd_cat":    ("Avg TVD (categorical)",   "lower_better",  "RdYlGn_r"),
    "tstr_gap":       ("TSTR Accuracy Gap",       "lower_better",  "RdYlGn_r"),
    "tstr_f1":        ("TSTR Macro F1",           "higher_better", "RdYlGn"),
    "tstr_auc":       ("TSTR ROC AUC",            "higher_better", "RdYlGn"),
    "prop_deviation": ("Propensity |AUC−0.5|",    "lower_better",  "RdYlGn_r"),
    "dcr_median":     ("DCR Median",              "higher_better", "RdYlGn"),
    "dcr_p5":         ("DCR 5th Pct",             "higher_better", "RdYlGn"),
}


# ─── single combination ───────────────────────────────────────────────────────

def run_combination(
    k: int,
    epsilon: float,
    n_synth: int,
    real_train: pd.DataFrame,
    real_test: pd.DataFrame,
    seed: int,
    repo_root: str,
    suppression_limit: float = 0.05,
) -> dict:
    """Run SPIDEr + all metrics for one (k, ε, n_synth) combination."""
    feature_cols = NUMERICAL_QIS + CATEGORICAL_QIS
    row: dict = {"k": k, "epsilon": epsilon, "n_synth": n_synth,
                 "n_real_train": len(real_train)}
    try:
        print(f"\n[spider] k={k}, ε={epsilon}, n={n_synth:,} …")
        synth = spider_pipeline(
            data=real_train,
            k=k, epsilon=epsilon, n_samples=n_synth,
            quasi_identifiers=QI_META,
            sensitive_columns=[SENSITIVE_COL],
            suppression_limit=suppression_limit,
            repo_root=repo_root,
            seed=seed,
        )
        for col in NUMERICAL_QIS:
            if col in synth.columns:
                synth[col] = synth[col].astype(float)
        row["n_synth_actual"] = len(synth)

        # ── fidelity ──────────────────────────────────────────────────────────
        stats = compute_fidelity_stats(real_train, synth)
        row["avg_js"]      = float(stats["js_divergence"].mean())
        row["avg_ks_num"]  = float(stats[stats["type"] == "numerical"]["stat_value"].mean())
        row["avg_tvd_cat"] = float(stats[stats["type"] == "categorical"]["stat_value"].mean())

        # ── utility: TSTR ─────────────────────────────────────────────────────
        X_real, y_real, X_test, y_test = encode_features(
            real_train, real_test, feature_cols)
        X_syn, y_syn, _, _ = encode_features(synth, real_test, feature_cols)

        base = train_and_eval(X_real, y_real, X_test, y_test, feature_cols, seed)
        tstr = train_and_eval(X_syn,  y_syn,  X_test, y_test, feature_cols, seed)

        row["baseline_acc"] = base["accuracy"]
        row["tstr_acc"]     = tstr["accuracy"]
        row["tstr_gap"]     = base["accuracy"] - tstr["accuracy"]
        row["tstr_f1"]      = tstr["macro_f1"]
        row["tstr_auc"]     = tstr["roc_auc"]

        # ── discriminator ─────────────────────────────────────────────────────
        auc, _, fig_p = run_propensity_test(real_train, synth, seed=seed)
        plt.close(fig_p)
        row["prop_deviation"] = float(abs(auc - 0.5))

        # ── privacy: DCR ──────────────────────────────────────────────────────
        dcr = compute_dcr(real_train, synth, seed=seed)
        row["dcr_median"] = float(np.median(dcr))
        row["dcr_p5"]     = float(np.percentile(dcr, 5))
        row["dcr_near"]   = float((dcr < 0.1).mean())

        row["success"] = True

    except Exception as exc:
        row["success"] = False
        row["error"]   = str(exc)[:120]
        for m in METRICS:
            row.setdefault(m, float("nan"))

    return row


# ─── plots ────────────────────────────────────────────────────────────────────

def _active_metrics(df: pd.DataFrame) -> list[str]:
    return [c for c in METRICS if c in df.columns and not df[c].isna().all()]


def plot_setup_page(
    k_vals: list, eps_vals: list, n_vals: list, n_train: int, n_test: int
) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(11, 8.5))
    ax.axis("off")
    T = ax.transAxes

    def hline(y):
        ax.plot([0.05, 0.95], [y, y], transform=T,
                color="#e5e7eb", linewidth=1, clip_on=False)

    def section(y, title):
        hline(y)
        ax.text(0.05, y - 0.005, title, transform=T, ha="left", va="top",
                fontsize=12, fontweight="bold", color="#2563eb")
        return y - 0.042

    def row(y, label, value):
        ax.text(0.08, y, label, transform=T, ha="left", va="top",
                fontsize=10, color="#555")
        ax.text(0.44, y, str(value), transform=T, ha="left", va="top",
                fontsize=10, fontweight="bold")
        return y - 0.033

    ax.text(0.5, 0.96, "SPIDEr Parameter Sweep — Comparison Report",
            transform=T, ha="center", va="top", fontsize=17, fontweight="bold")
    ax.text(0.5, 0.90,
            "How fidelity, utility, and privacy trade off across k, ε, and n_samples",
            transform=T, ha="center", va="top", fontsize=11, color="#555")

    y = 0.84
    y = section(y, "① Parameters swept")
    y = row(y, "k  (anonymity set size)", "  ×  ".join(str(v) for v in k_vals))
    y = row(y, "ε  (privacy budget)",     "  ×  ".join(str(v) for v in eps_vals))
    y = row(y, "n_samples",               "  ×  ".join(str(v) for v in n_vals))
    y = row(y, "Total combinations",
            len(k_vals) * len(eps_vals) * len(n_vals))
    y -= 0.005

    y = section(y, "② Dataset")
    y = row(y, "UCI Adult Census Income (OpenML v2)", "")
    y = row(y, "Training rows",  f"{n_train:,}")
    y = row(y, "Test rows",      f"{n_test:,}  (fixed across all combinations)")
    y -= 0.005

    y = section(y, "③ Metrics")
    ax.text(0.08, y,
            "Fidelity  ·  Avg JS Divergence · Avg KS (numerical) · Avg TVD (categorical)\n"
            "Utility   ·  TSTR accuracy gap · TSTR Macro F1 · TSTR ROC AUC ·"
            " Propensity |AUC−0.5|\n"
            "Privacy   ·  DCR Median · DCR 5th percentile",
            transform=T, ha="left", va="top", fontsize=10, linespacing=1.75, color="#222")
    y -= 0.10

    y = section(y, "④ How to read the heatmaps")
    ax.text(0.08, y,
            "Each cell = one (k, ε) pair.   Green = better outcome.   Red = worse.\n"
            "Fidelity: lower divergence = greener.   Utility: higher F1/AUC = greener.\n"
            "Privacy (DCR): higher distance = greener  (more separation from real records).\n"
            "Propensity |AUC−0.5|: closer to 0 = greener  (harder to tell real from synthetic).\n"
            "Line charts show how each metric changes as k or ε increases,\n"
            "revealing the privacy–utility trade-off curve.",
            transform=T, ha="left", va="top", fontsize=10, linespacing=1.7, color="#222")

    return fig


def plot_summary_table(df: pd.DataFrame) -> plt.Figure:
    """Colour-coded table: one row per combination, all key metrics."""
    mc = _active_metrics(df)
    col_labels = ["k", "ε", "n_synth"] + [METRICS[c][0] for c in mc]

    fig_h = max(5.0, len(df) * 0.42 + 1.8)
    fig, ax = plt.subplots(figsize=(min(20, 3 + len(mc) * 1.6), fig_h))
    ax.axis("off")

    cell_text = []
    for _, r in df.iterrows():
        row_vals = [str(int(r["k"])), str(r["epsilon"]), str(int(r["n_synth"]))]
        for c in mc:
            v = r[c]
            row_vals.append(f"{v:.4f}" if not np.isnan(v) else "—")
        cell_text.append(row_vals)

    tbl = ax.table(cellText=cell_text, colLabels=col_labels,
                   loc="center", cellLoc="center")
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(8.5)
    tbl.scale(1.0, 1.55)

    for j in range(len(col_labels)):
        tbl[0, j].set_facecolor("#1e40af")
        tbl[0, j].set_text_props(color="white", fontweight="bold")

    # colour metric cells by column-wise rank
    for ci, col in enumerate(mc, start=3):
        vals = df[col].dropna().values
        if len(vals) < 2:
            continue
        lo, hi = vals.min(), vals.max()
        direction = METRICS[col][1]
        for ri in range(1, len(df) + 1):
            v = df.iloc[ri - 1][col]
            if np.isnan(v) or hi == lo:
                continue
            norm = (v - lo) / (hi - lo)
            good = (1 - norm) if direction == "lower_better" else norm
            r_c = min(1.0, 2 * (1 - good)) * 0.85
            g_c = min(1.0, 2 * good) * 0.85
            tbl[ri, ci].set_facecolor((r_c, g_c, 0.15, 0.4))

    for ri in range(1, len(df) + 1):
        bg = "#f1f5f9" if ri % 2 else "white"
        for ci in range(3):
            tbl[ri, ci].set_facecolor(bg)

    ax.set_title(
        "Full Comparison Table  —  green = better, red = worse (within each column)",
        fontsize=11, fontweight="bold", pad=14,
    )
    fig.tight_layout()
    return fig


def plot_heatmaps(
    df: pd.DataFrame, k_vals: list, eps_vals: list
) -> list[plt.Figure]:
    """One heatmap per metric: k (rows) × ε (columns)."""
    # only use rows from the k×ε sweep (filter to n_synth == mode)
    mode_n = int(df["n_synth"].mode()[0])
    sub = df[df["n_synth"] == mode_n]

    figs = []
    for col, (label, direction, cmap) in METRICS.items():
        if col not in sub.columns or sub[col].isna().all():
            continue

        pivot = sub.pivot_table(
            index="k", columns="epsilon", values=col, aggfunc="mean"
        ).reindex(index=sorted(k_vals), columns=sorted(eps_vals))

        fig, ax = plt.subplots(
            figsize=(max(6, len(eps_vals) * 1.7), max(4, len(k_vals) * 1.3))
        )
        sns.heatmap(
            pivot, annot=True, fmt=".3f", cmap=cmap,
            linewidths=0.6, ax=ax,
            annot_kws={"size": 12, "weight": "bold"},
            cbar_kws={"shrink": 0.75},
        )
        ax.set_xlabel(
            "ε  (privacy budget)  →  larger ε = less Laplace noise = better utility",
            fontsize=9.5,
        )
        ax.set_ylabel(
            "k  (anonymity set size)  →  larger k = coarser bins = more privacy",
            fontsize=9.5,
        )
        arrow = "↓ lower is better" if direction == "lower_better" else "↑ higher is better"
        ax.set_title(
            f"{label}  ({arrow})\nn_synth = {mode_n:,}",
            fontsize=12, fontweight="bold",
        )
        fig.tight_layout()
        figs.append(fig)

    return figs


def plot_line_charts_k(df: pd.DataFrame, k_vals: list, eps_vals: list) -> plt.Figure:
    """Metric vs k — one line per ε value."""
    mc = _active_metrics(df)
    ncols = 3
    nrows = (len(mc) + ncols - 1) // ncols
    fig, axes = plt.subplots(nrows, ncols, figsize=(15, nrows * 3.8))
    axes = np.array(axes).flatten()
    palette = sns.color_palette("tab10", len(eps_vals))

    for ax_i, col in enumerate(mc):
        ax = axes[ax_i]
        label, direction, _ = METRICS[col]
        for fi, eps in enumerate(sorted(eps_vals)):
            sub = df[df["epsilon"] == eps].sort_values("k")
            if sub.empty:
                continue
            ax.plot(sub["k"], sub[col], marker="o", linewidth=2, markersize=5,
                    color=palette[fi], label=f"ε={eps}")
        ax.set_xlabel("k", fontsize=9)
        ax.set_ylabel(label, fontsize=9)
        ax.set_title(label, fontsize=10, fontweight="bold")
        ax.legend(fontsize=8)

    for i in range(len(mc), len(axes)):
        axes[i].set_visible(False)

    fig.suptitle(
        "Metric vs k  (one line per ε)\n"
        "Shows how increasing k (more privacy) affects each quality dimension",
        fontsize=12, fontweight="bold",
    )
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    return fig


def plot_line_charts_eps(df: pd.DataFrame, k_vals: list, eps_vals: list) -> plt.Figure:
    """Metric vs ε — one line per k value."""
    mc = _active_metrics(df)
    ncols = 3
    nrows = (len(mc) + ncols - 1) // ncols
    fig, axes = plt.subplots(nrows, ncols, figsize=(15, nrows * 3.8))
    axes = np.array(axes).flatten()
    palette = sns.color_palette("tab10", len(k_vals))

    for ax_i, col in enumerate(mc):
        ax = axes[ax_i]
        label, _, _ = METRICS[col]
        for fi, kv in enumerate(sorted(k_vals)):
            sub = df[df["k"] == kv].sort_values("epsilon")
            if sub.empty:
                continue
            ax.plot(sub["epsilon"], sub[col], marker="s", linewidth=2, markersize=5,
                    color=palette[fi], label=f"k={kv}")
        ax.set_xlabel("ε", fontsize=9)
        ax.set_ylabel(label, fontsize=9)
        ax.set_title(label, fontsize=10, fontweight="bold")
        ax.legend(fontsize=8)

    for i in range(len(mc), len(axes)):
        axes[i].set_visible(False)

    fig.suptitle(
        "Metric vs ε  (one line per k)\n"
        "Shows how increasing ε (less DP noise) affects each quality dimension",
        fontsize=12, fontweight="bold",
    )
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    return fig


def plot_n_sweep(df_n: pd.DataFrame) -> plt.Figure:
    """Metric vs n_samples (fixed k=50, ε=1.0)."""
    mc = _active_metrics(df_n)
    ncols = 3
    nrows = (len(mc) + ncols - 1) // ncols
    fig, axes = plt.subplots(nrows, ncols, figsize=(15, nrows * 3.8))
    axes = np.array(axes).flatten()

    for ax_i, col in enumerate(mc):
        ax = axes[ax_i]
        label, direction, _ = METRICS[col]
        sub = df_n.sort_values("n_synth")
        color = "#10b981" if direction == "higher_better" else "#7c3aed"
        ax.plot(sub["n_synth"], sub[col], marker="o", linewidth=2,
                markersize=6, color=color)
        ax.set_xlabel("n_samples", fontsize=9)
        ax.set_ylabel(label, fontsize=9)
        ax.set_title(label, fontsize=10, fontweight="bold")

    for i in range(len(mc), len(axes)):
        axes[i].set_visible(False)

    k_val   = int(df_n["k"].iloc[0])
    eps_val = df_n["epsilon"].iloc[0]
    fig.suptitle(
        f"Metric vs n_samples  (k={k_val}, ε={eps_val})\n"
        "Shows the effect of generating more or fewer synthetic records",
        fontsize=12, fontweight="bold",
    )
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    return fig


def save_pdf(figures: list[plt.Figure], path: str) -> None:
    with PdfPages(path) as pdf:
        for fig in figures:
            pdf.savefig(fig, bbox_inches="tight")
            plt.close(fig)


# ─── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sweep k/ε/n_samples and compare fidelity, utility, privacy."
    )
    parser.add_argument("--k",       type=int,   nargs="+", default=[5, 25, 50, 100],
                        help="k values to sweep (default: 5 25 50 100)")
    parser.add_argument("--epsilon", type=float, nargs="+", default=[0.1, 0.5, 1.0, 5.0],
                        help="ε values to sweep (default: 0.1 0.5 1.0 5.0)")
    parser.add_argument("--n-synth", type=int,   nargs="+", default=None,
                        help="Synthetic sample sizes. Default: same as n_train.")
    parser.add_argument("--n-train", type=int,   default=25000,
                        help="Real training rows to use (default 25000).")
    parser.add_argument("--suppression-limit", type=float, default=0.10, dest="suppression_limit",
                        help="SKALD suppression limit (default 0.10). "
                             "Increase if high-k runs fail on small datasets.")
    parser.add_argument("--n-sweep", action="store_true",
                        help="Add extra page: metrics vs n_samples (fixed k=50, ε=1.0).")
    parser.add_argument("--seed",    type=int,   default=42)
    args = parser.parse_args()

    repo_root = os.path.abspath(os.path.dirname(__file__))
    out_dir   = os.path.join(repo_root, "output")
    os.makedirs(out_dir, exist_ok=True)

    # ── load data once ────────────────────────────────────────────────────────
    print("[data] Loading UCI Adult …")
    full_df = load_adult()
    real_train_full, real_test = train_test_split(
        full_df, test_size=0.20, random_state=args.seed,
        stratify=full_df[SENSITIVE_COL],
    )
    if args.n_train < len(real_train_full):
        real_train, _ = train_test_split(
            real_train_full, train_size=args.n_train, random_state=args.seed,
            stratify=real_train_full[SENSITIVE_COL],
        )
    else:
        real_train = real_train_full
    print(f"[data] Train: {len(real_train):,}  |  Test: {len(real_test):,}")

    n_synth_vals = args.n_synth or [len(real_train)]
    combos = list(itertools.product(args.k, args.epsilon, n_synth_vals))

    # ── main sweep ────────────────────────────────────────────────────────────
    print(f"\n[sweep] {len(combos)} combinations  "
          f"(k={args.k}  ×  ε={args.epsilon}  ×  n={n_synth_vals})\n")
    results = []
    total_t = time.time()
    for i, (k, eps, n) in enumerate(combos, 1):
        print(f"  [{i:2d}/{len(combos)}]  k={k:4d}  ε={eps:<5}  n={n:,} … ",
              end="", flush=True)
        t0 = time.time()
        r  = run_combination(k, eps, n, real_train, real_test, args.seed, repo_root,
                             suppression_limit=args.suppression_limit)
        ok = "✓" if r.get("success") else f"✗ {r.get('error','')[:50]}"
        print(f"{ok}  ({time.time()-t0:.0f}s)")
        results.append(r)

    print(f"\n  Total: {time.time()-total_t:.0f}s")
    df_results = pd.DataFrame(results)

    # ── optional n_samples sweep ──────────────────────────────────────────────
    df_n_sweep = pd.DataFrame()
    if args.n_sweep:
        n_sweep_vals = sorted(set(
            [1000, 3000] +
            [int(len(real_train) * f) for f in [0.25, 0.5, 0.75, 1.0]]
        ))
        n_sweep_vals = [n for n in n_sweep_vals if n >= 500]
        print(f"\n[n-sweep] k=50, ε=1.0, n={n_sweep_vals}")
        n_rows = []
        for i, n in enumerate(n_sweep_vals, 1):
            print(f"  [{i}/{len(n_sweep_vals)}]  n={n:,} … ", end="", flush=True)
            t0 = time.time()
            r  = run_combination(50, 1.0, n, real_train, real_test, args.seed, repo_root,
                                 suppression_limit=args.suppression_limit)
            print(f"{'✓' if r.get('success') else '✗'}  ({time.time()-t0:.0f}s)")
            n_rows.append(r)
        df_n_sweep = pd.DataFrame(n_rows)

    # ── save CSV ──────────────────────────────────────────────────────────────
    csv_path = os.path.join(out_dir, "comparison_results.csv")
    df_results.to_csv(csv_path, index=False)
    print(f"\n[output] CSV → {csv_path}")

    # ── console summary table ─────────────────────────────────────────────────
    mc = _active_metrics(df_results)
    header = f"  {'k':>5}  {'ε':>5}  {'n':>6}  " + \
             "  ".join(f"{METRICS[c][0][:11]:>11}" for c in mc)
    print("\n" + "═" * len(header))
    print(header)
    print("  " + "─" * (len(header) - 2))
    for _, r in df_results.iterrows():
        if not r.get("success", True):
            continue
        vals = "  ".join(f"{r[c]:>11.4f}" for c in mc)
        print(f"  {int(r['k']):>5}  {r['epsilon']:>5}  {int(r['n_synth']):>6}  {vals}")
    print("═" * len(header) + "\n")

    # ── build PDF ─────────────────────────────────────────────────────────────
    print("[plot] Generating comparison report …")
    figs: list[plt.Figure] = [
        plot_setup_page(args.k, args.epsilon, n_synth_vals,
                        len(real_train), len(real_test)),
        plot_summary_table(df_results),
    ]
    figs += plot_heatmaps(df_results, args.k, args.epsilon)
    figs += [
        plot_line_charts_k(df_results,   args.k, args.epsilon),
        plot_line_charts_eps(df_results, args.k, args.epsilon),
    ]
    if not df_n_sweep.empty:
        figs.append(plot_n_sweep(df_n_sweep))

    pdf_path = os.path.join(out_dir, "comparison_report.pdf")
    save_pdf(figs, pdf_path)
    print(f"[plot] Saved → {pdf_path}")


if __name__ == "__main__":
    main()
