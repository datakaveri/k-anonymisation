#!/usr/bin/env python3
"""Comprehensive synthetic data evaluation for SPIDEr/FORGE output.

Three evaluation dimensions:
    Fidelity    — KS test, TVD, Chi-squared, Jensen-Shannon divergence,
                  descriptive stats, correlation matrices, PCA projection
    Utility     — TSTR (Train on Synthetic, Test on Real) with RandomForest;
                  discriminator / propensity-score test
    Privacy     — DCR (Distance to Closest Record) nearest-neighbour analysis

Usage:
    python3 evaluate_synthetic.py                   # defaults: k=50, ε=1.0
    python3 evaluate_synthetic.py --k 30 --epsilon 0.5 --seed 42
"""
from __future__ import annotations

import argparse
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np
import pandas as pd
import seaborn as sns
from scipy.spatial.distance import jensenshannon
from scipy.stats import chi2_contingency, ks_2samp
from sklearn.datasets import fetch_openml
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pipeline.spider import spider_pipeline

# ─── config ──────────────────────────────────────────────────────────────────

NUMERICAL_QIS   = ["age", "education-num", "hours-per-week"]
CATEGORICAL_QIS = ["gender"]
SENSITIVE_COL   = "class"
ALL_COLS        = NUMERICAL_QIS + CATEGORICAL_QIS + [SENSITIVE_COL]
CLASS_NAMES     = ["<=50K", ">50K"]

QI_META = {
    "age":            {"kind": "numerical", "dtype": "int"},
    "education-num":  {"kind": "numerical", "dtype": "int"},
    "hours-per-week": {"kind": "numerical", "dtype": "int"},
    "gender":         {"kind": "categorical"},
}

COLORS = {
    "Real → Real (baseline)":  "#2196F3",
    "Synthetic → Real (TSTR)": "#FF5722",
    "Real+Synth → Real (aug)": "#4CAF50",
}

sns.set_theme(style="whitegrid", font_scale=1.05)

_CAPTION_STYLE = dict(
    ha="center", va="bottom", fontsize=8.5, color="#444444", style="italic",
    bbox=dict(boxstyle="round,pad=0.4", facecolor="#f8fafc", edgecolor="#e5e7eb", alpha=0.9),
)


def _add_caption(fig: plt.Figure, text: str) -> None:
    """Render an italic caption box at the bottom of a figure."""
    fig.subplots_adjust(bottom=0.14)
    fig.text(0.5, 0.02, text, **_CAPTION_STYLE)


def plot_setup_page(k: int, epsilon: float, n_real: int, n_synth: int) -> plt.Figure:
    """Full-page text explaining the dataset, pipeline, and evaluation approach."""
    fig, ax = plt.subplots(figsize=(11, 8.5))
    ax.axis("off")
    T = ax.transAxes

    def heading(y, text, size=13, color="#2563eb"):
        ax.text(0.05, y, text, transform=T, va="top", ha="left",
                fontsize=size, fontweight="bold", color=color)
        ax.plot([0.05, 0.95], [y - 0.018, y - 0.018],
                transform=T, color="#e5e7eb", linewidth=1, clip_on=False)
        return y - 0.038

    def body(y, text, indent=0.08, size=9.5, color="#222222"):
        ax.text(indent, y, text, transform=T, va="top", ha="left",
                fontsize=size, color=color, linespacing=1.55)
        lines = text.count("\n") + 1
        return y - 0.026 * lines

    y = 0.96
    ax.text(0.5, y, "Evaluation Setup & Methodology",
            transform=T, va="top", ha="center", fontsize=16, fontweight="bold")
    y -= 0.06

    # Dataset
    y = heading(y, "① Dataset")
    y = body(y, (
        f"UCI Adult Census Income  (OpenML ID 1590, version 2) — {n_real + n_synth:,} rows total.\n"
        "Columns used:\n"
        "  • age, education-num, hours-per-week  — numerical quasi-identifiers (QI)\n"
        "  • gender                              — categorical quasi-identifier\n"
        "  • income class (≤50K / >50K)          — sensitive attribute (prediction target)\n"
        f"  • Train split: {n_real:,} rows  |  Test split: {round(n_real * 0.25):,} rows  (stratified by income class)"
    ))
    y -= 0.01

    # Pipeline
    y = heading(y, "② SPIDEr Pipeline  (3 stages)")
    y = body(y, (
        "Stage 1 — k-Anonymity (SKALD / OLA):  The lattice of possible generalisations is searched\n"
        "  to find the coarsest binning where every record belongs to a group of ≥ k individuals\n"
        "  sharing the same quasi-identifier values.  Rare combinations are suppressed (≤ 5%).\n\n"
        "Stage 2 — Differential Privacy (Laplace mechanism):  Each sensitive-value count inside\n"
        "  every equivalence class is perturbed with Laplace(0, 1/ε) noise before the class\n"
        "  proportions are used for sampling.  Smaller ε = more noise = stronger privacy.\n\n"
        "Stage 3 — Proportional sampling:  Synthetic records are drawn by sampling each class\n"
        "  proportionally to its noised count, with feature values drawn uniformly from within\n"
        "  the generalisation bounds."
    ))
    y -= 0.01

    # Parameters
    y = heading(y, "③ Parameters Used in This Report")
    y = body(y, (
        f"  k  (anonymity set size)   =  {k}          "
        f"ε  (privacy budget)       =  {epsilon}\n"
        f"  Suppression limit         =  5 %         "
        f"Synthetic records         =  {n_synth:,}"
    ))
    y -= 0.01

    # Evaluation dimensions
    y = heading(y, "④ Evaluation Dimensions")
    y = body(y, (
        "Fidelity  — How closely the synthetic distributions match the real ones.  Measured\n"
        "  per-column with KS (numerical), TVD + Chi-squared (categorical), Jensen-Shannon\n"
        "  divergence, Pearson correlation matrices, and a 2-D PCA projection.\n\n"
        "Utility   — TSTR (Train on Synthetic, Test on Real): a RandomForest is trained on\n"
        "  synthetic data and tested on real held-out data; the gap vs a real-data baseline\n"
        "  quantifies information loss.  A discriminator test (propensity score) asks whether\n"
        "  a classifier can distinguish real from synthetic records at all.\n\n"
        "Privacy   — DCR (Distance to Closest Record): for each synthetic row the Euclidean\n"
        "  distance to its nearest real neighbour is computed in normalised feature space.\n"
        "  Near-zero distances indicate memorisation of real individuals."
    ))

    return fig


# ─── data ─────────────────────────────────────────────────────────────────────

def load_adult() -> pd.DataFrame:
    print("[data] Fetching UCI Adult Census Income dataset …")
    raw = fetch_openml("adult", version=2, as_frame=True, parser="auto")
    df: pd.DataFrame = raw.frame.copy()
    df = df.rename(columns={"sex": "gender"})
    df = df[ALL_COLS].dropna().reset_index(drop=True)
    for col in NUMERICAL_QIS:
        df[col] = df[col].astype(int)
    print(f"[data] Loaded {len(df):,} rows × {len(df.columns)} columns")
    return df


# ─── encoding ────────────────────────────────────────────────────────────────

def encode_features(
    train: pd.DataFrame,
    test: pd.DataFrame,
    feature_cols: list[str],
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """TSTR-style encoding: fit on train, apply to test."""
    X_train = train[feature_cols].copy()
    X_test  = test[feature_cols].copy()

    le_target = LabelEncoder().fit(train[SENSITIVE_COL])
    y_train = le_target.transform(train[SENSITIVE_COL])
    y_test  = le_target.transform(test[SENSITIVE_COL])

    for col in CATEGORICAL_QIS:
        if col in feature_cols:
            le = LabelEncoder().fit(train[col])
            X_train[col] = le.transform(train[col])
            X_test[col] = X_test[col].map(
                lambda x, le=le: le.transform([x])[0]
                if x in le.classes_ else -1
            )

    return (
        X_train.to_numpy(dtype=float),
        y_train,
        X_test.to_numpy(dtype=float),
        y_test,
    )


def encode_full(
    df: pd.DataFrame,
    ref: pd.DataFrame,
    cols: list[str] | None = None,
) -> np.ndarray:
    """Encode all cols (including target) using ref to fit label encoders."""
    if cols is None:
        cols = ALL_COLS
    X = df[cols].copy()
    for col in [c for c in CATEGORICAL_QIS + [SENSITIVE_COL] if c in cols]:
        le = LabelEncoder().fit(ref[col])
        X[col] = X[col].map(
            lambda x, le=le: le.transform([x])[0] if x in le.classes_ else -1
        )
    return X.to_numpy(dtype=float)


# ─── classifier ──────────────────────────────────────────────────────────────

def train_and_eval(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test:  np.ndarray,
    y_test:  np.ndarray,
    feature_names: list[str],
    seed: int = 42,
) -> dict:
    clf = RandomForestClassifier(n_estimators=100, random_state=seed, n_jobs=-1)
    clf.fit(X_train, y_train)
    y_pred  = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    return {
        "accuracy":           accuracy_score(y_test, y_pred),
        "macro_f1":           f1_score(y_test, y_pred, average="macro"),
        "roc_auc":            roc_auc_score(y_test, y_proba),
        "report":             classification_report(y_test, y_pred, target_names=CLASS_NAMES),
        "y_pred":             y_pred,
        "y_proba":            y_proba,
        "feature_importance": dict(zip(feature_names, clf.feature_importances_)),
    }


# ─── synthetic generation ─────────────────────────────────────────────────────

def generate_synthetic(
    real_train: pd.DataFrame,
    k: int, epsilon: float, n_samples: int,
    seed: int, repo_root: str,
) -> pd.DataFrame:
    print(f"\n[spider] Running SPIDEr  (k={k}, ε={epsilon}, n={n_samples:,}) …")
    synthetic = spider_pipeline(
        data=real_train,
        k=k, epsilon=epsilon, n_samples=n_samples,
        quasi_identifiers=QI_META,
        sensitive_columns=[SENSITIVE_COL],
        suppression_limit=0.05,
        repo_root=repo_root,
        seed=seed,
    )
    for col in NUMERICAL_QIS:
        if col in synthetic.columns:
            synthetic[col] = synthetic[col].astype(float)
    print(f"[spider] Generated {len(synthetic):,} synthetic records.")
    return synthetic


# ─── fidelity ─────────────────────────────────────────────────────────────────

def compute_fidelity_stats(real: pd.DataFrame, synthetic: pd.DataFrame) -> pd.DataFrame:
    """
    Per-column fidelity metrics.

    Numerical  : KS statistic + p-value, Jensen-Shannon divergence
    Categorical: TVD (Total Variation Distance) + Chi-squared p-value, JS divergence

    Interpretation guide
    ──────────────────────────────────────────────────────────────────────
    KS statistic   0 = identical CDFs,  1 = completely different
    TVD            0 = identical PMFs,  1 = completely different
    JS divergence  0 = identical,       1 = completely different
                   (sqrt of JS is a true metric bounded in [0,1])
    p-value        < 0.05 → the difference is statistically significant
                   (i.e. distributions are unlikely to be the same)
    ──────────────────────────────────────────────────────────────────────
    """
    rows = []

    for col in NUMERICAL_QIS:
        r = real[col].astype(float).dropna()
        s = synthetic[col].astype(float).dropna()

        ks_stat, ks_p = ks_2samp(r, s)

        lo, hi = r.min(), r.max()
        bins = np.linspace(lo, hi, 31) if hi > lo else np.array([lo, lo + 1])
        r_hist = np.histogram(r, bins=bins)[0].astype(float) + 1e-9
        s_hist = np.histogram(s, bins=bins)[0].astype(float) + 1e-9
        r_hist /= r_hist.sum()
        s_hist /= s_hist.sum()
        js = float(jensenshannon(r_hist, s_hist))

        rows.append({
            "column": col, "type": "numerical",
            "stat_name": "KS", "stat_value": ks_stat, "p_value": ks_p,
            "js_divergence": js,
            "real_mean":   r.mean(),    "synth_mean":   s.mean(),
            "real_std":    r.std(),     "synth_std":    s.std(),
            "real_median": r.median(),  "synth_median": s.median(),
        })

    for col in CATEGORICAL_QIS + [SENSITIVE_COL]:
        r = real[col].dropna()
        s = synthetic[col].dropna()
        cats = sorted(set(r.unique()) | set(s.unique()))

        r_cnt = np.array([r.value_counts().get(c, 0) for c in cats], dtype=float)
        s_cnt = np.array([s.value_counts().get(c, 0) for c in cats], dtype=float)

        tvd = 0.5 * float(np.abs(r_cnt / r_cnt.sum() - s_cnt / s_cnt.sum()).sum())

        table = np.vstack([r_cnt, s_cnt])
        try:
            _, chi2_p, _, _ = chi2_contingency(table)
        except ValueError:
            chi2_p = float("nan")

        r_p = r_cnt / r_cnt.sum() + 1e-9
        s_p = s_cnt / s_cnt.sum() + 1e-9
        r_p /= r_p.sum()
        s_p /= s_p.sum()
        js = float(jensenshannon(r_p, s_p))

        rows.append({
            "column": col, "type": "categorical",
            "stat_name": "TVD", "stat_value": tvd, "p_value": chi2_p,
            "js_divergence": js,
            "real_mean": None, "synth_mean": None,
            "real_std": None,  "synth_std": None,
            "real_median": None, "synth_median": None,
        })

    return pd.DataFrame(rows)


def plot_fidelity_table(stats: pd.DataFrame, k: int, epsilon: float) -> plt.Figure:
    """Matplotlib table: per-column fidelity with pass/fail assessment."""
    fig, ax = plt.subplots(figsize=(13, max(4.5, len(stats) * 0.75 + 1.8)))
    ax.axis("off")

    headers = ["Column", "Type", "Test", "Statistic", "p-value", "JS Divergence", "Assessment"]
    rows_data = []
    for _, r in stats.iterrows():
        stat_v = f"{r['stat_value']:.4f}"
        p_v    = f"{r['p_value']:.3e}" if pd.notna(r["p_value"]) else "—"
        js_v   = f"{r['js_divergence']:.4f}"

        if r["type"] == "numerical":
            ok = r["stat_value"] < 0.10 and r["js_divergence"] < 0.10
        else:
            ok = r["stat_value"] < 0.05 and r["js_divergence"] < 0.10
        fair = r["js_divergence"] < 0.20
        assessment = "✓ Good" if ok else ("△ Fair" if fair else "✗ Poor")

        rows_data.append([r["column"], r["type"], r["stat_name"],
                          stat_v, p_v, js_v, assessment])

    tbl = ax.table(
        cellText=rows_data,
        colLabels=headers,
        loc="center",
        cellLoc="center",
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(1.0, 1.7)

    for j in range(len(headers)):
        tbl[0, j].set_facecolor("#2563eb")
        tbl[0, j].set_text_props(color="white", fontweight="bold")

    for i, row_vals in enumerate(rows_data, 1):
        assessment = row_vals[-1]
        row_bg = "#d1fae5" if assessment.startswith("✓") else (
                 "#fef3c7" if assessment.startswith("△") else "#fee2e2")
        for j in range(len(headers)):
            bg = row_bg if j == len(headers) - 1 else ("#f8fafc" if i % 2 else "white")
            tbl[i, j].set_facecolor(bg)

    ax.set_title(
        f"Per-Column Fidelity Summary  (k={k}, ε={epsilon})\n"
        "KS / TVD < 0.10 and JS < 0.10 → Good   |   p > 0.05 → distributions not significantly different",
        fontsize=11, fontweight="bold", pad=14,
    )
    fig.tight_layout()
    _add_caption(fig,
        "KS (Kolmogorov-Smirnov): max gap between the CDFs of real and synthetic — 0 = identical, 1 = fully different.  "
        "TVD (Total Variation Distance): L1 distance between probability mass functions.  "
        "JS Divergence: symmetric bounded [0,1] measure combining both effects.  "
        "p < 0.05 means the difference is statistically significant.")
    return fig


def plot_descriptive_stats(real: pd.DataFrame, synthetic: pd.DataFrame) -> plt.Figure:
    """Side-by-side mean ± 1 std for numerical columns."""
    fig, axes = plt.subplots(1, len(NUMERICAL_QIS), figsize=(13, 5))
    for ax, col in zip(axes, NUMERICAL_QIS):
        r = real[col].astype(float)
        s = synthetic[col].astype(float)
        means  = [r.mean(), s.mean()]
        stds   = [r.std(),  s.std()]
        colors_bar = [COLORS["Real → Real (baseline)"], COLORS["Synthetic → Real (TSTR)"]]

        bars = ax.bar(["Real", "Synthetic"], means, yerr=stds, capsize=6,
                      color=colors_bar, edgecolor="white", width=0.5)
        span = r.max() - r.min()
        for bar, mean, std in zip(bars, means, stds):
            ax.text(bar.get_x() + bar.get_width() / 2,
                    mean + std + span * 0.02,
                    f"μ={mean:.1f}\nσ={std:.1f}",
                    ha="center", va="bottom", fontsize=9)
        ax.set_title(col, fontweight="bold")
        ax.set_ylabel("Value")

    fig.suptitle("Descriptive Statistics: Mean ± Std Dev (Real vs Synthetic)",
                 fontsize=13, fontweight="bold")
    fig.tight_layout()
    _add_caption(fig,
        "Bar height = mean; error bars = ±1 standard deviation.  "
        "Close alignment between Real and Synthetic indicates central tendency and spread are preserved.  "
        "k-Anonymity bins values into ranges, so means shift toward bin midpoints — visible as a slight offset.")
    return fig


def plot_correlation_matrices(
    real: pd.DataFrame,
    synthetic: pd.DataFrame,
    feature_cols: list[str],
) -> plt.Figure:
    """
    Side-by-side Pearson correlation heatmaps on label-encoded features + target.

    The difference heatmap highlights which feature relationships the synthetic
    data fails to preserve. Values near 0 = preserved, near 1 = broken.
    """
    def encode_df(df: pd.DataFrame) -> pd.DataFrame:
        enc = df[feature_cols + [SENSITIVE_COL]].copy()
        for col in CATEGORICAL_QIS + [SENSITIVE_COL]:
            if col in enc.columns:
                le = LabelEncoder().fit(real[col])
                enc[col] = enc[col].map(
                    lambda x, le=le: le.transform([x])[0] if x in le.classes_ else np.nan
                )
        return enc.astype(float)

    r_corr = encode_df(real).corr()
    s_corr = encode_df(synthetic).corr()
    diff   = (r_corr - s_corr).abs()

    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    kw = dict(annot=True, fmt=".2f", vmin=-1, vmax=1, cmap="RdBu_r",
              linewidths=0.5, annot_kws={"size": 9})

    sns.heatmap(r_corr, ax=axes[0], **kw, cbar=False)
    axes[0].set_title("Real — Pearson Correlation", fontweight="bold")

    sns.heatmap(s_corr, ax=axes[1], **kw, cbar=False)
    axes[1].set_title("Synthetic — Pearson Correlation", fontweight="bold")

    sns.heatmap(diff, ax=axes[2], annot=True, fmt=".2f",
                vmin=0, vmax=0.5, cmap="YlOrRd",
                linewidths=0.5, annot_kws={"size": 9})
    axes[2].set_title("|Real − Synthetic| Correlation", fontweight="bold")

    fig.suptitle("Feature Correlation Matrices (including target column)",
                 fontsize=13, fontweight="bold")
    fig.tight_layout()
    _add_caption(fig,
        "Pearson correlation on label-encoded columns including the target.  "
        "Left = real data, Centre = synthetic data, Right = |Real − Synthetic|.  "
        "Values near 0 in the difference matrix (white) mean the pairwise relationship is preserved; "
        "warm colours flag correlations that k-anonymity or DP has distorted.")
    return fig


def plot_pca(
    real: pd.DataFrame,
    synthetic: pd.DataFrame,
    feature_cols: list[str],
    seed: int = 42,
) -> plt.Figure:
    """
    2D PCA scatter — real vs synthetic projected into the same space.

    Good overlap in PC1/PC2 space = high multi-variate fidelity.
    Systematic separation = k-anonymity or DP has shifted the distribution.
    """
    X_real  = encode_full(real, real, ALL_COLS).astype(float)
    X_synth = encode_full(synthetic, real, ALL_COLS).astype(float)

    scaler = StandardScaler()
    X_all  = scaler.fit_transform(np.vstack([X_real, X_synth]))
    X_real_s  = X_all[:len(X_real)]
    X_synth_s = X_all[len(X_real):]

    pca = PCA(n_components=2, random_state=seed)
    pca.fit(X_all)
    r2d = pca.transform(X_real_s)
    s2d = pca.transform(X_synth_s)

    rng = np.random.default_rng(seed)
    n   = min(2000, len(r2d), len(s2d))
    r2d = r2d[rng.choice(len(r2d), n, replace=False)]
    s2d = s2d[rng.choice(len(s2d), n, replace=False)]

    fig, ax = plt.subplots(figsize=(7, 6))
    ax.scatter(r2d[:, 0], r2d[:, 1], alpha=0.3, s=12,
               color=COLORS["Real → Real (baseline)"],  label=f"Real (n={n:,})")
    ax.scatter(s2d[:, 0], s2d[:, 1], alpha=0.3, s=12,
               color=COLORS["Synthetic → Real (TSTR)"], label=f"Synthetic (n={n:,})")

    var = pca.explained_variance_ratio_
    ax.set_xlabel(f"PC1  ({var[0]*100:.1f}% variance)")
    ax.set_ylabel(f"PC2  ({var[1]*100:.1f}% variance)")
    ax.set_title("PCA Projection: Real vs Synthetic\n"
                 "Overlap = good multivariate fidelity",
                 fontweight="bold")
    ax.legend(fontsize=10, markerscale=3)
    fig.tight_layout()
    _add_caption(fig,
        "All columns (including target) are label-encoded, standardised, and projected to 2D via PCA.  "
        "Overlap between the real (blue) and synthetic (orange) clouds indicates the synthetic data occupies "
        "the same multivariate space.  Systematic separation means the pipeline has introduced a "
        "distributional shift — typically visible as an offset along PC1 when binning is coarse.")
    return fig


# ─── discriminator (propensity score) ────────────────────────────────────────

def run_propensity_test(
    real: pd.DataFrame,
    synthetic: pd.DataFrame,
    seed: int = 42,
) -> tuple[float, float, plt.Figure]:
    """
    Train a LogisticRegression to distinguish real (label=1) from synthetic (label=0).

    AUC ≈ 0.5 → indistinguishable (ideal).
    AUC >> 0.5 → classifier can detect artifacts in the synthetic data.

    Uses 5-fold stratified cross-validation on balanced class sizes.
    """
    X_real  = encode_full(real, real, ALL_COLS).astype(float)
    X_synth = encode_full(synthetic, real, ALL_COLS).astype(float)

    rng = np.random.default_rng(seed)
    n   = min(len(X_real), len(X_synth))
    X_real  = X_real[rng.choice(len(X_real),   n, replace=False)]
    X_synth = X_synth[rng.choice(len(X_synth), n, replace=False)]

    X = np.vstack([X_real, X_synth])
    y = np.array([1] * n + [0] * n)

    X_s = StandardScaler().fit_transform(X)
    clf = LogisticRegression(max_iter=1000, random_state=seed)
    cv  = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    aucs = cross_val_score(clf, X_s, y, cv=cv, scoring="roc_auc")
    mean_auc, std_auc = float(aucs.mean()), float(aucs.std())

    bar_colors = [
        "#10b981" if a < 0.55 else ("#f59e0b" if a < 0.70 else "#ef4444")
        for a in aucs
    ]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.bar([f"Fold {i+1}" for i in range(len(aucs))], aucs,
           color=bar_colors, edgecolor="white")
    ax.axhline(0.5, color="#2563eb", linestyle="--", linewidth=1.8,
               label="Ideal: AUC = 0.5 (indistinguishable)")
    ax.axhline(mean_auc, color="#7c3aed", linestyle=":", linewidth=1.8,
               label=f"Mean AUC = {mean_auc:.3f} ± {std_auc:.3f}")
    for i, v in enumerate(aucs):
        ax.text(i, v + 0.006, f"{v:.3f}", ha="center", fontsize=9)
    ax.set_ylim(0.4, min(1.0, max(aucs) + 0.08))
    ax.set_ylabel("ROC AUC")
    ax.set_title(
        "Discriminator Test — Propensity Score\n"
        "Can a classifier tell real from synthetic?  (Green bars = good)",
        fontweight="bold",
    )
    ax.legend(fontsize=9)
    fig.tight_layout()
    _add_caption(fig,
        "5-fold stratified cross-validation of a LogisticRegression trained to classify records as "
        "real (1) or synthetic (0) on balanced class sizes.  "
        "AUC ≈ 0.5 = indistinguishable (ideal).  AUC > 0.60 = artefacts partially detectable, "
        "typically due to coarse numerical binning.  AUC > 0.80 = strongly detectable — synthetic is visibly artificial.")
    return mean_auc, std_auc, fig


# ─── privacy: DCR ─────────────────────────────────────────────────────────────

def compute_dcr(
    real: pd.DataFrame,
    synthetic: pd.DataFrame,
    seed: int = 42,
) -> np.ndarray:
    """
    Distance to Closest Record: for each synthetic row, the Euclidean distance
    to its nearest real-data neighbour (in normalised feature space).

    High DCR → synthetic records are far from any individual real record → good privacy.
    Near-zero DCR spike → synthetic records closely copy real records → memorisation risk.
    """
    X_real  = encode_full(real, real, ALL_COLS).astype(float)
    X_synth = encode_full(synthetic, real, ALL_COLS).astype(float)

    scaler  = StandardScaler()
    X_all_s = scaler.fit_transform(np.vstack([X_real, X_synth]))
    X_real_s  = X_all_s[:len(X_real)]
    X_synth_s = X_all_s[len(X_real):]

    rng   = np.random.default_rng(seed)
    max_n = 3000
    if len(X_real_s) > max_n:
        X_real_s = X_real_s[rng.choice(len(X_real_s), max_n, replace=False)]
    if len(X_synth_s) > max_n:
        X_synth_s = X_synth_s[rng.choice(len(X_synth_s), max_n, replace=False)]

    nn = NearestNeighbors(n_neighbors=1, algorithm="auto", n_jobs=-1)
    nn.fit(X_real_s)
    distances, _ = nn.kneighbors(X_synth_s)
    return distances.flatten()


def plot_dcr(dcr: np.ndarray) -> plt.Figure:
    """
    DCR histogram + ECDF.

    Right-skewed distribution with no near-zero spike → good privacy.
    A spike at zero means some synthetic records are nearly identical to real records.
    """
    med  = float(np.median(dcr))
    p5   = float(np.percentile(dcr, 5))
    near = float((dcr < 0.1).mean())

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))

    # Histogram
    axes[0].hist(dcr, bins=50, color="#7c3aed", edgecolor="white", alpha=0.85)
    axes[0].axvline(med, color="#ef4444", linewidth=2,
                    label=f"Median = {med:.3f}")
    axes[0].axvline(p5,  color="#f59e0b", linewidth=1.8, linestyle="--",
                    label=f"5th pct = {p5:.3f}")
    axes[0].set_xlabel("Euclidean distance (normalised features)")
    axes[0].set_ylabel("Count")
    axes[0].set_title("DCR Distribution", fontweight="bold")
    axes[0].legend(fontsize=9)

    # ECDF
    sorted_dcr = np.sort(dcr)
    ecdf = np.arange(1, len(sorted_dcr) + 1) / len(sorted_dcr)
    axes[1].plot(sorted_dcr, ecdf, color="#7c3aed", linewidth=2)
    axes[1].axvline(med, color="#ef4444", linewidth=1.5,
                    linestyle="--", label="Median")
    axes[1].set_xlabel("Distance to nearest real record")
    axes[1].set_ylabel("Cumulative fraction")
    axes[1].set_title("DCR ECDF", fontweight="bold")
    axes[1].legend(fontsize=9)

    fig.suptitle(
        f"Distance to Closest Real Record (DCR)\n"
        f"Median={med:.3f}   5th pct={p5:.3f}   "
        f"Fraction within 0.1 of a real record: {near:.1%}\n"
        "Higher median = more privacy.  Near-zero spike indicates memorisation.",
        fontsize=10, fontweight="bold",
    )
    fig.tight_layout()
    _add_caption(fig,
        "Left: histogram of per-synthetic-record distances to the nearest real record in normalised feature space.  "
        "Right: ECDF — y-axis reads 'what fraction of synthetic records are closer than x'.  "
        "A right-skewed histogram with no spike near zero is ideal: no synthetic record is a near-copy of a real person.  "
        "The 5th percentile flags the most privacy-sensitive records; values above 0.1 are generally safe.")
    return fig


# ─── existing utility plots ───────────────────────────────────────────────────

def plot_metrics_comparison(results: dict[str, dict], k: int, epsilon: float) -> plt.Figure:
    labels   = list(results.keys())
    metrics  = ["accuracy", "macro_f1", "roc_auc"]
    m_labels = ["Accuracy", "Macro F1", "ROC AUC"]
    x        = np.arange(len(metrics))
    width    = 0.22
    offsets  = [-width, 0, width]

    fig, ax = plt.subplots(figsize=(10, 5))
    for label, offset in zip(labels, offsets):
        vals = [results[label][m] for m in metrics]
        bars = ax.bar(x + offset, vals, width,
                      label=label, color=COLORS[label],
                      edgecolor="white", linewidth=0.8)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.008,
                    f"{v:.3f}", ha="center", va="bottom",
                    fontsize=8.5, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(m_labels, fontsize=11)
    ax.set_ylim(0, 1.0)
    ax.set_ylabel("Score")
    ax.legend(loc="lower right", fontsize=9)
    ax.set_title(f"Classifier Performance  (k={k}, ε={epsilon})", fontsize=12, pad=10)
    ax.axhline(y=results[labels[0]]["accuracy"],
               color=COLORS[labels[0]], linestyle="--", linewidth=0.8, alpha=0.5)
    fig.tight_layout()
    _add_caption(fig,
        "TSTR gap = Baseline accuracy − TSTR accuracy.  Gap < 0.05 = excellent utility; < 0.10 = acceptable.  "
        "Augmented (real + synthetic combined) tests whether synthetic adds complementary signal.  "
        "Macro F1 treats both income classes equally — more honest than accuracy on this imbalanced dataset.")
    return fig


def plot_confusion_matrices(results: dict[str, dict], y_test: np.ndarray) -> plt.Figure:
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.5))
    for ax, (label, r) in zip(axes, results.items()):
        cm     = confusion_matrix(y_test, r["y_pred"])
        cm_pct = cm.astype(float) / cm.sum(axis=1, keepdims=True) * 100
        sns.heatmap(cm_pct, annot=True, fmt=".1f", ax=ax, cmap="Blues",
                    xticklabels=CLASS_NAMES, yticklabels=CLASS_NAMES,
                    linewidths=0.5, cbar=False, annot_kws={"size": 11, "weight": "bold"})
        for i in range(2):
            for j in range(2):
                ax.text(j + 0.5, i + 0.72, f"n={cm[i,j]:,}",
                        ha="center", va="center", fontsize=8, color="#333333")
        ax.set_title(f"{label}\nAccuracy = {r['accuracy']:.4f}",
                     fontsize=10, color=COLORS[label], fontweight="bold")
        ax.set_xlabel("Predicted", fontsize=9)
        ax.set_ylabel("True", fontsize=9)
    fig.suptitle("Confusion Matrices  (% of true class)",
                 fontsize=13, fontweight="bold", y=1.02)
    fig.tight_layout()
    _add_caption(fig,
        "Cell values = percentage of that true class (rows sum to 100%).  Raw counts shown below each %.  "
        "Top-right cell = missed >50K records (false negatives) — the hardest class to preserve.  "
        "A drop in TSTR's true-positive rate for >50K is the most common sign that DP noise "
        "has perturbed the minority class distribution.")
    return fig


def plot_roc_curves(results: dict[str, dict], y_test: np.ndarray) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(6, 5))
    for label, r in results.items():
        fpr, tpr, _ = roc_curve(y_test, r["y_proba"])
        ax.plot(fpr, tpr, label=f"{label}  (AUC={r['roc_auc']:.3f})",
                color=COLORS[label], linewidth=2)
    ax.plot([0, 1], [0, 1], "k--", linewidth=1, label="Random (AUC=0.500)")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves — Real vs Synthetic Training Data",
                 fontsize=11, fontweight="bold")
    ax.legend(fontsize=9, loc="lower right")
    ax.set_xlim(0, 1); ax.set_ylim(0, 1.02)
    fig.tight_layout()
    _add_caption(fig,
        "AUC = area under the curve; random classifier = 0.5, perfect = 1.0.  "
        "A TSTR AUC close to the baseline AUC means the synthetic data preserved the statistical "
        "signal needed to predict income.  The curve's position relative to the diagonal shows "
        "ranking quality across all decision thresholds — not just the default 0.5 cut-off.")
    return fig


def plot_feature_distributions(real: pd.DataFrame, synthetic: pd.DataFrame) -> plt.Figure:
    num_cols = NUMERICAL_QIS
    cat_cols = CATEGORICAL_QIS + [SENSITIVE_COL]
    n_plots  = len(num_cols) + len(cat_cols)

    fig, axes = plt.subplots(2, 3, figsize=(15, 8))
    axes = axes.flatten()

    for i, col in enumerate(num_cols):
        ax = axes[i]
        ax.hist(real[col].astype(float), bins=30, density=True,
                alpha=0.45, color=COLORS["Real → Real (baseline)"],
                label="Real", edgecolor="white")
        ax.hist(synthetic[col].astype(float), bins=30, density=True,
                alpha=0.45, color=COLORS["Synthetic → Real (TSTR)"],
                label="Synthetic", edgecolor="white")
        r_mean = real[col].mean()
        s_mean = synthetic[col].astype(float).mean()
        ax.axvline(r_mean, color=COLORS["Real → Real (baseline)"],
                   linestyle="--", linewidth=1.5, label=f"Real μ={r_mean:.1f}")
        ax.axvline(s_mean, color=COLORS["Synthetic → Real (TSTR)"],
                   linestyle="--", linewidth=1.5, label=f"Synth μ={s_mean:.1f}")
        ax.set_title(col, fontsize=11, fontweight="bold")
        ax.set_xlabel("Value"); ax.set_ylabel("Density")
        ax.legend(fontsize=8)

    for j, col in enumerate(cat_cols):
        ax = axes[len(num_cols) + j]
        cats   = sorted(set(real[col].unique()) | set(synthetic[col].unique()))
        r_vals = [real[col].value_counts(normalize=True).get(c, 0) for c in cats]
        s_vals = [synthetic[col].value_counts(normalize=True).get(c, 0) for c in cats]
        x_pos = np.arange(len(cats)); w = 0.35
        ax.bar(x_pos - w/2, r_vals, w, color=COLORS["Real → Real (baseline)"],
               label="Real", edgecolor="white")
        ax.bar(x_pos + w/2, s_vals, w, color=COLORS["Synthetic → Real (TSTR)"],
               label="Synthetic", edgecolor="white")
        for xi, (rv, sv) in enumerate(zip(r_vals, s_vals)):
            ax.text(xi - w/2, rv + 0.01, f"{rv:.2f}", ha="center", va="bottom", fontsize=8)
            ax.text(xi + w/2, sv + 0.01, f"{sv:.2f}", ha="center", va="bottom", fontsize=8)
        ax.set_xticks(x_pos); ax.set_xticklabels(cats, rotation=15, ha="right")
        ax.set_title(col, fontsize=11, fontweight="bold")
        ax.set_ylabel("Proportion")
        ax.legend(fontsize=8)
        ax.set_ylim(0, max(max(r_vals), max(s_vals)) * 1.25)

    for k_idx in range(n_plots, len(axes)):
        axes[k_idx].set_visible(False)

    fig.suptitle("Feature Distribution: Real vs Synthetic Data",
                 fontsize=13, fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    _add_caption(fig,
        "Overlaid density histograms (numerical) and grouped bars (categorical).  "
        "The stepped / blocky shape in numerical histograms is the signature of k-anonymity binning — all values within a generalisation bin are "
        "replaced by a representative point.  Dashed lines = column means.  "
        "Categorical bars show the class proportion; near-equal heights = good preservation.")
    return fig


def plot_per_class_f1(results: dict[str, dict], y_test: np.ndarray) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    labels  = list(results.keys())
    x       = np.arange(len(CLASS_NAMES))
    width   = 0.25
    offsets = [-width, 0, width]
    for label, offset in zip(labels, offsets):
        f1s  = f1_score(y_test, results[label]["y_pred"], average=None)
        bars = ax.bar(x + offset, f1s, width,
                      label=label, color=COLORS[label], edgecolor="white")
        for bar, v in zip(bars, f1s):
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.01,
                    f"{v:.3f}", ha="center", va="bottom", fontsize=8.5)
    ax.set_xticks(x); ax.set_xticklabels(CLASS_NAMES, fontsize=11)
    ax.set_ylim(0, 1.0); ax.set_ylabel("F1 Score")
    ax.set_title("Per-Class F1: Real vs Synthetic Training",
                 fontsize=12, fontweight="bold")
    ax.legend(fontsize=9)
    fig.tight_layout()
    _add_caption(fig,
        "F1 = harmonic mean of precision and recall, computed separately per class.  "
        "The minority class (>50K, ~24% of records) F1 is the most sensitive indicator: "
        "small distributional shifts from DP noise disproportionately reduce recall on this class.  "
        "A near-equal ≤50K F1 but a sharply lower >50K F1 is the typical TSTR failure pattern.")
    return fig


def plot_feature_importance(results: dict[str, dict], feature_names: list[str]) -> plt.Figure:
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.5), sharey=True)
    for ax, (label, r) in zip(axes, results.items()):
        importances = [r["feature_importance"][f] for f in feature_names]
        y_pos = np.arange(len(feature_names))
        ax.barh(y_pos, importances, color=COLORS[label], edgecolor="white", height=0.6)
        ax.set_yticks(y_pos); ax.set_yticklabels(feature_names, fontsize=9)
        ax.set_xlabel("Importance")
        ax.set_title(label, fontsize=10, color=COLORS[label], fontweight="bold")
        for i, v in enumerate(importances):
            ax.text(v + 0.002, i, f"{v:.3f}", va="center", fontsize=8.5)
    fig.suptitle("RandomForest Feature Importances", fontsize=13, fontweight="bold")
    fig.tight_layout()
    _add_caption(fig,
        "Gini impurity-based importance: contribution of each feature to reducing prediction uncertainty.  "
        "Consistent ranking across Baseline and TSTR (e.g. age most important in both) means "
        "synthetic data preserved inter-feature relationships.  A rank change signals that "
        "coarse generalisation has shifted which feature the model leans on.")
    return fig


# ─── summary page ─────────────────────────────────────────────────────────────

def plot_summary_page(
    results: dict[str, dict],
    stats: pd.DataFrame,
    propensity_auc: float,
    propensity_std: float,
    dcr: np.ndarray,
    k: int, epsilon: float,
    n_real: int, n_synth: int,
) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(11, 8.5))
    ax.axis("off")
    T = ax.transAxes

    def txt(x, y, s, **kw):
        ax.text(x, y, s, transform=T, va="top", **kw)

    def hline(y):
        ax.plot([0.05, 0.95], [y, y], transform=T,
                color="#e5e7eb", linewidth=1, clip_on=False)

    y = 0.96
    txt(0.5, y, "SPIDEr Synthetic Data — Evaluation Report",
        ha="center", fontsize=18, fontweight="bold")
    y -= 0.055
    txt(0.5, y, f"k = {k}    ε = {epsilon}    "
        f"Real rows = {n_real:,}    Synthetic rows = {n_synth:,}",
        ha="center", fontsize=11, color="#555555")
    y -= 0.04

    def section(title, y_pos):
        hline(y_pos)
        txt(0.05, y_pos - 0.005, title, ha="left",
            fontsize=12, fontweight="bold", color="#2563eb")
        return y_pos - 0.040

    def row(label, value, y_pos, color="#111111"):
        txt(0.08,  y_pos, label, ha="left", fontsize=10, color="#666666")
        txt(0.48,  y_pos, value, ha="left", fontsize=10, fontweight="bold", color=color)
        return y_pos - 0.033

    # ── Fidelity ──────────────────────────────────────────────────────────────
    y = section("① Fidelity", y)
    avg_js  = stats["js_divergence"].mean()
    avg_ks  = stats[stats["type"] == "numerical"]["stat_value"].mean()
    avg_tvd = stats[stats["type"] == "categorical"]["stat_value"].mean()

    def fid_color(v, thr_g, thr_f):
        return "#10b981" if v < thr_g else ("#f59e0b" if v < thr_f else "#ef4444")

    y = row("Avg JS Divergence (all columns)",
            f"{avg_js:.4f}  {'✓ Good' if avg_js < 0.10 else '△ Fair' if avg_js < 0.20 else '✗ Poor'}",
            y, fid_color(avg_js, 0.10, 0.20))
    y = row("Avg KS Statistic (numerical cols)",    f"{avg_ks:.4f}",  y)
    y = row("Avg TVD (categorical + target cols)", f"{avg_tvd:.4f}", y)

    # ── Utility ───────────────────────────────────────────────────────────────
    y = section("② Utility  (TSTR — RandomForest, UCI Adult)", y)
    base = results["Real → Real (baseline)"]
    tstr = results["Synthetic → Real (TSTR)"]
    gap  = base["accuracy"] - tstr["accuracy"]

    y = row("Baseline accuracy  (real train → real test)",
            f"{base['accuracy']:.4f}", y)
    y = row("TSTR accuracy      (synth train → real test)",
            f"{tstr['accuracy']:.4f}   [gap: {gap:+.4f}]",
            y, fid_color(abs(gap), 0.05, 0.10))
    y = row("TSTR Macro F1",  f"{tstr['macro_f1']:.4f}", y)
    y = row("TSTR ROC AUC",   f"{tstr['roc_auc']:.4f}",  y)

    disc_label = (
        "✓ Indistinguishable" if propensity_auc < 0.55
        else ("△ Partially detectable" if propensity_auc < 0.70
              else "✗ Easily detected")
    )
    y = row("Discriminator AUC  (target: 0.5)",
            f"{propensity_auc:.3f} ± {propensity_std:.3f}   {disc_label}",
            y, fid_color(propensity_auc - 0.5, 0.05, 0.20))

    # ── Privacy ───────────────────────────────────────────────────────────────
    y = section("③ Privacy  (DCR — Distance to Closest Record)", y)
    med = float(np.median(dcr))
    p5  = float(np.percentile(dcr, 5))
    near = float((dcr < 0.1).mean())

    y = row("DCR Median",
            f"{med:.4f}   {'✓ Good' if med > 0.5 else '△ Moderate' if med > 0.2 else '✗ Low'}",
            y, fid_color(1 - med, 0.5, 0.8))
    y = row("DCR 5th percentile",
            f"{p5:.4f}   (fraction within 0.1 of a real record: {near:.1%})",
            y)

    ax.text(0.5, 0.02,
            "Pages 2–13: fidelity table · distributions · correlations · PCA · "
            "ROC · confusion matrices · discriminator · DCR →",
            transform=T, ha="center", fontsize=8.5, color="#999999", style="italic")
    return fig


# ─── console report ───────────────────────────────────────────────────────────

def _bar(value: float, width: int = 28) -> str:
    filled = int(round(value * width))
    return "█" * filled + "░" * (width - filled)


def print_report(
    results: dict[str, dict],
    stats: pd.DataFrame,
    propensity_auc: float,
    propensity_std: float,
    dcr: np.ndarray,
) -> None:
    print("\n" + "═" * 76)
    print("  SPIDEr SYNTHETIC DATA EVALUATION REPORT")
    print("  Dataset: UCI Adult Census Income  (target: income ≥ $50K)")
    print("═" * 76)

    print("\n── FIDELITY ──────────────────────────────────────────────────────────")
    print(f"  {'Column':<18}  {'Type':<12}  {'Test':<5}  {'Statistic':>10}  "
          f"{'p-value':>10}  {'JS Div':>8}")
    print("  " + "─" * 68)
    for _, r in stats.iterrows():
        p_str = f"{r['p_value']:.3e}" if pd.notna(r["p_value"]) else "         —"
        print(f"  {r['column']:<18}  {r['type']:<12}  {r['stat_name']:<5}  "
              f"{r['stat_value']:>10.4f}  {p_str:>10}  {r['js_divergence']:>8.4f}")

    print("\n── UTILITY (TSTR) ────────────────────────────────────────────────────")
    print(f"  {'Condition':<30}  {'Acc':>6}  {'F1':>6}  {'AUC':>6}  Bar")
    print("  " + "─" * 70)
    for label, r in results.items():
        print(f"  {label:<30}  {r['accuracy']:>6.4f}  "
              f"{r['macro_f1']:>6.4f}  {r['roc_auc']:>6.4f}  "
              f"{_bar(r['accuracy'])}")

    print("\n── DISCRIMINATOR ─────────────────────────────────────────────────────")
    disc = ("indistinguishable ✓" if propensity_auc < 0.55
            else ("partially detectable △" if propensity_auc < 0.70
                  else "easily detected ✗"))
    print(f"  Propensity AUC: {propensity_auc:.4f} ± {propensity_std:.4f}  ({disc})")

    print("\n── PRIVACY (DCR) ─────────────────────────────────────────────────────")
    print(f"  Median distance to nearest real record : {np.median(dcr):.4f}")
    print(f"  5th percentile                         : {np.percentile(dcr, 5):.4f}")
    print(f"  Fraction within 0.1 of a real record  : {(dcr < 0.1).mean():.2%}")
    print("═" * 76)

    print("\n─── Detailed classification reports ───\n")
    for label, r in results.items():
        print(f"[ {label} ]")
        print(r["report"])


# ─── I/O ──────────────────────────────────────────────────────────────────────

def save_pdf(figures: list[plt.Figure], path: str) -> None:
    with PdfPages(path) as pdf:
        for fig in figures:
            pdf.savefig(fig, bbox_inches="tight")
            plt.close(fig)


# ─── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Comprehensive synthetic data evaluation: fidelity + utility + privacy."
    )
    parser.add_argument("--k",         type=int,   default=50)
    parser.add_argument("--epsilon",   type=float, default=1.0)
    parser.add_argument("--seed",      type=int,   default=42)
    parser.add_argument("--test-size", type=float, default=0.20, dest="test_size")
    args = parser.parse_args()

    repo_root    = os.path.abspath(os.path.dirname(__file__))
    feature_cols = NUMERICAL_QIS + CATEGORICAL_QIS

    # 1. data
    df = load_adult()
    real_train, real_test = train_test_split(
        df, test_size=args.test_size, random_state=args.seed,
        stratify=df[SENSITIVE_COL],
    )
    print(f"[data] Train: {len(real_train):,}  |  Test: {len(real_test):,}")

    # 2. synthetic
    synthetic_train = generate_synthetic(
        real_train, k=args.k, epsilon=args.epsilon,
        n_samples=len(real_train), seed=args.seed, repo_root=repo_root,
    )

    # 3. encode (TSTR)
    X_real_tr, y_real_tr, X_test, y_test = encode_features(
        real_train, real_test, feature_cols)
    X_syn_tr, y_syn_tr, _, _ = encode_features(
        synthetic_train, real_test, feature_cols)
    X_aug_tr = np.vstack([X_real_tr, X_syn_tr])
    y_aug_tr = np.concatenate([y_real_tr, y_syn_tr])

    # 4. TSTR
    print("\n[eval] Training classifiers …")
    results: dict[str, dict] = {}
    print("  → Real baseline …")
    results["Real → Real (baseline)"] = train_and_eval(
        X_real_tr, y_real_tr, X_test, y_test, feature_cols, args.seed)
    print("  → TSTR (synthetic) …")
    results["Synthetic → Real (TSTR)"] = train_and_eval(
        X_syn_tr, y_syn_tr, X_test, y_test, feature_cols, args.seed)
    print("  → Augmented …")
    results["Real+Synth → Real (aug)"] = train_and_eval(
        X_aug_tr, y_aug_tr, X_test, y_test, feature_cols, args.seed)

    # 5. fidelity
    print("\n[fidelity] Computing statistical similarity …")
    stats = compute_fidelity_stats(real_train, synthetic_train)

    # 6. discriminator / propensity score
    print("[discriminator] Running propensity score test …")
    prop_auc, prop_std, fig_prop = run_propensity_test(
        real_train, synthetic_train, seed=args.seed)

    # 7. privacy: DCR
    print("[privacy] Computing DCR (Distance to Closest Record) …")
    dcr = compute_dcr(real_train, synthetic_train, seed=args.seed)

    # 8. console report
    print_report(results, stats, prop_auc, prop_std, dcr)

    # 9. PDF report (14 pages)
    print("\n[plot] Generating evaluation report …")
    figures = [
        plot_summary_page(results, stats, prop_auc, prop_std, dcr,
                          args.k, args.epsilon, len(real_train), len(synthetic_train)),
        plot_setup_page(args.k, args.epsilon, len(real_train), len(synthetic_train)),
        plot_fidelity_table(stats, args.k, args.epsilon),
        plot_descriptive_stats(real_train, synthetic_train),
        plot_feature_distributions(real_train, synthetic_train),
        plot_correlation_matrices(real_train, synthetic_train, feature_cols),
        plot_pca(real_train, synthetic_train, feature_cols, args.seed),
        plot_metrics_comparison(results, args.k, args.epsilon),
        plot_roc_curves(results, y_test),
        plot_confusion_matrices(results, y_test),
        plot_per_class_f1(results, y_test),
        plot_feature_importance(results, feature_cols),
        fig_prop,
        plot_dcr(dcr),
    ]

    out_dir = os.path.join(repo_root, "output")
    os.makedirs(out_dir, exist_ok=True)

    pdf_path = os.path.join(out_dir, "evaluation_report.pdf")
    save_pdf(figures, pdf_path)
    print(f"[plot] Saved → {pdf_path}")

    out_csv = os.path.join(out_dir, "synthetic_adult.csv")
    synthetic_train.to_csv(out_csv, index=False)
    print(f"[output] Synthetic data saved → {out_csv}")


if __name__ == "__main__":
    main()
