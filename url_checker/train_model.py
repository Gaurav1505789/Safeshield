"""
SafeShield URL Model Training Pipeline
=======================================
Trains a calibrated Gradient Boosting classifier on a balanced dataset of phishing
and legitimate URLs. Includes:
  - Automatic dataset preparation from verified_online.csv + negatives
  - Forced-negative overrides (forced_negatives.txt)
  - Hyperparameter tuning via RandomizedSearchCV (--tune flag)
  - F1-optimised decision threshold selection
  - Feature importance report
  - Calibrated probability output (CalibratedClassifierCV)

Usage
-----
  # From url_checker/ directory:
  python train_model.py                          # fast run, no tuning
  python train_model.py --tune                   # with hyperparameter search (~5-15 min)
  python train_model.py --tune --max-samples 30000  # tuning on capped subset
"""

import argparse
import json
import os
import pathlib
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# ── Path setup ────────────────────────────────────────────────────────────────
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import (
    GradientBoostingClassifier,
    HistGradientBoostingClassifier,
)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    brier_score_loss,
    classification_report,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    RandomizedSearchCV,
    StratifiedKFold,
    cross_val_score,
    train_test_split,
)
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.utils import resample
from scipy.stats import loguniform, randint, uniform

from dataset.utils.text_clean import clean_text
from dataset.utils.url_features import extract_url_features
from dataset.utils.url_normalize import normalize_url

# ── CLI args ──────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Train SafeShield URL fraud detection models")
parser.add_argument(
    "--max-samples", type=int, default=0,
    help="Limit training rows (0 = use all). Useful for quick experiments.",
)
parser.add_argument(
    "--tune", action="store_true", default=False,
    help="Run RandomizedSearchCV hyperparameter tuning for the GB model.",
)
parser.add_argument(
    "--n-iter", type=int, default=30,
    help="Number of RandomizedSearchCV iterations (default: 30).",
)
args, _rest = parser.parse_known_args()
max_samples = args.max_samples
run_tuning = args.tune
n_iter = args.n_iter

print(f"[train_model] max_samples={max_samples}, tune={run_tuning}, n_iter={n_iter}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MESSAGE MODEL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
print("\n── Training Message Fraud Detection Model ───────────────────────────────")
msg_data = pd.read_csv(str(CURRENT_DIR / "dataset" / "messages.csv"))
url_data = pd.read_csv(str(CURRENT_DIR / "dataset" / "urls.csv"))

msg_data["text"] = msg_data["text"].apply(clean_text)

vectorizer = TfidfVectorizer(
    max_features=1000,
    min_df=1,
    max_df=1.0,
    ngram_range=(1, 2),
    sublinear_tf=True,
    stop_words="english",
)
X_text = vectorizer.fit_transform(msg_data["text"])
y_text = msg_data["label"]

text_model = SVC(kernel="rbf", C=1.0, gamma="scale", probability=True)
text_model.fit(X_text, y_text)

if X_text.shape[0] > 2:
    cv_scores = cross_val_score(text_model, X_text, y_text, cv=min(3, X_text.shape[0]))
    print(f"  Text Model CV Score: {cv_scores.mean():.3f} (±{cv_scores.std():.3f})")

pickle.dump(text_model, open(str(CURRENT_DIR / "model" / "text_model.pkl"), "wb"))
pickle.dump(vectorizer, open(str(CURRENT_DIR / "model" / "vectorizer.pkl"), "wb"))
print("✓ Message model trained and saved")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DATASET PREPARATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
print("\n── Preparing URL dataset ────────────────────────────────────────────────")
phish_file = CURRENT_DIR / "dataset" / "verified_online.csv"

if phish_file.exists():
    phish_df = pd.read_csv(phish_file)
    phish_df = phish_df[
        (phish_df["verified"].str.lower() == "yes")
        & (phish_df["online"].str.lower() == "yes")
    ]
    phish_df = phish_df[["url", "phish_id", "submission_time", "target"]].dropna(subset=["url"])
    phish_df["label"] = 1
    print(f"  Verified phishing URLs (positives): {len(phish_df)}")

    # ── Negatives: base from urls.csv ─────────────────────────────────────────
    neg_df = url_data[url_data["label"] == 0][["url", "label"]].copy()

    # ── Negatives: built-in seed ──────────────────────────────────────────────
    seed_safe = pd.DataFrame(
        {
            "url": [
                "https://google.com", "https://youtube.com", "https://facebook.com",
                "https://amazon.com", "https://wikipedia.org", "https://twitter.com",
                "https://instagram.com", "https://linkedin.com", "https://apple.com",
                "https://microsoft.com", "https://reddit.com", "https://netflix.com",
                "https://paypal.com", "https://pinterest.com", "https://stackoverflow.com",
                "https://bing.com", "https://yahoo.com", "https://whatsapp.com",
                "https://etsy.com", "https://booking.com", "https://airbnb.com",
                "https://dropbox.com", "https://slideshare.net", "https://mozilla.org",
                "https://ubuntu.com", "https://cloudflare.com", "https://salesforce.com",
                "https://adobe.com", "https://medium.com", "https://quora.com",
                "https://telegram.org", "https://tiktok.com", "https://stripe.com",
                "https://shopify.com", "https://bbc.co.uk", "https://nytimes.com",
                "https://washingtonpost.com", "https://theguardian.com",
                "https://github.com", "https://gitlab.com",
            ],
            "label": [0] * 40,
        }
    )

    # ── Negatives: user-provided CSV / TXT seeds ──────────────────────────────
    for seed_path in [
        CURRENT_DIR / "dataset" / "negatives_seed.csv",
        CURRENT_DIR / "dataset" / "negatives_seed.txt",
    ]:
        if seed_path.exists():
            try:
                if seed_path.suffix == ".csv":
                    extra = pd.read_csv(seed_path)
                    if "label" not in extra.columns:
                        extra["label"] = 0
                else:
                    lines = [
                        line.strip()
                        for line in seed_path.read_text(encoding="utf-8").splitlines()
                        if line.strip()
                    ]
                    extra = pd.DataFrame({"url": lines, "label": [0] * len(lines)})
                seed_safe = pd.concat(
                    [seed_safe, extra[["url", "label"]].dropna(subset=["url"])],
                    ignore_index=True,
                )
                print(f"  Loaded {len(extra)} seeds from {seed_path.name}")
            except Exception as exc:
                print(f"  Could not load {seed_path.name}: {exc}")
            break  # use only the first that exists

    neg_df = (
        pd.concat([neg_df, seed_safe], ignore_index=True)
        .drop_duplicates(subset=["url"])
        .reset_index(drop=True)
    )
    print(f"  Negative pool after seeds: {len(neg_df)}")

    # ── Negatives: URL path/query augmentation ────────────────────────────────
    try:
        target_neg = min(20_000, max(len(phish_df), 2_000))
        aug = []
        sample_urls = list(neg_df["url"].dropna().unique())[:500]
        base_hosts = []
        for u in sample_urls:
            h = normalize_url(u).get("netloc", "")
            if h and h not in base_hosts:
                base_hosts.append(h)
        if not base_hosts:
            base_hosts = ["google.com", "github.com", "microsoft.com", "stackoverflow.com"]

        i = 0
        while len(neg_df) + len(aug) < target_neg:
            host = base_hosts[i % len(base_hosts)]
            pv = f"/page/{i % 1000}"
            aug.append({"url": f"https://{host}{pv}", "label": 0})
            aug.append({"url": f"https://{host}/search?q=term{i%200}", "label": 0})
            i += 1
            if i > 100_000:
                break

        if aug:
            aug_df = pd.DataFrame(aug).drop_duplicates(subset=["url"])
            neg_df = (
                pd.concat([neg_df, aug_df], ignore_index=True)
                .drop_duplicates(subset=["url"])
                .reset_index(drop=True)
            )
            print(f"  Augmented negative pool to {len(neg_df)} URLs")
    except Exception as exc:
        print(f"  Augmentation skipped: {exc}")

    # ── Balance classes ───────────────────────────────────────────────────────
    if len(neg_df) < len(phish_df):
        neg_df = resample(neg_df, replace=True, n_samples=len(phish_df), random_state=42)
    else:
        neg_df = neg_df.sample(n=min(len(neg_df), len(phish_df)), random_state=42)

    pos_sample = phish_df[["url", "label"]].sample(n=len(neg_df), random_state=42)
    combined = pd.concat([pos_sample, neg_df[["url", "label"]]], ignore_index=True)
    combined = combined.groupby("url", as_index=False)["label"].max()

    # ── Forced negatives override ─────────────────────────────────────────────
    for forced_path in [
        CURRENT_DIR / "dataset" / "forced_negatives.txt",
        CURRENT_DIR / "dataset" / "forced_negatives.csv",
    ]:
        if forced_path.exists():
            try:
                if forced_path.suffix == ".csv":
                    fdf = pd.read_csv(forced_path)
                    forced = fdf["url"].dropna().astype(str).tolist() if "url" in fdf.columns else []
                else:
                    forced = [
                        line.strip()
                        for line in forced_path.read_text(encoding="utf-8").splitlines()
                        if line.strip()
                    ]
                forced_set = set(forced)
                missing = forced_set - set(combined["url"])
                if missing:
                    combined = pd.concat(
                        [combined, pd.DataFrame({"url": list(missing), "label": [0] * len(missing)})],
                        ignore_index=True,
                    )
                combined.loc[combined["url"].isin(forced_set), "label"] = 0
                print(f"  Applied {len(forced_set)} forced negatives")
            except Exception as exc:
                print(f"  Forced negatives skipped: {exc}")
            break

    phish_count = int(combined["label"].sum())
    legit_count = len(combined) - phish_count
    print(f"  Balanced dataset: {len(combined)} samples (phish={phish_count}, legit={legit_count})")

else:
    combined = url_data[["url", "label"]].copy()
    print(f"  verified_online.csv not found — using urls.csv ({len(combined)} samples)")

# ── Clean and save ────────────────────────────────────────────────────────────
combined = (
    combined[combined["url"].notna() & (combined["url"].str.strip() != "")]
    .reset_index(drop=True)
)
train_csv = CURRENT_DIR / "dataset" / "urls_train.csv"
combined.to_csv(str(train_csv), index=False)
print(f"  Saved training set → {train_csv}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FEATURE EXTRACTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
print("\n── Extracting features ──────────────────────────────────────────────────")

# Optionally subsample for speed
if max_samples and max_samples < len(combined):
    combined = combined.sample(n=max_samples, random_state=42).reset_index(drop=True)
    print(f"  Subsampled to {len(combined)} rows (--max-samples {max_samples})")

X_url = [extract_url_features(u) for u in combined["url"]]
y_url = combined["label"].values
n_features = len(X_url[0])
print(f"  Feature vector length: {n_features}")

# ── Train / calibration / test split ─────────────────────────────────────────
if len(X_url) >= 10:
    X_tmp, X_test, y_tmp, y_test = train_test_split(
        X_url, y_url, test_size=0.15, stratify=y_url, random_state=42
    )
    X_train, X_calib, y_train, y_calib = train_test_split(
        X_tmp, y_tmp, test_size=0.20, stratify=y_tmp, random_state=42
    )
else:
    X_train = X_calib = X_test = X_url
    y_train = y_calib = y_test = y_url

print(f"  Train: {len(X_train)}, Calib: {len(X_calib)}, Test: {len(X_test)}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HYPERPARAMETER TUNING  (optional — enabled with --tune)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
gb_base_params = dict(n_estimators=200, learning_rate=0.08, max_depth=5,
                      min_samples_leaf=10, subsample=0.85, max_features="sqrt",
                      random_state=42)

if run_tuning:
    print(f"\n── Hyperparameter tuning (n_iter={n_iter}) ──────────────────────────────")
    param_dist = {
        "n_estimators":    randint(100, 600),
        "learning_rate":   loguniform(0.01, 0.3),
        "max_depth":       randint(3, 9),
        "min_samples_leaf": randint(5, 41),
        "subsample":       uniform(0.6, 0.4),   # [0.6, 1.0]
        "max_features":    ["sqrt", "log2", None],
    }
    base_gb = GradientBoostingClassifier(random_state=42)
    cv_inner = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
    search = RandomizedSearchCV(
        base_gb,
        param_distributions=param_dist,
        n_iter=n_iter,
        scoring="f1",           # optimise for F1 (balances Precision & Recall)
        cv=cv_inner,
        n_jobs=-1,
        verbose=1,
        random_state=42,
        refit=True,
    )
    search.fit(X_train, y_train)
    best_params = search.best_params_
    print(f"  Best params: {best_params}")
    print(f"  Best CV F1:  {search.best_score_:.4f}")
    gb_base_params = {**best_params, "random_state": 42}
else:
    print("\n── Using default GBM params (pass --tune to optimise) ───────────────────")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CANDIDATE MODELS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
print("\n── Training candidate models ────────────────────────────────────────────")
candidates = {
    "gb": GradientBoostingClassifier(**gb_base_params),
    "hgb": HistGradientBoostingClassifier(
        max_iter=200, learning_rate=0.08, max_depth=5,
        min_samples_leaf=10, random_state=42
    ),
    "logreg": LogisticRegression(
        max_iter=500, C=1.0, class_weight="balanced",
        solver="liblinear", random_state=42
    ),
}

best_model = None
best_metrics: dict | None = None
best_name: str | None = None

for name, model in candidates.items():
    try:
        model.fit(X_train, y_train)

        # Calibrate with sigmoid on hold-out calibration set.
        # cv=None means "model is already fitted, just fit the calibrator on X_calib".
        try:
            try:
                calibrator = CalibratedClassifierCV(estimator=model, method="sigmoid", cv=None)
            except TypeError:
                calibrator = CalibratedClassifierCV(base_estimator=model, method="sigmoid", cv=None)
            calibrator.fit(X_calib, y_calib)
            used_model = calibrator
            calibrated_used = True
        except Exception as cal_exc:
            print(f"  [{name}] Calibration failed ({cal_exc}); using uncalibrated model")
            used_model = model
            calibrated_used = False

        # Evaluate on held-out test set
        classes = list(
            used_model.classes_ if hasattr(used_model, "classes_") else model.classes_
        )
        fraud_idx = classes.index(1) if 1 in classes else -1
        probs = (
            used_model.predict_proba(X_test)[:, fraud_idx]
            if fraud_idx >= 0
            else np.max(used_model.predict_proba(X_test), axis=1)
        )
        brier = brier_score_loss(y_test, probs)
        roc_auc = roc_auc_score(y_test, probs) if len(set(y_test)) > 1 else float("nan")
        f1 = f1_score(y_test, (probs >= 0.5).astype(int), zero_division=0)

        print(f"  [{name}] Brier={brier:.4f}  ROC-AUC={roc_auc:.4f}  F1@0.5={f1:.4f}  calibrated={calibrated_used}")

        # Select by ROC-AUC (robust to threshold choice); tie-break by F1
        is_better = best_metrics is None or roc_auc > best_metrics["roc_auc"] + 1e-6 or (
            abs(roc_auc - best_metrics["roc_auc"]) <= 1e-6 and f1 > best_metrics["f1"]
        )
        if is_better:
            best_metrics = {"brier": brier, "roc_auc": roc_auc, "f1": f1, "calibrated": calibrated_used}
            best_model = used_model
            best_name = name

    except Exception as exc:
        print(f"  [{name}] Skipped due to error: {exc}")

# ── Fallback ──────────────────────────────────────────────────────────────────
if best_model is None:
    print("  No candidate succeeded; training fallback GBM on full data")
    best_model = GradientBoostingClassifier(**gb_base_params)
    best_model.fit(X_url, y_url)
    best_name = "gb_fallback"
    best_metrics = {"brier": None, "roc_auc": None, "f1": None, "calibrated": False}

print(f"\n  ✓ Selected model: {best_name}")

# ── Save models ───────────────────────────────────────────────────────────────
model_dir = CURRENT_DIR / "model"
pickle.dump(best_model, open(str(model_dir / "url_model_calibrated.pkl"), "wb"))
if best_name in ("logreg", "hgb"):
    pickle.dump(best_model, open(str(model_dir / "url_model_light.pkl"), "wb"))

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# THRESHOLD SELECTION  — maximise F1 (no FPR constraint)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
print("\n── Selecting decision threshold (max F1) ────────────────────────────────")

classes = list(best_model.classes_ if hasattr(best_model, "classes_") else [0, 1])
fraud_idx = classes.index(1) if 1 in classes else -1
probs_test = (
    best_model.predict_proba(X_test)[:, fraud_idx]
    if fraud_idx >= 0
    else np.max(best_model.predict_proba(X_test), axis=1)
)

thresholds = np.linspace(0.05, 0.95, 181)
best_thresh_info: dict | None = None

for t in thresholds:
    preds = (probs_test >= t).astype(int)
    y_arr = np.array(y_test)
    tp = int(((preds == 1) & (y_arr == 1)).sum())
    fp = int(((preds == 1) & (y_arr == 0)).sum())
    fn = int(((preds == 0) & (y_arr == 1)).sum())
    tn = int(((preds == 0) & (y_arr == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_t      = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    if best_thresh_info is None or f1_t > best_thresh_info["f1"]:
        best_thresh_info = {
            "threshold": float(t),
            "f1": f1_t,
            "precision": precision,
            "recall": recall,
            "fpr": fpr,
        }

# Clamp to sane bounds
raw_threshold = best_thresh_info["threshold"]
recommended_threshold = max(0.40, min(0.80, raw_threshold))
threshold_clamped = recommended_threshold != raw_threshold

print(
    f"  Best threshold: {raw_threshold:.3f} → clamped to {recommended_threshold:.3f}"
    f" | F1={best_thresh_info['f1']:.4f}"
    f"  P={best_thresh_info['precision']:.4f}  R={best_thresh_info['recall']:.4f}"
    f"  FPR={best_thresh_info['fpr']:.4f}"
)

# ── Classification report ─────────────────────────────────────────────────────
final_preds = (probs_test >= recommended_threshold).astype(int)
print("\n── Classification Report (test set) ─────────────────────────────────────")
print(classification_report(y_test, final_preds, target_names=["legit", "phishing"], digits=4))

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FEATURE IMPORTANCE REPORT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FEATURE_NAMES = [
    "url_len", "dot_count", "hyphen_count", "at_count", "is_https",
    "host_dot_count", "path_depth", "digit_count", "has_suspicious_kw",
    "underscore_count", "query_param_count", "is_ip", "is_punycode",
    "is_whitelisted", "domain_entropy", "path_entropy", "digit_ratio",
    "special_char_count", "subdomain_count", "tld_len", "has_port",
    "path_token_longest", "consecutive_digits_max", "brand_impersonation",
    "double_slash_in_path", "vowel_to_consonant", "consecutive_char_repeat",
    "hex_char_count", "suspicious_tld_flag", "typosquatting_flag"
]

# Retrieve importances from the underlying estimator if calibrated
def _get_importances(model):
    if hasattr(model, "feature_importances_"):
        return model.feature_importances_
    if hasattr(model, "calibrated_classifiers_"):
        # CalibratedClassifierCV wraps base estimators
        ests = [
            cc.estimator if hasattr(cc, "estimator") else cc.base_estimator
            for cc in model.calibrated_classifiers_
        ]
        imps = [e.feature_importances_ for e in ests if hasattr(e, "feature_importances_")]
        if imps:
            return np.mean(imps, axis=0)
    if hasattr(model, "coef_"):
        return np.abs(model.coef_).flatten()
    return None

importances = _get_importances(best_model)
if importances is not None and len(importances) == len(FEATURE_NAMES):
    print("\n── Feature Importance ────────────────────────────────────────────────────")
    pairs = sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    for feat, imp in pairs:
        bar = "█" * int(imp * 40)
        print(f"  {feat:<26} {imp:.4f}  {bar}")
else:
    print("\n  (Feature importances not available for this model type)")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SAVE CALIBRATION INFO
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
brier_final = brier_score_loss(y_test, probs_test)
roc_auc_final = roc_auc_score(y_test, probs_test) if len(set(y_test)) > 1 else None

calib_info = {
    "model_name": best_name,
    "n_features": n_features,
    "feature_names": FEATURE_NAMES[:n_features],
    "brier_score": float(brier_final),
    "roc_auc": float(roc_auc_final) if roc_auc_final is not None else None,
    "f1_at_threshold": float(best_thresh_info["f1"]),
    "precision_at_threshold": float(best_thresh_info["precision"]),
    "recall_at_threshold": float(best_thresh_info["recall"]),
    "recommended_threshold": float(recommended_threshold),
    "raw_threshold": float(raw_threshold),
    "threshold_clamped": threshold_clamped,
    "calibrated": bool(best_metrics.get("calibrated", False) if best_metrics else False),
    "tuning_enabled": run_tuning,
    "train_size": len(X_train),
    "test_size": len(X_test),
}

calib_path = model_dir / "url_model_calibration_info.json"
with open(str(calib_path), "w", encoding="utf-8") as fh:
    json.dump(calib_info, fh, indent=2)

print(f"\n✓ Saved model → {model_dir / 'url_model_calibrated.pkl'}")
print(f"✓ Saved calibration info → {calib_path}")
print(f"\n✓ All models trained successfully!")
roc_str = f"{roc_auc_final:.4f}" if roc_auc_final is not None else "n/a"
print(f"  Brier={brier_final:.4f}  ROC-AUC={roc_str}")