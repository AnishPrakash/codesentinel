"""Train the triage model and export it for CodeSentinel.

    python scripts/train_triage.py --data data/processed/dataset.csv --out models/

Produces exactly the two files inference expects:
    models/triage.onnx           float32[N,52] -> float32[N,13] sigmoid
    models/feature_scaler.json   min, max, feature_version, feature_names, thresholds

What this model is allowed to do, and the code that consumes it enforces this:
it reorders findings within a severity band and it emits a "needs review" hint
when it scores a class highly and no rule fired. It never creates a finding and
never names a CWE. So the metric that matters is ranking quality, not whether
you could ship it as a detector - and nothing here should be quoted as a
detection rate.

Two methodology points that decide whether the numbers mean anything:

  * The split is by GROUP, never by row. A vulnerable function and its own
    fixed twin share a group, so they cannot land on opposite sides. Splitting
    on rows makes every metric look far better than it is, and is the most
    common way a vulnerability dataset lies to you.

  * The scaler is fitted on the TRAINING fold only. Fitting on everything leaks
    the test distribution into the model's input range.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import average_precision_score, precision_recall_fscore_support
from sklearn.model_selection import GroupShuffleSplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from codesentinel.features.extract import (        # noqa: E402
    FEATURE_NAMES, FEATURE_VERSION,
)
from codesentinel.triage.model import CLASS_ORDER  # noqa: E402

SEED = 20260903


class TriageNet(nn.Module):
    """Deliberately small. 52 inputs and a few thousand samples do not support
    anything deeper, and a model that has to ship inside a pip package and run
    on a laptop CPU in single-digit milliseconds has a budget."""

    def __init__(self, n_features: int, n_classes: int, hidden: int = 256):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n_features, hidden),
            nn.BatchNorm1d(hidden),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden, hidden),
            nn.BatchNorm1d(hidden),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden, hidden // 2),
            nn.BatchNorm1d(hidden // 2),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden // 2, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)               # logits; sigmoid is applied at export


def load(path: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray, pd.DataFrame]:
    df = pd.read_csv(path)
    missing = [c for c in FEATURE_NAMES if c not in df.columns]
    if missing:
        raise SystemExit(f"dataset is missing {len(missing)} features: {missing[:5]}")
    label_cols = [f"y_{c}" for c in CLASS_ORDER]
    missing_y = [c for c in label_cols if c not in df.columns]
    if missing_y:
        raise SystemExit(f"dataset is missing labels: {missing_y}")

    X = df[FEATURE_NAMES].to_numpy(dtype=np.float32)
    y = df[label_cols].to_numpy(dtype=np.float32)
    groups = df["group"].to_numpy()
    return X, y, groups, df


def split(X, y, groups, test_size=0.2, val_size=0.2):
    outer = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=SEED)
    train_val_idx, test_idx = next(outer.split(X, y, groups))
    inner = GroupShuffleSplit(n_splits=1, test_size=val_size, random_state=SEED)
    tr_rel, va_rel = next(inner.split(X[train_val_idx], y[train_val_idx],
                                      groups[train_val_idx]))
    train_idx = train_val_idx[tr_rel]
    val_idx = train_val_idx[va_rel]

    overlap = (set(groups[train_idx]) & set(groups[test_idx])) | \
              (set(groups[val_idx]) & set(groups[test_idx]))
    assert not overlap, f"group leaked across the split: {sorted(overlap)[:3]}"
    return train_idx, val_idx, test_idx


def fit_scaler(X_train: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    mins = X_train.min(axis=0)
    maxs = X_train.max(axis=0)
    return mins.astype(np.float32), maxs.astype(np.float32)


def scale(X, mins, maxs):
    span = np.where((maxs - mins) == 0, 1.0, maxs - mins)
    return np.clip((X - mins) / span, 0.0, 1.0).astype(np.float32)


def train(Xtr, ytr, Xva, yva, epochs=300, patience=50, lr=1e-3):
    torch.manual_seed(SEED)
    np.random.seed(SEED)

    model = TriageNet(Xtr.shape[1], ytr.shape[1])
    # Rare classes would otherwise be ignored: predicting all-zero is already
    # ~95% accurate for them, and accuracy is not what we are optimising.
    positives = ytr.sum(axis=0)
    pos_weight = torch.tensor(
        np.where(positives > 0, (len(ytr) - positives) / np.maximum(positives, 1), 1.0),
        dtype=torch.float32).clamp(max=50.0)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, mode='max', factor=0.5, patience=10)

    Xtr_t = torch.from_numpy(Xtr)
    ytr_t = torch.from_numpy(ytr)
    Xva_t = torch.from_numpy(Xva)

    best_score, best_state, since = -1.0, None, 0
    batch = 64

    for epoch in range(1, epochs + 1):
        model.train()
        perm = torch.randperm(len(Xtr_t))
        for i in range(0, len(perm), batch):
            idx = perm[i:i + batch]
            if len(idx) < 2:                      # BatchNorm needs >1
                continue
            opt.zero_grad()
            loss = criterion(model(Xtr_t[idx]), ytr_t[idx])
            loss.backward()
            opt.step()

        model.eval()
        with torch.no_grad():
            va_prob = torch.sigmoid(model(Xva_t)).numpy()
        # Average precision is threshold-free, which is the right thing to
        # early-stop on for a ranker.
        trained = [i for i in range(yva.shape[1]) if yva[:, i].sum() > 0]
        score = float(np.mean([
            average_precision_score(yva[:, i], va_prob[:, i]) for i in trained
        ])) if trained else 0.0

        if score > best_score + 1e-4:
            best_score, best_state, since = score, {
                k: v.clone() for k, v in model.state_dict().items()}, 0
        else:
            since += 1
            if since >= patience:
                print(f"  early stop at epoch {epoch}")
                break
        
        scheduler.step(score)

        if epoch % 20 == 0:
            print(f"  epoch {epoch:3d}  val mAP {score:.3f}  (best {best_score:.3f})")

    model.load_state_dict(best_state)
    model.eval()
    print(f"  best validation mAP: {best_score:.3f}")
    return model


def tune_thresholds(model, Xva, yva) -> list[float]:
    """Per-class threshold, chosen on validation, maximising F1.

    A single 0.5 across thirteen classes with wildly different base rates is a
    number nobody chose. Classes with no validation positives keep 0.5 and are
    reported as untrained rather than tuned to noise.
    """
    with torch.no_grad():
        prob = torch.sigmoid(model(torch.from_numpy(Xva))).numpy()
    thresholds = []
    for i in range(yva.shape[1]):
        if yva[:, i].sum() == 0:
            thresholds.append(0.5)
            continue
        best_t, best_f1 = 0.5, -1.0
        for t in np.arange(0.05, 0.96, 0.05):
            pred = (prob[:, i] >= t).astype(int)
            _, _, f1, _ = precision_recall_fscore_support(
                yva[:, i], pred, average="binary", zero_division=0)
            if f1 > best_f1:
                best_t, best_f1 = float(t), float(f1)
        thresholds.append(round(best_t, 2))
    return thresholds


def evaluate(model, Xte, yte, thresholds, out_dir: Path) -> dict:
    with torch.no_grad():
        prob = torch.sigmoid(model(torch.from_numpy(Xte))).numpy()

    rows = []
    for i, cls in enumerate(CLASS_ORDER):
        support = int(yte[:, i].sum())
        if support == 0:
            rows.append({"class": cls, "support": 0, "precision": None,
                         "recall": None, "f1": None, "average_precision": None,
                         "threshold": thresholds[i], "status": "untrained"})
            continue
        pred = (prob[:, i] >= thresholds[i]).astype(int)
        p, r, f1, _ = precision_recall_fscore_support(
            yte[:, i], pred, average="binary", zero_division=0)
        ap = average_precision_score(yte[:, i], prob[:, i])
        rows.append({"class": cls, "support": support,
                     "precision": round(float(p), 3), "recall": round(float(r), 3),
                     "f1": round(float(f1), 3), "average_precision": round(float(ap), 3),
                     "threshold": thresholds[i],
                     "status": "ok" if support >= 30 else "too few samples"})

    report = pd.DataFrame(rows)
    out_dir.mkdir(parents=True, exist_ok=True)
    report.to_csv(out_dir / "test_report.csv", index=False)

    scored = report[report["support"] > 0]
    reliable = report[(report["support"] >= 30)]
    print("\n" + report.to_string(index=False))
    print(f"\ntest rows: {len(yte)}   classes with any test positive: {len(scored)}")
    if len(reliable):
        print(f"macro F1 over classes with >=30 test samples: "
              f"{reliable['f1'].mean():.3f}")
    print(f"\nwritten: {out_dir / 'test_report.csv'}")
    print("\nClasses marked 'untrained' had no positive sample in this dataset. "
          "They are not zero-performing - they are unmeasured. Say that, or add "
          "a source that covers them.")
    return {"report": report}


def export_onnx(model, mins, maxs, thresholds, out_dir: Path,
                languages: list[str] | None = None) -> None:
    """Export with sigmoid baked in, so inference does not have to know."""
    class WithSigmoid(nn.Module):
        def __init__(self, inner):
            super().__init__()
            self.inner = inner

        def forward(self, x):
            return torch.sigmoid(self.inner(x))

    out_dir.mkdir(parents=True, exist_ok=True)
    wrapped = WithSigmoid(model).eval()
    dummy = torch.zeros(1, len(FEATURE_NAMES), dtype=torch.float32)

    onnx_path = out_dir / "triage.onnx"
    torch.onnx.export(
        wrapped, dummy, str(onnx_path),
        input_names=["features"], output_names=["probabilities"],
        dynamic_axes={"features": {0: "batch"}, "probabilities": {0: "batch"}},
        opset_version=17,
    )

    # The exporter may write weights to a sibling triage.onnx.data file. That is
    # fine locally and broken everywhere else: `cs install-model` fetches two
    # files, and a model that silently needs a third fails to load on the demo
    # machine. Fold everything back into one file and delete the stray.
    import onnx

    model_proto = onnx.load(str(onnx_path))          # follows external data
    onnx.save_model(model_proto, str(onnx_path), save_as_external_data=False)
    stray = onnx_path.with_suffix(".onnx.data")
    if stray.exists():
        stray.unlink()
    for leftover in out_dir.glob("*.onnx.data"):
        leftover.unlink()

    scaler_path = out_dir / "feature_scaler.json"
    scaler_path.write_text(json.dumps({
        "min": [float(x) for x in mins],
        "max": [float(x) for x in maxs],
        "feature_version": FEATURE_VERSION,
        "feature_names": FEATURE_NAMES,
        "class_order": CLASS_ORDER,
        "thresholds": thresholds,
        # Inference refuses to score a language absent from this list. A model
        # trained only on Java has no basis for an opinion about Python, and
        # emitting 0.02 for it is worse than emitting nothing.
        "languages": sorted(languages or []),
        "max_clipped_fraction": 0.30,
    }, indent=2), encoding="utf-8")

    print(f"\nwritten: {onnx_path}  ({onnx_path.stat().st_size / 1024:.0f} KB)")
    print(f"written: {scaler_path}")

    # The export is only useful if it agrees with the model it came from.
    import onnxruntime as ort

    # Load from bytes, not from the path: that proves the file is self-contained
    # rather than quietly reading a sibling .data file that happens to be there.
    sess = ort.InferenceSession(onnx_path.read_bytes(),
                                providers=["CPUExecutionProvider"])
    probe = np.random.default_rng(SEED).random(
        (4, len(FEATURE_NAMES))).astype(np.float32)
    with torch.no_grad():
        expected = wrapped(torch.from_numpy(probe)).numpy()
    got = sess.run(None, {"features": probe})[0]
    drift = float(np.abs(expected - got).max())
    assert drift < 1e-4, f"ONNX disagrees with torch by {drift}"
    print(f"onnx matches torch to {drift:.2e} - export verified")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, default=Path("data/processed/dataset.csv"))
    ap.add_argument("--out", type=Path, default=Path("models"))
    ap.add_argument("--epochs", type=int, default=200)
    args = ap.parse_args()

    if not args.data.exists():
        raise SystemExit(f"{args.data} not found - run scripts/build_dataset.py first")

    X, y, groups, df = load(args.data)
    print(f"{len(X)} rows, {X.shape[1]} features, {len(set(groups))} groups")

    tr, va, te = split(X, y, groups)
    print(f"split: {len(tr)} train / {len(va)} val / {len(te)} test "
          f"(by group, verified disjoint)")

    mins, maxs = fit_scaler(X[tr])          # training fold only
    Xtr, Xva, Xte = scale(X[tr], mins, maxs), scale(X[va], mins, maxs), \
        scale(X[te], mins, maxs)

    print("\ntraining:")
    model = train(Xtr, y[tr], Xva, y[va], epochs=args.epochs)

    thresholds = tune_thresholds(model, Xva, y[va])
    print(f"\ntuned thresholds: {dict(zip(CLASS_ORDER, thresholds))}")

    evaluate(model, Xte, y[te], thresholds, ROOT / "docs" / "model")
    languages = sorted(df["language"].unique().tolist())
    export_onnx(model, mins, maxs, thresholds, args.out, languages)
    print(f"\ntrained on languages: {languages}")
    print("Inference will decline to score any other language, "
          "and will decline when a vector falls outside the "
          "training range.")

    print("\nNext:")
    print("  cs version                       # should say: triage model: loaded")
    print("  cs scan demo/invoices.py         # findings now carry a confidence")
    print("  python scripts/benchmark.py      # the honest cost of the model")


if __name__ == "__main__":
    main()
