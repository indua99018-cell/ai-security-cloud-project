"""
train_model.py
----------------
Standalone script to (re)train the AI threat-detection model and produce
a full evaluation report: classification metrics, a confusion matrix,
and a per-attack-type detection chart — saved as images under
evaluation/ so they can be dropped straight into your review slides/report.

Run this whenever you want fresh model files, or to demonstrate the AI
training + evaluation process live during your review.

Usage:
    python train_model.py
"""

import os
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report

from modules.traffic_generator import generate_training_dataset, FEATURE_COLUMNS
from modules.threat_detector import ThreatDetector

EVAL_DIR = "evaluation"


def main():
    os.makedirs(EVAL_DIR, exist_ok=True)

    print("=" * 60)
    print("AI-Based Security-Aware Auto Scaling — Model Training")
    print("=" * 60)

    print("\n[1/4] Generating simulated training dataset...")
    df = generate_training_dataset(n_normal=4000, n_attack=400)
    df.to_csv("data/training_dataset.csv", index=False)
    print(f"      -> {df.shape[0]} samples "
          f"({(df['label']=='normal').sum()} normal / {(df['label']=='attack').sum()} attack)")
    print(f"      -> saved to data/training_dataset.csv")

    print("\n[2/4] Training Isolation Forest on normal traffic only...")
    detector = ThreatDetector()
    detector.train(df)
    print("      -> model saved to models/isolation_forest.joblib")
    print("      -> scaler saved to models/scaler.joblib")

    print("\n[3/4] Evaluating on a balanced held-out set...")
    attacks = df[df["label"] == "attack"].reset_index(drop=True)
    normals = df[df["label"] == "normal"].sample(
        n=min(400, (df["label"] == "normal").sum()), random_state=1
    ).reset_index(drop=True)

    eval_rows = list(attacks.itertuples(index=False)) + list(normals.itertuples(index=False))

    y_true, y_pred, subtypes = [], [], []
    for row in eval_rows:
        row_dict = row._asdict()
        features = [row_dict[c] for c in FEATURE_COLUMNS]
        assessment = detector.predict(features)
        y_true.append(1 if row_dict["label"] == "attack" else 0)
        y_pred.append(1 if assessment.is_threat else 0)
        subtypes.append(row_dict["subtype"])

    cm = confusion_matrix(y_true, y_pred)
    report_dict = classification_report(
        y_true, y_pred, target_names=["normal", "attack"], output_dict=True, zero_division=0
    )
    report_text = classification_report(
        y_true, y_pred, target_names=["normal", "attack"], zero_division=0
    )
    print("\n" + report_text)

    # ---- per-attack-subtype recall (ddos / bruteforce / bot_scrape) ----
    subtype_recall = {}
    for st in sorted(set(subtypes) - {"normal"}):
        idx = [i for i, s in enumerate(subtypes) if s == st]
        correct = sum(y_pred[i] == 1 for i in idx)
        subtype_recall[st] = correct / len(idx) * 100 if idx else 0.0
        print(f"      {st:12s} detection rate: {correct}/{len(idx)}  ({subtype_recall[st]:.1f}%)")

    print("\n[4/4] Saving evaluation charts to evaluation/ ...")

    # --- Confusion matrix heatmap ---
    plt.figure(figsize=(5, 4.2))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["normal", "attack"], yticklabels=["normal", "attack"],
        cbar=False, annot_kws={"size": 14, "weight": "bold"}
    )
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Threat Detector — Confusion Matrix")
    plt.tight_layout()
    plt.savefig(os.path.join(EVAL_DIR, "confusion_matrix.png"), dpi=150)
    plt.close()

    # --- Per-attack-type detection rate bar chart ---
    plt.figure(figsize=(6, 4.2))
    names = list(subtype_recall.keys())
    values = [subtype_recall[n] for n in names]
    bars = plt.bar(names, values, color=["#EF4444", "#F0B429", "#5B8DEF"][:len(names)])
    plt.ylim(0, 105)
    plt.ylabel("Detection Rate (%)")
    plt.title("Detection Rate by Attack Type")
    for b, v in zip(bars, values):
        plt.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.1f}%", ha="center", fontsize=10, fontweight="bold")
    plt.tight_layout()
    plt.savefig(os.path.join(EVAL_DIR, "detection_rate_by_type.png"), dpi=150)
    plt.close()

    # --- Overall precision/recall/f1 bar chart ---
    plt.figure(figsize=(5, 4.2))
    metrics_names = ["Precision", "Recall", "F1-score"]
    metrics_values = [
        report_dict["attack"]["precision"] * 100,
        report_dict["attack"]["recall"] * 100,
        report_dict["attack"]["f1-score"] * 100,
    ]
    bars = plt.bar(metrics_names, metrics_values, color="#4FD1C5")
    plt.ylim(0, 105)
    plt.ylabel("Score (%)")
    plt.title("Attack-Class Detection Metrics")
    for b, v in zip(bars, metrics_values):
        plt.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.1f}%", ha="center", fontsize=10, fontweight="bold")
    plt.tight_layout()
    plt.savefig(os.path.join(EVAL_DIR, "precision_recall_f1.png"), dpi=150)
    plt.close()

    # --- Save raw metrics as JSON for the report/appendix ---
    with open(os.path.join(EVAL_DIR, "metrics.json"), "w") as f:
        json.dump({
            "confusion_matrix": cm.tolist(),
            "classification_report": report_dict,
            "subtype_detection_rate": subtype_recall,
            "n_samples_evaluated": len(y_true),
        }, f, indent=2)

    print("      -> evaluation/confusion_matrix.png")
    print("      -> evaluation/detection_rate_by_type.png")
    print("      -> evaluation/precision_recall_f1.png")
    print("      -> evaluation/metrics.json")

    print("\nDone. Run `python app.py` to launch the live dashboard.")
    print("=" * 60)


if __name__ == "__main__":
    main()
