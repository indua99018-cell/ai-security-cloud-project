"""
threat_detector.py
--------------------
The AI core of the system.

Uses an Isolation Forest (unsupervised anomaly detection) trained ONLY on
normal traffic. In production/real cloud systems you rarely have clean
labeled attack data in advance, so an isolation forest that learns "what
normal looks like" and flags deviations is a realistic and defensible
choice for a security-aware system - it can catch attack patterns it has
never explicitly seen before (zero-day-style anomalies), unlike a plain
supervised classifier.

A secondary rule-based layer adds explainability (SOC analysts / your
project evaluators will want to know WHY something was flagged, not just
a black-box score) and catches obvious signals (auth-failure floods).

Public API:
    train()                 -> trains + persists the model
    load()                  -> loads a persisted model
    predict(features_dict)  -> returns a ThreatAssessment
"""

import os
import joblib
import numpy as np
from dataclasses import dataclass, field
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from modules.traffic_generator import FEATURE_COLUMNS, generate_training_dataset

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")


@dataclass
class ThreatAssessment:
    is_threat: bool
    anomaly_score: float          # 0 (normal) - 100 (highly anomalous)
    security_score: float         # 100 (fully secure) - 0 (critical)
    reasons: list = field(default_factory=list)
    severity: str = "LOW"         # LOW / MEDIUM / HIGH / CRITICAL


class ThreatDetector:
    def __init__(self):
        self.model = None
        self.scaler = None

    # ---------------------------------------------------------- training
    def train(self, df=None, contamination=0.03):
        """Train the Isolation Forest on normal traffic only."""
        if df is None:
            df = generate_training_dataset()

        normal_df = df[df["label"] == "normal"][FEATURE_COLUMNS]

        self.scaler = StandardScaler()
        X = self.scaler.fit_transform(normal_df.values)

        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)

        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)
        return self

    def load(self):
        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        return self

    def is_ready(self):
        return self.model is not None and self.scaler is not None

    # --------------------------------------------------------- inference
    def predict(self, features):
        """features: list/array in FEATURE_COLUMNS order."""
        if not self.is_ready():
            raise RuntimeError("ThreatDetector model not loaded. Call train() or load() first.")

        X = self.scaler.transform([features])
        raw_score = self.model.decision_function(X)[0]   # higher = more normal
        pred = self.model.predict(X)[0]                    # 1 = normal, -1 = anomaly

        # Map decision_function (~ -0.3..0.3) to an intuitive 0-100 anomaly score
        anomaly_score = float(np.clip((0.25 - raw_score) / 0.5 * 100, 0, 100))

        cpu, mem, req_rate, resp_time, error_rate, unique_ips, pkt_size, login_fail = features

        reasons = []
        rule_penalty = 0

        if login_fail >= 10:
            reasons.append(f"Excessive login failures detected ({int(login_fail)} in window)")
            rule_penalty += 30
        if error_rate >= 30:
            reasons.append(f"High error rate ({error_rate:.1f}%) suggests malformed/malicious requests")
            rule_penalty += 20
        if req_rate >= 900:
            reasons.append(f"Request rate spike ({req_rate:.0f} req/s) consistent with DDoS")
            rule_penalty += 25
        if unique_ips >= 400:
            reasons.append(f"Traffic from unusually large IP pool ({unique_ips:.0f} IPs) — possible botnet")
            rule_penalty += 20
        if pkt_size <= 250 and req_rate >= 500:
            reasons.append("Small packet flood pattern typical of volumetric DDoS")
            rule_penalty += 10

        is_anomaly_ml = bool(pred == -1)
        if is_anomaly_ml and not reasons:
            reasons.append("AI model flagged statistical deviation from learned normal traffic profile")

        combined_score = float(np.clip(anomaly_score * 0.6 + rule_penalty * 1.0, 0, 100))
        is_threat = bool(is_anomaly_ml or combined_score >= 40)

        if combined_score >= 75:
            severity = "CRITICAL"
        elif combined_score >= 55:
            severity = "HIGH"
        elif combined_score >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        security_score = float(np.clip(100 - combined_score, 0, 100))

        return ThreatAssessment(
            is_threat=is_threat,
            anomaly_score=round(combined_score, 2),
            security_score=round(security_score, 2),
            reasons=reasons,
            severity=severity,
        )


if __name__ == "__main__":
    detector = ThreatDetector()
    df = generate_training_dataset()
    detector.train(df)
    print("Model trained and saved to", MODEL_PATH)

    # quick sanity evaluation on held-out attack rows
    from modules.traffic_generator import FEATURE_COLUMNS as FC
    attacks = df[df["label"] == "attack"]
    normals = df[df["label"] == "normal"]

    caught = sum(detector.predict(row[FC].values.tolist()).is_threat for _, row in attacks.iterrows())
    false_alarms = sum(detector.predict(row[FC].values.tolist()).is_threat for _, row in normals.sample(200, random_state=1).iterrows())

    print(f"Detected {caught}/{len(attacks)} attack samples ({caught/len(attacks)*100:.1f}% recall)")
    print(f"False alarms on 200 normal samples: {false_alarms} ({false_alarms/200*100:.1f}%)")
