"""
workload_predictor.py
-----------------------
Predicts near-future workload (CPU utilization) from the recent history of
observations, so the auto-scaler can act proactively instead of only
reacting after resources are already saturated.

Approach: a lightweight sliding-window linear regression over the last N
samples (trend + level) — deliberately simple and explainable, which is
exactly what a proactive-vs-reactive scaling argument needs for a review
demo. It is swapped out easily for an LSTM/Prophet model later without
touching any other module, since only `predict_next()` is called
externally.
"""

import numpy as np
from collections import deque


class WorkloadPredictor:
    def __init__(self, window_size=12, horizon=3):
        """
        window_size: number of most recent samples used to fit the trend
        horizon: how many steps ahead to forecast
        """
        self.window_size = window_size
        self.horizon = horizon
        self.history = deque(maxlen=window_size)

    def update(self, cpu_usage):
        self.history.append(cpu_usage)

    def predict_next(self):
        """Returns (predicted_cpu, trend_direction, confidence)."""
        n = len(self.history)
        if n < 3:
            last = self.history[-1] if n else 30.0
            return last, "stable", 0.3

        y = np.array(self.history)
        x = np.arange(n)

        # simple least-squares linear fit
        A = np.vstack([x, np.ones(n)]).T
        slope, intercept = np.linalg.lstsq(A, y, rcond=None)[0]

        predicted = slope * (n - 1 + self.horizon) + intercept
        predicted = float(np.clip(predicted, 0, 100))

        if slope > 0.8:
            trend = "rising"
        elif slope < -0.8:
            trend = "falling"
        else:
            trend = "stable"

        # confidence grows with more history and a cleaner (lower variance) fit
        residuals = y - (slope * x + intercept)
        fit_quality = 1.0 / (1.0 + np.std(residuals))
        confidence = float(np.clip(0.3 + 0.5 * (n / self.window_size) * fit_quality, 0, 0.95))

        return round(predicted, 2), trend, round(confidence, 2)
