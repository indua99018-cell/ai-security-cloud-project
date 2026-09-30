"""
traffic_generator.py
---------------------
Simulates real-time cloud traffic since we don't have a live cloud cluster.
Generates realistic feature vectors representing incoming requests:

    cpu_usage        -> % CPU utilization at the moment
    memory_usage      -> % memory utilization
    request_rate      -> requests per second hitting the API
    avg_response_time -> ms
    error_rate        -> % of requests returning 4xx/5xx
    unique_ips        -> number of distinct source IPs in the window
    packet_size_avg   -> average packet size (bytes)
    login_failures    -> failed auth attempts in the window

Two traffic classes are produced:
    1. "normal"   -> everyday workload fluctuation (diurnal pattern)
    2. "attack"   -> DDoS / brute-force / suspicious-bot style traffic

This module is used both to build the training dataset for the AI threat
detector and to drive the live simulation shown on the dashboard.
"""

import numpy as np
import pandas as pd
import time
import random


FEATURE_COLUMNS = [
    "cpu_usage", "memory_usage", "request_rate", "avg_response_time",
    "error_rate", "unique_ips", "packet_size_avg", "login_failures"
]


def _normal_sample(t=None):
    """Generate one sample of normal, healthy cloud traffic.
    A mild diurnal (time-of-day) load pattern is layered in so the
    workload predictor has a genuine pattern to learn."""
    if t is None:
        t = time.time()

    # Diurnal wave: load rises during "day" hours, falls at "night"
    hour_phase = (t % 86400) / 86400.0
    diurnal = 0.5 + 0.4 * np.sin(2 * np.pi * (hour_phase - 0.25))

    base_load = max(0.05, diurnal + np.random.normal(0, 0.05))

    cpu = np.clip(20 + base_load * 55 + np.random.normal(0, 4), 5, 90)
    mem = np.clip(25 + base_load * 45 + np.random.normal(0, 4), 10, 85)
    req_rate = max(1, np.random.normal(80 + base_load * 150, 15))
    resp_time = max(5, np.random.normal(120 + base_load * 40, 15))
    error_rate = np.clip(np.random.normal(1.2, 0.6), 0, 5)
    unique_ips = max(5, np.random.normal(40 + base_load * 60, 8))
    pkt_size = np.random.normal(850, 90)
    login_fail = max(0, np.random.poisson(0.6))

    return [cpu, mem, req_rate, resp_time, error_rate, unique_ips, pkt_size, login_fail]


def _attack_sample(kind=None):
    """Generate one sample of malicious / abnormal traffic.
    kind: 'ddos', 'bruteforce', 'bot', or None (random choice)."""
    kind = kind or random.choice(["ddos", "bruteforce", "bot_scrape"])

    if kind == "ddos":
        cpu = np.clip(np.random.normal(92, 4), 70, 100)
        mem = np.clip(np.random.normal(88, 5), 60, 100)
        req_rate = np.random.normal(1400, 250)
        resp_time = np.random.normal(1800, 400)
        error_rate = np.random.normal(45, 10)
        unique_ips = np.random.normal(900, 150)     # botnet -> huge spread of IPs
        pkt_size = np.random.normal(200, 40)         # small flood packets
        login_fail = np.random.poisson(1)

    elif kind == "bruteforce":
        cpu = np.clip(np.random.normal(55, 8), 30, 80)
        mem = np.clip(np.random.normal(50, 8), 25, 75)
        req_rate = np.random.normal(300, 60)
        resp_time = np.random.normal(300, 80)
        error_rate = np.random.normal(60, 12)        # lots of auth failures -> 4xx
        unique_ips = np.random.normal(8, 3)           # few IPs hammering login
        pkt_size = np.random.normal(500, 60)
        login_fail = np.random.poisson(40)

    else:  # bot_scrape
        cpu = np.clip(np.random.normal(70, 6), 45, 95)
        mem = np.clip(np.random.normal(60, 6), 35, 85)
        req_rate = np.random.normal(600, 100)
        resp_time = np.random.normal(400, 100)
        error_rate = np.random.normal(15, 5)
        unique_ips = np.random.normal(25, 8)
        pkt_size = np.random.normal(1400, 150)        # large scraped payloads
        login_fail = np.random.poisson(2)

    cpu = float(np.clip(cpu, 0, 100))
    mem = float(np.clip(mem, 0, 100))
    req_rate = float(max(1, req_rate))
    resp_time = float(max(5, resp_time))
    error_rate = float(np.clip(error_rate, 0, 100))
    unique_ips = float(max(1, unique_ips))
    pkt_size = float(max(40, pkt_size))
    login_fail = float(max(0, login_fail))

    return [cpu, mem, req_rate, resp_time, error_rate, unique_ips, pkt_size, login_fail], kind


def generate_training_dataset(n_normal=4000, n_attack=400, seed=42):
    """Build a labeled dataset for offline model training / evaluation.
    The AI model itself only trains on the 'normal' rows (unsupervised
    anomaly detection), the attack rows are kept aside purely to measure
    detection accuracy afterwards."""
    np.random.seed(seed)
    random.seed(seed)

    rows = []
    base_t = time.time() - 86400  # walk through a simulated day
    for i in range(n_normal):
        t = base_t + i * (86400 / n_normal)
        sample = _normal_sample(t)
        rows.append(sample + ["normal", "normal"])

    for i in range(n_attack):
        sample, kind = _attack_sample()
        rows.append(sample + ["attack", kind])

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS + ["label", "subtype"])
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    return df


def live_sample(attack_probability=0.12):
    """Produce a single live sample for the running dashboard simulation.
    Randomly injects attack traffic at the given probability so the
    dashboard has something interesting to detect."""
    if random.random() < attack_probability:
        features, kind = _attack_sample()
        return features, "attack", kind
    else:
        return _normal_sample(), "normal", "normal"


if __name__ == "__main__":
    df = generate_training_dataset()
    df.to_csv("data/training_dataset.csv", index=False)
    print(f"Generated dataset: {df.shape[0]} rows -> data/training_dataset.csv")
    print(df["label"].value_counts())
