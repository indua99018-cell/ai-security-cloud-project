# AI-Based Security-Aware Auto Scaling Cloud System

**Group 20 — Dept. of ISE, SJC Institute of Technology**
Project Work Phase 2 — Implementation

A working prototype of a cloud auto-scaling system whose scaling decisions
are driven by **both** workload conditions **and** a live AI security
assessment — not CPU utilization alone, which is the gap this project's
literature review identified in existing IEEE work.

---

## 1. What this implements

| Slide topic (from Review 1 / 2) | Implemented as |
|---|---|
| Real-Time Monitoring | `modules/traffic_generator.py` — simulated live cloud traffic feed (CPU, memory, request rate, response time, error rate, unique IPs, login failures) |
| AI-Based Threat Detection | `modules/threat_detector.py` — **Isolation Forest** (unsupervised anomaly detection) trained on normal traffic, plus an explainable rule layer (DDoS / brute-force / bot patterns) |
| Intelligent Workload Prediction | `modules/workload_predictor.py` — sliding-window trend forecasting of near-future CPU load |
| Security-Aware Auto Scaling | `modules/auto_scaler.py` — the decision engine: scales on workload **only when traffic is clean**; mitigates instead of scaling during an active attack |
| Resource Management | `AutoScaler` instance pool (2–20 instances) with scale-up/down/hold logic |
| Alert & Reporting System | `modules/alert_system.py` — in-memory + CSV audit log (`logs/system_events.csv`) |
| Live Dashboard | `app.py` (Flask) + `templates/dashboard.html` — real-time charts, scaling log, alert feed |

### Why Isolation Forest?
Real cloud systems rarely have clean labeled attack data up front. Isolation
Forest learns what *normal* traffic looks like and flags statistical
deviations — so it can catch attack patterns it has never explicitly seen,
which matches the "unknown/zero-day anomaly" angle from your literature
review's research gap. A rule-based layer sits on top purely for
**explainability** (why was this flagged?), which a security dashboard needs.

### The "security-aware" decision logic (the core novelty)
```
IF a CRITICAL/HIGH threat is detected:
    -> Do NOT reward the attacker with more resources.
    -> MITIGATE (simulate blocking/throttling malicious sources).
    -> Only scale up, cautiously, if legitimate load is ALSO critical.
ELSE (traffic is clean):
    -> Scale UP proactively if CPU is high or predicted to rise.
    -> Scale DOWN if CPU is low and stable (cost optimization).
    -> Otherwise HOLD.
```
This is what existing CPU-only or security-only papers (see your Literature
Review table) don't combine — this project integrates both signals into one
decision.

---

## 2. Project structure

```
AI_Security_AutoScaling/
├── app.py                      # Flask app — dashboard + API + simulation loop
├── train_model.py              # Standalone script to (re)train the AI model
├── requirements.txt
├── modules/
│   ├── traffic_generator.py    # Simulated cloud traffic (normal + attacks)
│   ├── threat_detector.py      # AI anomaly detection (Isolation Forest)
│   ├── workload_predictor.py   # Workload forecasting
│   ├── auto_scaler.py          # Security-aware scaling decision engine
│   └── alert_system.py         # Logging / alerting
├── templates/
│   └── dashboard.html
├── static/
│   ├── css/style.css
│   └── js/dashboard.js
├── data/
│   └── training_dataset.csv    # Generated training data (regenerated on train)
├── evaluation/                 # AI model evaluation charts (generated on train)
│   ├── confusion_matrix.png
│   ├── detection_rate_by_type.png
│   ├── precision_recall_f1.png
│   └── metrics.json
├── models/
│   ├── isolation_forest.joblib # Trained model (regenerated on train)
│   └── scaler.joblib
└── logs/
    └── system_events.csv       # Audit trail of all alerts/decisions
```

---

## 3. Setup & running

Requires Python 3.9+.

```bash
cd AI_Security_AutoScaling
pip install -r requirements.txt

# Train the AI model (also runs automatically on first app launch if missing)
python train_model.py

# Launch the live dashboard
python app.py
```

Then open **http://localhost:5000** in a browser.

The simulation runs continuously in a background thread (one tick every
2.5s), randomly injecting attack traffic (~15% of samples: DDoS,
brute-force login, or bot scraping patterns) so you can watch the system
detect and respond to threats live, without needing a real cloud cluster
or actual attack traffic for the demo.

**Reset Simulation** button on the dashboard clears the instance pool and
history back to the starting state.

---

## 4. AI Model Evaluation (for your report/slides)

Running `python train_model.py` now also generates a full evaluation
report under `evaluation/`:

| File | What it shows |
|---|---|
| `confusion_matrix.png` | True/false positives & negatives on a balanced 800-sample held-out set |
| `detection_rate_by_type.png` | Detection rate broken down by attack type (DDoS / brute-force / bot-scrape) |
| `precision_recall_f1.png` | Precision, recall, F1-score for the attack class |
| `metrics.json` | Raw numbers behind all three charts, for your report appendix |

On the latest run: **99% overall accuracy**, **100% recall on all three
attack types**, **97.8% precision** (a handful of false positives on
normal traffic, expected of an unsupervised anomaly detector). Drop
these three PNGs straight into your Review PPT as the "AI Model
Evaluation" slide.

## 5. What to show in your Review

1. **`train_model.py` output** — model training + evaluation numbers
   (detection recall / false-positive rate) as your "AI model accuracy"
   result. The `evaluation/` charts are your visual evidence.
2. **Live dashboard** — let it run for a minute; point out:
   - CPU chart vs AI-predicted CPU (proactive prediction)
   - Anomaly/security score chart reacting to injected attacks
   - Scaling Decisions panel showing **MITIGATE** during attacks vs
     **SCALE_UP/DOWN** during clean traffic — this is the security-aware
     differentiator
   - Live traffic table with per-request classification
3. **`logs/system_events.csv`** — the audit trail, if asked about
   accountability/reporting.

---

## 6. Notes on this being a prototype

Traffic is **simulated**, not pulled from a real cloud provider — this is
standard for an academic Phase-2 prototype where provisioning a live
attacked cluster isn't practical. The `AutoScaler`'s "instances" and
"blocked sources" are a simulated resource pool rather than real VM/container
API calls. Swapping in real metrics (e.g., a cloud provider's monitoring
API) or a real mitigation action (e.g., a WAF/security-group API call) would
only require changing `traffic_generator.py`'s data source and adding an API
call inside `auto_scaler.py`'s `MITIGATE`/`SCALE_UP` branches — the AI
detection and decision logic itself would not need to change.

---

## Real Cloud Mode (Updated)

This project now uses **genuine system metrics** via `psutil` instead of
purely simulated numbers — CPU and memory readings are real, live data
from whatever machine runs it, and request/error rates are tracked from
actual incoming HTTP requests.

Two new things:
- **`modules/real_metrics.py`** — reads real OS-level CPU/memory, tracks real requests
- **"Run Load Test" buttons on the dashboard** — safely spike this server's
  own real CPU and inject realistic traffic signals, so the AI has
  something genuine to detect during a live demo (instead of an external
  attacker, which isn't safe or ethical to run against a free-tier account)

See **`DEPLOYMENT.md`** for step-by-step instructions to deploy this to a
real free cloud server (Render or Oracle Cloud Always Free).
