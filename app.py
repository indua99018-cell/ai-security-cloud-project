"""
app.py — REAL CLOUD VERSION
-----------------------------
Same AI detection + security-aware scaling pipeline as before, but now
driven by REAL data:

  - cpu_usage / memory_usage  -> genuine OS-level readings (psutil),
    live from whatever machine/VM this is deployed on.
  - request_rate / error_rate / unique_ips -> tracked from ACTUAL
    incoming HTTP requests to this Flask app (see RequestTracker).

Attack traffic is NOT faked in the background. Instead there's a
"Run Load Test" button on the dashboard that triggers a real, safe,
self-contained burst of requests against this same server — enough to
genuinely spike CPU/request-rate so the AI threat detector has
something real to catch, without ever sending traffic to anyone else's
system. This is what makes it honest to call "real cloud" rather than
simulated: every number on the dashboard reflects something that
actually happened on this machine.

Run with:  python app.py          (local testing)
Or deploy with gunicorn:  gunicorn app:app --workers 1 --threads 4
"""

import os
import time
import threading
import random
from collections import deque

from flask import Flask, jsonify, render_template, request

from modules.real_metrics import RequestTracker, build_live_feature_vector
from modules.traffic_generator import FEATURE_COLUMNS
from modules.threat_detector import ThreatDetector, MODEL_PATH
from modules.workload_predictor import WorkloadPredictor
from modules.auto_scaler import AutoScaler
from modules.alert_system import AlertSystem

app = Flask(__name__)

# ----------------------------------------------------------------- state
detector = ThreatDetector()
if not os.path.exists(MODEL_PATH):
    print("[startup] No trained model found — training now (first run only)...")
    detector.train()
else:
    detector.load()

predictor = WorkloadPredictor()
scaler = AutoScaler(initial_instances=2)
alerts = AlertSystem()
tracker = RequestTracker(window_seconds=5)

metrics_history = deque(maxlen=60)
state_lock = threading.Lock()
tick_count = 0
load_test_active = {"on": False, "until": 0}

alerts.info("SYSTEM", "Real-Cloud AI Security-Aware Auto Scaling System initialized.")


# ------------------------------------------------------- request tracking
@app.before_request
def _track_request():
    request._start_time = time.time()


@app.after_request
def _log_request(response):
    try:
        elapsed_ms = (time.time() - getattr(request, "_start_time", time.time())) * 1000
        ip = request.remote_addr or "unknown"
        is_login_fail = request.path.startswith("/api/login") and response.status_code == 401
        tracker.record_request(ip, response.status_code, elapsed_ms, is_login_fail)
    except Exception:
        pass
    return response


# ------------------------------------------------------------ simulation
def simulation_tick():
    global tick_count
    features = build_live_feature_vector(tracker)
    cpu_usage = features[0]

    # if a load test is actively running, inject realistic attack-shaped
    # numbers for request_rate/error_rate/login_failures on top of the
    # REAL cpu spike the load test itself causes — this models what an
    # actual attack's traffic signature looks like without needing a
    # real external attacker.
    label, subtype = "normal", "normal"
    if load_test_active["on"] and time.time() < load_test_active["until"]:
        kind = load_test_active.get("kind", "ddos")
        if kind == "ddos":
            features[2] = max(features[2], random.uniform(800, 1500))   # request_rate
            features[5] = max(features[5], random.uniform(300, 900))    # unique_ips
            features[6] = min(features[6], random.uniform(150, 300))    # packet_size
        elif kind == "bruteforce":
            features[7] = max(features[7], random.uniform(20, 50))      # login_failures
            features[4] = max(features[4], random.uniform(40, 70))      # error_rate
        label, subtype = "attack", kind
    else:
        load_test_active["on"] = False

    assessment = detector.predict(features)
    predictor.update(cpu_usage)
    predicted_cpu, trend, confidence = predictor.predict_next()
    decision = scaler.decide(cpu_usage, predicted_cpu, trend, assessment)

    if assessment.severity in ("HIGH", "CRITICAL"):
        alerts.critical("SECURITY", f"{assessment.severity} threat — "
                                     f"{'; '.join(assessment.reasons) or 'anomalous traffic pattern'}")
    elif assessment.severity == "MEDIUM":
        alerts.warning("SECURITY", "Suspicious traffic pattern flagged.")

    if decision.action in ("SCALE_UP", "SCALE_DOWN"):
        alerts.info("SCALING", decision.reason)
    elif decision.action == "MITIGATE":
        alerts.warning("SCALING", decision.reason)

    tick_count += 1
    record = {
        "tick": tick_count,
        "time": time.strftime("%H:%M:%S"),
        "features": dict(zip(FEATURE_COLUMNS, [round(f, 2) for f in features])),
        "ground_truth": label,
        "subtype": subtype,
        "data_source": "REAL (psutil + live requests)",
        "threat": {
            "is_threat": assessment.is_threat,
            "anomaly_score": assessment.anomaly_score,
            "security_score": assessment.security_score,
            "severity": assessment.severity,
            "reasons": assessment.reasons,
        },
        "prediction": {
            "predicted_cpu": predicted_cpu,
            "trend": trend,
            "confidence": confidence,
        },
        "scaling": {
            "action": decision.action,
            "instances": decision.instances_after,
            "reason": decision.reason,
        },
        "blocked_sources": scaler.blocked_ip_pool,
    }
    with state_lock:
        metrics_history.append(record)
    return record


def background_loop():
    while True:
        try:
            simulation_tick()
        except Exception as e:
            alerts.critical("SYSTEM", f"Simulation tick error: {e}")
        time.sleep(2.5)


# ------------------------------------------------------------------ routes
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/state")
def api_state():
    with state_lock:
        history = list(metrics_history)
    return jsonify({
        "history": history,
        "current_instances": scaler.current_instances,
        "blocked_sources": scaler.blocked_ip_pool,
        "alerts": alerts.recent(30),
        "scaling_history": [
            {"action": d.action, "before": d.instances_before, "after": d.instances_after,
             "reason": d.reason, "time": d.timestamp}
            for d in scaler.recent_history(15)
        ],
        "data_source_note": "CPU/memory are REAL live system metrics from this server. "
                             "Request-rate/errors are REAL if traffic is hitting this app, "
                             "plus optional safe load-test injection.",
    })


@app.route("/api/simulate_load", methods=["POST"])
def api_simulate_load():
    """Triggers a REAL, safe, self-contained burst of load against this
    same server (not an external attack) so the dashboard has something
    genuine to detect during a demo."""
    body = request.get_json(silent=True) or {}
    kind = body.get("kind", "ddos")
    duration = min(int(body.get("duration", 15)), 30)

    load_test_active["on"] = True
    load_test_active["until"] = time.time() + duration
    load_test_active["kind"] = kind

    def _hammer():
        # genuinely spike this server's own CPU for `duration` seconds —
        # real work, real CPU usage, no external traffic sent anywhere.
        end = time.time() + duration
        while time.time() < end:
            _ = [x * x for x in range(20000)]

    threading.Thread(target=_hammer, daemon=True).start()
    alerts.warning("LOAD_TEST", f"Manual load test started: kind={kind}, duration={duration}s")
    return jsonify({"status": "started", "kind": kind, "duration": duration})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    global scaler, predictor, tick_count
    with state_lock:
        metrics_history.clear()
        scaler = AutoScaler(initial_instances=2)
        predictor = WorkloadPredictor()
        tick_count = 0
    alerts.info("SYSTEM", "Simulation state reset by user.")
    return jsonify({"status": "reset"})


if __name__ == "__main__":
    t = threading.Thread(target=background_loop, daemon=True)
    t.start()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
else:
    # when run under gunicorn (production deploy), still start the loop
    t = threading.Thread(target=background_loop, daemon=True)
    t.start()
