"""
real_metrics.py
-----------------
Replaces simulated CPU/memory numbers with REAL system metrics, read live
from whatever machine this runs on — your laptop, or once deployed, an
actual free-tier cloud VM (Oracle Cloud Always Free, Render, etc).

This is what makes the project genuinely "real cloud" rather than purely
simulated: cpu_usage and memory_usage below are true OS-level readings,
not generated numbers.

Request-level features (request_rate, error_rate, unique_ips,
login_failures) are tracked from ACTUAL incoming Flask requests — see
RequestTracker below — so if you open the dashboard from multiple
browsers/devices, those are real numbers too.

Attack simulation stays intentionally separate (see /api/simulate_load
in app.py): you can't ethically launch a real DDoS at your own free-tier
server without risking account suspension, so attacks are triggered
on-demand, locally, as a safe controlled load test — not a fabricated
background number.
"""

import psutil
import time
import threading
from collections import deque


class RequestTracker:
    """Tracks real incoming HTTP requests in a sliding time window."""

    def __init__(self, window_seconds=5):
        self.window_seconds = window_seconds
        self.lock = threading.Lock()
        self.timestamps = deque()
        self.errors = deque()
        self.ips = deque()
        self.login_failures = deque()
        self.response_times = deque()

    def record_request(self, ip, status_code, response_time_ms, is_login_failure=False):
        now = time.time()
        with self.lock:
            self.timestamps.append(now)
            self.ips.append((now, ip))
            self.response_times.append((now, response_time_ms))
            if status_code >= 400:
                self.errors.append(now)
            if is_login_failure:
                self.login_failures.append(now)
            self._prune(now)

    def _prune(self, now):
        cutoff = now - self.window_seconds
        for dq in (self.timestamps, self.errors, self.login_failures):
            while dq and dq[0] < cutoff:
                dq.popleft()
        while self.ips and self.ips[0][0] < cutoff:
            self.ips.popleft()
        while self.response_times and self.response_times[0][0] < cutoff:
            self.response_times.popleft()

    def snapshot(self):
        now = time.time()
        with self.lock:
            self._prune(now)
            req_count = len(self.timestamps)
            request_rate = req_count / max(self.window_seconds, 1)
            error_count = len(self.errors)
            error_rate = (error_count / req_count * 100) if req_count else 0.0
            unique_ips = len(set(ip for _, ip in self.ips)) or 1
            login_failures = len(self.login_failures)
            resp_times = [t for _, t in self.response_times]
            avg_response_time = sum(resp_times) / len(resp_times) if resp_times else 50.0
        return {
            "request_rate": max(request_rate, 1.0),
            "error_rate": error_rate,
            "unique_ips": float(unique_ips),
            "login_failures": float(login_failures),
            "avg_response_time": avg_response_time,
        }


def get_real_system_metrics():
    """Real, live OS-level CPU and memory usage — not simulated."""
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory().percent
    net = psutil.net_io_counters()
    return {
        "cpu_usage": float(cpu),
        "memory_usage": float(mem),
        "bytes_sent": net.bytes_sent,
        "bytes_recv": net.bytes_recv,
    }


def build_live_feature_vector(tracker: RequestTracker, packet_size_avg=800.0):
    """Combines real system metrics + real request-tracker data into the
    8-feature vector the AI threat detector expects."""
    sys_m = get_real_system_metrics()
    req_m = tracker.snapshot()
    features = [
        sys_m["cpu_usage"],
        sys_m["memory_usage"],
        req_m["request_rate"],
        req_m["avg_response_time"],
        req_m["error_rate"],
        req_m["unique_ips"],
        packet_size_avg,
        req_m["login_failures"],
    ]
    return features
